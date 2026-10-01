# 01 — 问题基线：radiata 当前同步架构与冗余来源

> 目的：把「本地回环强连通网络下约 95% 同步流量是冗余」这一观测还原成可推导的
> 结构性事实，作为后续所有调研与方案的锚点。全部结论给出源码位置。

## 1. radiata 同步的是什么

radiata 是一个去中心化集群的**收敛元数据库** + 路由数据面。需要收敛的元数据分四类
（`src/membership/sync.rs`、`src/resource/sync.rs`）：

| 泳道 | 内容 | 合并语义 |
| --- | --- | --- |
| membership descriptors | 成员描述符（端点、能力） | owner-marked，按属主收敛 |
| issuer trust bindings | 签发者信任快照（分页 keyset） | 单调并集 |
| resources | LWW 版本化寄存器 + CAS 条件写 | last-writer-wins / CAS |
| tombstones | leave / cleanup / revocation / checkpoint | 终态并集（有界重发） |

同步只在**已认证会话**（TLS 1.3）上直接进行，不经中继；多跳收敛靠「每一跳应用后再向
自己的对端推送」实现。连接度由 `k(n)` 公式维护（`src/membership/degree.rs`）：

| n | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 4096 |
|---|---|---|---|---|---|---|---|---|---|
| k(n) | 4 | 5 | 6 | 7 | 7 | 8 | 9 | 10 | 11 |

## 2. 当前引擎：推送式 watermark 反熵（push-only, sender-side diff）

核心状态机是 `WatermarkWalk<K>`（`src/sync_common.rs:897` 起），三个泳道共享同一套
「diff-only 推送」模型（`src/sync_common.rs` 模块注释自述为 git remote-tracking 思路）：

1. **发送方**为每个对端维护一张 watermark 表：该侧「认为对端已持有」的每行内容摘要
   （`row_digest`，进程内哈希，不上线）。
2. 每轮 pass 从扫描游标起按序扫描本地目录（每 tick 预算 256 行，
   `SCAN_BUDGET_PER_TICK`），把「存储摘要 ≠ 对端 watermark」的行打成有界页推给对端。
3. 页送达（admission-ack delivery truth）→ 提交 watermark 并推进游标；未送达 → 回退
   到该页扫描起点，下轮重发。
4. 关键常量（`src/sync_common.rs:733–748`、`src/membership/sync.rs:672–696`、
   `src/config.rs` 默认值）：

| 常量 | 值 | 含义 |
| --- | --- | --- |
| `anti_entropy_interval` | 1 s | 反熵驱动 tick |
| `DETECTION_CADENCE_TICKS` | 32 | 静默对端 ~32 s 一轮检测性重扫 |
| `WATERMARK_TABLE_CAP` | 8 192 | 每对端 watermark 条目上限 |
| `WATERMARK_REFRESH_PASSES` | 64 | 每 64 个完整 pass 清空表 → **向该对端整目录重发** |
| `SYNC_PEERS_PER_ROUND` | 2 | 每轮公平窗口服务的对端数 |
| `SNAPSHOT_RESEND_TICKS` | 8 | 未确认墓碑每 8 tick 重发 |
| `TOMBSTONE_CONFIRM_REFRESH_TICKS` | 16 | 墓碑确认集周期性重查 |
| `LEAVE_RESEND_CAP` | 64 | 每轮携带墓碑上限 |

5. 本地任何写入（`store.register_epoch()` 变化）会把**所有**对端的 walk `arm()` 起来
   （`src/membership/sync.rs:1220` 附近）：下一 tick 即向每个已连接对端推送 diff
   ——这是「变更一跳一 tick」的传播波。

## 3. 冗余的定量推导

设集群规模 n、每节点会话度 k（≈ k(n)），稳态下出现**一条**新行 r（例如一次
`resources().put()`）。

**理论必要成本**：r 的载荷到达其余 n−1 个节点各一次 → n−1 次载荷投递。

**实际成本**（推送模型的必然）：

- 持有 r 的每个节点都会向自己的 k 个对端各推一次 r（发送侧 watermark 只有在「我已向
  你送达过 r」之后才会过滤它；在此之前，对每个首次见到 r 的节点，r 都会穿过它的每条
  出边）。总载荷投递次数 ≈ **n·k**（每条有向会话边各一次）。
- 冗余率 ≈ 1 − (n−1)/(n·k) ≈ **1 − 1/k**：
  - n=64, k=7 → ~86% 冗余；
  - n=256, k=8 → ~88% 冗余。
- 叠加第二层周期性成本：每对端每 64 个 pass 一次的**整目录重发**、静默期检测重扫、
  墓碑每 8 tick 的重发与确认重查、以及丢 ack 后的 watermark 回退重发。在回环网络高
  tick 速率下，这些周期项摊到观测窗口里的占比可以轻易把 ~86% 推到观测的 **~95%**。

这与源码注释的自我审计一致（`src/sync_common.rs:910–920`）：

> "…delivering one changed row cost O(catalog × peers × hops) — **98% redundant traffic
> under churn**. The watermark model costs O(changed rows) per peer per hop; **the
> structural remainder is epidemic-wave duplication (a row crosses each session edge about
> once), which no push design removes.**"

即：watermark 修复了「整目录重发」的一半问题（变更规模部分），但**没有也不能**消除
「每条边一次」的流行病波复制 —— 那是 push 模型的结构属性（见 `02` 的理论佐证）。

## 4. 结构性根因（三条）

1. **发送方猜测接收方状态。** watermark 是发送方对「对端有什么」的单边记忆，需要
   周期性整表清空自愈（否则漂移永久不修复），清空即全量重发。接收方明明确切知道
   自己有什么，却从不发言。
2. **载荷字节乘坐流行病波。** 行数据本身作为 gossip 载体扩散，冗余度天然 = 每行
   穿过的边数，与 k(n) 同阶，且与网络质量无关 —— 它是为「最坏弱网」预付的固定保险费。
3. **静默也有成本。** 无变更时每对端仍按 cadence 扫描目录做「空检测」，有界但非零；
   墓碑/确认重发在无事件时也周期性发生。

## 5. 改良目标的正确形态

用户场景定义了目标函数：**冗余在弱网下是保险，在强连通下是浪费**。因此改良不是
「调小常量」，而是把冗余变成一个**分层、可随链路质量伸缩**的预算：

- **摘要/提示流量**（字节小、幂等、可重复）：允许随弱网程度增加 —— 这是对不稳定的
  合理保险；
- **载荷流量**（行字节）：结构性只发「接收方能证明自己缺」的部分 —— 无论网络好坏，
  重复载荷都应趋近于零，弱网用**重试**（协商幂等）而非**复制**换取韧性。

这正是后文三个方向各自给出的共同答案：让接收方成为自己状态的权威（协商/和解），
把流行病机制降级为只承载微小摘要的失效通知。
