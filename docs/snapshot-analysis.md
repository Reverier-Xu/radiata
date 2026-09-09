# Snapshot 设计专项分析

> 2026-09-09，基于分支 fix-audit-findings @ `fbfaa14` 的只读专项审查。
> 起因：owner 命题——"大部分 snapshot 都会引发数据不一致问题，并且仅仅只是为了绕过某种工程上的不合理设计"。本分析逐个验证该命题在本项目是否成立。

## 1. Snapshot 清单与判定

| 概念 | 位置 | 一致性模型 | 不一致窗口 | 判定 |
| --- | --- | --- | --- | --- |
| `StoreSnapshot` 存储快照 | provider.rs:666-678、storage/mod.rs:267-269 | 本地 store 单 revision 钉住的不可变读视图；契约"后续提交绝不改动未决快照"（provider.rs:708-711） | 仅"快照后 store 前进"一种，由 base-revision CAS + 逐键 digest expectation 在提交点检测为 `Conflict` | **资产**（一致性机制本体） |
| `TrustSnapshotV1` 信任快照 | identity/trust.rs:51-69 | 收敛记录：per-issuer revision 单调、latest-wins、冲突 fail-closed；**注意无对象签名**，真实性来自认证会话通道（trust.rs:1-7） | 跨节点传播滞后 ≤ 8 tick（250ms/tick）；条目级滞后由反熵修复 | **资产为主，带一笔规模债务**（见 §2.2） |
| `ObservabilitySnapshot` | view.rs:186-230、runtime/views.rs:200-247 | 实时聚合（锁下计数 + 原子量 + store 计数，`captured_at` 戳） | 计数器间微秒级不同步；无决策依赖 | **资产** |
| 描述符/资源内容指纹 | membership/sync.rs:541-568、sync_common.rs:66-71、resource/page.rs:149-160 | 易失内存游标，仅"本进程内与上轮比较" | 误判最多少发/多发一页；32 tick 慢重发兜底 | **资产**（DefaultHasher 用于同进程自比，恰当） |
| 每 tick 单快照批读 | membership.rs:264-272、runtime/recovery.rs:157-171、routing.rs:694-714 | 一个周期钉一个 revision 的性能批读 | 读到旧描述符 → 下个 recovery tick 自愈 | **资产** |
| `LifecycleSnapshot` | runtime/lifecycle.rs:12 | watch 单值状态机 | 无 | 平凡资产 |
| `SimulationSnapshot` | simulation/network.rs | 测试设施 | 测试内 | 非生产面 |

## 2. 重点分析

### 2.1 StoreSnapshot —— 防 TOCTOU 的本体，非权宜之计

- 读到恰好一个 revision 的完整截面；"快照后别人提交"的窗口被三层兜住：WriterLock 单写者线性区（storage/mod.rs:259-265）→ 不持许可者由 CAS 把陈旧性转类型化 `Conflict` + 有界重试（supervisor.rs:1289-1296）→ 未知结局走 receipt 幂等回放，崩溃边界只有 old-or-new。
- 与 `snapshot_expectation`（provider.rs:476-486）单源配对，杜绝"期望与 CAS 基准不一致"。删掉它每个条件写都得自带读-比-写三段式，更糟。

### 2.2 TrustSnapshotV1 —— 设计正当，两笔债务

- **勘误**：此前架构文档称"签发者签名的绑定集合"不准确——记录体内无签名字段，真实性由投递会话背书（trust.rs:2-5）。持久化的快照不可离线复核。
- 叠加语义清晰：不存在"合并两个 issuer 快照"；每节点持久化每 issuer 各自 latest（键 `{issuer}/{revision:020}` 前缀隔离），采纳逐条落进 IDENTITY_BINDING，换钥 fail-closed。真值唯一：IDENTITY_BINDING 的并集。
- **债务 1（发射面无阶梯）**：页有 64 条上限 + 减半阶梯，快照没有——单记录必须整装 ≤64 KiB（≈870 绑定饱和）；超限时 `refresh_issuer_snapshot` 的 encode `?` 令**整个 sync_tick 失败**（含描述符页反熵一起停摆，每轮同样失败）。trust.rs:117-118 注释"larger memberships heal through the resend cadence"与该失败模式不符。
- **债务 2（只写不读的持久副本）**：对端持久化的远程快照无生产读者（`latest_snapshot_ctx` 仅 issuer 本人在 refresh 中读自己前缀），纯审计留存还带逐 issuer 修剪的写放大。
- 怀疑点 2 验证（计数短路）：TRUST_BINDING 族淘汰后仍成立——撤销不删绑定（revocation.rs:200-212 用 Check 把绑定钉进事务）、清退伴随换钥重启（前缀扫出 None）、写路径全部单调；单例自绑定进入计数是淘汰时的有意新语义，口径统一。

### 2.3 stale-base 同类残留排查（怀疑点 3）

逐点排查现存"一个快照多次提交"的消费处：retention 单事务多 Delete（已修）、leave 按族单批、快照修剪 Put+Delete 同事务；其余多提交流全部逐次重取快照（逐绑定采纳、逐墓碑 GC、逐 receipt 清理）。**无同类残留**。批事务在持续写压下可能整批反复落败属活性权衡（有界 pass 推进），非正确性问题。

## 3. 总结论

**Owner 命题基本不成立（约 1-2 成成立）**。StoreSnapshot 是地基而非绕路；TrustSnapshotV1 的传播单元抽象正当；观测/指纹类无一致性主张越界。成立的部分：快照发射面的 64 KiB 悬崖会连带杀死描述符同步（工程上确实该解耦没解耦），以及无读者的持久副本。

## 4. 改进建议（按价值排序）

1. **解耦快照刷新失败与描述符反熵（小）**：`sync_tick` 中 `refresh_issuer_snapshot(...)?`（sync.rs:595）失败时降级为"跳过本轮快照发送、保留页面发射"+ 回归测试。
2. **修正 trust.rs 注释与远程快照持久化语义（小）**：如实描述 encode 上限与整 tick 失败模式；模块文档写明"对端副本仅审计证据"，或评估不持久化远程快照（省一族写放大）。
3. **超 16 节点 SLO 再动协议（中-大，暂不建议）**：绑定传播改为 per-binding 事件 + per-issuer revision 游标的分页反熵，彻底移除整集快照；v1 冻结 wire 面有兼容成本。
