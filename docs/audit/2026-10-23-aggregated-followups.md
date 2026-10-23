# 聚合审计后续问题报告（2026-10-23）

## 来源与方法

本报告聚合 GitHub issue #81 中两份由不同 agent 产出的审计报告：

- **报告一**（issue 正文，gpt-6-astra）：评审 `de207c5`，对比基线 `fd549c7`。
- **报告二**（issue 评论）：审计 `ad5c91be`（即 `ad5c91b`）。

**验证基线**：当前 HEAD `6183c4b`。`git diff de207c5..HEAD -- src/ tests/` 为空，`ad5c91b..HEAD` 仅删除旧的 `docs/audit/` 文档。因此两份报告引用的行号与当前源码一一对应，全部发现已按报告所给位置逐项人工复核。

**收录范围**：两份报告均声明已排除各自已解决的发现；本次复核确认下列条目在当前源码中**仍然存在**，无一已修复。两报告的重叠项已合并标注。

严重级别约定：P1 = 核心正确性/活性/隔离；P2 = 资源边界/较窄正确性/契约缺口；P3 = 可维护性。

---

## 一、P1 行为问题

### P1-1（R2-A02）未见过的资源其新鲜删除证据被丢弃 — verified

- 位置：`src/reconcile/plane.rs` `deliver` 的 Resources 接收过滤器；`resource_swept`（约 1478 行）
- 结论：接收方把"本地不持有该 key"当作"删除已被回收"的证据。从未见过该资源的节点会丢弃一条合法的新鲜删除记录；之后到达的更旧活跃值可能被接受（已复现）。需区分"未见过的 key"与"已确知被回收"。

### P1-2（R2-A10）wire 流 EOF 后存活的 consumer 无生命周期预算 — verified

- 位置：`src/session/inbound.rs` End 处理（约 249–269）与准入检查/consumer spawn（约 440–505）
- 结论：End 从 `incoming` 表移除流、释放准入槽位，但其 consumer 任务可在读完 EOF 后继续运行（如等待本地业务操作）。准入只按 `incoming.len()` 计数，运行中的 consumer 总量无预算（已复现：预算 8 时 32 个 Open/End 对全部准入并残留 32 个 consumer）。任务仍有归属、shutdown 会 drain，缺陷是缺少运行人口预算。

### P1-3（R2-A11）以短超时判定 key 写入方已死 — verified

- 位置：`src/keys/file.rs` `EMPTY_ARTIFACT_WAIT = 50ms`（约 62 行）、独占创建与写入（约 244–265）、空工件接管（约 435–458）
- 结论：写方 A 在独占 open 之后、写入之前被调度挂起时，写方 B 等待 50ms 后 unlink 仍为空的文件并创建另一把 key；A 恢复后可能写入已 unlink 的 inode 并报告自己的 seed。两个并发创建者可能对同一操作返回不同的 key（源码确认的交错，未做跨进程复现）。

### P1-4（R2-A15）旧会话清理可关闭替代会话的路由 — verified

- 位置：`src/session/stream.rs` winner 先安装后退休旧会话（约 396–423）、旧会话清理（约 490–505）；`src/routing/forward.rs` `close_for_peer`（约 285–318）
- 结论：转发跳点仅以 `NodeId` 标识上游。替代会话已可用时，旧会话的 teardown 扫描可按 peer 扫到并中断 winner 新注册的路由。需把转发跳点绑定到具体会话代际。

### P1-5（R1-F1）路由策略仍可阻塞控制循环 — verified（含争议）

- 位置：`src/runtime/supervisor.rs` packet 分支内联 await `send_packet`（约 491–509）；策略解析 `src/runtime/recovery.rs` 约 108–160
- 结论：控制循环内联等待调用方提供的 next-hop / load-balancing 策略；一个永远 pending 的策略会阻塞后续控制查询、包准入和 shutdown。代码注释声明此为有意设计（保 record-before-pump 顺序），报告一认为可用有界 admission worker 保持顺序。属于"有意但仍有风险"的设计争议项。

### P1-6（R1-F2）扩展任务与核心本地任务共享执行槽可死锁 — verified

- 位置：`src/task/mod.rs` `slot_class`（约 78–82）；`src/runtime/task_manager.rs` worker 取槽（约 1063–1123）；`src/node/api.rs` `submit`（约 502–514）
- 结论：只有 Join/Connect 走 Network 槽；Extension 与资源写入同走 Local 槽。单个本地槽时：reconciler 持槽 → 通过 handle 提交子写入 → await 子任务 → 子任务等不到槽，死锁。默认两槽配置下两个此类工作流即可耗尽。

### P1-7（R1-F4a）origin 侧 body 失败不终止远端流 — verified

- 位置：`src/routing/outbound.rs` `pump_chunks` 错误出口（约 95–120、268–270）
- 结论：body 出错时 origin 记录本地终态后直接返回，不发送 interrupted End；会话健康时远端 consumer 可能一直等待。新增的 typed End 只覆盖了 relay 会话中断的情形。

### P1-8（R1-F4b）准入后的 ACK 归属信息丢失 — verified

- 位置：`src/routing/forward.rs` `ack_from_current_downstream`（约 657–674）；`src/session/inbound.rs` `resolve_ack`（约 575–580）
- 结论：归属检查要求存在活跃的 `PendingAck::Relay`，但准入 ACK 到达时 `resolve_ack` 已移除该条目。同一下游会话随后合法的失败 ACK 会被当作"过时分支的迟到 ACK"丢弃。准入完成不应抹掉后续流控事件所需的所有权信息。

### P1-9（R1-F4c）慢流阻塞共享 inbound 读取循环 — verified

- 位置：`src/session/inbound.rs` chunk 转发内联 await 有界 channel `send`（约 560–563）
- 结论：等待某个 consumer 的有界通道会阻塞整个会话的共享 reader，包括后续 ACK、其他流与 Pong 处理。需要按流有界处理 + 显式过载策略。

### P1-10（R1-F5 ≈ R2-provider-completion）存储执行完成未与 shutdown 打通 — verified

- 位置：`src/storage/redb/store.rs` `commit`（约 312–392）、`flush` 立即返回 Ok；`src/runtime/supervisor.rs` `finish_shutdown`（约 583–612）
- 结论：detached commit 的注册与 reconcile 等待已大幅改善原取消竞态，但完成 guard 挂在外层异步任务而非真正的阻塞 commit 上；存储执行任务不在节点 drain 集合内；`flush()` 立即成功；节点 shutdown 返回时执行可能仍持有数据库或尚未提交。"每个已完成事务都 fsync"与"每个在途事务都结束"是两个不同保证。

### P1-11（R1-F6）吊销与最终会话发布缺少共享授权边界 — verified

- 位置：`src/session/driver.rs` `member_inner` 在握手前读取绑定（约 547–572）；`src/session/stream.rs` 会话安装（约 367–411）；`src/runtime/task_effects.rs` 吊销提交即退休会话（约 554–569）
- 结论：以下序列仍然可能：握手通过绑定校验 → 吊销提交并退休现有会话 → 握手完成 → 新会话在未做最终授权复核的情况下发布。需在发布前做一次短的同步边界复核（不跨网络协商持有）。

---

## 二、P2 行为与资源问题

### P2-1（R1-F3）非阻塞 hook 产生无界 detached 工作 — verified

- 位置：`src/runtime/task_manager.rs` `observe`/`detach_observations`（约 587–634）；`src/task/mod.rs` `notify_resource_observers`（约 869–885）
- 结论：action hook 不再占用执行槽（修复了旧的阻塞问题），但每次状态迁移 spawn 一个观察任务，终态时丢弃句柄；resource observer 同样 detached。永远 pending 的 hook 会跨成功操作累积任务与捕获状态，并能活过节点 shutdown；终态历史上限不约束这些 observer。

### P2-2（R2-A13）已准入的非终态任务无界 — verified

- 位置：`src/runtime/task_manager.rs` 准入插入 Pending 并立即 spawn worker（约 995–1024）；worker 之后才获取信号量（约 1066）
- 结论：提交 channel 只约束在途消息；manager 消费后立即插入 Pending 并 spawn 等待执行容量的 worker。缓慢的 effect + 持续的不同 intent 可累积非终态条目、捕获的输入与等待任务；终态历史上限不约束它们。

### P2-3（R2-B01 = R1-O1）未到期的 hint 重试被丢弃 — verified

- 位置：`src/reconcile/plane.rs` tick 末尾的 hint-retry 段（约 944–956）
- 结论：`hint_retry.take()` 先移除槽位；当 `resume_at_tick` 在未来时分支直接 `continue` 且不放回，重试丢失。ROOT 交换是兜底，但 1/2/4/8-tick 的预期退避调度未被执行。

### P2-4（R2-B02）资源 stamp 签发不是一次原子推进 — verified

- 位置：`src/runtime/resources.rs` `issue_write_stamp_since`（约 105–109）
- 结论：两次 `fetch_max` 夹着一个本地计算；两个写者可在任何一方回折前观察到相同的 previous，返回相同 stamp，违反本地严格推进约定。需用单次 CAS/update 完成计算与推进。

### P2-5（R2-B03）转发容量在 await 之前检查 — verified

- 位置：`src/routing/forward.rs` 容量检查（约 176–195）、dispatch await（约 388–406）、`register`（约 690–698）
- 结论：并发会话 reader 可都通过容量检查、都在 dispatch 上等待，随后插入总量超过配置上限。需在 dispatch 前预留容量并在失败/取消时释放。

### P2-6（R2-B04）trace 留存过度驱逐且把计划删除数当作已提交 — verified

- 位置：`src/routing/trace.rs` `sweep` 计算与返回值（约 484–510）、未提交批次返回 0（约 525–549）；`src/runtime/retention.rs` 计数器（约 16–42）
- 结论：overflow 把已单独删除的 expired 记录计入基数，导致多删新鲜终态记录；sweep 丢弃 `apply_batched` 的已提交计数、返回计划总数；未提交的批次因此也会扣减运行时计数器，计数到零可能抑制后续 sweep 而记录仍在。

### P2-7（R2-B05）WSS 把请求的 HTTP hostname 换成 IP — verified

- 位置：`src/transport/connection.rs` `connect_tls_ws`（约 176–190）
- 结论：TLS SNI 用请求的 hostname，但 WebSocket upgrade 的 authority 来自 `tcp.peer_addr()`。按 Host 虚拟主机路由的反向代理可能接受 TLS 却把 HTTP upgrade 路由错。

### P2-8（R2-B07）端点证书 pin 缓存无生命周期与容量策略 — verified

- 位置：`src/session/driver.rs` `MemberSpkiTable`（约 126–146）
- 结论：节点生命期的缓存无限插入 `(peer, endpoint)` 锚点；频繁换地址的持久 peer 会在本 incarnation 内累积废弃条目。需淘汰 departed/obsolete 端点或有界驱逐。

### P2-9（R2-B08）redb 回填把迭代器错误当作 EOF — verified

- 位置：`src/storage/redb/store.rs` 回填循环（约 711–729）
- 结论：`while let Some(Ok(...))` 遇到 `Err` 即停，随后部分回填可提交、open 报告成功——失败的扫描被误认为成功 EOF。提交前需传播/映射迭代器错误。

### P2-10（R2-B10）中止的 remerge/adoption 把合法既有绑定误报为损坏 — verified

- 位置：`src/identity/merge.rs` merge 分类器（约 587–601）、adoption 分类器（约 465–474）
- 结论：操作可合法地以既有精确绑定起步；若新的 use/grant 未提交，分类器看到"有绑定但无操作记录"的组合会报 `discovery_corrupt()`，而非识别为合法的未应用基线。中止分类需保留并校验先前的 union 基线。

### P2-11（R2-#14）规范证据替换与吊销事件未区分 — verified

- 位置：`src/identity/revocation.rs` 替换结局（约 221–265）；`src/identity/records.rs` 不变安装结局（约 262–275）；通知调用方 `src/runtime/task_effects.rs`（约 560–577）与 `src/membership/sync.rs`（约 435–462）
- 结论：对已吊销绑定替换规范证据可再次返回 `Revoked` 且 `was_already_revoked = false`；精确重放或合法落败记录返回 no-op 成功后同步路径仍发出变更通知。需区分"新授权转移 / 规范证据替换 / 证据未变"三种结局。执行面保持独立（已吊销会话仍需退休），不重开 A14。

### P2-12（R2-#15 ≈ R1-S2）dial 计数器在 panic/取消时不释放 — verified

- 位置：`src/runtime/degree.rs` 手动自增/自减（约 310–355）；`src/runtime/recovery.rs` 同型（约 392–453）
- 结论：自定义 transport future panic 会绕过 `fetch_sub`：卡住的 maintenance 槽抑制后续探测，卡住的 recovery 槽消耗本 incarnation 的 fan-out 预算。需用作用域 permit（RAII）在完成/panic/取消时都释放。

### P2-13（R2-#16）receipt 扫描本身无界 — verified

- 位置：`src/storage/receipt.rs` `apply_receipt_retention`（约 459–489）
- 结论：删除批次按到期目标数有界，但未到期 anchor 不计数——一轮可扫描任意大的未到期群体。需对扫描条目或耗时设界并支持续扫，避免反复停在未到期前缀而饿死后段的到期 anchor。

### P2-14（R1-O2）receipt 留存的生产的资格路径不完整 — verified

- 位置：`src/storage/receipt.rs` `anchor_receipt`（约 1182 起，位于 `retention_testing`）；调用方仅 `src/runtime/supervisor.rs` 测试
- 结论：4097 条目分批缺陷已修复，但生产路径中没有任何代码为 receipt 建 anchor——"从未被引用的 receipt 转变为可发现的留存候选"这一正常过渡仍未闭合，只有测试显式建 anchor。

### P2-15（R1-O4）认证 deadline 被归类为不可重试的认证失败 — verified

- 位置：`src/session/driver.rs` 认证超时映射（约 540–545）
- 结论：缓慢的存储或调度可耗尽握手 deadline 而凭证本身有效；当前一律映射为 `Error::authentication_failed("authentication deadline")`，与永久性身份拒绝不可区分。应可与永久拒绝区分（可重试语义）。

---

## 三、需要决策的契约项（非直接缺陷）

| 编号 | 条目 | 现状（已核对源码） | 决策目标 |
| --- | --- | --- | --- |
| D-1 | 稀疏拓扑的 probe 边保留策略 | `src/runtime/degree.rs`：健康节点对未连接成员周期性 bridge 探测（5 分钟间隔），成功 probe 成为普通保留边，无 lease/类别 | 定义保留 probe/maintenance 边的长期稀疏预算；不要恢复已解决的总度数抑制条件 |
| D-2（R2-D01） | 资源冲突与 CAS 语义 | 资源是 timestamp-maximum 寄存器；CAS 只保护本节点观察 | 文档化支持的时钟异常、accepted-loser 处理与可操作的纠正路径；不暗示 K8s 式全局 resourceVersion |
| D-3（R2-D02） | 离线时长 vs 删除证据留存 | 删除证据有有限窗口且可被容量驱逐 | 选择支持的离线地平线 / 持久版本知识 / rejoin-resnapshot 屏障；与 P1-1 是不同问题 |
| D-4（R2-D03 = R1-O3） | GC 后的终端排除 | `peer_is_terminal`（`src/identity/trust.rs:530`）读 leave/cleanup 记录；checkpoint GC 删除这些记录而历史绑定仍在 | 明确"永久排除"是运维前提还是核心强制；若核心承诺永久拒绝则需保留紧凑排除证据 |
| D-5（R2-D04） | 传输偏好与自动选择 | TLS/WSS/TCP/自定义并存；生产偏好策略未建立 | 定义可选的有界 per-peer 选择/回退策略；业务加密仍属调用方 |
| D-6（R2-D05） | 稀疏路由知识 | 策略只拿到本地 live peers；核心不提供学习到的全网可达性 | 测量稀疏环/树/死胡同上的路由成功率与延迟，再决定路由扩展是否需要可达性观察 |
| D-7（R2-B06） | 便捷路由回复 | `derive_return_stream`（`src/packet/mod.rs:399–409`）显式 direct-only、硬编码 1 跳 | 若需要便捷多跳回复则加显式策略/跳数预算变体；否则文档化限制 |
| D-8（R2-D06） | 任务观察 vs 持久工作 | 任务观察在内存；持久性由各 effect 的足迹提供 | 定义离线期间未提交业务意图由谁保留 |
| D-9（R2-D07） | 内置传输替换的文档暗示 | 内置名保留、内置注册私有；builder 文档暗示可按 tag 替换 | 修正文档或仅在有具体需求时加覆盖 API |
| D-10（R2-B09 = R1-S1） | writer 锁以 task id 推断可重入 | `src/storage/mod.rs:50–100`：`tokio::task::try_id()` 相同即视为嵌套；同任务内 `join!` 分支共享身份 | 这些路径若并发组合，改为显式 permit/操作所有权；当前无生产调用方，属潜在 P2 债务 |

---

## 四、文档与工程证据缺口（均已核对源码确认）

| 条目 | 位置 | 问题 |
| --- | --- | --- |
| 无效资源名示例 | `src/guide.rs:251` | 用了 `example.woooo.tech/config/edge`，而 `ResourceName` 要求 `resources` 类别（`src/resource/mod.rs:67`）；`no_run` 掩盖了即时的 `InvalidInput` |
| 无条件写措辞 | `src/guide.rs:32–34` | 称 plain put "无条件替换 winner"；应描述为无 expected-version 前提的准入并要求检查 accepted-versus-winning |
| 全集群连通与恢复上界 | `src/guide.rs:80–90,118–124` | 把本地 live 会话当作全集群路径，且未提及 5 分钟 bridge 间隔 |
| degree 作为内存上限 | `src/guide.rs:632–638` | 按 `k(n)` 估算邻居数，但超额会话会被保留；隐含的上限不成立 |
| 健康维护被描述为空闲 | `src/guide.rs:654–656` | 称健康时无工作；实际健康节点有周期 bridge 探测（`src/runtime/degree.rs`） |
| 恢复时长量化 | `src/config.rs:578–583` | `as_secs().max(1)` 向下取整并把亚秒提升为 1 秒；需文档化/校验/保留精度（P3） |
| 类型化诊断丢失 | `src/transport/framing.rs:267`（截断与 OS 错误不分）、`src/protocol/handshake.rs:163,180`、`src/protocol/selection.rs:43`、`src/error.rs:114,121,143` | 公共投影丢失结构化细节 |
| golden witness 自比较 | `src/compatibility.rs:435–445,844–857` | `bytes(name)` 与 `hex_decode(entry(name).hex)` 解同一 manifest 条目互相比 |
| 命名空间守卫高估 | `tests/static_invariants.rs:55–75` | 集合比较不校验字面量出现位置，也不对比 `metadata_families()` 注册表（`src/storage/families.rs:143–164`）；在目录外重复已有字面量仍通过（同 R1-E1） |
| 重放测试只测顺序 | `src/protocol/handshake.rs:1666–1703` | 重复同一确定性 setup 并断言 `OutOfOrder`，未在有效证明位置独立更换 exporter 与 nonce 重放 |
| 大 trust 快照未往返 | `src/identity/trust.rs:312–338` | 只编码并断言长度，未做 decode 相等与超控制预算的持久读回 |
| 分区/重复断言窄于标签 | `tests/membership_sync.rs:921–989`；拓扑辅助在 696–705 先去重 | 未测真正分裂/离线写/自动重连/快照一致；重复断言观察的是去重后的多重性 |
| 页面无变更证明非零传输证明 | `src/resource/page.rs:514–530`；`src/resource/e2e.rs:142–153` | 重发页面只断言零安装；声称零传输需测线上字节，声称无整目录物化需测分配 |
| 预算矩阵选择性 | `src/reconcile/budget.rs:672–679` | 宣称 n×形态×重连矩阵，实测 6 个 cell |
| 模型仿真 ≠ 运行时恢复 | `src/simulation/network.rs:101` | 按字节数调度；运行时声明需真实节点/受控传输/持久重开证据 |
| 共享参考提供者非独立 oracle | `src/storage/contract/reference.rs:160,300` | 复用生产 `commit_precheck`/`classify_receipt` |
| 严格 SLO 证据需手工开关 | `tests/membership_sync.rs:1010,1159` | `<10s` 断言要求 `RADIATA_SLO_PROFILE_STRICT=1`，常规 CI 不设置 |

---

## 五、P3 代码质量维护项（均已核对源码确认存在）

- **职责分解**：`src/session/inbound.rs:345` 附近的晚期路由失败状态/事件/trace 决策应移入 routing；`ReconcilePlane::tick`（`src/reconcile/plane.rs:551–1015`）只应围绕剩余 scan/cadence/retry 职责分解。
- **重复 helper**（偏好小的 owner-local helper 与作用域 permit，不要新通用框架）：
  - receipt 分组展开：`src/storage/pending.rs:515` / `src/storage/receipt.rs:207`
  - dial 计数：`src/runtime/degree.rs:310` / `src/runtime/recovery.rs:392`（与 P2-12 同修）
  - raw 接收翻译：`src/transport/connection.rs:302` / `:475`
  - descriptor winner 选择：`src/membership.rs:442` / `src/reconcile/plane.rs:1704`
  - provider-key 校验：`src/identity/lifecycle.rs:438` / `src/identity/leave.rs:522`
  - issuer/subject 校验：`src/identity/cleanup.rs:195` / `src/identity/revocation.rs:292`
  - 任务终态等待：`src/node/api.rs:442–478` / `src/task/mod.rs:666–691`（R1-S3）
- **kind 集中归属**：tombstone kind code 在 `src/reconcile/plane.rs:1606–1612` 与 `src/membership/sync.rs:502–631` 重复；共享的 typed 解码器可防漂移。
- **杂项**：`src/error.rs:347` 的定长数组转换在 `src/hex.rs:39`、`src/membership/page.rs:213`、`src/protocol/offer.rs:229`、`src/protocol/cbor.rs:410` 重复；`src/routing/trace.rs:91–119` `kind_code` 与 `src/resource/mod.rs:441–458` `seal_prepared` 对不可失败构造返回失败容器；`src/routing/forward.rs:780–782` `async fail_upstream` 只调用同步函数。
- **广播适配**（R1-S4）：`src/node/event.rs:65–89,153–175` 多个入口复制 receiver 所有权与完成处理；可评估 `tokio-stream` broadcast 适配（需保留 Lagged/Empty/恰一个 Closed 语义）。
- **会话队列记账**（R1-S5）：`src/session/queue.rs:204–265` 的消息计数/唤醒/关闭部分重复 bounded mpsc 功能；扩展自定义 Notify/backstop 状态机前先评估 mpsc permit + 字节 permit。

---

## 六、验证状态总表

| 条目 | 级别 | 状态 |
| --- | --- | --- |
| P1-1 删除证据丢弃（A02） | P1 | verified（R2 已复现） |
| P1-2 consumer 生命周期（A10） | P1 | verified（R2 已复现） |
| P1-3 key 接管超时（A11） | P1 | verified（源码交错） |
| P1-4 旧会话清理（A15） | P1 | verified（源码交错） |
| P1-5 策略阻塞控制循环（F1） | P1 | verified（代码标注为有意设计，存争议） |
| P1-6 扩展任务槽位（F2） | P1 | verified（源码结构） |
| P1-7 origin 失败不终止远端（F4a） | P1 | verified |
| P1-8 ACK 归属丢失（F4b） | P1 | verified |
| P1-9 慢流阻塞 reader（F4c） | P1 | verified |
| P1-10 存储完成 vs shutdown（F5） | P1 | verified |
| P1-11 吊销 vs 会话发布（F6） | P1 | verified |
| P2-1 detached observer（F3） | P2 | verified |
| P2-2 准入积压无界（A13） | P2 | verified |
| P2-3 hint 重试丢失（B01） | P2 | verified |
| P2-4 stamp 非原子（B02） | P2 | verified |
| P2-5 转发容量竞态（B03） | P2 | verified |
| P2-6 trace 留存记账（B04） | P2 | verified |
| P2-7 WSS authority（B05） | P2 | verified |
| P2-8 pin 缓存无界（B07） | P2 | verified |
| P2-9 redb 回填 EOF（B08） | P2 | verified |
| P2-10 remerge/adoption 误报（B10） | P2 | verified |
| P2-11 证据替换 vs 吊销事件（#14） | P2 | verified |
| P2-12 dial 计数器释放（#15） | P2 | verified |
| P2-13 receipt 扫描无界（#16） | P2 | verified |
| P2-14 receipt 资格路径（O2） | P2 | verified |
| P2-15 认证 deadline 分类（O4） | P2 | verified |
| D-1 … D-10 | decision | 现状已核对，待维护者决策 |
| 文档/证据缺口 ×14 | P2/P3 | verified |
| P3 维护项 ×6 组 | P3 | verified |

## 七、处理决定（维护者，2026-10-23）

- **修复**：P1-1、P1-2、P1-4…P1-11（10 项）与全部 15 项 P2。
- **忽略**：P1-3（key 并发创建接管）——并发创建同一操作的 key 在本库的任何使用场景下都不会出现，修复只会引入过度设计。
- **D 系列**：全部需要维护者契约决策，逐项讨论后落地文档。
- **文档/证据缺口**：本轮只修文档项（guide.rs 等）；测试/证据强化类暂缓。
- **P3 维护项**：随本轮行为修复顺手清理。

**实施约束（维护者）**：修复必须是结构性的——不得在业务代码中四处打 `if` 补丁、不得用白名单限制堆砌、不得滥用 snapshot 规避并发问题；保持架构干净。

## 八、建议处理顺序（综合两份报告）

1. P1-1（A02）与 P1-2（A10）：删除证据保留 + consumer 生命周期预算。
2. P1-3、P1-4、P2-2、P2-12：key 创建者所有权、会话代际清理、准入积压、dial 计数器。
3. P2-3、P2-4、P2-5、P2-6、P2-7、P2-10：重试调度、原子 stamp、转发容量、trace 记账、WSS authority、中止分类。
4. P1-5…P1-11 与 P2-1：执行隔离、流生命周期、持久化与授权边界（改动面较大，宜逐项小步）。
5. D 系列契约决策 + 文档对齐 + 对应端到端证据。
6. P3 清理仅随已接受的行为变更顺带进行。
