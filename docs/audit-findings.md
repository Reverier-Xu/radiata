# 审计结果（本轮待修复）

- 基线：`fix/connectivity-liveness-integrity`（起始提交 `cb831f4`，基于 `main` 的 `a8e9fc3`）
- 登记时间：2026-10-13
- 状态：原始发现已登记；每条的代码证据、根因与修复方向见下方各条目的 **Recon** 小节（由只读侦察生成后补充）。
- 范围：仅修复下列 19 条；其他发现本轮不处理。

约定：`状态` 取值 `raw`（仅登记）/ `confirmed`（已在当前代码中复核）/ `refuted`（复核后不成立）。

## 修复状态总表

| 条目 | 复核结论 | 状态 | 提交 |
|---|---|---|---|
| #3 SPKI pin 阻断换信道 | confirmed（部分） | 已修 | `4b0dc90` |
| #5 keepalive 超时不可达 | confirmed | 已修 | `d6d25eb` |
| #7 tombstone GC 头部截断 | confirmed（就地修正） | 已修 | `877ff1a` |
| #8 inbound consumer JoinSet 不回收 | confirmed（就地修正） | 已修 | `5ef62a6` |
| #12 redb commit 结果未知被当未提交 | confirmed | 已修 | `26e0caf` |
| #13 内建 tag 解析冗余 | confirmed | 已修 | `9a4d79b` |
| #14 冻结 registry 仍用可变锁 | confirmed（定位更正） | 已修 | `c47fb6e` |
| #18 超大帧无限等待 | confirmed | 已修 | `8bbf0c2` |
| #19 拨号未纳入 shutdown 所有权 | confirmed（部分） | 已修 | `df4328c` |
| #1 分区不自动重连 | refuted（所述场景）+ 残留边界已修 | 已修（跨区桥接探测） | `8e897f1` |
| #2 fan-out 固定前缀 | refuted | 不改 | — |
| #4 显式网络命令阻塞 supervisor | refuted | 不改 | — |
| #6 只用第一个端点 | refuted | 不改 | — |
| #9 取消绕过 consumer drain | refuted | 不改 | — |
| #10 watermark 修复不触发 | refuted（结构上已不存在） | 不改 | — |
| #11 条件 Put 的 expected 非事务 | refuted | 不改 | — |
| #15 分支切换未同步 retry 副本 | refuted | 不改 | — |
| #16 取消 recv 永久关闭订阅 | refuted | 不改 | — |
| #17 被取消 commit 仍在后台 | refuted | 不改 | — |

---

---

## 1. 内部联通的分区无法自动重连

- 状态：**refuted（就所述场景）** — 恢复控制器确实在"任一路由"满足后静默（`src/membership/recovery.rs:129-165`），但**已有预算的周期探测**：连接度维护面 `src/runtime/degree.rs:38-40`（30s tick）+ `degree_plan`/`select_degree_dials`。n=4 时 k(4)=3，每节点 1 session → `dial_budget=2`，首个 tick 即拨向另一分区。已有验收：`tests/connection_degree.rs`、`tests/transport_chaos.rs:1068-1107`。
- **残留边界已修复**（`8e897f1`）：当两个子分区各自已达 k(n)、`dial_budget=0` 时，度维护面新增低频跨区桥接探测（`BRIDGE_PROBE_INTERVAL_TICKS=10` ≈ 5 分钟，`BRIDGE_PROBE_SLACK=1`），仅对 Healthy 且低于 `target+slack` 且有未连接成员的节点发起单条随机拨号；探测边为 caller-class，稀疏剪边不会剪断。测试：`bridge_probe_dials_a_cross_partition_member_within_two_intervals`、`a_fully_connected_healthy_node_never_probes`。详见 `docs/recon/membership-recovery.md`。
- 现象
- 期望：加入**有预算的周期性探测**，与现有的稀疏剪边（sparse edge trimming）算法结合，使分区能够自动重建跨分区的边。
- 初始定位：`src/membership.rs`、`src/membership/degree.rs`、`src/membership/recovery.rs`、`src/runtime/recovery.rs`、`src/runtime/supervisor.rs`、`src/config.rs`

## 2. fan-out 固定前缀重试导致隔离节点永久不通

- 状态：**refuted** — 候选窗口已轮转：`src/membership/recovery.rs:78-88` 的 `cursor` + `next_step`（175-205）使 `fan_out=1` 时依次拨 m1,m2,m3,m1…，不再固定前缀。已有测试 `recovery_rotates_the_candidate_window_across_steps`。详见 `docs/recon/membership-recovery.md`。
- 现象`src/membership/recovery.rs`（约 158 行与 314 行）在 `fan_out = 1` 时总是按 node id 排序后的**第一个**成员；若该成员关闭、后续成员可达，则隔离节点持续不通，必须显式连接才能恢复。
- 期望：记录**节点 × 地址的尝试状态**；重试预算到期后继续推进到后缀，而不是只重置回前缀。
- 初始定位：`src/membership/recovery.rs`、`src/membership.rs`

## 3. 临时监听器证书固定阻断同一身份的合法换信道

- 状态：confirmed（部分）— SPKI 缓存确实仅以 `NodeId` 为 key（`src/session/driver.rs:117`），但存在 merge-trust 回退（`src/runtime/supervisor.rs:962-1000`）使"永久失败"不成立；真实影响是每次交替拨号都先失败一次 TLS 握手再回退，且同 scheme 的第二个监听器也会命中。详见 `docs/recon/transport-identity.md`。
- 现象：成功 merge 的 TLS leaf SPKI 按 node id 缓存，之后所有回连都读该缓存。节点轮换掉临时证书、或同时开 TLS 与 WSS 两条隧道时，连接失败。
- 期望：对同一 node id 的连接，TLS→WSS 迁移、监听器重启、地址切换都应能"无凭证重连"，仅凭**身份密钥**验证对端；不应把临时 leaf SPKI 当作长期 pin。
- 初始定位：`src/transport/tls.rs`、`src/transport/tls_transport.rs`、`src/transport/cert.rs`、`src/transport/verify.rs`、`src/transport/registry.rs`、`src/transport/wss.rs`

## 4. 显式网络命令仍阻塞 supervisor 循环

- 状态：**refuted** — `Control` 枚举（`src/runtime/lifecycle.rs:61-119`）只有 `Shutdown` + 只读查询，无任何 Connect/Listen/Join/Disconnect；这些动词经 `TaskEffect` 提交给 task manager（`src/runtime/task_effects.rs:209-318`），由独立 attempt 任务执行（`src/runtime/task_manager.rs:1079`）。详见 `docs/recon/membership-recovery.md`。
- 现象
- 期望：与独立拨号任务一样，采用相同的任务隔离方式（spawn 到独立任务并纳入所有权/取消管理）。
- 初始定位：`src/runtime/supervisor.rs`、`src/runtime/task_effects.rs`、`src/runtime/task_manager.rs`

## 5. ping 节奏与 keep-alive 限额混用导致超时永不触发

- 状态：confirmed — `src/session/liveness.rs:44` 的 `last_ping` 同时承担"发送节奏"与"探测 deadline"；发送分支（91-96）每次无条件刷新它，而关闭分支（82-89）在其前求值，`now - last_ping` 最多到 `interval + tick`，配置又强制 `timeout > interval`，故 keepalive 超时不可达。现有测试靠手动时钟跳变才通过。详见 `docs/recon/session-liveness.md`。
- 现象
- 期望：**分开记录 ping 节奏与探测 deadline**；keep-alive 预算的刷新必须以"收到对端响应"为条件，或独立的 probe deadline 单独计算。
- 初始定位：`src/session/liveness.rs`、`src/session/driver.rs`、`src/session/mod.rs`

## 6. recovery 只使用每个 node 的第一个端点

- 状态：**refuted** — `known_online_member_endpoints`（`src/runtime/recovery.rs:194-243`）收录每个成员**全部**已发布端点；`recovery_endpoint`（509-513）按 attempt 序号轮转。已有测试 `recovery_endpoints_rotate_with_the_attempt_serial` 与 degree 侧双监听器测试。详见 `docs/recon/membership-recovery.md`。
- 现象
- 期望：完整尝试该 node 声明的**所有**监听端点。
- 初始定位：`src/membership/recovery.rs`、`src/transport/endpoint.rs`

## 7. 吊销/离开/清理同步永久截断前 64 条

- 状态：confirmed（就地修正） — 现有 reconcile plane 的 tombstone 通道**不截断**（`src/reconcile/plane.rs:1449-1482` 无限扫，engine 按 64 行分块而非截断）。但同类头部截断仍在 **checkpoint GC sweep** 存活：`src/identity/records.rs:326` 的 `TOMBSTONE_GC_BATCH=64` 作用于"扫描的记录数"，过滤（`collect_tombstones_before`，333-367）在其后，导致"前 64 个 key 都晚于 watermark"时尾部陈旧记录永不被收集（仅存储滁留，非传播/安全问题）。调用点：`src/identity/leave.rs:291-301`、`src/identity/cleanup.rs:405-421`。详见 `docs/recon/sync-paging-watermark.md`。
- 现象
- 期望：把每轮工作上限实现为**可继续的游标分页**（cursor pagination），跨轮推进直到完整覆盖。
- 初始定位：`src/identity/revocation.rs`、`src/identity/leave.rs`、`src/identity/cleanup.rs`、`src/membership/sync.rs`、`src/runtime/anti_entropy.rs`

## 8. 两处 JoinSet 不回收已完成条目

- 状态：confirmed（就地修正） — `src/runtime/task_manager.rs` 中**没有** `JoinSet`（原定位错误）。两个生产 `JoinSet` 中，`src/runtime/supervisor.rs:303` 已在 select 臂回收（499-511）；真正未回收的是 `src/session/inbound.rs:89` 的 consumer `JoinSet`：`admit_open` 只 spawn，只有 teardown 时由 drain 任务 `join_next`（105）。会话存活期间按已服务流数线性累积（非永久泄漏，teardown 全量回收）。修复：`read_loop` 中非阻塞 `try_join_next` 排空。详见 `docs/recon/session-liveness.md`。
- 现象
- 期望：在循环中回收已完成条目（如非阻塞 `try_join_next` 排空），并保留错误处理语义。
- 初始定位：`src/runtime/task_manager.rs` 及另一处（待 recon 定位）

## 9. 会话取消绕过 consumer drain

- 状态：**refuted** — `ConsumerDrainGuard` 在 read loop 入口就注册（`src/session/inbound.rs:119-123`），其 `Drop`（96-108）在**任何**退出路径（含取消）都把 consumers 交给节点级 drain。已有测试 `cancelled_read_loop_still_registers_the_consumer_drain`（940）、`orderly_read_loop_registers_exactly_one_consumer_drain`（978）。详见 `docs/recon/session-liveness.md`。
- 现象
- 期望：取消路径统一经过 consumer drain（或复用同一清理函数），保证语义一致。
- 初始定位：`src/session/mod.rs`、`src/session/driver.rs`、`src/session/queue.rs`

## 10. sync 的 passes-since-refresh 只在空尾页自增，watermark 修复永不触发

- 状态：**refuted（结构上已不存在）** — 本条描述的是已被删除的 watermark-walk anti-entropy（`f33f0d9`/`272c037` 引入，`506e6e8`/`a359379` 等删除）。当前所有 lane 走 reconcile plane + receiver-evidenced fingerprint；`grep passes_since_refresh src/` 无命中，无 watermark 表、无 admission-ack 交付记忆。unknown-writer 行是"跳过而非拒绝"，会在 descriptor 到达（epoch 推进）时由 repair pass 重试，并有测试固定。详见 `docs/recon/sync-paging-watermark.md`。
- 现象：只有"无 page 且 walk cursor 到尾部"时才增加 `passes since refresh`；非空尾页仅发送 `cursor = None`，不计数。若每次扫描尾部都有新写入数据，则"64 次完整扫描后清除 watermark"的修复永远不会触发。叠加"未知 writer 超时跳过记录"与"admission ack 先于应用"，某个不再变化的早期 key 可能长期缺失。
- 期望：把"完整扫描一轮"判定为游标回到起点/尾部且覆盖全部范围，而非仅在空尾页时计数；确保 watermark 清理能在持续写入下推进。
- 初始定位：`src/membership/sync.rs`、`src/runtime/anti_entropy.rs`、`src/sync_common.rs`

## 11. 条件 PutResource 的 expected 未进入同一事务

- 状态：**refuted** — `expected` 已在同一 snapshot 下复核（`src/resource/store.rs:108-150`），且 redb 写事务内 `commit_precheck` 再次校验 base revision 与 per-key digest（`src/storage/redb/store.rs:707` 附近，`src/provider.rs:968-1007`）。已有回归测试 `raced_expected_puts_resolve_to_one_install_at_the_boundary`。详见 `docs/recon/storage-atomicity.md`。
- 现象：条件写入 `PutResource` 的 `expected` 校验没有与写入放在同一个事务里，签名等待期间的新入站数据可以绕过授权（校验与提交之间存在 TOCTOU 窗口）。
- 期望：把 `expected` 比较与写入放进同一个存储事务（compare-and-swap 语义）。
- 初始定位：`src/resource/store.rs`、`src/resource/mod.rs`、`src/storage/redb/store.rs`、`src/storage/pending.rs`、`src/storage/contract/*`

## 12. redb commit 错误被解释为"确定未提交"

- 状态：confirmed — `map_commit_error`（`src/storage/redb/store.rs:824-830`）从不产生 `ProviderErrorKind::CommitUnknown`；`MetadataStore::commit`（`src/storage/mod.rs:498-501`）对任何非 `CommitUnknown` 错误走 `finish_ready` 解冻，把"结果未知"当成"确定未提交"。修复需限定在最终 `write.commit()` 的 outcome-unknown 分支。详见 `docs/recon/storage-atomicity.md`。
- 现象：redb 的 commit 错误被当成确定性未提交处理，实际可能出现"提交结果未知"的情形，导致上层状态与实际存储不一致。
- 期望：区分"确定未提交"与"提交结果未知"；未知时按保守/可恢复语义处理。
- 初始定位：`src/storage/redb/store.rs`、`src/storage/redb/crash.rs`、`src/storage/mod.rs`

## 13. registry / tls transport / wss 存在多套内建 tag 解析逻辑

- 状态：confirmed — 实为 4 处独立 `OnceLock`：`registry.rs:47-66`、`tls_transport.rs:57-71`、`wss.rs:57-70`、`plain.rs:57`。语法本身已单源（`src/protocol/tag.rs`），冗余仅是"解析并缓存字面量"。详见 `docs/recon/transport-identity.md`。
- 现象：registry、TLS transport、WSS 三处对相同内建 tag 各有一套解析逻辑，属逻辑冗余。
- 期望：抽出单一 tag 解析入口，三方复用。
- 初始定位：`src/transport/registry.rs`、`src/transport/tls_transport.rs`、`src/transport/wss.rs`、`src/protocol/tag.rs`

## 14. 冻结后的只读 registry 仍使用可变锁

- 状态：confirmed（更正定位）— 问题不在 `src/transport/registry.rs`（该文件生产代码无锁），而在 `src/extension_registry.rs:64-84` 的 `protocols`/`load_balancers`/`next_hops` 等 map：冻结后仍用 `std::sync::Mutex` 独占读。热路径：`src/session/inbound.rs:414`、`src/packet/mod.rs:402`。详见 `docs/recon/transport-identity.md`。
- 现象：registry 冻结（frozen）后应为只读，但仍走可变锁，存在不必要的互斥与可变性。
- 期望：冻结后以只读访问路径（共享锁/不可变引用）读取。
- 初始定位：`src/transport/registry.rs`

## 15. 分支切换只更新了 hop.downstream acks，未同步 retry 内副本

- 状态：**refuted** — `src/routing/forward.rs:539-551` 已在表锁内同时交换 `hop.downstream_acks` 与 `retry.downstream_acks`；过期事件用 map 指针身份 + live entry 判定丢弃（`ack_from_current_downstream`，`src/routing/forward.rs:605-623`），并在 `src/session/inbound.rs:258-281` 统一把关。已有测试 `a_failed_branch_redispatches_on_the_next_candidate`。详见 `docs/recon/routing-attempt.md`。
- 现象：路由 attempt 切分支时只更新 `hop.downstream` 的 acks，未更新 retry 内的副本。旧 ack/timeout 可能错误地作用于新 attempt。
- 期望：让"当前 attempt 的 peer + ack 表 + generation"有**单一所有者**，切分支时同步更新；旧 ack/timeout 只能作用于自己的 attempt（用 generation/attempt id 丢弃过期事件）。
- 初始定位：`src/routing/table.rs`、`src/routing.rs`、`src/routing/forward.rs`、`src/routing/trace.rs`

## 16. 取消一次事件 recv 会永久关闭订阅

- 状态：**refuted** — `recv`（`src/node/event.rs:65-89`）用 `Idle→InFlight` 迁出模式：先同步把 receiver 放进 parked future 写回 `self.state`，再 await；取消时 receiver 仍归订阅所有。已有测试 `event_subscription_recv_survives_cancellation`（355）。详见 `docs/recon/session-liveness.md`。
- 现象，先把 `self.state` 替换成 `terminate`，再在局部变量里 `await receiver`；外层 `timeout`/`select` 取消后 receiver 被 drop，订阅永远不会回到 idle。
- 期望：状态变更与 await 顺序调整，使取消不会破坏订阅状态（例如只在真正完成时变更状态，取消走可恢复路径）。
- 初始定位：`src/node/event.rs`

## 17. 被取消的 redb 提交仍在后台运行，reconcile 可能过早返回 aborted

- 状态：**refuted** — commit 在执行前就注册 detached landing 并 eager spawn（`src/storage/redb/store.rs:154-244`），`reconcile` 先等待该事务的在途落地再判读 receipt（`src/storage/redb/store.rs:246-282`）。已有测试 `redb_adapter_dropped_commit_future_still_lands_durably`、`redb_adapter_reconcile_waits_for_a_detached_landing_before_judging`。注意：claims 里点名的 `reconcile/engine.rs`/`plane.rs` 是 anti-entropy 同步面，与本条无关。详见 `docs/recon/storage-atomicity.md`。
- 现象：取消一个 redb commit 后，底层提交仍在后台执行；reconcile 却可能已按"aborted"返回，导致状态误判。
- 期望：取消路径等待/接管后台提交，或让 reconcile 在提交确实结束前不返回最终结论。
- 初始定位：`src/storage/redb/store.rs`、`src/reconcile/engine.rs`、`src/reconcile/plane.rs`

## 18. 转发队列把永久超大帧当成暂时饱和无限等待

- 状态：confirmed — `BoundedSender::send_waiting`（`src/session/queue.rs:191-216`）在 `reserve` 因 `FRAME_OVERHEAD + body > max_bytes` 永久返回 `None` 时无限等待，只有队列关闭才退出；`send` 路径有 `Error::overloaded`，但没有任何转发调用方使用。门限：`MAX_CHUNK_BYTES = 32KiB`（`src/packet/mod.rs:60`）对 `session_queue_bytes`（`src/config.rs:81-85`）。详见 `docs/recon/routing-attempt.md`。
- 现象：转发队列遇到永久超过容量的帧时，当作暂时饱和而无限等待，造成队头阻塞/死等。
- 期望：区分"暂时饱和"与"永久不可容纳"；后者应报错/丢弃并给出明确诊断。
- 初始定位：`src/routing/forward.rs`、`src/session/queue.rs`

## 19. 恢复拨号未纳入 shutdown 任务所有权

- 状态：confirmed（部分） — 机制真实：恢复/度维护拨号是裸 `tokio::spawn` 且 `JoinHandle` 随手丢弃（`src/runtime/recovery.rs:382`、`src/runtime/degree.rs:188`），`into_dependencies`（`src/runtime/supervisor.rs:875-905`）的 shutdown 只 abort+await `sync_driver`/`tick_workers`/`connection_tasks`，不含它们；拨号阶段不 select shutdown。暴露由 `dial_deadline`+`authentication_deadline`（~40s）上界。修复：把 JoinHandle 注册进现有 `connection_tasks`（约两行/处）。详见 `docs/recon/membership-recovery.md`。
- 现象，关闭时可能泄漏或在途遗留。
- 期望：把恢复拨号纳入统一任务管理器（task manager）的 shutdown/所有权语义。
- 初始定位：`src/membership/recovery.rs`、`src/runtime/recovery.rs`、`src/runtime/task_manager.rs`、`src/runtime/supervisor.rs`

---

## Recon 证据

（见 `docs/recon/` 下的分区侦察记录，随后并入各条目。）
