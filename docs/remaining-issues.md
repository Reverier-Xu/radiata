# 遗留问题清单（本轮未处理）

- 时间：2026-10-13
- 来源：本轮 6 份只读侦察中发现的相邻问题（不在审计 19 条内）+ 本轮修复引入后需复核的点。
- 说明：以下均已在当前 `fix/connectivity-liveness-integrity` 上核对，给出 file:line 与影响。这些不属于本轮已修复的 11 条。

## P1 — 正确性 / 任务所有权

1. **member-mode session pump 未纳入任务所有权**
   `dial_member` 用裸 `tokio::spawn(session_task)`（`src/runtime/supervisor.rs:1035-1036`），而 `reconcile_join` 走 `track_connection_task`（`src/runtime/task_effects.rs`）。由显式 `connect` 以及 recovery/degree 拨号建立的会话因此不被 recovery tick 回收、不计入 connection-task 观测、shutdown 不 await（它们仍观察 shutdown/retire 而退出，只是无人观测与等待）。与本轮 #19 同源，注册进同一 `connection_tasks` 即可。

2. **优雅 consumer drain 在节点 shutdown 时被 abort**
   drain handle 进 `connection_tasks`，但 `into_dependencies` 在 shutdown 时直接 `abort()` 这些 handle（`src/runtime/supervisor.rs:904-909`），drop `JoinSet` 会 abort 其子任务（tokio 1.53 `Drop for JoinSet` 是 abort 而非 detach）。因此 in-flight apply 只对会话级 teardown 受保护，对节点 shutdown 不受保护，与 `ConsumerDrainGuard` 注释"shutdown still awaits it"（`src/session/inbound.rs:96-100`）矛盾。需决定：shutdown 对 drain 给 bounded grace 而非 abort，或修正注释使其与实现一致。

3. **plane prune 把 unknown-writer 跳过行当 superseded**
   `src/reconcile/plane.rs:733` 的 `keys.contains(key)` 分支无法区分"资源竞争中落败"与"因 unknown writer 尚未准入"，会把后者当作 superseded 剪出 repair 集，于是其重试回退到 32-tick cadence（而非 descriptor 到达的 epoch 推进），且每轮重复付 2s unknown-writer 等待。建议 Resources apply 臂单独报告 "deferred"（unknown writer）行并在 prune 中豁免。

## P2 — 边界 / 健壮性

4. **rollover fallback 使单次拨号上限翻倍**
   `src/runtime/supervisor.rs:989` 与 `:1010` 两次 `connect_with_deadline(..., dial_deadline)` 各使用完整 `dial_deadline`；pinned 拨号首次超时后总耗时可达 2×。第二次应传剩余时间。

5. **recovery/degree in-flight 计数可短暂超 `fan_out`**
   `recovery_tick_inner` 在批次前只检查一次 `recovery_pending >= fan_out`，随后最多 spawn `fan_out` 个，瞬时可达 `2·fan_out−1`（`src/runtime/recovery.rs:313-320`）；degree 侧同类。文档声称的 in-flight 上界与实际不符（有界、可自校正）。

6. **`send` 与"永久不可容纳"共用一个错误判别**
   `Error::overloaded("session queue")` 同时表示"暂时满"与"帧永久超界"（`src/session/queue.rs:226-236`），源端调用方无法区分可重试背压与配置错误。可考虑为永久不可容纳增加独立判别（本轮 #18 已在 `send_waiting` 内 fail-closed，但两者仍共享判别）。

7. **`relay_open` 在可能阻塞的 `send_waiting` 之前插入 pending 条目**
   `src/routing/forward.rs:335-376`：极端时序下 hop deadline 可重派给另一候选，而原 open 的 `send_waiting` 仍可能事后入队。概率低，但条目与帧的生命周期未耦合。

8. **若干 `#[allow(dead_code)]` 可复核是否可移除**
   `src/transport/verify.rs:57`（`TrustMode::Member`，注释称已 wired，属性仍在）、`src/reconcile/mod.rs:34`（fingerprint 模块）、`src/resource/store.rs:42`（`Installed(CommitReceipt)`）。

## P3 — 错误分类 / 资源

9. **`decode_revision` 的损坏分类**
   对持久化的非法字节返回 `Error::invalid_input("redb store revision")`（`src/storage/redb/store.rs:584-588`），应归类 `StorageCorrupt`；调用点包括 `read_receipt` 与 reconcile，会把存储损坏误报为调用方输入错误。

10. **`commit_page_batch_ctx` 把 `Aborted` 与 `Conflict` 混同重试**
    `src/resource/store.rs:195-216` 对两者都重试一次。`Aborted` 语义上是确定未落地，与 Conflict 不同；若 #12 引入更细的 Unknown 语义需复核该分支。

11. **`arm_hop_deadline` 每 attempt 派发无取消句柄的定时任务**
    `src/routing/forward.rs:673-688` 每次 attempt `tokio::spawn` 一个定时器，成功/失败路径都不取消；高负载下短命定时器持续累积（有界于候选数与转发容量，但属泄漏面）。

12. **`snapshot()` 在 async 线程直接 `begin_read`**
    `src/storage/redb/store.rs` 的 `snapshot()` 未走 `spawn_blocking`；redb 读事务持内部文件锁，写压力下可能阻塞 runtime（性能，非正确性）。

## P4 — 文档 / 注释一致性

13. `RecoveryController::immediate` 文档重复句（`src/membership/recovery.rs:265-266`）。
14. `known_revocation_records_ctx` 的 `#[cfg(test)]` 夹在文档注释中间（`src/identity/revocation.rs:276-279`），注释仍称 "for sync forwarding"，实际已 test-only；函数或可删除、注释需修正。
15. `sync_common::delivered_within_bound` 文档仍叙述已删除的 watermark 设计（`src/sync_common.rs:283-300`）。
16. `src/identity/cleanup.rs:373-379` 注释重复且第二份残缺。
17. `src/session/inbound.rs:83-85` 称"Dropping a JoinSet detaches its children"，与 tokio 1.53 实际（Drop 会 abort）相反。
18. 多处注释仍引用旧轮次审计编号（"audit 2026-10-09 item N"）；本轮修复后编号含义已变，建议改为描述性说明或引用本文件。

## 待确认（可能为误报）

- `src/protocol/handshake.rs:513` 对 `HandshakeKind::MergeGrantDelivery` 使用 `unreachable!()`：若该 kind 经此路径到达会 panic。需确认该臂确实不可达；若可达，对 hostile input 应返回协议错误而非 panic。
- `src/runtime/recovery.rs` 的 `recovery_endpoint` 与 degree 共用 `degree_attempt` 序号：`fan_out>1` 时同一步骤内所有目标使用同一端点索引。当前对 failover 无害，但属共享序号设计。
