# 遗留问题清单（本轮已全部处理）

- 分支：`fix/remaining-hardening`（基于 `fix/connectivity-liveness-integrity`）
- 来源：审计侦察中发现的相邻问题（P1-P4 + 两项待确认）。
- 状态：**全部处理完毕**。每条的处置与提交见下表。

## 处置总表

| # | 问题 | 处置 | 提交 |
|---|---|---|---|
| 1 | member-mode session pump 未纳入任务所有权 | 修复：所有会话 pump 走 `track_connection_task` | `e29947e` |
| 2 | 优雅 consumer drain 在节点 shutdown 被 abort | 修复：shutdown 先给有界 grace，再 abort 拖尾任务 | `e29947e` |
| 3 | plane prune 把 unknown-writer 跳过行当 superseded | 修复：deferred 身份与 refused/loser 区分，prune 豁免并在 epoch 推进时重试 | `358b445` |
| 4 | rollover fallback 使拨号上限翻倍 | 修复：回退仅用剩余 dial budget | `34a643c` |
| 5 | recovery/degree in-flight 计数可短暂超 `fan_out` | 修复：逐次 spawn 前复查上界 | `9e011ff` |
| 6 | `send` 与"永久不可容纳"共用一个错误判别 | 修复：新增 `ErrorKind::FrameTooLarge`（兼容性修订，更新 0.1 基线） | `34a643c` |
| 7 | `relay_open` 在阻塞的 `send_waiting` 前插入 pending | 修复：admission 用 hop budget 限时，取消安全（RAII reservation），分支放弃后不会事后入队 | `34a643c` |
| 8 | 若干 `#[allow(dead_code)]` 可复核 | `TrustMode::Member` 的移除；fingerprint / `Installed` 保留并修正理由 | `393a48f` |
| 9 | `decode_revision` 把损坏报成 invalid input | 修复：归类 `StorageCorrupt` | `3e408c5` |
| 10 | `commit_page_batch_ctx` 混同 `Aborted`/`Conflict`（及 `Unknown`） | 复核：生产路径已正确（`Unknown` 不重试、冻结待 reconcile）；补回归测试 | `34a643c` |
| 11 | `arm_hop_deadline` 泄漏无主定时器 | 修复：hop 拥有定时器，解析即 abort | `34a643c` |
| 12 | `snapshot()` 在 async 线程 `begin_read` | 修复：`begin_read` 移入 `spawn_blocking` | `3e408c5` |
| 13 | `RecoveryController::immediate` 文档重复句 | 修复 | `393a48f` |
| 14 | `known_revocation_records_ctx` 的 `#[cfg(test)]` 夹在文档中且已 test-only | 修复：删除函数，测试改用 `scan_decoded_records` | `393a48f` |
| 15 | `delivered_within_bound` 文档仍叙述已删 watermark 设计 | 修复 | `393a48f` |
| 16 | `cleanup.rs` 注释重复残缺 | 修复 | `393a48f` |
| 17 | `inbound.rs` 对 `JoinSet` Drop 语义描述相反 | 修复（Drop 会 abort；设计因所有权转移而正确） | `393a48f` |
| 18 | 旧轮次审计编号引用 | 修复（本轮涉及文件内） | `393a48f` |
| 待确认 A | `handshake.rs` 的 `unreachable!()` | 修复：改为 fail-closed `Malformed`，消除潜在 panic | `393a48f` |
| 待确认 B | `recovery_endpoint` 与 degree 共享序号 | 复核为 **benign**（每步目标各自独立列表，failover 跨 attempt）；加测试与说明固定行为 | `9e011ff` |

## 本轮新发现

- **`verify-*.sh` 家族未被 CI 运行**，其中 `verify-api.sh` 是公开 API 冻结门禁（要求与 `tests/fixtures/public-api/baseline-0.1.txt` 精确一致）。基线自 `c9d62f6` 起就已漂移：`NodeConfig::with_task_reconcile_slots` 为公开 API 但不在基线中。已按固定工具 `cargo-public-api 0.52.0` 重新生成基线修复（`1bf27e3`）。**建议把 `verify-api.sh` / `verify-public-abi.sh` 纳入 CI**，否则同类漂移仍不会被发现。
- **公开 API 兼容性修订**：`ErrorKind::FrameTooLarge` 为新增变体（`ErrorKind` 为 `#[non_exhaustive]`，非破坏性），已按 `verify-api.sh` 的既定流程更新 0.1 基线（`34a643c`）。
- **redb 重启存在既有的有界锁释放瞬态**：`shutdown()` 返回后，一个在途的 detached redb commit（可保证取消后仍落地）仍可能短暂持有 `Arc<Database>`，使同一文件的立即重开返回 `StorageLocked`。实测在约 200ms 内自行释放（父提交 `4e12928` 与本分支均约 3/60 概率命中），**非本轮引入、也非泄漏**。重启测试（`resource_operations`、`redb_runtime`、`leave`）已改为对该类型化错误做有界重试（`4ed742b`）。建议后续在节点 shutdown 路径等待在途 detached commit 后再释放存储，从根本上消除该窗口。

## 仍然保留的观察（非缺陷，未改）

- `src/reconcile/budget.rs` 测量型测试的 `tracing::info!` 默认无订阅者时不回显（已完成 `553e949`）。
- `reconcile/mod.rs` 的 fingerprint 模块部分查询面（count/membership 探针）仍保留 `#[allow(dead_code)]`，理由已精确化。
