# 修复计划（本轮有效条目）

- 分支：`fix/connectivity-liveness-integrity`（基线 `cb831f4`）
- 依据：`docs/audit-findings.md` 各条目的 Recon 复核结论
- 模型调度原则：默认 `zai-coding-cn/glm-5.3`（复杂）与 `zai-coding-cn/glm-5.3-flash`（简单/机械）；`kimi-coding/k3` 仅在 glm 失败或判定确实超过其能力时才升级使用（提高 k3 门槛、控制成本）

## 复核结论概览

- **有效，纳入修复（9 条）**：#3、#5、#7、#8、#12、#13、#14、#18、#19
- **已由现有代码修复，refuted，本轮不改（9 条）**：#1（就所述场景）、#2、#4、#6、#9、#11、#15、#16、#17
- **结构上已不存在（1 条）**：#10 — 其描述的 watermark-walk anti-entropy 已被删除；当前 reconcile plane 无该缺陷

## 修复 lane

| Lane | 条目 | 模型 | 文件（预计） | 关键验收 |
|---|---|---|---|---|
| F1 | #5 keepalive 探测 deadline | glm-5.3 | `src/session/liveness.rs` | 逐 tick 推进时钟、无响应时 observer 仍会 resolve；有响应则保活 |
| F2 | #8 inbound consumer JoinSet 回收 | glm-5.3-flash | `src/session/inbound.rs` | read_loop 中 `try_join_next` 排空；drain 语义不变 |
| F3 | #12 redb commit 结果未知分类 | glm-5.3 | `src/storage/redb/store.rs` | 仅最终 `write.commit()` 的 outcome-unknown 归为 `CommitUnknown`/`Unknown`，store 进入 frozen，其余仍为确定 abort |
| F4 | #3 SPKI 按端点/信道 keying | glm-5.3 | `src/session/driver.rs`、`src/runtime/supervisor.rs`、`src/runtime/task_effects.rs`、`tests/secure_join.rs` | 同一 node 的多监听器/多信道交替拨号不再每次先失败一次 TLS |
| F5 | #13 内建 tag 解析去重 | glm-5.3-flash | `src/transport/{tls_transport,wss,plain}.rs`、`src/node/builder.rs`、`src/runtime/supervisor.rs` | 单一 `builtin_transport_tag` 缓存；调用点替换；无行为变化 |
| F6 | #14 冻结 registry 只读路径 | glm-5.3-flash | `src/extension_registry.rs` | 读路径用共享锁（`RwLock::read`），写注册仍独占；无 public API 变化 |
| F7 | #7 tombstone GC 按可收集量限批 | glm-5.3 | `src/identity/records.rs`、`src/identity/leave.rs`、`src/identity/cleanup.rs` | 前 64 个 key 均晚于 watermark 时，第 65 个陈旧记录仍被收集 |
| F8 | #18 send_waiting 永久超大帧 | glm-5.3-flash | `src/session/queue.rs` | 超容量帧立即返回类型化错误而非无限等待 |
| F9 | #19 恢复/度拨号纳入任务所有权 | glm-5.3 | `src/runtime/recovery.rs`、`src/runtime/degree.rs` | 拨号 `JoinHandle` 注册进 `connection_tasks`；shutdown 会 abort+await 它们 |

## 编排方式

1. 每 lane 一个 writer 子代理，使用独立 worktree 隔离（`worktree: true`），从当前干净 HEAD 起分支。
2. 主 agent（我）按 wave 收集各 lane 的 patch/handoff，**顺序**应用到主工作树，逐 lane 复核 diff 并运行定向测试。
3. 波次按文件不相交分组，避免同文件并发写：
   - Wave 1：F8、F1、F6
   - Wave 2：F2、F7、F3
   - Wave 3：F4、F5、F9
4. 每 lane 完成后：`cargo check/clippy/test`（定向）→ 主 agent 复核 → 应用并提交。
5. 全部完成后：`taplo fmt --check`、`cargo +nightly fmt --all -- --check`、`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、`cargo test --workspace --all-features --locked`，以及相关 `scripts/verify-*.sh`。

## 执行结果（已完成）

全部 9 条 lane 已完成、复核、应用并提交（每条独立 commit）：

| Lane | 条目 | 提交 |
|---|---|---|
| F8 | #18 send_waiting 永久超大帧 | `8bbf0c2` |
| F1 | #5 keepalive 探测 deadline | `d6d25eb` |
| F6 | #14 registry 只读路径 | `c47fb6e` |
| F2 | #8 inbound consumer 回收 | `5ef62a6` |
| F5 | #13 内建 tag 去重 | `9a4d79b` |
| F7 | #7 tombstone GC 限批 | `877ff1a` |
| F3 | #12 redb commit 不可知结果 | `26e0caf` |
| F9 | #19 拨号任务所有权 | `df4328c` |
| F4 | #3 SPKI 按目标 keying | `4b0dc90` |

终态门禁：`taplo fmt --check`、`cargo +nightly fmt --all -- --check`、`cargo check/clippy --workspace --all-targets --all-features --locked`、`cargo test --workspace --all-features --locked`（含 doctest）全部通过。相关 `scripts/verify-*.sh`（membership-recovery、reconnect、transport-registry、session-stream-liveness、revocation、cleanup、leave-rotation、redb-integrity、storage-runtime、packet-forwarding、node-lifecycle、sync-budget）全部通过。

**唯一未绿**：`scripts/verify-tls-transport.sh` —— 其 `secure_join` 测试 18/18 通过，但脚本会扫描整个 `src/` 拒绝 `eprintln!/println!`，而 `src/reconcile/budget.rs:708,719` 的**测量型测试**存在两条 `eprintln!`。该违规在基线 `cb831f4` 已存在（来自提交 `e3891de`），非本轮改动引入，需决定如何处置（见下）。

## 待决策 / 超出本轮

- **#1 残留边界**：两个子分区各自已达 `k(n)`（或 `connection_degree(1)`）时 `dial_budget=0`，跨区永不重建。属设计缺口，非本条所述 4 节点场景。是否需要低频跨区桥接探测，待确认。
- **#10 guard test**（可选）：为 reconcile plane 的 unknown-writer 修复路径补一个守护测试。
- **基线既有门禁失败**：`scripts/verify-tls-transport.sh` 因 `src/reconcile/budget.rs:708,719` 的两条测量型测试 `eprintln!` 失败。AGENTS.md 明确禁止 `println!/eprintln!`，但这两条在基线就存在。选项：(a) 把测试输出改为 `tracing`（跨测试可见性可能变差）；(b) 将测量型报告改为写入 `target/` 文件；(c) 在脚本的扫描中排除测量型测试。待确认。
- 侦察中发现的相邻问题（不在本 19 条内，暂不修）：member-mode session pump 未纳入 `connection_tasks`；plane prune 把 unknown-writer 跳过行当 superseded；`decode_revision` 错误分类；recovery in-flight 计数可短暂超 `fan_out`；若干文档/注释冗余。
