# 测试套件专项（2026-11-03）

## 目标与判据

维护者裁决：**测试以用户场景为准，链路场景覆盖完善即可**。不为历史原因保留测试；
不必要或已被其他路径覆盖的测试一律精简。

因此本专项的判据是两条，而不是"单元测试 vs 集成测试"：

1. **公共链路优先**：`tests/` 下的集成 lane 通过 `NodeBuilder` / `NodeHandle` 等公共
   面驱动真实节点（真实 TLS、真实存储、真实任务表）。凡是同一契约已被某条公共 lane
   端到端断言的 `src/` 单元测试，删除——它们只是用假 observer / 假 store 把同一件事
   又断言了一遍。
2. **内部契约保留**：公共链路**到不了**的内部契约不删。具体包括：存储 provider
   契约与崩溃边界（old-or-new）、wire golden 与字节冻结、确定性故障矩阵、背压与
   容量上限（伪造 NEED 洪泛压 backlog、观测 lane 溢出、每类 admission backlog）、
   通道隔离、毒锁读、以及"只有内部才能构造"的异常态（坏行、Unknown 提交结果）。

判据 2 的边界是"删了会真的降覆盖"，而不是"看起来像单元测试"。据此保留的典型例子：
`reconcile/engine.rs` 的 wire 边界与 backlog 上限、`storage/contract/*` 的原子性与
幂等、`session/inbound.rs` 的窗口背压、`resource/mod.rs` 的记录代数与 golden 向量。

## 本轮删除（63 个测试，约 1900 行）

| commit | 范围 | 删除 | 依据 |
| --- | --- | --- | --- |
| `9c8c36b` | `src/task/mod.rs`、`src/runtime/task_manager.rs` | 33 | `tests/tasks.rs` 端到端驱动同一批契约：生命周期阶段、值语义 wait、每转换一个事件、keyset 分页、终态淘汰、shutdown 取消、重试与耗尽、coalescing、凭据一次性投递、hook 顺序与 panic 隔离 |
| `85eecc6` | `src/config.rs` | 4（净） | 五个逐旋钮测试断言同一个 setter 契约（存值 + 拒绝零），合并为一张表 |
| `21620e5` | `src/protocol/tag.rs` | 5 | `tests/core_values.rs` 从公共面解析/拒绝同一批 tag 形态，含同一批非规范拼写 |
| `9fdb80b` | `src/resource/store.rs` | 8 | `tests/resource_operations.rs` 驱动同一批寄存器契约（原子提交、单事件、tuple 收敛、put/remove 的精确版本前置、两后端重启保持）；后端逻辑版本对另与 storage contract lane 重复 |
| `cf1d8f2` | `src/runtime/recovery.rs` | 2 | `every_member_sweeps_every_endpoint_for_any_schedule_shape` 已对全部 candidate/endpoint/fan-out 组合穷举同一性质 |
| `6064f9c` | `src/view.rs`、`src/operation.rs`、`src/hex.rs`、`src/api.rs` | 10 | 纯形状/访问器断言：构造什么就读回什么。公共面已覆盖（task view 经 `node.tasks()`、事件经 `event_parity`、hex 经磁盘 key 文件名与全部冻结向量） |

删除过程中顺带清理的死代码：`src/task/mod.rs` 的 `Harness` 假 observer 与
`merge_view`/`issued_credential` 夹具、`task_manager.rs` 的 `RecordingHook` /
`PanickingHook` / `WedgingHook` / `await_hook_calls`、`src/view.rs` 的 `task_id` /
`record` 夹具。`src/protocol/tag.rs` 的 `as_str`/`domain` 原本只被那个测试使用，
现改为宏内 `#[allow(dead_code)]` 并注明理由——不再用一个测试给生产方法续命。

## 保留清单（判据 2 的实例）

| 位置 | 保留理由 |
| --- | --- |
| `src/task/mod.rs` | 观测 lane 的溢出丢弃与 drop 取消、资源 hook 的提交顺序调度、毒锁读报 typed internal |
| `src/runtime/task_manager.rs` | 每类 backlog 上限与 typed overload、extension 通道隔离、journaled kind 的 drain 顺序、wedged hook 的 shutdown 取消、按 pinned key 比较的 revoke coalescing、本地通道预算、重试策略表 |
| `src/resource/store.rs` | 坏行 plain-put 自愈、install epoch 信号、page batch 的 Unknown 不重试 |
| `src/runtime/recovery.rs` | 端点轮换穷举、worker 单 tick in-flight、fan-out 在飞上限、DialPermit 的 panic/取消释放、毒 controller 报错、探针边不被冗余剪枝回收 |
| `src/runtime/degree.rs` | 探针生命周期/轮换/回退、cadence 与寿命常量 pin、在飞预算、panic 释放槽位 |
| `src/storage/contract/*`、`src/storage/{redb,json}`、`src/resource/crash.rs` | provider 契约、崩溃边界、原子性与幂等 |
| `src/reconcile/engine.rs`、`src/reconcile/plane.rs` | wire 边界、backlog 上限、伪造 NEED 洪泛、eager piggyback、派生视图修复 |
| `src/simulation/*` | 确定性故障矩阵与产物 |
| `tests/static_invariants.rs` | 行为测试观察不到的源码级不变量（命名空间单一来源、retired 词汇、无 println 等）——不是用户场景，但删了就没有任何替代 |

## 尚未精简的候选（留给后续增量）

按判据 1 还有重复嫌疑、但本轮未动的区域（每条都需要逐测试确认公共 lane 的确切断言，
不宜批量删）：

- `src/session/inbound.rs`（26）对 `tests/routed_packets.rs` / `tests/transport_chaos.rs`：
  多数是窗口背压与 hop 所有权，属判据 2；少数（metadata digest、拒绝计数）可能重复。
- `src/routing/trace.rs`（22）对 `tests/observability.rs`：retention 与 sweep 计数属判据 2；
  `failure_codes_round_trip` 之类可能重复。
- `src/identity/records.rs`（20）：golden 向量与 canonical 拒绝属判据 2；访问器类可删。
- `src/transport/registry.rs`（19）对 `tests/transport_override.rs` /
  `tests/transport_provider.rs`：override/provider 面已被公共 lane 覆盖，部分可删。
- `src/storage/migration.rs`（13）：`*_json` / `*_redb` 成对测试可合并为参数化一份。

## 验证

- 全量质量门（单进程）：`taplo fmt --check`、nightly `rustfmt --check`、
  `check --all-targets --all-features`、`clippy -D warnings`、
  `test --workspace --all-features --locked` 全绿。
- 测试规模：1121 → 1058 个用例（净减 63），`src/` 单元测试 924 → 861。
- 本轮不做变异验证（维护者裁决）：删除的依据是"公共 lane 已断言同一契约"，由公共 lane
  本身作为回归网。
