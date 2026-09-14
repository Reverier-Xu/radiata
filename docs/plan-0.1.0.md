# radiata 0.1.0 工程计划（改进清单）

> 状态基线：`plan-0.1.0-baseline` 分支 @ `765d663`（2026-09-12；原 main @ `3b47887` 工作树已按
> 修复口径分 9 个 commit 落账）。
> 全量测试 628 通过 0 失败；clippy `-D warnings`、nightly fmt、verify-api 全绿。
> 本文档是 **0.1.0 前唯一的任务清单**：所有改进项在此登记、追踪状态、记录验收。
> 完成一项就地更新状态行（`状态：待办 / 进行中 / 已完成（commit）`）；新发现的问题先入档再开工。

## 0. 总则

- **来源**：条目来自三轮 e2e 战役（cluster 治理场景、chat 场景矩阵、hub 故障恢复）、
  两份历史审计（已归档至 archive/）的未了事项、以及实现中暴露的公共 API 缺口。
- **原则**：
  1. 业务面保持最小：join / send / leave；路由、恢复、同步收敛一律是库的职责；
  2. 公共 API 的每次变更都对应 ABI 基线重生成 + `tests/public_api.rs` 钉住；
  3. 行为变更必须有测试钉住（单元 + 进程内集成 + 容器级 e2e 三层中至少两层）；
  4. 每项独立 commit，gitmoji 规范，全门禁绿才合入。
- **门禁**（每批次收口执行）：`taplo fmt --check`、`cargo +nightly fmt --all -- --check`、
  `cargo check/clippy/test --workspace --all-features --locked`（clippy `-D warnings`）、
  `scripts/verify-api.sh`、examples 编译（P0-3 落地后由 CI 承担）、
  两套容器级 e2e（`examples/cluster/test_governance.py`、`examples/chat/test_chat.py`）回归。

## 0.1 已落地的语义决策记录（防止后续回退）

| # | 决策 | 落点 |
| --- | --- | --- |
| D1 | **any one route 恢复契约**：有任一认证路径即 Connected，恢复面绝不主动扩张已连通节点的拓扑；完全隔离时对成员表挨个重试（有界 fan-out + 退避） | `membership/recovery.rs`、`runtime/recovery.rs`、`tests/membership_sync.rs` 拓扑矩阵 |
| D2 | **投递真相**：sync 页以 admission ack 回执判定投递，失败丢弃对端续传状态、下一 tick 从头重投；排队仍是 fire-and-forget，不阻塞 tick | `sync_common.rs`、`resource/sync.rs`、`membership/sync.rs` |
| D3 | **版本元组公开往返**：`ResourceVersion::from_parts` 使条件删除可跨进程使用 | `resource/mod.rs`、ABI 基线、`tests/public_api.rs` |
| D4 | **examples 独立于 workspace**（customer-style）：example 是"外部消费者视角"的交付证据，其 e2e（容器级）是库缺陷的充分暴露面 | `examples/cluster`、`examples/chat` |
| D5 | **恢复宇宙 = 成员表**：每 tick 从描述符表全量扫描恢复候选（非一次性 seed 的会话历史），首次 join 的叶子在 bootstrap 死后可拨向从未直连的成员 | `runtime/recovery.rs` |
| D6 | **错误面采用 thiserror crate**（非仅风格）：`Error` 与内部错误枚举（`HandshakeError`、`SelectionError`、`LimitedWriteError`、`FailureCaptureError`、`SimulationError`）的 `Display`/`Error`/`Debug` 样板 impl 全部改 derive；kind/context 的 `From` 映射表是域逻辑保留，`Error` 的 const 构造器保留；公开面提供类型化的调用方错误构造入口（替代 `provider` 冒用），消费者经 `#[from]` 集成 `radiata::Error`；不开放 `Error::new(kind, context)` 全量构造 | P0-1 |
| D7 | **CAS Put 冲突映射 = `Error::conflict`**：expected 不匹配与 `RemoveResource` 现行为一致，与普通 Put 的 `Superseded` 落败路径区分 | P1-1 |
| D8 | **join 凭据并发化 = `IssueMergeCredential` 非轮换签发 + 接收端世代多次准入**：世代 10 分钟寿命内可准入任意多节点，`reserve` 允许多在途；`Rotate` 保留为撤销/升级手段 | P1-4 |
| D9 | **wire 不引入 v2**：0.1.0 未发布，直接删除旧快照传播实现，分页反熵新设计继承 v1 名义作为唯一 wire 形态，不留双栈兼容窗 | P2-1 |
| D10 | **拓扑剪枝改为实施**：冗余边的成本经源码量化为真实（反熵 tick 每 250ms 全 peer 扇出，流量/CPU/fd 随边数线性增长，恢复累积的 O(N²) 边永不回收）；实现有界剪枝：仅回收恢复面拨出的冗余边，保有 any-one-route 保底与迟滞防振荡；soak 基准验证边数回归基线 | P2-2 |
| D11 | **群成员多赢家记录 = 决策记录 + 观望**：P1-1 CAS 把静默丢失变显式冲突，多赢家子记录等真实需求 | P2-4 |
| D12 | **默认 feature 反转为 `redb`**：`json` 需显式；0.1.0 发布说明标 breaking | P2-6 |
| D13 | **`store_scan_stream` 保留**：补"扩展作者面"定位 rustdoc，保留外部驱动测试 | P2-7 |

> 以上 D6–D13 为 2026-09-12 owner 决策（源码逐条核实后拍板），对应条目的方案草案已按决策更新。

---

## 1. P0（0.1.0 冻结前必须完成）

### P0-1 公共错误构造入口

- **状态**：已完成（0ba771a；thiserror 采纳 + `ErrorKind::CallerError` + `Error::caller`，
  chat 两处冒用已替换，语义钉在 public_api 测试）
- **问题**：公共回调（`PacketConsumer`、`RouteNextHop`）需要返回 `radiata::Result`，
  但公开面只有 `Error::provider(ProviderErrorKind, ProviderErrorContext)`——语义错位。
  chat example 被迫用 `provider(Io, TransportConnect)` 冒充"无中继可用"，
  用 `provider(Io, StorageCommit)` 冒充"消息存储失败"。
- **根因**：`Error` 字段私有，per-kind 构造器全部 `pub(crate)`，`ErrorKind` 未实现 `From` 到 `Error` 的公开路径。
- **方案**（按 D6 定案，含 thiserror 采纳）：
  1. 引入 thiserror 依赖；`Error` 的手写 `Debug`/`Display`/`Error` 三个 impl 改为
     `#[derive(Debug, Error)]` + `#[error("{context}: {kind:?}")]`；内部错误枚举
     （`HandshakeError`、`SelectionError`、`LimitedWriteError`、`FailureCaptureError`、
     `SimulationError`）的手写 `Display` 样板同样 derive 化；kind/context 的 `From`
     映射表是域逻辑，保留不动；const 构造器保留。
  2. 为调用方起源的失败提供类型化构造入口（单一 caller-error 变体 + 构造器），
     保留 `provider` 不动；不开放 `Error::new(kind, context)` 全量构造。
- **验收**：chat example 的两处冒用替换为正确构造（含 `chat.rs:134-135` 注释与 README
  同步清理）；`public_api` 基线重生成并钉住；全门禁绿。
- **涉及面**：`error.rs`、ABI 基线、examples/chat。**规模：S**

### P0-2 ack 投递语义的规模化验证（soak）

- **状态**：已完成（9f31d0b；`tests/sync_scale_benchmark.rs` 释放模式基准 + 数据入档）
- **问题**：D2 引入"每页一次回执 + 2s 有界等待"的新流量形态。小集群已验证正确性，
  但千级资源 × 多对端下的时延/带宽影响未量化；包泵的逐请求串行 admission
  在高并发回执等待下是否成为瓶颈未知。
- **实测结论**（loopback，16 workers，redb 存储语义）：
  - 收敛矩阵：8×512=6.0s，16×512=16.0s，8×2048=28.1s，**16×4096=52.4s**；
  - 全矩阵零 Overloaded、稳态队列排空：`SEND_ACK_WAIT` 2s 上限**无需参数化**；
  - flapping-leaf 格与干净格同速（6.0s）：单叶会话抖动不拖累整轮（D2 结论保持）；
  - 深目录下的交付失败重扫是此前 16×4096 停滞的真因，已由单页回退修复消除；
    MemoryStorage 基座的 snapshot 全量克隆在基准中污染量度（hub 每 tick 30 次
    O(n) 克隆争全局锁），基准改用 redb（生产语义、MVCC O(1) snapshot）后消失。
- **验收**：基准数据入档（本条目即台账；替换归档的 benchmark-loopback 结论）✓。
- **后续观察**（P2-3 验证期间捕获，先在问题）：16 节点合并爆发负载下，一次
  merge 握手因存储提交状态机入口等待超时被拒（`metadata storage reconcile:
  NotReady` → `AuthenticationFailed: handshake closed`）。生产语义为运维重试；
  基准已加同款退避重试（`merge_with_retry`）。入口等待上界与 provider 调用时延
  的匹配关系值得独立排查（候选后续项，非 P2-3 范围）。
- **涉及面**：`tests/sync_scale_benchmark.rs`（新增）、`sync_common.rs` 单页回退。**规模：M**

### P0-3 examples 纳入 CI 门禁

- **状态**：已完成（1365b69 + 同批 lock 刷新；examples lane 含 clippy -D warnings、
  nightly fmt --check、py_compile；act 演练与本地逐命令验证通过；
  cluster 既有 warning 与 fmt 漂移已清零）
- **问题**：workspace 门禁不覆盖 `examples/*`（cluster 的 `http_client.rs` 曾有 clippy
  warning 漏网；chat 修复时才暴露同款问题）。examples 是交付证据链的一部分，必须受门禁约束。
- **方案草案**：`.github/workflows/quality_check.yml` 增加 examples 编译 lane：
  对每个 `examples/*/` 执行 `cargo clippy --all-targets -- -D warnings`、
  `cargo +nightly fmt --all -- --check`、`python3 -m py_compile`（e2e 脚本语法）。
  容器级 e2e 保持手动/夜间（依赖 podman，不做 CI 硬门禁）。
- **验收**：CI 对 examples 变更强制编译门禁；`act` 本地演练或逐命令本地验证。
- **涉及面**：CI workflow、examples（cluster 的既有 clippy warning 顺手清零）。**规模：S**

### P0-4 issuer 快照刷新失败与描述符反熵解耦

- **状态**：已完成（f19b0f1；核实：降级路径 + 回归测试 `sync_tick_survives_snapshot_refresh_overflow`
  均已落地，trust.rs:121-127 注释已如实化）
- **来源**：archive/snapshot-analysis.md §4.1（未了事项）
- **问题**：membership `sync_tick` 中 `refresh_issuer_snapshot(...)?` 一旦失败
  （编码超限、存储抖动），**整个 tick 失败**——描述符页反熵随之停摆，且每轮同样失败，
  形成持续停摆。trust.rs 的注释（"larger memberships heal through the resend cadence"）
  与该失败模式矛盾。
- **方案草案**：快照刷新失败降级为"跳过本轮快照发送、保留页面发射"+ 带类型化的
  debug 日志；回归测试：注入快照编码失败，断言描述符页继续流动。
- **验收**：上述回归测试；受影响 verify 脚本 PASS。
- **涉及面**：`membership/sync.rs`、`identity/trust.rs` 注释。**规模：S**

---

## 2. P1（0.1.0 前完成）

### P1-1 条件写（CAS Put）

- **状态**：已完成（c6e6fe0；`PutResource::with_expected` + D7 conflict 映射 +
  chat 群 join 改 CAS 有界重试、文档警告去除；集成测试三态钉住）
- **问题**：`RemoveResource` 有 expected 版本前置，`PutResource` 没有——业务读改写
  （chat 群成员变更即实例）存在丢更新竞态，目前只能靠编排串行规避。
- **方案草案**（按 D7 定案）：`PutResource::with_expected(version)`（或 `PutResource::new` 保持不变 +
  新构造器），提交路径复用 `commit_put_ctx` 的 snapshot-exact CAS；"本地 winner ≠ expected"
  映射为显式 `Error::conflict`（与 `RemoveResource` 一致），普通 Put 的 `Superseded`
  落败路径保持不变。
- **验收**：公共 API 测试钉住；chat example 群 join 改用 CAS 并去除"并发 join 丢更新"
  的文档警告；e2e 回归。
- **涉及面**：`operation.rs`、`runtime/supervisor.rs`、`resource/store.rs`、ABI 基线。**规模：M**

### P1-2 内置默认 next-hop 策略

- **状态**：已完成（8d26f7f；`DefaultNextHop` + `TAG` 常量 + 确定性单元测试；
  chat 换用内置。范围修正：tests/routed_packets、tests/public_api、slo-node 的
  手写策略是拓扑表驱动/外部可实现性证据，语义不同，不换用）
- **问题**：任何要用多跳中继的业务都要手写约 25 行 `DefaultNextHop`（取一个存活 peer）。核实：
  `src/` 下零个 `RouteNextHop` 实现；examples/chat（chat.rs:119-143）、
  `slo/src/bin/slo-node.rs:165`、`tests/routed_packets.rs:43`、`tests/public_api.rs:544`
  共四份同款手写。库内已有扩展点与完整的转发/信封机制，只差一个确定性默认实现。
- **方案草案**：`routing.rs` 内置 `DefaultNextHop`（destination ∈ peers 直发由调用方保证；
  策略取 NodeId 排序最小的存活 peer），公共构造器/常量 tag；文档写明可替换。
- **验收**：chat、slo-node、两个测试全部换用内置策略后 e2e 回归；单元测试钉住确定性。
- **涉及面**：`routing.rs`、`lib.rs` 导出、examples/chat、`slo`、tests。**规模：S**

### P1-3 LeaveApplied 回执统一 ack 处理

- **状态**：已完成（实现：发送侧回执的 admission ack 改为可观测——detach 任务有界等待、
  失败仅 tracing::debug 诊断，不重投不阻塞泵；`delivered_within_bound` 单元测试钉住
  成败两态）
- **问题**（核实修正）：membership lane 的 leave 回执发送侧是最后一个 fire-and-forget
  调用点（ack receiver 直接丢弃，sync.rs:416-421），与 D2 的投递真相语义不一致。
  注意：leaver 侧 `announce_leave` 已有 `LEAVE_ACK_WAIT` 回执等待（sync.rs:271-344，
  优先 applied receipt、次 admission ack），落地时不得与其重复/冲突——缺口仅在
  发送侧回执的 ack 采集与轮末判定。
- **方案草案**：发送侧与页投递同样收集 ack、轮末判定；失败仅计入诊断（回执是提示，
  不重投——leave 公告本身有重发预算覆盖）。
- **验收**：与 D2 一致的单元测试；leave 集成测试回归。
- **涉及面**：`membership/sync.rs`。**规模：S**

### P1-4 join 凭据：非轮换签发 + 多次准入

- **状态**：已完成（27a13d3 + bb05b7d；`IssueMergeCredential` 非轮换签发、世代多次准入、
  凭据使用记录按 subject 粒度、re-admission 幂等返回既有 grant、预留机制移除；
  两 example join 去串行化，chat/cluster e2e 均并发 join 断言通过）
- **顺带修复**：重入网暴露的会话拆除竞态（`retire_all_sessions` 宕底）与
  撤销同步不关闭远端会话的缺口，见 2f247bd
- **来源**：archive/example-findings.md #2（未了项）
- **问题**（核实补充）：并发 join 有**两层**卡点——`RotateMergeCredential` 签发即轮换作废
  旧 token；且接收端世代单次准入（`reserve` 至多一个在途、提交成功即 `consume` 作废，
  `credential.rs`），不轮换的 token 也会撞 `join credential reserved` 冲突。业务必须串行化
  join（chat/cluster 两 example 都被迫如此编排）。
- **方案**（按 D8 定案）：新增 `IssueMergeCredential` 命令（非轮换签发）；接收端世代改为
  10 分钟寿命内多次准入（`reserve` 允许多在途，准入成功不 `consume` 整个世代）；
  `Rotate` 保留为撤销/升级手段。
- **验收**：两 example 的 join 编排去掉串行化（并发 join e2e 断言）；ABI 基线更新。
- **涉及面**：`operation.rs`、`identity/credential.rs`、merge 准入状态机、runtime、两 example。**规模：M**

### P1-5 恢复退避参数复审 + RecoveryView 语义文档

- **状态**：已完成（b98bdc3；rustdoc 按 any-one-route 语义补齐。参数复审结论：恢复默认值
  未出现在实测瓶颈路径上——收敛由 sync 平面节奏主导，恢复默认值维持现状；
  benchmark 中 2s initial / 60s max 表现良好）
- **问题**（核实修正）：D1/D5 落地后，`RecoveryConfig` 默认值（neighbors 4 / fan-out 64 /
  initial 1s / max 5min，`config.rs:320-323`）的合理性未复审。公开视图字段为
  `unreachable_members`（`view.rs:867`，映射内部 `pending_count` 诊断计数，**不等于**失联）
  与 `is_connected`（"至少一条通路"）；缺口是 `is_connected`/`next_attempt_at` 完全无 rustdoc、
  `unreachable_members` 未显式声明"仅诊断计数"，`RecoveryConfig::new` 对 neighbors/fan-out
  语义亦无文档——并非"描述旧语义"。
- **方案草案**：用 P0-2 的 soak 数据校准默认值；rustdoc 重写两个视图字段的语义，
  显式给出"星型叶子失联 → 恢复 → 收敛"的时间预期公式（tick 周期 × backoff）。
- **验收**：rustdoc 评审；`GetRecovery` 相关测试注释与新语义一致。
- **涉及面**：`config.rs`、`view.rs`、`membership/recovery.rs` 文档。**规模：S**

### P1-6 rustdoc 指南补齐

- **状态**：待办
- **问题**：本轮沉淀的业务接入模式散落在 example 里，rustdoc 无指南：
  版本元组往返（`from_parts` → 条件删除）、any-one-route 契约、
  `RouteNextHop`/`PacketConsumer`/`KeyProvider` 三大扩展点的接入步骤。
- **方案草案**：crate root 增加 doc-camino 模块（`#![doc]` 内联指南或 `docs` 模块），
  覆盖上述四题；每题给最小可运行片段（doctest 或编译期示例）。
- **验收**：`cargo doc` 可读、示例编译；两个 example 的 README 指向 rustdoc。
- **涉及面**：`lib.rs`、各扩展点模块文档。**规模：M**

### P1-7 trust.rs 注释与远程快照持久化语义修正

- **状态**：已完成（ddd24e9、bae764d；核实：注释如实化、远程快照不再持久化并有
  `accept_snapshot_adopts_without_persisting_the_remote_snapshot` 钉住、模块文档已声明
  无对象签名限制）
- **来源**：archive/snapshot-analysis.md §4.2（未了事项）
- **问题**：trust.rs 注释与快照发射失败模式不符（见 P0-4）；远程 issuer 快照的
  持久副本无读者（纯写放大），且"无对象签名、真实性由投递会话背书"的限制未在模块文档声明。
- **方案草案**：随 P0-4 一并落：注释如实化；模块文档声明审计证据定位；
  评估并（若 owner 确认）移除远程快照持久化。
- **验收**：注释/文档与行为一致；若移除持久化，附带迁移说明与回归。
- **涉及面**：`identity/trust.rs`、`membership/sync.rs`。**规模：S**

### P1-8 反轮子清账（2026-09-12 五分区全量审计）

- **状态**：待办
- **来源**：五分区并行代码审计（protocol / identity / transport-session /
  storage-runtime / facade-crosscut），全部 P2 已逐条抽查行号属实。审计同时确认
  hex/canonical CBOR/WriterLock/base62/宏族/EventHub/三处语义各异退避等为**合理自造**，
  本项不含它们的变更。
- **问题与修法**（全部 crate 内收敛，零新依赖，行为不变）：
  1. `CommitOutcome`→typed-error 四臂映射在 ~10 处内联重复（identity 7 处、
     membership.rs:345、routing/trace.rs ×2、migration.rs 变体），且已漂移：
     trace.rs 对 Unknown 用 `StorageReconcile`、其余用 `StorageCommit`。
     修：provider.rs 增 `commit_verdict(outcome, conflict_ctx, unknown_ctx) -> Result<()>`，
     各处改调；resource/store.rs 的自有 outcome enum 变体不并入。
  2. `session/driver.rs:424-453 ↔ 515-543` 发起方握手 24 行逐字重复。
     修：提取 `async fn initiate(&self, connection, config) -> Result<Handshake>`。
  3. `session/stream.rs:681-698 ↔ 830-847` pending-ack 清算两处重复。
     修：提取 `fn fail_pending(&PendingAcks) -> Vec<(TraceId, BoundedSender)>`。
  4. `protocol/offer.rs` `FeatureOffer::new` 与 `from_wire` 容量/类别/required
     三项校验逐行镜像（offer.rs:87-118 ↔ 203-246）。修：提取共享 `finalize`。
  5. `identity/signature.rs:34` `verify_strict_message` 零调用者 + 死 `_domain`
     参数。修：删除，`verify_strict` 内联其两行。
  6. `routing.rs:214` category 用裸字面量匹配，`CATEGORY_LABELS`/`CATEGORY_RESOURCES`
     常量已在 tag.rs:22-23。修：换常量。
  7. P3 随手项（可选）：`trust.rs:168,176` 绕过 `error::fixed_bytes`；
     `merge_rate.rs:52` 手写 IPv4-mapped 检测改 `to_ipv4_mapped()`；
     `routing/trace.rs:76-119` ErrorKind 编码表单源化去 Option。
- **验收**：全门禁绿（纯重构，无行为变更）；审计引用的重复点逐条消失
  （以 grep 复核）。
- **涉及面**：`provider.rs`、`session/driver.rs`、`session/stream.rs`、
  `protocol/offer.rs`、`identity/signature.rs`、`routing.rs`、`identity/trust.rs`、
  `identity/merge_rate.rs`、`routing/trace.rs`。**规模：M**

---

## 3. P2（0.1.0 前完成；规模较大或需设计先行）

### P2-1 绑定传播协议改造（per-binding 事件 + revision 游标）

- **状态**：已完成（10d306d + 7df5d74；按 D9 直接删除整集 wire 形态，新分页设计继承 v1；
  接收端逐页采纳 + issuer key 校验；发送端 per-peer keyset 游标一 tick 一页，
  空页关 pass 才记 revision；tombstone 拆独立重发节奏；会话消费者失败补
  warn 日志；规模验收：70 成员星型 70 绑定双页传播 3.6s 全收敛，
  cleanup/lifecycle e2e 回归绿）
- **来源**：archive/snapshot-analysis.md §2.2 债务 1、§4.3
- **问题**（核实修正）：`TrustSnapshotV1` 是"整集快照"传播单元：无 64 KiB 发射阶梯
  （≈870 绑定饱和；超限不再令 tick 失败——P0-4 已修复，但快照发送会持续跳过，
  绑定传播实质停摆）；>16 节点规模的绑定传播没有分页反熵（核实：绑定只在 revision
  变化或 8 tick 慢节奏整份重发，`paged_trust_ctx` 仅本地读视图、不在 wire 路径上；
  记录 schema 无版本协商，但握手层有 feature/limit 协商可承载）。
- **方案**（按 D9 定案）：快照降级为引导/审计用途；绑定传播改为 per-binding 记录 +
  per-issuer revision 游标的分页反熵（复用 resource/membership 页面的
  scan_paged + 指纹 quiet 语义）。**不引入 v2**：直接删除旧快照传播实现，
  新设计继承 v1 名义作为唯一 wire 形态，不留双栈兼容窗。
- **验收**：节点数 >16 的规模测试（绑定数量超一页）。
- **涉及面**：`identity/trust.rs`、`membership/sync.rs`、`protocol/`、规模测试。**规模：L**

### P2-2 拓扑自优化（恢复累积冗余边有界剪枝）

- **状态**：已完成（剪枝 + 会话 provenance 标记 + 集成测试 + chat e2e 星型回落断言 18.1s）
- **问题**（成本已源码量化）：D1 语义下恢复只在隔离时拨号、连通后不剪枝——故障恢复
  事件会永久累积冗余边（chat e2e 实测：hub 死后叶子互拨的边在 hub 回归后留存；核实：
  `retire_session` 仅命令/leave/revocation/模拟调用，无自动剪枝路径）。代价不是审美的：
  - 反熵 tick 每 250ms 全 peer 扇出（`anti_entropy_interval`，supervisor.rs:158/174，
    两 plane 各一次 `alive_peers()` 遍历）；
  - 每 peer 每 tick 每 plane 固定成本：quiet 也要一次存储 scan + 指纹 hash，不 quiet
    则一页 16 条分发 + 2s ack 等待（D2）；
  - 每条会话稳态持有：TLS + WebSocket + 有界队列 + 读写任务 + ping watch。
  流量/CPU/内存/fd 全部随边数线性增长：O(N²) 累积使 16 节点下每节点从 ~4 度
  漂移到 ~15 度，反熵负载约 ×4。
  功能无损（多跳中继兜底），但长期运行的拓扑会漂移向稠密。
- **方案**：有界剪枝——标记恢复面拨出的会话；Connected 且度数高于目标拓扑时，
  周期性、确定性（NodeId 序）、小批量地退役恢复面冗余边；永不剪到断开
  any-one-route（度数 >1 才动），带迟滞防振荡（两次评估间隔 + 最小存活期）。
  caller 显式建立的边（直连配置）不回收。
- **验收**：剪枝收敛测试（故障恢复事件后边数回归基线拓扑）；chat e2e 断言
  hub 回归后边数下降；soak 基准记录边数与流量变化。
- **涉及面**：`runtime/recovery.rs`、`runtime/supervisor.rs`、会话来源标记、e2e。**规模：M**

### P2-3 sync per-key 水位

- **状态**：已实施（资源通道）
- **问题**（核实修正）：资源/成员反熵按名字序分页（`PAGE_DEFAULT_LIMIT = 16`，
  `paging.rs:18`）+ 下一页区间指纹 quiet 判定（非整目录指纹）+ 全量重投兜底
  （`arm_full_pass` 每 128 轮）。核实新事实：**中段记录变更在本 pass 内不触发重发，
  需等 `PAGE_RESEND_TICKS = 32` tick 或 128 轮全量 pass 才被覆盖**——变更可能滞留
  多达 ~128 轮才收敛，比原陈述更强地支撑 per-key 水位的必要性。
- **实施**（资源通道；成员通道保留指纹游标——节点数即目录上界，无收益）：
  - `ResourcePeerState`：每对端 walk 游标 + 有界水位表（`WATERMARK_TABLE_CAP =
    8192`，溢出清空回退全量）+ 检测节奏 `DETECTION_CADENCE_TICKS = 32`；
  - 发射按水位过滤（`emit_page_filtered_ctx`），预算 `SCAN_BUDGET_PER_TICK = 256`
    摊销扫描；**预算窗口静默时 pass 从窗口边界继续而非关闭**（否则首个静默窗口
    之后的记录永久搁浅——规模基准抓到的真实缺陷，带回归测试）；
  - 水位提交 verdict-gated（admission ack 裁决，失败 rewind 到页起点）；
  - 写入者信任等待：页可先于其写入者描述符到达（两通道同 tick 双向竞速），
    应用侧有界等待描述符收敛（2s），超时跳过并 warn；
  - 水位定期刷新（`WATERMARK_REFRESH_PASSES = 64`）：整表清空重投一次，为
    admission≠apply 类偏差（任何未知 skip）保留有界修复上界。
- **验收结果**（`sync_scale_benchmark`，release，loopback）：
  - 矩阵全绿：8×512 = 16.0s、16×512 = 16.0s、8×2048 = 36.1s、16×4096 = 60.4s
    （旧指纹基线 52.4s，+15% 为水位记账代价），稳态 queued_bytes 全零；
  - **中段单写验收样本：4096 目录收敛后单写收敛 10.1s**（= 32 tick 检测节奏
    8s + 摊销扫描 2s + 单页），旧设计需全量重发 ~64s+；
  - 回归测试：静默预算窗口继续 pass（`a_quiet_budget_window_continues_the_pass_instead_of_closing_it`）。
- **涉及面**：`resource/sync.rs`、`resource/page.rs`。**规模：L**

### P2-4 群成员多赢家记录支持（决策项）

- **状态**：已决策关闭（D11，2026-09-12）：决策记录 + 观望
- **问题**：LWW 整记录寄存器上，群花名册的并发读改写存在丢更新；
  P1-1 的 CAS 变体把"静默丢失"变为"显式冲突"，但并发 join 仍需重试。
- **决策**：先以 P1-1 落地并观察真实需求；"并发 join 全部生效"的多赢家子记录
  （成员作为独立子键 resource 或 add/remove 操作日志）暂不实现，被否理由：
  CAS 冲突已可满足正确性，多赢家寄存器与 LWW 单记录契约冲突，需真实需求支撑
  再立战役。本项交付物为本决策记录。
- **验收**：chat README 的限制说明更新为指向决策（随 P1-4 去串行化一并修订）。

### P2-5 生产级 KeyProvider 参考实现

- **状态**：待办
- **来源**：archive/example-findings.md #1（未了项）
- **问题**：库内只有测试用 ScriptedKeys；生产接入最难的一步是带崩溃恢复语义的
  密钥生命周期（三态 create/delete + reconcile）。cluster/chat example 的
  `FileKeyProvider` 是参考实现，但未审计、随 example 分发。
- **方案草案**：将 FileKeyProvider 提升为经过审计的参考实现——独立 crate
  （`radiata-provider-file`，避免核库依赖膨胀）或 `adapters` 下 feature-gated；
  补崩溃窗口测试（torn write、权限收紧、并发创建）。
- **验收**：crate 独立门禁；崩溃矩阵测试；两个 example 消费同一实现。
- **涉及面**：新 crate、两 example。**规模：M**

### P2-6 默认 feature 反转

- **状态**：已完成（42473b3；默认 `redb`、`json` 显式；powerset 与 no-default/json/redb
  矩阵本地全绿）
- **来源**：archive/example-findings.md #5（未了项）
- **问题**：默认 feature 是 `json`（test-only 适配器），生产推荐 `redb`——
  新用户 `cargo add radiata` 即得到非生产存储，且默认拉 serde 全家给所有消费者。
- **方案**（D12 定案）：反转默认——`redb` 为默认，`json` 需显式；
  0.1.0 发布说明标 breaking。
- **验收**：feature 矩阵（cargo-hack）全绿；文档更新；发布说明标注 breaking。
- **涉及面**：`Cargo.toml`、CI、两 example 的依赖声明。**规模：S（反转 + 矩阵核对）**

### P2-7 store_scan_stream 定位声明 + 审计性能/规模项清账

- **状态**：已决策（D13，2026-09-12）：保留导出；rustdoc 待补
- **来源**：archive/audit-findings.md（"性能与规模项与 store_scan_stream 公开面保留待后续"）
- **问题**：`store_scan_stream` 公开导出（自定义存储适配器作者的 Stream 桥接缝隙，
  10 行 try_unfold，库内零调用是有意设计）但 rustdoc 无定位声明；
  审计中缓缴的性能与规模项无台账归属。
- **方案**（D13 定案）：保留导出；rustdoc 补"扩展作者面"定位说明；
  保留外部驱动测试；逐条核对审计"未修（有意保留）"清单，关闭或转本计划条目。
- **验收**：rustdoc 更新；公开面与基线一致；无未归属的遗留项。
- **涉及面**：`provider.rs`。**规模：S**

### P2-8 architecture.md 全量重审刷新

- **状态**：待办
- **问题**：架构文档钉在 main @ `faf7833`；此后 D1/D2/D3/D5 语义、ack 投递、
  CAS 写（P1-1）、协议改造（P2-1）均未反映。
- **方案草案**：**在 P0–P2 全部代码定稿后执行**（避免反复刷新）：按当前代码
  重写受影响章节，头部标注对应 commit；删除时点性声明。
- **验收**：文档与代码逐节核对（审计式走查）；作为 0.1.0 发布说明的架构附件。
- **涉及面**：`docs/architecture.md`。**规模：M**

---

## 4. 批次顺序与依赖

| 批次 | 内容 | 依赖 | 收口 |
| --- | --- | --- | --- |
| 0 | 计划对账（状态行刷新、决策台账 D6–D13 入档、表述修正） | 无 | 本 commit |
| A | P0-1（D6：thiserror 采纳 + 错误构造入口）、P0-3（CI examples lane）、P1-3（leave 回执 ack） | 0 | 全门禁 |
| B | P1-1（CAS Put，D7）、P1-2（默认 next-hop，含 slo/tests 同步）、P1-4（凭据并发化，D8）、P1-5（rustdoc 补齐） | 0 | 全门禁 + chat/cluster e2e（并发 join 断言） |
| C | P0-2（soak 基准）、P2-2（有界剪枝实施，D10）、P2-6（默认 feature 反转实施） | A、B | 基准数据入档 + 剪枝收敛 + 矩阵全绿 |
| D | P2-1（绑定传播分页化，D9 不留 v2）、P2-3（per-key 水位） | C | 规模测试 + e2e 回归 |
| E | P2-5（KeyProvider crate）、P2-7（rustdoc 定位 + 审计清账） | 无硬依赖 | 新 crate 门禁 + 清账记录 |
| G | P1-8（反轮子清账：commit verdict 单源、握手/清算/校验镜像收敛、死抽象删除、常量替换） | A | 全门禁（纯重构，无 e2e 依赖） |
| F | P1-6（rustdoc 指南，含 D10 契约表述）、P2-8（架构文档刷新） | A–E、G 全部定稿 | `cargo doc` 评审 + 发布说明 |

- P2-2/P2-4 已以决策关闭（D10/D11）；P2-6 决策已定、实施在批次 C；P2-7 决策已定、rustdoc 在批次 E。
- 每批次合入前：`git status` 干净、无临时产物、逐 commit gitmoji 规范。

## 5. 0.1.0 冻结判据

1. 本清单全部条目状态为"已完成"或有 owner 签字的决策记录（P2-2/P2-4/P2-6/P2-7 允许以决策关闭）；
2. 全部门禁绿，含 examples 编译 lane；
3. 三套 e2e（cluster 治理、chat 场景矩阵、cluster 基线）全绿且报告入档；
4. ABI 基线与公开面一致，`cargo public-api` 0.52.0 重生成无 diff；
5. rustdoc 指南（P1-6）与刷新后的 architecture.md（P2-8）评审通过；
6. `Cargo.toml` 版本升至 0.1.0，发布说明引用本计划的完成台账。
