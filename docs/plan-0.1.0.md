# radiata 0.1.0 工程计划（改进清单）

> 状态基线：main @ `3b47887` 之后的工作树（2026-09-12）。
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

---

## 1. P0（0.1.0 冻结前必须完成）

### P0-1 公共错误构造入口

- **状态**：待办
- **问题**：公共回调（`PacketConsumer`、`RouteNextHop`）需要返回 `radiata::Result`，
  但公开面只有 `Error::provider(ProviderErrorKind, ProviderErrorContext)`——语义错位。
  chat example 被迫用 `provider(Io, TransportConnect)` 冒充"无中继可用"，
  用 `provider(Io, StorageCommit)` 冒充"消息存储失败"。
- **根因**：`Error` 字段私有，per-kind 构造器全部 `pub(crate)`，`ErrorKind` 未实现 `From` 到 `Error` 的公开路径。
- **方案草案**：`impl Error { pub fn new(kind: ErrorKind, context: &'static str) -> Self }`
  （或按需的最小集合：`invalid_input`/`unavailable`）。保留 `provider` 不动。
- **验收**：chat example 的两处冒用替换为正确构造；`public_api` 基线重生成并钉住；
  全门禁绿。
- **涉及面**：`error.rs`、ABI 基线、examples/chat。**规模：S**

### P0-2 ack 投递语义的规模化验证（soak）

- **状态**：待办
- **问题**：D2 引入"每页一次回执 + 2s 有界等待"的新流量形态。小集群已验证正确性，
  但千级资源 × 多对端下的时延/带宽影响未量化；包泵的逐请求串行 admission
  在高并发回执等待下是否成为瓶颈未知。
- **方案草案**：扩展 `tests/latency_benchmark.rs` / soak 场景：
  1) 基线重测（对齐 archive/benchmark-loopback.md 的方法）；
  2) 512–4096 资源 × 8–16 对端的反熵收敛与稳态流量测量；
  3) 注入慢对端（人为延迟 ack）验证 2s 上限不引发级联超时。
  视结果决定：`SEND_ACK_WAIT` 是否参数化进 `NodeConfig`；重发节奏是否需要自适应。
- **验收**：基准数据入档（替换归档的 benchmark-loopback 结论）；
  若触发参数化，附带配置项 + 测试。
- **涉及面**：`tests/latency_benchmark.rs`、`tests/soak.rs`、可能的 `config.rs`。**规模：M**

### P0-3 examples 纳入 CI 门禁

- **状态**：待办
- **问题**：workspace 门禁不覆盖 `examples/*`（cluster 的 `http_client.rs` 曾有 clippy
  warning 漏网；chat 修复时才暴露同款问题）。examples 是交付证据链的一部分，必须受门禁约束。
- **方案草案**：`.github/workflows/quality_check.yml` 增加 examples 编译 lane：
  对每个 `examples/*/` 执行 `cargo clippy --all-targets -- -D warnings`、
  `cargo +nightly fmt --all -- --check`、`python3 -m py_compile`（e2e 脚本语法）。
  容器级 e2e 保持手动/夜间（依赖 podman，不做 CI 硬门禁）。
- **验收**：CI 对 examples 变更强制编译门禁；`act` 本地演练或逐命令本地验证。
- **涉及面**：CI workflow、examples（cluster 的既有 clippy warning 顺手清零）。**规模：S**

### P0-4 issuer 快照刷新失败与描述符反熵解耦

- **状态**：待办
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

- **状态**：待办
- **问题**：`RemoveResource` 有 expected 版本前置，`PutResource` 没有——业务读改写
  （chat 群成员变更即实例）存在丢更新竞态，目前只能靠编排串行规避。
- **方案草案**：`PutResource::with_expected(version)`（或 `PutResource::new` 保持不变 +
  新构造器），提交路径复用 `commit_put_ctx` 的 snapshot-exact CAS，把"本地 winner ≠ expected"
  从 LWW 降为显式 `Conflict`。
- **验收**：公共 API 测试钉住；chat example 群 join 改用 CAS 并去除"并发 join 丢更新"
  的文档警告；e2e 回归。
- **涉及面**：`operation.rs`、`runtime/supervisor.rs`、`resource/store.rs`、ABI 基线。**规模：M**

### P1-2 内置默认 next-hop 策略

- **状态**：待办
- **问题**：任何要用多跳中继的业务都要手写十行 `DefaultNextHop`（取一个存活 peer）。
  库内已有扩展点与完整的转发/信封机制，只差一个确定性默认实现。
- **方案草案**：`routing.rs` 内置 `DefaultNextHop`（destination ∈ peers 直发由调用方保证；
  策略取 NodeId 排序最小的存活 peer），公共构造器/常量 tag；文档写明可替换。
- **验收**：chat example 换用内置策略后 e2e 回归；单元测试钉住确定性。
- **涉及面**：`routing.rs`、`lib.rs` 导出、examples/chat。**规模：S**

### P1-3 LeaveApplied 回执统一 ack 处理

- **状态**：待办
- **问题**：membership lane 的 leave 回执是最后一个 fire-and-forget 调用点（best-effort 提示），
  与 D2 的投递真相语义不一致。
- **方案草案**：与页投递同样收集 ack、轮末判定；失败仅计入诊断（回执是提示，不重投——
  leave 公告本身有重发预算覆盖）。
- **验收**：与 D2 一致的单元测试；leave 集成测试回归。
- **涉及面**：`membership/sync.rs`。**规模：S**

### P1-4 join 凭据：只读查询或多发凭据选项

- **状态**：待办
- **来源**：archive/example-findings.md #2（未了项）
- **问题**：`RotateMergeCredential` 是唯一凭据签发口且签发即轮换——并发 join 互相作废，
  业务必须串行化 join（chat/cluster 两个 example 都被迫如此编排）。
- **方案草案**（二选一，实现前 owner 决策）：
  a) `IssueMergeCredential`（不轮换的只读签发，凭据世代不变，多次有效）；
  b) `GetMergeCredential`（只读查询当前世代，配合现有轮换语义）。
  倾向 a)：彻底消除"签发即作废"的摩擦，同时保留 `Rotate` 作为升级手段。
- **验收**：两 example 的 join 编排去掉串行化（并发 join e2e 断言）；ABI 基线更新。
- **涉及面**：`operation.rs`、`identity/credential.rs`、runtime、两 example。**规模：M**

### P1-5 恢复退避参数复审 + RecoveryView 语义文档

- **状态**：待办
- **问题**：D1/D5 落地后，`RecoveryConfig` 默认值（initial 1s / max 5min / fan-out 64）的
  合理性未复审；`RecoveryView::pending_count` 语义已变为诊断计数
  （未直连的活跃成员数，**不等于**失联），`is_connected` 语义变为"至少一条通路"——
  rustdoc 未同步。
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

- **状态**：待办
- **来源**：archive/snapshot-analysis.md §4.2（未了事项）
- **问题**：trust.rs 注释与快照发射失败模式不符（见 P0-4）；远程 issuer 快照的
  持久副本无读者（纯写放大），且"无对象签名、真实性由投递会话背书"的限制未在模块文档声明。
- **方案草案**：随 P0-4 一并落：注释如实化；模块文档声明审计证据定位；
  评估并（若 owner 确认）移除远程快照持久化。
- **验收**：注释/文档与行为一致；若移除持久化，附带迁移说明与回归。
- **涉及面**：`identity/trust.rs`、`membership/sync.rs`。**规模：S**

---

## 3. P2（0.1.0 前完成；规模较大或需设计先行）

### P2-1 绑定传播协议改造（per-binding 事件 + revision 游标）

- **状态**：待办
- **来源**：archive/snapshot-analysis.md §2.2 债务 1、§4.3
- **问题**：`TrustSnapshotV1` 是"整集快照"传播单元：无 64 KiB 发射阶梯
  （≈870 绑定饱和，超限令整个 sync_tick 失败，见 P0-4）；>16 节点规模的绑定传播
  没有分页反熵。v1 wire 面已冻结，改造有兼容成本。
- **方案草案**：快照降级为引导/审计用途；绑定传播改为 per-binding 记录 +
  per-issuer revision 游标的分页反熵（复用 resource/membership 页面的
  scan_paged + 指纹 quiet 语义）；wire schema 走 v2 版本协商。
- **验收**：节点数 >16 的规模测试（绑定数量超一页）；旧节点兼容策略
  （owner 决策：0.1.0 前 wire 可破坏性变更，无需兼容窗）。
- **涉及面**：`identity/trust.rs`、`membership/sync.rs`、`protocol/`、规模测试。**规模：L**

### P2-2 拓扑自优化（恢复累积冗余边剪枝）

- **状态**：待办
- **问题**：D1 语义下恢复只在隔离时拨号、连通后不剪枝——故障恢复事件会永久累积
  冗余边（chat e2e 实测：hub 死后叶子互拨的边在 hub 回归后留存）。
  功能无损（多跳中继兜底），但长期运行的拓扑会漂移向稠密。
- **方案草案**：评估两向：a) 修剪——Connected 状态下周期性评估"边冗余度"
  （两端度数 + 替代路径存在性），低价值边有界主动退役；
  b) 不修——记录"恢复偏好连通性而非最优拓扑"为最终契约。
  实现前 owner 决策；倾向 b) 记录决策 + 文档，除非 soak 显示边数是实际瓶颈。
- **验收**：决策记录 + （若实现）剪枝的收敛测试与 e2e 回归。
- **涉及面**：`runtime/recovery.rs`。**规模：M（决策）/ L（实现）**

### P2-3 sync per-key 水位

- **状态**：待办
- **问题**：资源/成员反熵按名字序分页 + 整目录指纹（quiet 判定）+ 全量重投兜底。
  大目录下单条记录变更触发整目录重扫与分页重发（16 条/页/轮）。
- **方案草案**：per-key 水位（记录级 last-sent revision/digest 表，bounded），
  增量页只装"水位之后变化的记录"；全量重投保留为兜底。
  需先有 P0-2 的基准数据支撑必要性判断。
- **验收**：大目录下单写收敛轮数显著下降的基准对比；正确性测试（乱序/丢失窗口）。
- **涉及面**：`sync_common.rs`、`resource/sync.rs`、`membership/sync.rs`、存储。**规模：L**

### P2-4 群成员多赢家记录支持（决策项）

- **状态**：待办
- **问题**：LWW 整记录寄存器上，群花名册的并发读改写存在丢更新；
  P1-1 的 CAS 变体把"静默丢失"变为"显式冲突"，但并发 join 仍需重试。
- **方案草案**：先以 P1-1 落地并观察真实需求；若业务仍需要"并发 join 全部生效"，
  评估 member-set 的多赢家子记录（成员作为独立子键 resource 或 add/remove 操作日志）。
  本项的 0.1.0 交付物是**决策记录**（含被否方案的理由），实现视需求另立战役。
- **验收**：ADR 入档；chat README 的限制说明更新为指向决策。
- **涉及面**：文档为主。**规模：S（决策）**

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

### P2-6 默认 feature 反转评估

- **状态**：待办
- **来源**：archive/example-findings.md #5（未了项）
- **问题**：默认 feature 是 `json`（test-only 适配器），生产推荐 `redb`——
  新用户 `cargo add radiata` 即得到非生产存储。
- **方案草案**：owner 决策三选一：a) 反转默认（redb 为默认，json 需显式）；
  b) 无默认 feature（按需显式）；c) 保持现状 + 文档加粗。
  若 a/b：发布说明标注 breaking，检查 `--no-default-features` 矩阵。
- **验收**：决策记录；feature 矩阵（cargo-hack）全绿；文档更新。
- **涉及面**：`Cargo.toml`、CI。**规模：S（决策）/ M（反转）**

### P2-7 store_scan_stream 公开面决策 + 审计性能/规模项清账

- **状态**：待办
- **来源**：archive/audit-findings.md（"性能与规模项与 store_scan_stream 公开面保留待后续"）
- **问题**：`store_scan_stream` 公开导出但 crate 内零生产调用（仅外部测试驱动），
  留作扩展作者面；审计中缓缴的性能与规模项无台账归属。
- **方案草案**：owner 决策：保留（写入 rustdoc 定位说明 + 保留外部驱动测试）
  或移除（紧缩公开面）；逐条核对审计"未修（有意保留）"清单，关闭或转本计划条目。
- **验收**：决策记录；公开面与基线一致；无未归属的遗留项。
- **涉及面**：`provider.rs`/存储域、ABI 基线。**规模：S（决策）**

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
| A | P0-1、P0-3、P0-4、P1-7（小改集中清障） | 无 | 全门禁 + 两 e2e 回归 |
| B | P1-1（CAS Put）、P1-2（默认 next-hop）、P1-3（leave 回执） | 无（相互独立） | 全门禁 + chat e2e（join 去串行化断言） |
| C | P0-2（soak 基准与参数化）、P1-4（凭据签发）、P1-5（参数复审） | A（门禁完备）、B（CAS 影响基准口径） | 基准数据入档 + e2e 回归 |
| D | P2-1（绑定传播协议）、P2-3（per-key 水位） | C（基准数据支撑必要性） | 规模测试 + e2e 回归 |
| E | P2-4/P2-6/P2-7（三项决策记录）、P2-5（KeyProvider crate） | 无硬依赖 | 决策入档 + 新 crate 门禁 |
| F | P1-6（rustdoc 指南）、P2-8（架构文档刷新） | A–E 全部定稿 | `cargo doc` 评审 + 发布说明 |

- P2-2（拓扑剪枝）倾向"记录决策、不实现"，若 soak 显示边数是实际瓶颈则升级为 L 级条目插入批次 D。
- 每批次合入前：`git status` 干净、无临时产物、逐 commit gitmoji 规范。

## 5. 0.1.0 冻结判据

1. 本清单全部条目状态为"已完成"或有 owner 签字的决策记录（P2-2/P2-4/P2-6/P2-7 允许以决策关闭）；
2. 全部门禁绿，含 examples 编译 lane；
3. 三套 e2e（cluster 治理、chat 场景矩阵、cluster 基线）全绿且报告入档；
4. ABI 基线与公开面一致，`cargo public-api` 0.52.0 重生成无 diff；
5. rustdoc 指南（P1-6）与刷新后的 architecture.md（P2-8）评审通过；
6. `Cargo.toml` 版本升至 0.1.0，发布说明引用本计划的完成台账。
