# 遗留项目清单（2026-10-10）

承接 `audit-2026-10-09.md`（16 项审计发现）与 `fix-plan-2026-10-09.md`（两波修复）。
本文是两波修复完成后的遗留总账：已修复对照、仍未修复项、需决策项、部署注意与后续
验收纪律。全部条目于 2026-10-10 在当前分支（含 PR #63-#66 已合并修复与 PR #67 待合并
分支 `fix/lane-cd-session-recovery-tls` 的同内容提交）逐条重新取证，未照抄任何报告原话。

图例：**待合并** = 修复已提交在 PR #67（OPEN），合并前不计入 main。

---

## 已修复对照（16 项 × PR）

| 项 | 审计结论 | 状态 | PR / commit | 落点（一行） |
| --- | --- | --- | --- | --- |
| 1 | CONFIRMED | 已修复 | #64（`c9d62f6`） | `TaskKind::slot_class`（`src/task/mod.rs:78`）把执行槽拆成 Network/Local 双通道（`src/runtime/task_manager.rs:55-69`），额度进 `NodeConfig::with_task_reconcile_slots`（`src/config.rs:174`，默认 2+2）。 |
| 2 | CONFIRMED | 已修复 | #64（`ff164ed`） | 四静默对端占满网络槽的 starvation 场景（`tests/starvation.rs:275`），读/发包/本地写三探针均限时盒内完成。 |
| 3 | CONFIRMED | **未修复** | — | 唯一遗留的确认项，见下节详述。 |
| 4 | CONFIRMED | 已修复 | #66（`ae73b25`） | supervisor select 循环加 `join_next` 回收臂（`src/runtime/supervisor.rs:458-467`，非空才 poll）；回归 `tests/observability.rs:434`。 |
| 5 | CONFIRMED | 已修复 | #64（`c9d62f6`） | 终态相位先落表、permit 先释放；ActionHook/ResourceHook.observed 移入独立 spawn 观察任务（`src/runtime/task_manager.rs`、`src/task/mod.rs:826-884`）；leave 信号由任务表终态相位直接驱动。 |
| 6 | CONFIRMED | 已修复 | #63（`27861e2`） | `commit_expected_record_ctx` 在提交自己的快照内复查 expected（`src/resource/store.rs:108`），生产写入点 `src/runtime/task_effects.rs:860`；并发 CAS 竞态以 `tests/resource_operations.rs:907` 钉住。 |
| 7 | CONFIRMED | 已修复，**待合并** | #67（`7b72533`） | 恢复候选轮转游标（`src/membership/recovery.rs:86,170-187`）+ `known_online_member_endpoints` 携带全部 endpoint + 按尝试序号端点级 failover（`src/runtime/recovery.rs:267+`）。 |
| 8 | CONFIRMED | 已修复，**待合并** | #67（`8a822b3`） | SPKI pin 失败（严格限 `AuthenticationFailed`）回退一次 Merge 信任拨号，证明层认证通过后重录锚（`src/runtime/supervisor.rs:867-888, 919-921`）；换证回连回归 `tests/secure_join.rs:2181`。 |
| 9 | REFUTED | 无需修复；防再审计注释已落 | #63（`0e9295e`） | `src/identity/cleanup.rs:269-277` 文档注明 checkpoint 按设计无 ack 协议。 |
| 10 | PARTIAL | 已修复（真实丢失路径） | #63（`64edaff`） | `ensure_local_descriptor` 重写携带既有 labels（`src/membership/sync.rs:696-704,719-721`）；labels 存活本地+对端回归 `tests/membership_sync.rs:1282`。附带 endpoint 语义文档化，见"需决策"。 |
| 11 | PARTIAL | 已修复，**待合并** | #67（`2b692d3`） | End 帧增加类型化 `EndReason`（Completed/Interrupted，`src/packet/wire.rs:123-146`，未知码 fail-closed `:339`）；中继合成/透传 + 目的端映射恰一次 `Err(StreamInterrupted)`；**线上格式变更**（见"部署注意"）。 |
| 12 | REFUTED（主项）；附带 P2 | 附带已修复，**待合并** | #67（`964dfea`） | `ConsumerDrainGuard`（`src/session/inbound.rs:77-93`）保证 read_loop 取消路径同样注册 drain，正常/取消/shutdown/panic 全路径覆盖。 |
| 13 | PARTIAL | 已修复，**待合并**（含附带） | #67（`964dfea`） | Ack 归属门：指针等同 + live `Relay` 条目（`src/routing/forward.rs:605+`，`src/session/inbound.rs:254-267`）；重派同步换 `retry.downstream_acks`（`forward.rs:541-550`）；prune/retire 原子化按条目身份（`src/runtime/recovery.rs:127+`、`src/session/stream.rs:545+`）。 |
| 14 | PARTIAL（主项驳回）；潜伏 P2 | 潜伏面已修复 | #65（`d03cbaf`） | redb commit 在同步序言注册落地信号并 eager spawn（`src/storage/redb/store.rs:259-291`），`reconcile` 先等在途落地再读收据——不再以 future-drop 推断 settled。 |
| 15 | CONFIRMED（P1） | 已修复 | #65（`e311ed8`） | 合并后的 `FeatureRegistry` 以 `Arc` 注入 `SessionDriver`，三处握手统一经 `handshake_registry()`（`src/session/driver.rs:214, 357, 466, 543`）；公共 API 级回归 `tests/secure_join.rs:2071`。 |
| 16 | PARTIAL | 已修复 | #65（`a8cccb9`） | `EventSubscription::recv` 对齐 `poll_next` 的取出-存回模式（`src/node/event.rs:65`），取消后订阅仍可用；回归 `src/node/event.rs:355`。 |

统计：16 项中 12 项已修复（其中 5 项半的落点在待合并的 #67）、3 项驳回（9/12-主项/14-主项，
其中 9 与 12/14 的附带面已分别处理）、1 项未修复（项 3）。

---

## 待修复（按优先级）

### P1 — 项 3：路由策略与周期维护仍在 supervisor 循环内同步等待（唯一未修复确认项）

- 来源：`audit-2026-10-09.md` 项 3（CONFIRMED）；两波 lane 文件面均未覆盖，#67 亦未触及。
- 当前代码证据（2026-10-10 复核，行号为当前分支实况）：
  - `src/runtime/supervisor.rs:456` — packet 臂 `send_packet(request, &mut tasks).await`
    inline。`send_packet` 本体（`src/runtime/packets.rs:42-149`）在循环内完成：匹配节点
    目标经 `select_matching_destination`（`src/runtime/recovery.rs:93-125`，await 描述符
    store 快照 + 读描述符 = 存储 IO）、直连缺失时经 `select_forward_entry`（`src/runtime/recovery.rs:54-90`，
    await 下一跳策略 `resolve_next_hop` + session 表锁）。pump 本体是 spawn 进 JoinSet 的
    任务（`src/runtime/packets.rs:141-147`，由项 4 的回收臂收割），inline 的只是路由/策略解析。
  - `src/runtime/supervisor.rs:487-496` — recovery tick 臂：`recovery_tick()`
    （`src/runtime/recovery.rs:218`）与 trace/resource/receipt 三个 sweep
    （`src/runtime/retention.rs:13, 54, 76`）全部 inline await（含 tombstone 扫描等存储读）。
  - `src/runtime/supervisor.rs:497-503` — maintenance tick 臂：`maintenance_tick()`
    （`src/runtime/degree.rs:37`）inline await（成员表读 + 缺口拨号）。
- 后果（同审计原文）：慢存储或慢策略解析时读查询与包路由被短暂阻塞；程度远低于重构前，
  但结构性来源未根除。
- 建议修复方向：recovery/maintenance tick 的 sweep 工作派生为任务（复用 task manager 的
  内部 kind 或独立 spawn，保持有界记账——不得重蹈项 4）；包路由臂保持 inline（它是背压点），
  但把描述符快照/策略解析的存储 IO 移出循环臂（预解析、后台刷新或快照外置）。
- 建议文件面：`src/runtime/supervisor.rs`、`src/runtime/packets.rs`、`src/runtime/recovery.rs`、
  `src/runtime/retention.rs`、`src/runtime/degree.rs`。

### P2 列表（lane 报告与审查发现中仍成立的项，逐条已复核）

1. **挂起的资源观察者是未追踪 detached 任务**（lane-a 审查 P2）
   - 证据：`src/task/mod.rs:864-884` — `notify_resource_observers` 以裸 `tokio::spawn`
     派发观察任务，无记账、无超时看护；永久挂起的 caller hook 会以 detached 任务存活到
     进程结束（与项 4 同类，量级小：每个 put/delete 至多一条）。trait 文档
     （`src/task/mod.rs:749-753`）已声明"不拖延任务/关机"的另一面即 detached 存活。
   - 方向：暂无需行动；若要收紧，把观察任务纳入有界记账或加超时看护（需先有挂起 hook
     的真实案例）。
   - 文件面：`src/task/mod.rs`、`src/runtime/task_manager.rs`。
2. **`slot_class` 的 `_` 通配符静默路由 Local**（lane-a 审查 P2）
   - 证据：`src/task/mod.rs:78-83` — 未来新增 `TaskKind` 变体默认进 Local 通道；封闭集
     测试（`src/task/mod.rs:1133`）是显式枚举，新增变体时不会编译失败。
   - 方向：无需立即修改（默认 Local 是安全方向）；新增变体时须人工确认分类并补进封闭集
     测试（写入验收纪律）。
   - 文件面：`src/task/mod.rs`。
3. **源端 pump 在 mid-flight Failed 后仍发完已入队尾部，路由终态存在双写者竞争**
   （lane-cd 报告遗留 1）——**已收敛（lane-g）**：复核发现内存 record 的单调终态机
   （`src/routing/table.rs:47-56`，Failed 覆盖一切/Failed 后拒绝一切）早已存在，
   终态本就确定；lane-g 补齐契约锚点（`src/routing/outbound.rs:11-23,291-306`、
   `src/session/inbound.rs:287-296`）与回归钉（`tests/routed_packets.rs:864`，
   红绿验证），生产代码零行为变更。
   - 证据：`src/routing/outbound.rs:247-285` — admission 成功后 pump 无条件泵完 body 并
     发 End，End 入队成功即记 `Delivered`（`:267-274`）；同一时刻
     `src/session/inbound.rs:296-302` 的迟到 Failed 会把 origin 的 route record 翻为
     `Failed`——两个写者竞争，最终状态取决于落序（"已出队"与"已投递"语义混用）。
     at-most-once 数据面既有行为，#67 未扩大处理。
   - 方向：pump 感知路由终态（route record 翻转即提前终态化），或明确文档化
     "Delivered = 已从本节点出队"语义；中继腿死亡对消费者的可见性已由 #67 的
     `StreamInterrupted` 解决，本项只余 route record 语义。
   - 文件面：`src/routing/outbound.rs`、`src/session/inbound.rs`。
7. **durable route-trace 终态与内存 record 分叉（durable twin 未镜像迟到失败）**
   （lane-g 复核发现，主控裁决登记）
   - 证据：`src/routing/outbound.rs` pump 尾部——`update_route(Delivered)` 被单调终态机
     拒绝后，仍无条件 emit RouteChanged 并经 `record_terminal_trace` 持久化 durable
     终态 `Delivered`；真实落序下 pump 尾部先落，durable store 对一条消费者已收到
     `StreamInterrupted` 的路由保留 `Delivered` 整个保留期。durable trace 的记录访问器
     为 `#[cfg(test)]`，生产面无内容消费方（只写审计日志），影响为取证失真而非功能
     正确性。
   - 方向：二选一——(a) 完整镜像：inbound 迟到 Failed 同步持久化 durable Failed
     （需把 TraceSink 穿进 `SessionPacketContext` 构造点，`src/session/stream.rs:102-127`），
     构造点级改动，单独 lane；(b) 文档化"durable 终态 = 源端出队证据（enqueue
     evidence）"语义并接受与内存 record 的分工。
   - 文件面（若立项 a）：`src/routing/outbound.rs`、`src/session/stream.rs`、
     `src/session/inbound.rs`、构造点（`src/session/driver.rs` / `src/runtime/supervisor.rs`）。
8. **`insert_route` 是唯一不经 Failed 粘性守卫的记录写点**（lane-g 审查 P2，加固项）
   - 证据：`src/routing/table.rs:24-45`（`:43` 对已存在 key 无条件覆盖）与
     `record_terminal_failure` 的"未追踪"分支（`:84-87`）放锁后调用它，存在窄 TOCTOU
     窗口。当前生产调用点均不可达该竞态（每流新 trace id / 已确认 key 不存在），
     属加固而非缺陷。
   - 方向：随 durable twin 条目一并处理，或为 `insert_route` 补 Failed 粘性不变量。
   - 文件面：`src/routing/table.rs`。
4. **重派指针换出亚毫秒窗口**（lane-cd 审查 P2，已文档化接受）
   - 证据：`src/routing/forward.rs:546-549` 注释在案 — 同分支 ack 落在 `send_waiting`
     返回与 forwarding 表更新之间会被归属门误丢，hop deadline 超时后重派别分支；
     fail-closed、自愈，窗口远小于一次网络 RTT。
   - 方向：无需修复（固有局限已注释）；若未来重派路径加 await 点放大窗口，需重新评估。
   - 文件面：`src/routing/forward.rs`（仅注释锚点）。
5. **degree 平面仍按首 endpoint 投影拨号**（lane-cd 报告遗留 3）
   - 证据：`src/membership/degree.rs:135` — `select_degree_dials` 签名收
     `BTreeMap<NodeId, Endpoint>`（单 endpoint），该文件未被两波修复触碰（末次变更
     `ffc630a`）；`src/runtime/recovery.rs:241-256` — `known_online_members` 显式投影到
     首 endpoint（注释写明"the degree dialer's single-endpoint selection contract"），
     `src/runtime/degree.rs:40` 消费该投影。
   - 后果：多宿主端点级 failover 目前只惠及 recovery 拨号；degree 维护拨号仍可能反复
     撞成员不可达的首 endpoint。
   - 方向：把 degree 拨号升级为携带全部 endpoint 并复用 `recovery_endpoint` 式的按尝试
     轮转；或维持现状并文档化（维护拨号失败由 recovery 轮转兜底）。
   - 文件面：`src/membership/degree.rs`、`src/runtime/degree.rs`、`src/runtime/recovery.rs`。
6. **SPKI 回退仅在 `AuthenticationFailed` 时触发**（lane-cd 报告遗留 2）
   - 证据：`src/runtime/supervisor.rs:877-888` — 回退守卫严格
     `pinned.is_some() && kind == AuthenticationFailed`；rustls 握手失败（含 pin 失败）
     映射为 `authentication_failed("tls connect")`（`src/transport/tls_transport.rs:98-101`），
     有测试钉住该映射。
   - 风险：若未来传输层把 pin 失败改映射为其它 kind，回退将静默失效（不报错，只是
     换证节点回连退化为无限退避重试）。
   - 方向：无需立即修改；修改 `tls_transport.rs` 错误映射时必须同步核对该守卫（写入
     验收纪律），或让回退守卫改为显式的"pin 在场且 TLS 层失败"判别。
   - 文件面：`src/runtime/supervisor.rs`、`src/transport/tls_transport.rs`。

### 既有 P2 审查发现中已关闭的项（防重查）

以下审查 P2 在合入前已修正，2026-10-10 复核确认在位，不再是遗留：
`Superseded` 文档措辞（`src/resource/store.rs:43-49`，已限定 preconditioned 才映射
Conflict）；labels 单测文档过度声明（措辞已收敛）；观察顺序文档措辞（`src/task/mod.rs:729,
749-751` 改为"commit lands 后"表述）；redb 注册项改 commit 同步序言（`store.rs:263-273`）；
landing hold RAII 化 + 时限盒（`store.rs:105-119` 的 `LandingHold`）；inbound 迟到 Failed
注释 origin 限定（`inbound.rs:296-298`）；recovery.rs 注释排版与 wire.rs round-trip 测试
注释（`src/packet/wire.rs:508-510` 已改述金样钉住）。

---

## 需决策

1. **endpoint patched-but-unlistened 的保留语义**（lane-b 报告遗留 1）——**已决策（2026-10-10）：维持文档化回滚语义，不支持预告未监听 endpoint**，不立项。现状（注释+文档+测试）即终态闭环。
   - 来源：审计项 10 附带。当前语义：patch 进来但没有 listener 绑定的 endpoint 是
     advisory，维护重写会在下一个 tick 回滚它。
   - 当前代码证据：`src/membership/sync.rs:700-709`（回滚语义与理由注释）、
     `src/membership.rs:182-189`（`apply_metadata_patch` 文档）；集成测试
     `tests/membership_sync.rs:1282` 钉住回滚行为。
   - 决策点：仅凭 `(existing, published)` 无法区分"owner 添加但未监听"与"listener 已
     停止"；真正保留需要 per-endpoint 来源追踪（新 durable 状态 + 迁移面），属于架构
     立项。**决策（2026-10-10）：不立项，回滚语义为终态。**
   - 文件面（若立项）：`src/membership/sync.rs`、`src/membership.rs`、描述符存储模式。
2. **examples/chat 驱动脚本的 b_rapid_disconnect_loop flake**（fix-plan flake 观察的结案）——**已决策（2026-10-10）：排期修复驱动脚本（重发改走 /flush 复用 pending 条目方向），由 lane-h 承接。**
   - 结论：**与库无关**。库对两次独立 send 各恰好投递一次；双份 marker 来自驱动脚本
     重发路径：每次 `POST /dm` 都 mint 新 msg_id（`examples/chat/src/http.rs:365-403`
     → `record_outbox`，`examples/chat/src/store.rs:137`），接收端 inbox 仅按 msg_id
     去重（`examples/chat/src/store.rs:108-117`）；`test_boundary.py:274-286` 在 3s 轮询
     窗（`:278-284`）内未观察到首封送达就再次 `POST /dm`，两条独立消息最终都落地。
     lane-cd worker 本地复验：fresh mesh ×12 周期 + warm mesh ×20 次调用零复现；
     归属修复在位后仍复现一次，证实与项 13 无关。
   - 修复建议（examples 改进，不在库文件面）：重发改走 `POST /flush` 复用 pending 条目
     （`http.rs:407` flush 已存在）并由接收端按 (from, 客户端幂等键) 去重；或放宽 3s
     轮询窗 / 先等 edge re-formed（`test_boundary.py:291` 已有 60s 等待臂）再判收敛。
     CI 复验建议按 fresh mesh × ≥10 次重复运行 boundary 套件。
   - **已排期（2026-10-10，lane-h）**：重发改走 `/flush` 复用 pending 条目（或等价幂等键方案），examples 面修复，不涉及库代码。
3. **ActionHook panic 语义变更是否为最终语义**（lane-a 报告遗留 2）——**已决策（2026-10-10）：确认为最终语义。** 用户判断：注入资源变更链路的 effect hook（validate/mutate）不在此列；任务完成后的观察 hook 本就不应决定任务成败，不做兜底。
   - 来源：PR #64 的有意语义变更 — hook 在 Running 转换上 panic 原先使任务 typed 失败，
     现在被包含为 warn 诊断、任务照常运行。
   - 当前代码证据：`src/task/mod.rs:760-768`（trait 文档："an error or a panic is a
     `tracing` diagnostic, so no hook can fail, wedge, or delay a task…"）、`:826-842`
     （catch_unwind 实现）；双层测试钉住：`src/runtime/task_manager.rs:1404`、
     `tests/tasks.rs:881`。
   - 决策点：这是"观察移出 attempt body"的必然推论；任务执行失败的 Failed 落表路径完全
     不变，观察 hook 运行在终态发布之后，允许其改写状态会破坏终态单调性。**决策
     （2026-10-10）：维持现状为最终语义，不重新设计观察相位。**

---

## 部署注意

1. **End 帧线上格式变更（#67，待合并）——混布不兼容**。
   End 帧 CBOR 体从 `["trace_id"]` 变为 `["trace_id", reason]`（0=Completed，
   1=Interrupted）。金样 `end-v1` 重生成、`end-interrupted-v1` 新增
   （`src/compatibility.rs:202-215`，冻结字节注释 `:373-375`，manifest 总数 21→22
   `:555`）；未知 reason 码在 decode 边界 fail-closed（`src/packet/wire.rs:339`）。
   **旧版本节点会把新 End 帧判为非 canonical 而断开会话**：合并 #67 前必须确认无
   新旧混布部署。pre-release 计划内 amendment（`src/compatibility.rs:10`："a format
   change is a deliberate compatibility amendment, never an accident"）。
2. **网络类任务并发默认 4→2（#64）**。执行槽拆分后 network 通道默认 2 槽
   （`src/config.rs:382-388` 注释文档化：总额度保持历史 4，本地类保底 2）。重拨号
   （join/connect 密集）部署可用 `NodeConfig::with_task_reconcile_slots(local, network)`
   调大 network 侧；recovery/degree 维护拨号不走任务通道，不受影响。
3. **ActionHook panic 不再使任务失败（#64，对 hook 作者可见）**。见"需决策"第 3 条；
   hook 作者不应依赖 panic 传播来中止任务。
4. **SPKI 锚仍为进程内有效（语义与修复前一致，#67 补充了换证兜底）**。重启丢锚、
   不再重新 pin 的行为不变（`src/session/driver.rs` 的 `MemberSpkiTable` 语义注释）；
   对端合法换证由 pin 失败回退一次 Merge 拨号 + 认证后重录锚兜底（#67）。

---

## 验收纪律（后续修复的统一验收要求）

以上条目的成因多数是"语义变更缺锚点"。为避免边修边新增遗留，后续一切修复遵循：

1. **一项一 commit**：gitmoji 前缀、单逻辑变更、kebab-case 分支；lane 间文件面零交集。
2. **红绿验证**：每个新测试在回退修复后必须失败，恢复后通过；时限盒一律
   `tokio::time::timeout` 或既有 `wait_for` 惯例。
3. **语义变更三锚点，缺一即登记为新遗留**：
   - 代码注释（引用审计项或写明约束不可省的原因）；
   - 面向使用者的文档（trait/doc comment，或本目录 docs）；
   - 测试钉住（单元或集成，与语义同层）。
4. **生产写入点纪律**：`commit_record_ctx` 已降为 `#[cfg(test)]`
   （`src/resource/store.rs:83-91`）；一切新增生产写入必须走
   `commit_expected_record_ctx`（无条件写传 `None`），禁止恢复无条件生产入口。
5. **可见性放宽必须带语义注释**（先例：`src/session/stream.rs:545-551` `retire`
   改 `pub(crate)` 附身份退休注释）；`slot_class`/封闭集枚举新增变体时必须人工复核
   分类并更新封闭集测试（`src/task/mod.rs:1133`）。
6. **线上格式变更**：同步重生成/新增 `src/compatibility.rs` 金样（族清单关闭）、
   decode 边界 fail-closed，并在 PR 描述中披露混布影响与金样计数变化。
7. **并发形状变更后重跑并发敏感测试**：槽位/并发配置改动必须重跑
   `tests/resource_operations.rs::concurrent_expected_puts_commit_exactly_one`
   等依赖并发槽的确定性窗口测试（PR #63/#64 互相重跑约定；#67 验收全量
   917 passed 已覆盖一轮）。
8. **传输层错误映射改动必须核对 SPKI 回退守卫**（待修复 P2-6 的耦合面）。
9. **门禁零警告**：`taplo fmt --check`、`cargo +nightly fmt --all -- --check`、
   `cargo check --workspace --all-targets --all-features --locked`、
   `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`、
   `cargo test --workspace --all-features --locked`。
10. **滚动更新本清单**：每项修复合并后在本文件对应条目标注 PR/commit 并移出遗留
    分区；新增语义变更若无锚点，直接登记进"待修复"或"需决策"，不允许无主变更。
