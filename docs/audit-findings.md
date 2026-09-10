# radiata 全量代码审计报告

> 审计基线：main @ `faf7833`（2026-09-09）。
> **修复记录**：全部 P1×3、P2×22（含 owner 决策后的 P2-12）、P3×14 已在分支 `fix-audit-fixes`（worktree `../radiata-audit-fixes`）逐项修复落盘，每项独立 commit、全部门禁绿（taplo/fmt/clippy -D warnings/全量测试 550→608/0、受影响 verify 脚本全 PASS、cargo-hack each-feature 矩阵、fuzzing 构建零警告）。详见 §9 修复台账。P2-12、OpenWireV1、canonical_record! 宏均已 owner 决策并落地（见 §9 台账与 §4 勘误）；性能与规模项与 store_scan_stream 公开面保留待后续。
> 方法：4 个并行 reviewer 分区深读全部生产代码（L1 协议+L2 传输 / L5 身份+成员 / L3 会话+L4 路由+L7 运行时 / L6 存储+资源+跨模块扫描），统一 7+4 维度评分表；全部 P0/P1 与关键 P2 已由主审逐条对照源码复核（子代理行号可能有 ±10 行漂移，但事实均成立）。
> 质量门禁基线：taplo ✓ / nightly fmt ✓ / check ✓ / clippy `-D warnings` ✓ / **cargo test 550 通过 0 失败**。
> 架构与模块职责见 [architecture.md](architecture.md)。

## 0. 总体结论

无 P0；整体健康度高，核心不变量（有界性、fail-closed、单源化、崩溃安全）在当前代码中成立（见 §1 正向基线）。本次发现 **3 个 P1**（均为"代码与自身文档承诺矛盾"类缺陷，而非安全漏洞）、**约 16 个 P2**（职责耦合、重复逻辑、装饰性 API、兜底吞错、限制链失配）、**30+ 个 P3**。四个重点维度（用户指定）总体表现：

| 重点维度 | 结论 |
| --- | --- |
| 职责耦合 | 少量残留：session⇄routing 循环依赖（代码内已无标记）、trust 策略栖身 membership/sync、传输层做限速归一化。总体层次清晰。 |
| if-else 特判绕过 | **基本没有**。分派全部枚举/数据驱动；唯二例外是 tag 保留域比较在 case-fold 之前（P1-1 附带）、select.rs 两个保留键 if/else（P3，可接受）。 |
| 冗余加固 | 主要形态是**死代码/装饰性扩展面**而非多余防御：candidates.rs 整模块死、Discovery 注册面零消费者、RoutingPolicy 公开 API 无行为、大面积过期 `allow(dead_code)`。对不存在的安全场景的多余验证——未发现。 |
| 兜底泛滥 | 少数高危点：retention 把自家 stale-base Conflict 当正常（P1-3）、membership 把 Aborted 当成功、sync.rs 吞掉 NotTrusted、liveness 兜底前提失效（P1-2）。绝大多数兜底有注释论证且正当。 |

## 1. 正向基线（本次独立复核确认成立的核心不变量）

以下不变量经本次逐条源码独立核实成立（仅以当前代码与其自身文档为依据）：

- pending_acks 无界 HashMap → `MAX_PENDING_ADMISSIONS=256`，origin/中继双侧受界，超限回 `Overloaded`。
- 撤销 TOCTOU → revoke 事务以 `StoreExpectation::Exact(binding_digest)` 钉住绑定摘要。
- relay_chunk 锁跨 await → 每 hop 独立 `relay_lock`，chunk-then-end 保序有并发测试钉住。
- trace 未知 code → `kind_from_code` 返回 `Err`（fail-closed），文档与实现一致。
- trust 快照 key `unwrap_or(0)` fail-open → 严格解析、宽度常量单源、失败返回错误。
- `adopt_binding_ctx` 已咨询本地 revocation；新鲜绑定采纳对本地已撤销身份拒绝。
- revision-gap 永久分歧 → `store_descriptor_ctx` 接受严格更高 revision 的 skip-gap 愈合。
- oracle-dup（condition_matches 双份）→ 唯一定义在 provider.rs:716，json/redb/reference 三方共享。
- receipt outcome 按 `operations.len()==2` 分类 → 显式 `(anchoring, operations)` 元组。
- `StoreNamespace::new` → 不可能失败的 `const fn`。
- purpose 字符串拼接 → `JournalPurpose::text()` 单源类型化。
- kind 表重复（handshake probe/position vs wire 注册表）→ `KIND_*` 全部由 `HandshakeKind::kind_id()` 派生。
- Connection 收发循环双份 → 共享 `next_message`/`encode_frame`。
- forwarding capacity 误接 trace 预算 → 独立常量 `FORWARDING_ROUTE_CAPACITY_DEFAULT=8192`。
- retention 全量 materialize → 流式扫描 + 有界堆（但见 P1-3 残留缺陷）。
- TypeId if-else 类型总线 → sealed trait + 每命令 `control()` 闭包武装。
- `ErrorKind::Revoked` 死变体 → 三处生产产生方（driver.rs:238/464/569）。
- 全 crate：无 unsafe、无生产 unwrap/expect、无 println/dbg、诊断全走 tracing。

## 2. P1 发现（应修，3 项）

### P1-1 `protocol/tag.rs` — canonical 域名检查：文档承诺存在，代码未实现

`valid_dns_hostname`（tag.rs:171-175）的文档声称"the canonical checks (lowercase, no trailing dot, no underscore, alphanumeric label edges) **stay explicit**"，但函数体只有 `host.parse::<domain::base::name::Name>().is_ok()`，四项检查一项都不存在。经核对 domain 0.11 实际行为：**接受尾点**（末字符非点也静默添加 root label）、**接受大写/下划线/`+`/`~` 等全部可打印 ASCII**。

可复现后果：
- `Endpoint::parse("wss://relay.example.com.:443")` 被接受，与 `wss://relay.example.com:443` 成为**两个不相等的 Endpoint 值**——违反 endpoint.rs"rejects every non-canonical representation"契约，破坏按文本相等的候选去重。
- `QualifiedTag::parse("example.com./features/x")` 被接受——同一域名的尾点拼写成为独立 tag 身份。

附带（同根 P2）：`QualifiedTag::parse`（tag.rs:31-41）先做**原文**的 builtin 域/crypto 类别保留比较、后 lowercase 折叠——`"RADIATA.WOOOO.TECH/crypto/session-v1"` 绕过 crypto 保留后折叠成保留 tag；尾点拼写同理绕过 `FeatureDefinition::new` 的 builtin 域拒绝。远端不可利用（线标签经 parse 后未知 label 在 select 固定点被丢弃），属本地 canonical 卫生问题。

**修复**：`valid_dns_hostname` 内显式拒绝尾点/下划线、强制 LDH 标签（复用 `valid_name_component` 字符规则）；把 case-fold/规范化提到 `validate_tag` 内部、再做全部保留比较；补尾点/大写/下划线 fixtures 到 `tests/core_values.rs`。

### P1-2 liveness 子系统生产不可达，且被当作其他路径的兜底前提

`NodeConfig` 的 `session_idle_timeout`/`keepalive_interval`/`keepalive_timeout` 三个字段**没有任何公开 setter**（config.rs 仅有 7 个 `with_*`，均不覆盖 liveness；字段默认恒为零）。因此 `liveness_observer`（session/stream.rs:749-757）在每个真实会话上直接 `std::future::pending()` 永不激活——约 120 行 idle/keepalive 逻辑与全部相关测试在生产路径上是死代码。

更严重的是**其他路径把它文档化为兜底前提**：饱和队列丢弃转发 ack 时注释"the upstream liveness policy bounds the wait regardless"（stream.rs:316 一带；forward.rs 同型）。该前提在生产为假：一条被丢弃的中继 ack 会让对端 `send_sync` 的等待**无限挂起**（会话永不因空闲/keepalive 关闭）。

**修复**（择一）：为 `NodeConfig` 增加 `with_session_liveness(idle, interval, timeout)` setter（校验 interval < timeout）；或删除整套不可达路径及所有引用 liveness 作为界的注释承诺。倾向前者——send_sync 无限挂起是真实的可用性风险。

### P1-3 `resource/retention.rs` — 过期删除复用陈旧 base revision，每 pass 只能落地 1 条

`sweep_removed_ctx`（retention.rs:107-170）在循环外取**一次** `snapshot`（:114），过期删除循环（:132）与溢出删除循环（:157）都传入 `snapshot.revision()`。第一条 `delete_exact` 提交后 store revision 前进，其后每条删除在 provider 的 base-revision 检查处必然 `Conflict`，被 `Conflict | Aborted => Ok(false)`（:83）静默吞掉。后果：

1. 每 pass 实际只清理 1 条 removal——与模块文档"expired removals are deleted inline while streaming / One pass evicts at most cap overflow records"矛盾；
2. N 条过期记录需 N 次全命名空间扫描——回到 O(n·m) 复杂度形态；
3. `Conflict` 语义被混用（既表示"寄存器被并发移动"也表示"我们自己的 base 过期"），掩盖缺陷。

对照正确写法：receipt.rs `cleanup_receipt` 每次调用自取新快照。

**修复**（择一）：把过期键合并为**一个**多 Delete 事务；或 `delete_exact` 内部自取快照；并在外层每条成功后刷新 revision。补"单 pass 两条过期记录"回归测试（现有测试恰好都只有 1 条过期/1 条溢出，掩盖了缺陷）。附带 P3：`cap=0` 时堆恒空、上限永不生效，应文档化 `cap>0` 前置条件。

## 3. P2 发现（建议排期，按域分组）

### 协议/传输（L1+L2）

| # | 位置 | 问题 | 修复 |
| --- | --- | --- | --- |
| P2-4 | transport/candidates.rs 整模块 | `#![allow(dead_code)]`，`EndpointCandidates`/`EndpointTable`/`CandidateSet` 生产零消费者（~190 行投机代码），`candidates()` 每次调用还做全表 O(nodes) expire | 接入 discovery/dialing 或删除 |
| P2-5 | transport/registry.rs + lib.rs:90 | `Discovery` trait、`DiscoveryPage`、`PageCursor` 等公开扩展面生产零调用（`register_discovery`/`.discovery()` 为 cfg(test)）；builder.rs:47-52 自认 WSS 硬编码——开放注册表的扩展面在 builder 处未被消费 | 在里程碑内接线或收缩 `pub(crate)` |
| P2-6 | transport/connection.rs:69,88-90,179-181 | 传输层 import `identity::merge_rate::MergeSource` 做准入归一化（L2 知道 L5 概念）；`peer_addr().ok()` 把读取失败静默折叠为"无限速来源" | Connection 暴露 `Option<SocketAddr>`，归一化上移 |

### 身份/成员（L5）

| # | 位置 | 问题 | 修复 |
| --- | --- | --- | --- |
| P2-7 | membership/sync.rs:377-410,555-598 | trust 域策略（issuer key 替换检查、binding 采纳 persist/adopt、`refresh_issuer_snapshot`）全部实现于 sync.rs；`trust.rs::assert_no_key_substitution` 反而生产无人调用 | 策略移入 `identity::trust`，sync.rs 只做 wire 分发 |
| P2-8 | membership/sync.rs:391-407 | `persist_binding_ctx` 出错一律 `debug!+continue`（含 NotTrusted 被静默降级）；`let _ = adopt_binding_ctx(...)` 吞掉全部错误（含 revocation 拒绝）——与"conflicting evidence fails closed"文档矛盾 | 仅 Conflict/NotReady 继续，NotTrusted/decode 错误上抛 |
| P2-9 | membership.rs:360 | `Committed | Aborted => Ok(())`：`commit_with_reconcile` 明确 Aborted = definitely not applied；当前适配器恰不返回 Aborted，属潜伏缺陷——未来 provider 返回 Aborted 时写被静默丢弃且 `apply_page_ctx` 仍发 `member_changed` 事件 | `Aborted` 与 `Conflict` 同样返回 Err |
| P2-10 | identity/merge_rate.rs:127-160 | `begin` 先 `global_window.record`（消耗配额）再检查 per-source 限额：单源超限后被拒的每次尝试仍消耗全局窗口——一个源 ~256 次被拒尝试即可耗尽 `RATE_GLOBAL`，全部来源合并被阻塞至多 60s（限速器自身引入的放大） | per-source 判定全通过后再 record 两窗口，或拒绝时回退全局计数 |
| P2-11 | identity/trust.rs:4 + identity/mod.rs:1-13 | 文件级/模块级 blanket `#[allow(dead_code)]` 已过时：被掩盖的模块**全部已接线生产**（merge→session/driver.rs:34、deletion→leave.rs:681、cleanup→supervisor.rs:1437+ 等）；真死 item 仅 4 个（`snapshot_digest` 零调用、`is_newer_than`/`assert_no_key_substitution`/`page_bindings` 仅测试） | 删模块级 allow，逐 item cfg(test) 或删除——让编译器重新守护 |
| P2-12 | trust.rs:545-588 vs 671-707 | 双重绑定表示：TRUST_BINDING 存 raw `version+32B key`，IDENTITY_BINDING 存 `IdentityBindingV1`，sync.rs 两处分别非原子更新 | TRUST_BINDING 家族改存 IdentityBindingV1 编码或合并 |
| P2-13 | identity/leave.rs:486+ | `WIPE_NAMESPACES` 硬编码 family 清单；families.rs 的目录 `metadata_families` 是 cfg(test)，生产无可派生源——新增域 family 不会自动进入清退清单，静默残留旧身份数据 | families.rs 提供生产可见的 domain 分区，leave 按域派生 |

### 会话/路由/运行时（L3+L4+L7）

| # | 位置 | 问题 | 修复 |
| --- | --- | --- | --- |
| P2-14 | session/stream.rs:40-46 ↔ routing/forward.rs:17-19 | session⇄routing 循环互依：`PendingAck::Relay`（转发域概念）栖身会话类型；`admit_open` 内嵌 `RouteContext::from_frame`+`envelope.receive` 路由语义；代码内已无任何待办标记但耦合存在 | `PendingAck` 迁入 routing::forward；信封校验提取为 routing 纯函数 |
| P2-15 | runtime/supervisor.rs:1309-1395 | `remove_resource` 手写 encode→sign→seal 管线且 `seal` 内部再次 `encode_signed_body`（**body 双重编码**）——违反 `sign_with_provider` 文档承诺的"single production construction path for put and remove, no double encode"（put 侧已修，remove 侧漏网） | remove 直接调 `ResourceRecordV1::sign_with_provider(..., removal_rank, true, keys, handle)` |
| P2-16 | runtime/supervisor.rs:965-978 vs routing/table.rs:65-79 | `record_route_failure` 重复 `record_rejection` 骨架且更弱：后者有"终态记录不再增长"守卫，前者没有；且 `insert_route` 的 `table.insert` **无条件整记录替换**——失败路径用 `RouteRecord::failing`（selected_node=None）覆盖 send_packet 先前插入的带真实 destination 的记录，失败后 GetRoute 查不到选中节点 | 统一走 `record_rejection`（或提取 `record_terminal_failure`），失败路径用 update 而非重插 |
| P2-17 | packet/mod.rs:46-52,78-103 | `RoutingPolicy` 单变体枚举 + `StreamPolicy.routing_policy` 公开访问器生产零消费者、零行为效果（文档还声称"must resolve to direct"但无校验）——装饰性公共 API，已进 0.1 基线 | open_stream 实际拒绝非 Direct 值，或废弃参数 |
| P2-18 | runtime/views.rs:213-228 | routes 表锁与 connection_tasks 锁的中毒都映射 `Error::session_table`（错误上下文串"session table"），诊断误导 | 逐锁正确上下文或通用 `poisoned(ctx)` 构造器 |

### 存储/资源（L6）

| # | 位置 | 问题 | 修复 |
| --- | --- | --- | --- |
| P2-19 | storage/pending.rs:553+ vs storage/mod.rs:218-241 | `open_pending_recovered_with_clock` 绕过 `migration::ensure_open_schema` 门（mod.rs:235 对普通 open 强制）并逐字段复制 `open_with_state` 构造——schema 指向未知版本的外来 store 经 local-identity bootstrap 打开**不 fail closed**，与 mod.rs 注释宣称的打开前提矛盾 | 复用 open_with_state(Ready) 后再 discovery，或 discovery 前补 ensure_open_schema |
| P2-20 | provider.rs:686-703 | `Storage` trait 与 `commit` **零文档**：json/redb/reference 三处手写重复的提交检查顺序（receipt replay→base→conditions→apply→bump）只靠测试行为钉住，trait 文档未记录该顺序契约 | 在 `Storage::commit` 文档写明顺序契约与 Unknown 语义 |
| P2-21 | 六处命名空间 helper | `family 常量 → StoreNamespace` 分散：records.rs:122（含检查）、pending.rs:769、receipt.rs:924、migration.rs:37、trace.rs:295、membership.rs:255（后五个无 category 检查）——规范形态只在 cfg(test) 的 families.rs | families.rs 生产侧提供唯一 `namespace(tag)`，六处委托 |
| P2-22 | storage/mod.rs / resource/mod.rs | blanket `#[allow(dead_code)]` 覆盖**活的生产代码**（MetadataStore/migration/pending/receipt/resource 全域都被生产调用）——dead-code 检测对两个核心域失明 | 逐一移除并清理暴露项 |

## 4. P3 汇总（择机清理）

**封装/分层**：registry.rs 双职责（注册表类型+内建 WSS 同文件）；`resource::page::sync` 与 `resource::sync` 同名模块；runtime/recovery.rs 与 forward.rs 的 next-hop 解析两写；supervisor LeaveCluster 臂内嵌整个 shutdown 序列；`TrustPage` 内外双类型逐字段搬运。

**重复**：identity 13 组同构 Wire/encode/decode triple（canonical_record! 宏候选）；三个签名墓碑 driver 80% 同形；`is_left_ctx`/`is_cleaned_ctx` 等两对同构；`sync_tick` 双 regime 分发循环；driver.rs left/cleaned/revoked admission gate 两写（语义差异需保留）；put/remove 有界冲突重试骨架两写；views.rs 分页尾样板 ×4；`connection.rs` 与 `envelope.rs` 的 declared/flags/limit 校验三元组镜像；`ParserLimits::default` 复述 16/1024 字面量（应引用 `CONTROL_CBOR_LIMITS`）。

**命名/文档与代码矛盾**：`handshake_frame_rules` 名不副实（覆盖整个连接生命周期含 packet kinds）；ws.rs `check_path` 注释承诺 SPKI 失败拒绝升级、实现静默省略；time.rs"pure conversions"文档 vs `now_*` 宿主直读；leave.rs"journaled"措辞 vs 实际幂等重扫恢复；revocation"only cleared by purge"文档漏 leave 轮换例外；transport/mod.rs"only Endpoint crosses"vs 实际公开 6 类型；redb `relay-*` 表名与 crate 名漂移（冻结格式，加注释即可）。

**算法/边界**：`LimitedWriter::new` 每次 encode 预零化整个 64 KiB 预算（chunk 高频路径成本翻倍）；`revision+1` 非饱和 vs `saturating_add` 同语义两写（membership.rs:199）；首装特例允许 revision 0 落库（违反自述 revision≥1）；`RecoveryStep::backoff_seconds` 返回自增前值、语义误导；WriterLock root 伪身份在 `tokio::join!` 场景绕过互斥（生产单提交槽兜底，注释需排除该场景）；分页每页全 namespace 重扫 O(N²/L)（StoreScan 无 seek 接口的固有成本，规模上万再议）；终态 trace 记录无界 spawn（并发有界、排队无界）；accept 错误无退避热循环风险。

**死代码**：`store_scan_stream` 公开导出但 crate 内零生产调用（仅外部测试驱动）；`signature_message_from_digest` 零调用；`MergeCredentialIssuer::issue` 的活跃代冲突分支永不触发；id.rs 的 const fn shim 与宏内 allow 已过时；`OpenWireV1` 双形态——见下方勘误。

> **勘误（批 7 修复时发现）**：原认定"crate 从不发出 legacy 5 元素形态"不成立——minicbor derive 的 array 编码跳过 nil 字段并收缩数组长度，direct open 帧（`route: None`）的 canonical 编码**就是 5 元素体**，6 字段解码器本就通过 Option 缺省接受它（改动前兼容测试已逐字节钉住该形态）。实际缺陷仅为：(1) `OpenWireV1` 回退分支是永不为解码成功贡献的死代码；(2) routed 解码失败时误报 "packet open decode" 上下文。修复 = 删除死分支、单一 `decode_canonical_strict` 路径、统一错误上下文；线上格式零变化（direct=5 元素、routed=6 元素），冻结向量 `open-direct-v1` 保持 byte-stable。

## 5. 分层评价（自底向上）

### 协议设计（L0–L2 + 线格式）

线格式是本 crate 的强项：封闭 kind 注册表 + 编译期常量断言、确定性 CBOR（迭代有界、re-encode 字节比较、proptest 不 panic）、位置锁定握手、TLS 1.3-only 收紧面全部有真实 loopback 测试、exporter 通道绑定对称性被钉住。`verify.rs` 安全主张与实现逐条一致（join 仅放宽链/主机名，CertificateVerify 无条件全验，TLS 1.2 编译期关闭）。**唯一实质缺口是 P1-1 的 canonical 域名检查**——它破坏"canonical 即唯一身份"这一 crate 反复承诺的契约。

### 模块封装（L3–L7）

职责划分总体清晰：supervisor 已按 views/recovery 分文件、分派表显式无骨架重复、类型化总线消除 TypeId if-else、`FrameRules` 归协议域所有方向正确。残留问题集中在**三处跨域错位**（session⇄routing 循环、trust 策略在 sync.rs、传输层做限速归一化）与**装饰性扩展面**（Discovery、RoutingPolicy、candidates.rs）——后者的共同形态是"注册表/类型已建好、生产消费方从未接上"，属于投机扩展性债而非设计错误。

### 算法（收敛/限速/分页/调度）

收敛代数（tuple_order 全序、描述符 skip-gap 愈合+墓碑挡降级、receipt 引用计数审计）有穷举测试且有界确定；recovery 状态机对挂钟回拨/冻结/前跳的处理与文档一致；分页单一 end-of-stream 规则被全部分页点采用。三个算法缺陷：**P1-3 retention stale-base**（收敛率与文档不符）、**P2-10 限速器全局窗口被被拒尝试消耗**（限速器自身成为放大器）、以及 O(N²/L) 分页重扫（结构性、暂可接受）。

## 6. 健康面（防止报告只呈现债务）

1. 全 crate 无 unsafe、无生产 unwrap/expect、无调试打印、tracing 使用规范、秘密 Debug 全脱敏。
2. 崩溃安全文化：merge/deletion/leave/revocation/资源 的子进程崩溃矩阵覆盖 json+redb 双后端，old-or-new 二值断言；pending journal 精确恢复打开。
3. 审计文化：`audit_reference_index`、digest tripwire、代链字节级校验、redb 缺行即腐坏——防御对象是存储腐坏而非幻影攻击者，与信任模型一致。
4. 单源化纪律：hex/time/paging/base62/AckStatus 映射/fixed_bytes/JournalPurpose 各唯一家。
5. 拒绝面系统化：握手全位置单字节变异、乱序、反射、replay；canonical 变异、尾随字节、字段数变异全测。
6. 扩展点真实性：`PacketConsumer`/`LoadBalancingPolicy`/`RouteNextHop` 均有生产消费者并做权威复核（唯 discovery 例外）。
7. 测试资产：19 个 metadata family 的合约套件、混合后端字节级一致收敛 E2E、1024 节点趋势测试、golden 向量冻结 7 格式族。

## 7. 校验与限制体系评定（全量盘点）

对 src/ 全部生产常量、容量、格式校验、速率窗、重试预算的穷尽盘点与逐条保留必要性评定（`cfg(test)`/`simulation`/`compatibility` 等测试专用代码不计入）。

### 7.1 清单与判定

判定档位：**必要**（去掉即破坏正确性/有界性/fail-closed）｜**合理默认**（操作面默认值，有论证）｜**可疑**（魔数/双轨/失配）｜**冗余/失效**｜**防御纵深**（不可达但保留）。

**A. 协议核心 / CBOR**

| 常量/校验 | 位置 | 值/规则 | 判定 |
| --- | --- | --- | --- |
| `ADR0002_BODY_BYTES` | protocol/mod.rs:14 | 65 536，一切 wire body 根上限 | 必要（单源根，ws/parser/offer 均派生） |
| `CONTROL_CBOR_LIMITS` | protocol/mod.rs:22 | (16, 1 024, 65 536) 全控制面 | 必要 |
| `validate_canonical` 深度/条目/非定长/最短编码/map 键序/尾随拒绝 | protocol/cbor.rs:166-360 | — | 必要（有界解析+规范型唯一性） |
| `validate_canonical` 拒 0-limit | cbor.rs:170-175 | — | 防御纵深（构造点已拦零） |
| `MAGIC`/`MAGIC_BYTES` + 编译期断言 | wire.rs:78-92 | "MRLY" | 防御纵深（编译期钉住） |
| kind 注册表闭合检查 | wire.rs `lookup`/`is_declared` | 未知 schema/kind fail-closed | 必要（golden 钉死） |
| `PRELUDE_LEN`=16、`split_message` 双限（协议×本地） | envelope.rs:3,83-100 | — | 必要 |
| 标签长度 5..=128 / 组件 ≤63 | tag.rs:5-7 | — | 必要（与 endpoint 共用校验） |
| 握手定长：GEN=16/NONCE=32/PK=32/SIG=64、ROLE_KEY=32/PROOF=32 | handshake.rs:73-76、credential.rs:30-31 | — | 必要 |
| offer 集合上限 ×3 = 128 | offer.rs:21-23 | — | 必要（防单 offer 主导 64 KiB） |
| feature 协商值域：data-body 64KiB/1MiB/8MiB、in-flight 1/256/1 024 | feature.rs:66-71 | 三元 floor/default/ceiling | 必要+合理默认 |
| `DEFINITION_LIMITS` | feature.rs:73 | (16, 1 024, **字面量 65 536**) | **可疑**：未引用 `ADR0002_BODY_BYTES`（见 P3-L7） |

**B. 格式校验（ID/标签/Endpoint/Selector）**

| 常量/校验 | 位置 | 值/规则 | 判定 |
| --- | --- | --- | --- |
| `RANDOM_SUFFIX_LEN`=21（62²¹≈4.3e37）+ 拒绝采样无模偏差 | identity/id.rs:5-18 | — | 必要 |
| `validate_id`（精确长度+前缀+base62） | id.rs:150-163 | — | 必要 |
| `LABEL_VALUE_MAX_BYTES`=256 / `LABEL_SET_MAX_ENTRIES`=64 | label.rs:19,23 | — | 必要（页预算匹配，有注释） |
| `ResourceUri` 复用 256B / `ResourceName` 复用 tag 语法 | resource/mod.rs:64-70,113 | — | 必要（单源复用） |
| selector：输入 ≤1 024B / 谓词 ≤16 / 集合值 ≤16 | routing.rs:34-40 | — | 必要 |
| Endpoint：scheme 固定/端口 443 默认/主机 ≤253/拒绝非规范形 | endpoint.rs:23-25 | — | 必要（但见 P1-1：canonical 域名检查缺失） |
| `MAX_PURPOSE_LEN`=128 + `validate_purpose` ×2 双轨 | records.rs:64,68、pending.rs:43,759 | — | **可疑**（同值同语义双实现，见 P3-L2） |
| hex 严格小写偶长 / schema-version 等值比对 / ID 全部严格 parse | hex.rs:25-52、各 decode | — | 必要 |

**C. 并发与容量**

| 常量 | 位置 | 值 | 判定 |
| --- | --- | --- | --- |
| `session_queue_messages`=256 / `bytes`=8 MiB（可配，`ensure_nonzero`） | config.rs:155-156 | 出站帧队列 | 必要+合理默认（原子双界） |
| `MAX_PENDING_ADMISSIONS`=256（固定内部界） | session/stream.rs:100 | 每会话未确认 admission | 必要（注释论证防不-ack 对端） |
| 入站流表共用 `queue_messages` 预算 / 每流 `INCOMING_STREAM_CHUNKS`=8 | stream.rs:1133-1135,51 | — | 必要 |
| `WAIT_BACKSTOP`=50ms / keepalive tick 錠 `min(1s).max(10ms)` | stream.rs:279,768-772 | 防自旋 | 合理默认/必要 |
| `CONTROL_CAPACITY`=32 → `PACKET_CHANNEL_CAPACITY` 派生 / `SYNC_ROUND`=8 | supervisor.rs:34-47 | 命令通道 | 合理默认（**注释错位**见 P3-L3） |
| `DEFAULT_EVENT_CAPACITY`=256（可配+非零校验） | node/event.rs:10 | broadcast | 合理默认 |
| 路由表容量 = `trace_metadata_limits.active`（默认 8 192） | supervisor.rs:659 | 活跃 trace 记录 | 必要（仅逐出 terminal） |
| `FORWARDING_ROUTE_CAPACITY_DEFAULT`=8 192 | forward.rs:61、supervisor.rs:658 | 在途转发路由 | 合理默认（**命名暗示可配但无旋钮**，见 P3-L5） |
| `MAX_CONCURRENT_TRACE_PERSISTENCE`=16 信号量 | trace.rs:892-906 | 终态落盘并发 | 必要 |
| 容量满载 → 类型化 `Overloaded` | stream.rs:1133、forward.rs:86-93 | fail-closed 背压 | 必要 |
| neighbor degree 錠 1..=64 / maintenance max_pending、max_queue（调用方） | membership/neighbor.rs:45,95-100 | — | 必要（模块当前生产死代码，盘点保留） |
| `MergeLimiter` 全固定：per-source pending 4 / global pending 64 / per-source 16/min / global 256/min / 窗 60s / bucket 表 1 024 / 空闲 600s | merge_rate.rs:26-32 | join 准入 | 必要（模块头完整论证；检查顺序缺陷见 P2-10） |

**D. 数据面**

| 常量 | 位置 | 值 | 判定 |
| --- | --- | --- | --- |
| 流元数据 `METADATA_MAX_ENTRIES`=256 / `MAX_BYTES`=32 KiB（insert 强制） | packet/mod.rs:53-56 | — | 必要 |
| `MAX_CHUNK_BYTES`=32 KiB（编码/解码/泵三处执行同一常量） | packet/mod.rs:60、wire.rs:297,313、stream.rs:1436 | — | 必要（单源多执行点，非双轨） |
| `PACKET_CBOR_LIMITS`=CONTROL / open 帧严格升序+去重链 / AckStatus 闭合码表 | packet/wire.rs:26,259-291,66-88 | — | 必要 |
| `max_hops` 调用方非零校验；内部/回程流固定 1 | packet/mod.rs:99-108、sync_common.rs:81 | — | 必要 |

**E. 反熵 / 页 / 重试节奏**

| 常量 | 位置 | 值 | 判定 |
| --- | --- | --- | --- |
| 成员页：默认 16 / 接收上限 64；资源页：16/64 平行双轨 | membership/page.rs:14,17、resource/page.rs:19,23 | — | 必要（**双轨漂移风险**见 P3-L6） |
| `MAX_VIEW_PAGE_ITEMS`=64（公共视图五处錠制引用同一常量） | paging.rs:157 | — | 必要（单源） |
| `MAX_SYNC_BYTES`=256 KiB / `MAX_SYNC_CHUNKS`=4 096 | sync_common.rs:18-20 | 接收侧 sync 体 | 必要（防御界；但发送侧尺寸链失配见 P2-23） |
| resend：`LEAVE_RESEND_CAP`=64 / snapshot 8 / page 32（membership 与 resource 各声明 32） | membership/sync.rs:639-646、resource/sync.rs:145 | — | 合理默认（**同值双轨**见 P3-L6） |
| `anti_entropy_interval`=250ms（可配非零） / `RECOVERY_TICK_PERIOD`=2s（注释明确不进 config） | config.rs:153、supervisor.rs:38 | — | 合理默认 |
| `RecoveryConfig`：neighbors=4、fan_out=64、backoff 1s→300s（构造校验 neighbors≤fan_out、initial≤max） | config.rs:288-296 | — | 必要+合理默认 |
| 指数退避 `attempts.min(16)` 防移位饱和 | membership/recovery.rs:148 | — | 防御纵深 |
| `AUTHENTICATION_DEADLINE`=10s / `CLOSE_DRAIN_GRACE`=250ms | session/driver.rs:58,64 | — | 必要+合理默认（RTT 量级注释） |
| keepalive/idle 默认 0（禁用，可配） | config.rs:157-159 | — | 合理默认（但无 setter → 生产不可达，见 P1-2） |
| join credential `LIFETIME`=600s / 32B / `join_`+43 字符 | identity/credential.rs:25-28 | — | 合理默认+必要 |

**F. 存储 / 持久层**

| 常量 | 位置 | 值 | 判定 |
| --- | --- | --- | --- |
| `ENTRY_WAIT_BOUND`=5s / `ENTRY_WAIT_BACKOFF`=10ms | storage/mod.rs:16-19 | 提交槽等待 | 必要 |
| `RETENTION_SWEEP_BOUND`=4 096 | receipt.rs:30 | 单次 sweep 延迟 | 必要 |
| `RESOURCE_REMOVAL_RETENTION`=30d / `RESOURCE_REGISTER_CAP`=262 144 | retention.rs:25,29 | 删除证据留存 | 合理默认（**注释指向错误**见 P3-L4） |
| `TraceMetadataLimits` active=8 192 / terminal=262 144 / retention=24h（可配非零） | config.rs:236-241 | — | 必要+合理默认 |
| `receipt_retention`=30d（可配） | config.rs:163 | — | 合理默认 |
| JSON：`MAX_GENERATIONS`=1 024 / `MAX_TOTAL_BYTES`=4 GiB / 定宽世代号 20 / 锁重试 ≥20 | json/store.rs:64-66,182-195 | — | 必要+合理默认 |
| redb 定长表值 32/40B / 引用 token 32 / wall-time 13 | redb/store.rs:27,30、receipt.rs:35-36 | — | 必要 |
| `REVISION_KEY_DIGITS`=20 零填充定宽键 | trust.rs:420 | 字典序=revision 序 | 必要 |
| 每 schema 精确 CBOR 界（identity (1,16,1024) … pending (8,1024,65536) … resource (4,256,16KiB)） | records.rs:93、revocation.rs:37、leave.rs:49,152、cleanup.rs:38、pending.rs:44、resource/mod.rs:49 | — | 必要（"扁平记录、恰好够用"，均紧于 CONTROL） |
| `WIPE_BATCH`=64 / `WIPE_RETRIES`=8 / `INTENT_RACE_BUDGET`=8 / `TOMBSTONE_GC_BATCH`=64 | leave.rs:499-502,735、records.rs:325 | — | 必要（风暴→类型化失败有注释） |
| CAS 竞态重试：attempts<3+10ms 线性退避 ×2；deletion/lifecycle attempts≥2 | supervisor.rs:1275,1393、deletion.rs:123,144、lifecycle.rs:224,231 | — | 合理默认 |

**G. 传输**

| 常量 | 位置 | 值 | 判定 |
| --- | --- | --- | --- |
| `MAX_MESSAGE_BYTES`=ADR0002+PRELUDE（聚合与单帧双设） | ws.rs:89,~100-110 | 65 552 | 必要（单源派生，帧级 guard 防预分配攻击） |
| `CHANNEL_BINDING_LEN`=32 / RFC 9266 exporter | connection.rs:45-48 | — | 必要 |
| `ED25519_PKCS8_PREFIX`/`SEED_LEN`=32 | cert.rs:26-30 | — | 必要 |
| `EndpointCandidates`（TTL 调用方参数） | candidates.rs | — | 观测（模块自认仅单测使用） |

### 7.2 问题条目（可疑/冗余/失效）

**P2-23（新发现）sync 载荷尺寸三轨失配：64 KiB 编码界 > 32 KiB 单 chunk 发送界 < 256 KiB 接收界**

- 证据：页/快照以 `CONTROL_CBOR_LIMITS`（64 KiB body）编码（paging.rs:62、trust.rs:115）；发送侧 `send_payload` 用 `StaticBody` 单 chunk（sync_common.rs:72），泵处 `bytes.len() > MAX_CHUNK_BYTES`（32 KiB）即终止流（stream.rs:1436-1439）；接收侧却是 `MAX_SYNC_BYTES`=256 KiB / 4 096 chunks（sync_common.rs:18-20）。
- 后果（主审复核补强）：数值链未协同——合法上限内的载荷会在发送端失败。算术：满配描述符（64 标签 × (≤128B key + ≤256B value) ≈ 25 KiB），默认 16 条/页 ≈ 400 KiB，页编码本身即超 64 KiB；仅 2 个胖描述符即超 32 KiB chunk 界；trust snapshot ≈75B/binding，≈440 bindings 超 32 KiB、≈870 超 64 KiB。且 `sync_tick` 里 `page.encode()?`/`page_payload.encode()?` 用 `?` 上抛：胖页编码失败使**整个 tick 失败并每 tick 重试**（存储的记录不会自己变小）→ 对应页序列永久停滞；编码过关但超 32 KiB 的载荷则被泵静默终止（fire-and-forget 吞掉）且游标不前进，同样永久停滞。当前 16 节点 SLO 规模不可达，但限制体系内部自相矛盾。
- 建议：sync 发送改多 chunk 体，或新增 `SYNC_PAYLOAD_MAX = MAX_CHUNK_BYTES` 并在页/快照发射侧用它推导每页条数；`MAX_SYNC_BYTES` 保留为对端防御界并注释三层尺寸关系。

**P3 级（低风险清理）：**

- **L2 `MAX_PURPOSE_LEN=128` 双轨**：identity/records.rs:64 与 storage/pending.rs:43 同值同语义，`validate_purpose` 两处独立实现——pending 复用 records 的常量与校验。
- **L3 supervisor.rs:40-44 注释错位**：描述 packet channel 的文档挂在 `SYNC_ROUND_CHANNEL_CAPACITY` 上，`PACKET_CHANNEL_CAPACITY` 反而无注释。
- **L4 retention.rs:22-25 注释指向错误**："Mirrors the trace-metadata default"，但 30d 实际对应 `receipt_retention` 默认（trace 默认 24h）。
- **L5 `FORWARDING_ROUTE_CAPACITY_DEFAULT` 命名误导**：`_DEFAULT` 后缀暗示可配，但唯一调用点硬编码传入、`NodeConfig` 无对应字段；同域路由表容量却走 config——"一个真可配、一个假默认"不对称。改名或真正接入 config。
- **L6 membership/resource 页参数平行双轨**：默认 16/上限 64 ×2 处 + resend 32 ×2 处，两 lane 共享 `sync_common` 收发代码但数值各自声明，单边调整易漂移。建议集中在 `paging.rs`（已自称单一来源）。
- **L7 `DEFINITION_LIMITS` 复述字面量 65 536**：protocol/feature.rs:73 未引用 `ADR0002_BODY_BYTES`，违反 mod.rs:16-20 "every derived limit derives from this constant" 的自述。

未发现：cap=0 类死界、生产永不可达的失效限制（除 P2-23 中对自身流量不可达的接收界，其对端防御价值仍成立）、双保险式冗余限制。

### 7.3 总体评价

这套限制体系整体质量高：**单源化是主旋律**——`ADR0002_BODY_BYTES` 根上限、`CborLimits` 按 schema 精确分层、`MAX_VIEW_PAGE_ITEMS`/`LABEL_VALUE_MAX_BYTES` 等关键界均有唯一常量并被多处引用；几乎所有常量带论证注释；`ensure_nonzero`/值域校验在构造点统一拦截"零=无限制"；fail-closed 贯彻到位（未知 kind/schema/status、超页、超界一律类型化拒绝而非截断）。"零=禁用"语义（keepalive/idle）有文档但受 P1-2 影响。最值得收口的三件事：(a) 统一 sync 载荷尺寸链（P2-23）；(b) 页参数/purpose 长度并入单源（L2/L6）；(c) 修正 `_DEFAULT` 命名与两处注释错位，让"可配默认"与"固定内部界"一眼可辨。

## 8. 修复优先级建议（已被 §9 台账取代，保留作原始评估）

1. **立即**（0.1.0 发布前）：P1-1 canonical 域名、P1-2 liveness 不可达、P1-3 retention stale-base；P2-15（一行级修复）、P2-16、P2-9。
2. **短期**（一次批量清理 PR）：P2-8/P2-10/P2-11/P2-22（allow(dead_code) 三处收敛 + sync.rs 错误分级 + 限速顺序）、P2-19、P2-20、P2-21、P2-23（sync 尺寸链：发送多 chunk 化或发射侧按 chunk 界推导页条数）。
3. **中期**（结构性，各自独立 ticket）：P2-14 session/routing 分离、P2-7 trust 策略归位、P2-12 绑定表示统一、P2-13 leave 清单派生、P2-4/P2-5/P2-17 装饰面接线或收缩。
4. **择机**：P3 清单，其中 canonical_record! 宏（13 组 triple）与 P3 文档-代码矛盾修正收益最高。

## 9. 修复台账（分支 fix-audit-fixings）

| 发现 | commit | 修复摘要 |
| --- | --- | --- |
| 文档基线 | `86c25b2` | 本审计文档入库 |
| P1-1 canonical 域名 | `61dbf27` | 显式拒绝尾点/大写/下划线/非 LDH；保留比较移到折叠后；LabelKey/ResourceName 域段折叠保留归一化契约 |
| P1-2 liveness 不可达 | `0633930` | `with_session_liveness` setter + 校验 + public-api 基线更新 |
| P1-3 retention 陈旧 base | `c39f9f3` | 过期+溢出合并为单事务多 Delete；回归测试（旧代码下失败） |
| P2-4 candidates 死模块 | `4047828`+`1c7d1b2` | 删除模块与孤儿 verify 脚本，文档同步 |
| P2-5 Discovery 面装饰 | `b35ab89` | 公开面收缩（基线 -15 项），Discovery 面 cfg(test) |
| P2-6 传输层身份依赖 | `98eb5c0` | 归一化/准入上移 session driver，`grep identity:: src/transport/` 清零 |
| P3-L7 字面量 | `000834d` | DEFINITION_LIMITS 引用 ADR0002_BODY_BYTES |
| P2-9 Aborted 当成功 | `8e429fa` | Conflict|Aborted→Err + AbortingOnceFactory 测试 |
| P2-10 限速配额 | `0792a65` | 检查全部通过后再 record 两窗口；回归测试 |
| P2-11 identity dead_code | `10b6bdd` | 删 6 处压制；死 item 删/cfg 化（清单见 commit） |
| P2-13 WIPE 清单 | `1a49f67` | families 域归属注册表派生 + 守卫/集合相等测试 |
| P2-7 trust 策略归位 | `eac5cb3` | accept_snapshot/refresh_issuer_snapshot 移入 trust.rs（纯移动） |
| P2-8 绑定错误分级 | `9db6c64` | 仅 Conflict/NotReady 跳过，NotTrusted 上抛；回归测试 |
| P2-15 remove 双重编码 | `a83eacb` | remove 走 sign_with_provider 单源管线 |
| P2-16 终态路由抹 destination | `2e69f52` | 统一 record_terminal_failure，保留 selected_node；3 新单测 |
| P2-17 RoutingPolicy 装饰 | `6425630` | 穷尽 match 强制 Direct 不变量（类型+运行时双保证） |
| P2-18 锁上下文串名 | `11ae067` | routes/connection_tasks 锁中毒准确命名 |
| P2-23 sync 尺寸链 | `c2b2b59` | 多 chunk 发送 + 发射侧减半阶梯；集成回归测试（stash 验证旧代码 257s 卡死） |
| P2-19 pending 绕 schema 门 | `c9723c7` | 复用 open_with_state；json/redb 双后端 fail-closed 测试 |
| P2-20 Storage 零文档 | `4ae4dbb` | 提交顺序契约/Unknown 语义/snapshot 不可变/reconcile 三态入 trait 文档 |
| P2-21 namespace 六处重写 | `8cf7569` | families::namespace 单源，六处委托 |
| P2-22 storage/resource dead_code | `3afca42` | 删全部过时压制；死 item 按政策 cfg 化（清单见 commit） |
| P2-14 session⇄routing 循环 | `1386718` | PendingAck/PendingAcks 迁入 routing；receive_open_envelope 纯函数 |
| P3×12（帧校验/墓碑收敛/分发收敛/尾样板/revision 边界/SPKI/accept 退避/next-hop 单源/LeaveCluster 提取/改名/注释漂移/死助手） | `ac041a6`…`b94b0b5` | 逐项见 git log，全部行为等价或收紧 |
| feature 矩阵门控 | `3ecf0f6` | 迁移测试 helper 补 any(json+unix,redb) 门，each-feature 矩阵零警告 |
| P2-12 绑定单一表示（owner 决策：淘汰族） | `1134df0`+`681c34e`+`bf8a0e8` | 删 TRUST_BINDING 族：读侧流式解码 IDENTITY_BINDING、写侧只走 adopt、目录/清退联动；单例节点可见自身绑定（有意新语义）；撤销防护统一变强；顺带修 verify-storage-contract 的 relay→radiata 陈旧正则 |
| OpenWireV1 死分支（见 §4 勘误） | `00d227c` | 删回退分支与误导上下文，单路径 decode_canonical_strict，冻结向量 byte-stable，3 条陈旧语料刷新 |
| canonical_record! 宏（12/13） | `6aa28ea`+`3b5dfea` | 宏 + records.rs 7 类型 + cleanup/leave/revocation 5 类型收敛，净 −277 行，trust 快照豁免有文档背书 |
| snapshot 专项分析 | `e8b5e20` | docs/snapshot-analysis.md：7 种快照判定（owner 命题 1-2 成成立）；计数短路与 stale-base 残留均验证 |
| 留档排队上限 | `fbfaa14` | 终态 trace sink 排队 64 上限，溢出丢弃 + `trace-records-dropped` 观测计数器；基线 +1 行 |
| 快照三连修（owner 决策） | `466b1f2`+`6585be4`+`5d0f7aa` | 快照溢出不再拖死描述符反熵；远端快照停止持久化（issuer 自写自读保留）；注释如实化 |
| 分页 seek 扩展（owner 决策） | `c33fcf8`+`73ec5fd` | StoreSnapshot::scan_from 定位扫描（default 方法保兼容）+ 三后端 + 合约；分页 O(N²/L)→O(page)（实测 1100 vs 50600 步）；基线 +1 行 |

**未修（有意保留）**：store_scan_stream 公开面（保留供扩展作者，有外部驱动测试）；trust.rs `TrustSnapshotV1` 脚手架保持手写（canonical_record! 豁免，canonical.rs 模块文档已记录）。~~LimitedWriter 预零化~~（已修：容量预留不初始化、追加式写入、限流原子）；~~分页 O(N²) 重扫~~（已修：scan_from 定位扫描全路径接管，见上行）；~~终态 trace 无界 spawn~~（已修：fbfaa14 排队上限 + 丢弃计数，本行系过时记载）。

**已决策落地**：P2-12（owner 决策：淘汰 TRUST_BINDING 族——IDENTITY_BINDING 成为绑定唯一表示，读侧流式解码、写侧只走 adopt、撤销防护统一变强、单例节点可见自身绑定为有意新语义）；OpenWireV1（owner 决策：删死分支保线上格式，见 §4 勘误）；canonical_record! 宏（12/13 组收敛，净 −277 行，金样本逐字节不变）。
