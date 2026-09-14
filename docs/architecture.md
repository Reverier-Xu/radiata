# radiata 技术架构与模块职责

> 本文档对应 `plan-0.1.0-baseline` 分支 0.1.0 代码定稿（2026-09-15，随
> plan-0.1.0.md P2-8 全量重审刷新；上一版对应 main @ `faf7833`）。
> 权威 API 参考仍是 rustdoc（`cargo doc`，业务接入指南见 crate root 的
> `radiata::guide` 模块）；本文描述实现层架构与职责边界。

## 1. 项目定位

radiata 是一个确定性中继节点运行时库：为群组应用提供认证 P2P 连接、不透明数据流（opaque packet streams）、以及核心元数据的收敛（身份绑定、凭据授权的集群合并、成员/资源收敛），全部构建在 TLS 1.3 之上。

**信任模型**（来自 README，代码结构与之吻合）：

- 无条件防御**链路**：TLS 1.3 exporter 绑定、握手转录、合并凭据、对保留身份绑定的签名验证。
- 明确不防御**被正确准入后的恶意成员**（peer-trust 模型）：Sybil、合谋、敌意元数据是部署方责任。
- 清理检查点只在全集群收敛后签发；`cleanup_node` 墓碑是终态，无复活路径。

## 2. 分层总览（自底向上）

```
┌─────────────────────────────────────────────────────────────────┐
│ L7 门面/运行时    node/ runtime/ api config error operation view │
│                  guide lib.rs (crate root) extension_registry    │
├─────────────────────────────────────────────────────────────────┤
│ L6 存储域         provider.rs storage/ (json redb contract       │
│                  migration pending receipt families)            │
├─────────────────────────────────────────────────────────────────┤
│ L5 元数据域       identity/ membership(+membership/*) resource/  │
├─────────────────────────────────────────────────────────────────┤
│ L4 数据面         routing.rs routing/{table,forward,trace}       │
│                  packet/ {wire,mod}                             │
├─────────────────────────────────────────────────────────────────┤
│ L3 会话域         session/ {driver,stream}                       │
├─────────────────────────────────────────────────────────────────┤
│ L2 传输域         transport/ {tls,verify,cert,ws,connection,     │
│                  endpoint,registry}                              │
├─────────────────────────────────────────────────────────────────┤
│ L1 协议域         protocol/ {cbor,envelope,tag,wire,handshake,   │
│                  offer,selection,feature,credential}            │
├─────────────────────────────────────────────────────────────────┤
│ L0 值与工具       identity/{id,value,signature} hex time label   │
│                  paging sync_common audit                       │
└─────────────────────────────────────────────────────────────────┘
横切（test-only / feature-gated）:
  simulation/ compatibility.rs fuzz_adapters.rs
  identity/testing.rs storage/contract/reference.rs
  audit feature（语义路径事件，生产构建零开销）
外部 crate:       test-support（集成测试公共设施）
```

依赖方向总体自上而下（上层依赖下层），`pub(crate)` 为默认可见性；crate 边界只暴露 `lib.rs` 中列出的门面类型。

## 3. 各层职责与模块清单

### L0 值与编码基础

| 模块 | 职责 |
| --- | --- |
| `protocol/cbor.rs` | 确定性 CBOR（最短参数、map 排序、深度上限、有界 writer/reader）。所有线上与持久化编码的唯一来源。 |
| `protocol/envelope.rs` | 16 字节消息前奏（prelude）与消息拆分语义（kind/flag/class-limit/receive-limit/尾字节检查）。 |
| `protocol/tag.rs` | 域限定标签类型（`ProtocolTag`/`FeatureTag`/`TransportTag`/`DiscoveryTag`/`QualifiedTag`），保留命名空间校验。 |
| `protocol/wire.rs` | 基 schema `0x0001` 的**封闭 kind 注册表**：6 个握手 kind（位置 1–5 严格锁定认证交换 + 位置 6 join 模式准入授权）+ 4 个包 kind（open/chunk/end/ack）。未知 kind 在 body 分发前拒绝。 |
| `identity/id.rs` | 强类型 ID 的**单源命名生成器**：`{业务前缀}-{21 位小写字母数字}`（36 进制后缀，14 字节 112-bit 拒绝采样——36²¹ 远超 u128 整体拒绝采样的接受窗口）；`validate_id` 让所有 ID 族（`NodeId`/`SessionId`/`TraceId`/`TransactionId`/`ListenerId`/`KeyOperationId`）的命名规则不可分叉。`OperationId` 是原始 16 字节（`GenerationId`/`MergeId` 语义包装），不走文本命名。 |
| `identity/value.rs` | `Digest`/`PublicKey`/`Signature` 值类型。 |
| `identity/signature.rs` | ed25519 签名域分隔（domain separation）、规范签名消息组装、严格验证。 |
| `hex.rs` | 全 crate 唯一小写 hex 编解码，所有线转录/持久化文档/摘要渲染共用。 |
| `time.rs` | 挂钟时间获取（供注入）。 |
| `label.rs` | 有界规范标签（`LabelKey`/`LabelValue`/`LabelSet`），选择器求值依据。 |
| `paging.rs` | keyset-cursor 分页单一实现（membership/resource/公共视图共用；依赖存储 SPI 的 `scan_from` 定位扫描，复杂度 O(page)）。容量处仅在可证明还有下一条时才给续游标。 |
| `sync_common.rs` | 同步公共机制单源：alive-peer 枚举、`delivered_within_bound`（`SEND_ACK_WAIT` 2s 有界回执等待，投递真相 D2 的裁决点）、页轮判定 `PageRound`（区间指纹 quiet / 32 tick 重发节奏 `PAGE_RESEND_TICKS`）。 |
| `audit.rs` | `audit` feature 门控的语义路径事件（`member descriptor installed`、`resource pass settled`、`journal resolved` 等）：一行一决策、字段与消息文本稳定。fuzz harness（P2-9）以解析这些事件断言执行路径；feature 关闭时函数体为空，生产构建零开销。 |

### L1 协议域（控制面语义）

| 模块 | 职责 |
| --- | --- |
| `protocol/handshake.rs` | **纯内存**认证握手状态机：消息顺序、转录组装、双端独立重算校验；无 socket/TLS 代码。 |
| `protocol/credential.rs` | join 模式凭据证明推导（HKDF-SHA256 + exporter 绑定，见模块文档的精确推导式）。 |
| `protocol/offer.rs` | 规范认证 feature offer 编码与校验（排序去重集合、强制数值上限；`FeatureOffer::finalize` 单源容量/类别/required 校验）。 |
| `protocol/selection.rs` | 精确 feature 选择：双方独立计算同一有效集（摘要相等交集 C0 等）。 |
| `protocol/feature.rs` | 域限定 feature 定义与封闭校验注册表；定义摘要 = SHA-256(确定性 CBOR)。 |
| `protocol/mod.rs` | 全控制面 CBOR 预算 `CONTROL_CBOR_LIMITS`（depth 16 / 1024 items / 64 KiB body，常量 `ADR0002_BODY_BYTES`）。 |

### L2 传输域

| 模块 | 职责 |
| --- | --- |
| `transport/tls.rs` | TLS 1.3-only rustls 配置（ring、无 1.2、无 early data、无会话恢复）。 |
| `transport/verify.rs` | **安全关键**服务端证书验证器：join 模式仅放宽链/主机名信任，`CertificateVerify` 签名无条件全验证。 |
| `transport/cert.rs` | 接收方临时自签监听证书（注入熵生成、仅内存、每监听器一份，非节点身份）。 |
| `transport/ws.rs` | 固定 `/mrly` 路径的 WebSocket 升级（仅二进制、无压缩）；升级响应携带非秘密 join 提示（cluster ID、凭据 generation ID）。 |
| `transport/connection.rs` | TLS-WS 流上的分帧连接（一条二进制 WS 消息 = 16B prelude + body），双重有界接收；RFC 9266 `tls-exporter` 通道绑定推导；向会话层暴露原始 `Option<SocketAddr>`（准入归一化在身份域）。 |
| `transport/endpoint.rs` | 公开 `Endpoint` 值类型（规范 `wss://host[:port]` 文本；严格 canonical 域名校验）。 |
| `transport/registry.rs` | 开放 transport 注册表（内置 WSS 注册为默认；Discovery 扩展面现为 test-only）。注册永不绕过认证与流安全。 |

### L3 会话域

| 模块 | 职责 |
| --- | --- |
| `session/driver.rs` | 在 `Connection` 上编排 `Handshake` 状态机：签名顺序（发起方 `KeyProvider::sign`）、固定 10 秒认证 deadline；发起方路径单源为 `SessionDriver::initiate`。 |
| `session/stream.rs` | 已建立会话的保活与包流多路复用：写半 = 有界帧通道（session queue，条数+字节双限），读循环按四 packet kind 分路；open 先验证并准入有界入站表再返回当前进程 ack；chunk 有序进入有界 body 通道；中断 = `StreamInterrupted`（不重放、不恢复）。pending-ack 清算单源为 `fail_pending_waits`；会话条目携带来源标记（caller 配置/入站/恢复拨出），供恢复面剪枝判定。 |

### L4 数据面（路由与包）

| 模块 | 职责 |
| --- | --- |
| `packet/wire.rs` | 包流四帧（`0x0010..=0x0013`）确定性 CBOR：open（trace/双端/协议标签/有界元数据）、chunk（序号 + ≤`MAX_CHUNK_BYTES`）、end、ack。 |
| `packet/mod.rs` | 公开流类型（`OutboundStream`/`IncomingStream`/`RouteHandle` 等）：`send_sync` 只等目的端当前进程准入 ack；`send_async` 立即返回 RouteHandle。恒定内存、恒定背压、字节序保持、从不持久化 payload、从不重放。 |
| `routing.rs` | 路由目标（精确 `NodeId` 或标签选择器 `Selector`）、`LoadBalancingPolicy` 选择、`RouteContext` 逐跳信封（每跳对会话认证对端重验证，篡改即失败关闭）；内置确定性 next-hop 策略 `DefaultNextHop`（未直连目的地经最小存活 peer 中继，`TAG` 常量注册，业务可整体替换）。 |
| `routing/table.rs` | 节点本地有界内存路由表（仅 trace 元数据，非 payload）。 |
| `routing/forward.rs` | 中间节点逐跳转发（`ForwardingHop`：帧只过一次、序保持、中断以显式类型化 ack 上报）。 |
| `routing/trace.rs` | 持久化路由 trace 元数据（身份/目的/尝试次数/进度/终态；无 payload 字节；走条件事务，按 `TransactionId`+摘要收敛；`commit_verdict` 单源映射提交裁决）。 |

### L5 元数据域（身份 / 成员 / 资源）

| 模块 | 职责 |
| --- | --- |
| `identity/records.rs` | 全部身份记录类型（绑定、凭据使用、信任锚、快照、意图等）的规范编码/解码/摘要脚手架；golden 向量钉住字节。 |
| `identity/lifecycle.rs` | 本地身份打开/创建（journaled key 生命周期 + key-provider 操作协议，精确有界恢复）。 |
| `identity/merge.rs` | **原子合并记录提交**：握手验证凭据/身份证明后调用；此层永不接触凭据/证明/exporter/转录/私钥。一笔 journaled 事务原子提交不可变 `IdentityBinding`、唯一 per-subject `CredentialUse` 等。 |
| `identity/merge_rate.rs` | 固定凭据合并限速（per-source/global pending + 60s 固定窗口 + 有界 source-bucket 表 + 10 秒裁剪）。 |
| `identity/credential.rs` | join 凭据：`IssueMergeCredential` **非轮换签发**（世代 10 分钟内存寿命内可准入任意多节点，`reserve` 允许多在途，准入成功不消费世代；per-subject 使用记录挡同世代重放）+ `RotateMergeCredential` 保留为撤销/升级手段。凭据文本/派生密钥/证明值永不持久化/复制。 |
| `identity/trust.rs` | 签发者信任快照与**per-binding 分页传播**：`TrustSnapshotPage`（每页 ≤64 绑定、keyset 游标、per-issuer revision 游标一 tick 一页、空页关 pass 才记 revision；接收端逐绑定采纳 + issuer key 校验，远程快照页**不持久化**——投递会话即信任背书）。整集快照降级为引导/审计用途。 |
| `identity/revocation.rs` | 收敛永久撤销：任何成员可对精确 node→key 绑定签发移除墓碑；永不进检查点覆盖；仅显式本地清除；持久化即关闭本节点对该身份的会话。 |
| `identity/cleanup.rs` | 死节点清理墓碑（签发者签名、针对精确 subject 绑定；终态无复活）+ 水位检查点（max-wins、不覆盖活体/撤销）。 |
| `identity/leave.rs` | 主动退出与身份替换：journaled leave-intent → 崩溃安全地替换身份并擦除旧身份本地核心元数据；leaver 等待 applied 回执（applied 优先、admission ack 次之）。 |
| `identity/deletion.rs` | key 删除意图（目标绑定；先快照证明无已提交 generation 引用该 handle）。 |
| `membership.rs` | 所有者标记节点描述符（`NodeDescriptorV1`）：owning node 的 `NodeId` 标记 + endpoint 候选 + 严格递增 revision + 移除标志 + 能力标签；会话信任边界（无逐条签名）。 |
| `membership/page.rs` | 有界成员反熵页（描述符列表 + 不透明 cursor，非全量分配）；`apply_page_ctx` 只接受严格更高 revision。 |
| `membership/sync.rs` | 会话承载成员同步：每会话每 tick 多车道有界载荷——`MembershipPage`（描述符反熵）、`TrustSnapshotPage`（per-issuer revision 游标）、墓碑车道（leave/cleanup/revocation/checkpoint，独立重发节奏）、leave applied 回执（leaver 等待、peer 回执的 admission ack 有界可观测不重投）。快照刷新失败只跳过本轮快照发送，页面反熵不停摆。 |
| `membership/neighbor.rs` | 确定性稀疏邻居规划 + 维护限流（非 test 构建中刻意 dead）。 |
| `membership/recovery.rs` | 连续恢复状态机：仅在已知在线成员互不可达时激活，按配置挂钟退避（读 `SystemTime` 处理回拨/冻结/前跳）、有界扇出、静默收敛；**恢复宇宙 = 描述符成员表**（非一次性 seed 会话）。`maybe_prune_recovery_edges` 实施有界拓扑剪枝（Connected 态、每 cooldown 一条、确定性取最高 peer id、保底非恢复边存在才剪；caller 配置与入站会话永不回收）。 |
| `resource/mod.rs` | 通用命名资源元数据：签名记录（公共名/标签/排序版本）。多写者时间戳最大值寄存器（tuple: 挂钟时间戳 → 写者 NodeId → removal rank → 记录摘要，字典序最大者胜）；`ResourceVersion::from_parts` 支持跨进程重建元组做条件写（`PutResource::with_expected`，冲突显式 `ErrorKind::Conflict`）。 |
| `resource/store.rs` | 资源条件本地事务：寄存器键上条件提交整条记录，仅当严格胜出；败者接受但不存储（接受≠当前或未来胜出）。 |
| `resource/page.rs` / `resource/sync.rs` | 有界资源页 + **per-key 水位反熵**（对端 walk 游标 + 有界水位表 `WATERMARK_TABLE_CAP=8192`、检测节奏 32 tick、`SCAN_BUDGET_PER_TICK=256` 摊销扫描、发射按水位过滤、水位推进 verdict-gated——admission ack 裁决失败即回退页起点、预算窗口静默时 pass 从窗口边界继续、写入者信任等待 2s、`WATERMARK_REFRESH_PASSES=64` 整表清空重投兜底 admission≠apply 偏差）。成员通道保留指纹游标（节点数即目录上界）。 |
| `resource/retention.rs` | 签名移除保留与精确核心元数据清理（只清 `removed()` 记录，条件删除期望 = 精确存储摘要；清理事务 id 确定性派生，重放幂等）。 |
| `resource/select.rs` | 选择器驱动的分页资源选择（对 winner 全标签空间求值，规范名序流式）。 |
| `resource/crash.rs` / `resource/e2e.rs` | 子进程崩溃矩阵 / 双组件端到端收敛（test-only）。 |

### L6 存储域

| 模块 | 职责 |
| --- | --- |
| `provider.rs` | 公开存储/key 提供者边界：`Storage`/`StorageFactory`/`KeyProvider` trait、`StoreTransaction`/`StoreOperation`/`CommitOutcome` 等类型、能力协商（`StoreCapabilities`/`KeyCapabilities`）；`store_scan_stream` 是存储适配器作者的 Stream 桥接缝隙（库内零调用为有意设计，外部驱动测试钉住契约）。`KeyProvider` 三态 create/delete + reconcile 崩溃恢复契约见 `radiata::guide`。 |
| `storage/mod.rs` | `MetadataStore`：进程级单写者互斥（`WriterLock`，任务可重入；journaled 流程全程持 permit，同 purpose 串行化）+ 条件提交/reconcile 编排；`resolve_pending_journal` 对持久证据直读恢复（journal 与业务事务同 commit 原子写入 → provider 收据即权威），残留缺席即 fail closed 冻结；Ready 态 reconcile 立即类型化拒绝，不进入 5s 空等；`reconcile_if_frozen` 供 Unknown 后解冻自检。 |
| `storage/receipt.rs` | 提交回执与引用状态（live-marker/head/edge/anchor 读取、审计前奏、token 域分离摘要、保留清扫的事务 id 确定性派生）。 |
| `storage/pending.rs` | 挂起事务 journal（精确恢复打开：单例键、记录目标事务身份/pre-base revision/操作列表；与被描述事务原子写入）。 |
| `storage/families.rs` | 后端中立元数据族目录（所有命名空间单一定义点；all-family 合约测试遍历此目录）。 |
| `storage/migration.rs` | 事务性 schema 迁移（显式不可变边链；构造期拒绝重复边/环/歧义路径/未知端点/缺失解码器/隐式排序/降级；每边确定性事务 id，重放幂等）。 |
| `storage/json/*` | JSON 适配器（feature `json`，显式启用，测试用不可变 generation 存储；别名安全排他生命周期锁；crash.rs = 子进程崩溃矩阵）。 |
| `storage/redb/*` | redb 适配器（feature `redb`，**默认 feature**，生产后端；每 commit fsync；crash.rs = 6 提交点崩溃矩阵）。 |
| `storage/contract/*` | 后端中立存储合约引擎（reference 参考实现 + 全族快照/扫描/事务/reconcile/能力合约；JSON/redb 必须逐字节等价）。 |

### L7 运行时与门面

| 模块 | 职责 |
| --- | --- |
| `runtime/supervisor.rs` | 节点核心监督者：持有 `RuntimeDependencies`，管理监听器/会话任务（JoinSet）、控制通道（`Control`/`RuntimeClient`）、包命令通道、同步轮通道；聚合所有命令/查询分派；每 tick 驱动恢复面评估（含恢复边剪枝）。 |
| `runtime/lifecycle.rs` | 运行时生命周期控制与快照。 |
| `runtime/recovery.rs` | 恢复面（any-one-route 契约）：Connected = 至少一条认证通路；恢复面只在完全隔离时按成员表有界扇出拨号，连通后绝不主动扩张拓扑；`unreachable_members` 仅诊断计数；转发入口选择、有界恢复 tick、剪枝实施（见 `membership/recovery.rs`）。 |
| `runtime/views.rs` | 纯观察分页读/点读（成员/资源/监听器/会话/拓扑/信任/可观测性），无状态迁移。 |
| `node/builder.rs` | `NodeBuilder`：存储工厂 + key provider + config + 熵 + 扩展注册表 → 派生运行时。 |
| `node/handle.rs` | `NodeHandle`：类型化命令/查询总线（sealed `Command`/`Query` trait + `async fn run`）发送端。 |
| `node/event.rs` | `EventHub`（每订阅通道、毒恢复锁、prune 语义）。 |
| `node/revision.rs` | 成员 revision 计数器（与 `MemberChanged` 事件同序；晚订阅者立即看到当前值）。 |
| `operation.rs` | 全部命令/查询类型定义（Shutdown、MergeCluster、`IssueMergeCredential`/`RotateMergeCredential`、`PutResource`（含 `with_expected` CAS）、`RemoveResource`、`UpdateNodeMetadata`、`StartRecovery`、`GetRecovery`…）。 |
| `view.rs` | 公开视图 DTO（MemberView、TopologyPage、SessionView、RecoveryView…）；`RecoveryView.is_connected` = 至少一条通路，`unreachable_members` 仅恢复面诊断计数。 |
| `config.rs` | `NodeConfig`（反熵间隔、会话队列条数+字节、空闲超时、keepalive、parser limits、trace 元数据限制、路由策略、回执保留、必需 features、恢复退避参数及语义文档）。 |
| `error.rs` | thiserror 派生的封闭 `ErrorKind`（秘密安全分类）+ `ProviderErrorKind` 投影；调用方起源失败走类型化 `Error::caller`（`ErrorKind::CallerError`），不开放全量构造；per-kind `From` 映射表保留为域逻辑。 |
| `api.rs` | `BoxFuture` 别名 + `Entropy` trait（`SystemEntropy`）。 |
| `extension_registry.rs` | 节点本地扩展注册表：`ProtocolDefinition` ↔ `PacketConsumer` 绑定、feature 定义、LB/路由策略注册（重复注册冲突，永不隐式替换）。 |
| `guide.rs` | doc-only 业务接入指南（版本元组往返、any-one-route 契约、三大扩展点接入步骤，示例全部参与编译）。 |
| `lib.rs` | crate root：模块声明、公开 re-export、`extension`/`adapters` 子模块；`#![cfg_attr(not(test), deny(clippy::unwrap_used, expect_used))]`。默认 feature = `redb`；`json` 显式启用；`audit` 门控语义路径事件。 |

### 横切（test-only / feature-gated / 辅助）

| 模块 | 职责 |
| --- | --- |
| `simulation/*` | 种子化仿真（拓扑/网络故障矩阵/事件排序/工件捕获），`cfg(test)`。 |
| `compatibility.rs` | 冻结的 `0.1.0` 兼容性 golden 向量清单（7 格式族 21 向量），`cfg(test)`。 |
| `fuzz_adapters.rs` | 规范解码器/选择器 fuzz 目标的有界适配器，`cfg(any(test, fuzzing))`。 |
| `audit` feature | 语义路径事件（见 L0 `audit.rs`）。 |
| `examples/chat/test_fuzz.py` | P2-9 场景 fuzz harness：模型驱动状态化 fuzz（9+ 原子操作、期望状态 map、状态+执行路径双重断言、种子可复现），容器级运行、非 CI 门禁。 |
| `test-support` crate | 集成测试公共设施。 |

## 4. 关键数据流

### 4.1 节点构建与生命周期

```
NodeBuilder::new(storage_factory, key_provider)
  + config + entropy + extensions
  → build() → spawn_runtime(RuntimeDependencies)
  → Supervisor 任务 + RuntimeClient (typed Control channel)
  → NodeHandle { command/query bus, event hub, revision signal }
Shutdown / LeaveCluster / IdentityReplaced 经 Control 通道驱动，
WaitForShutdown 观察生命周期 watch 通道。
```

### 4.2 成员加入（join / merge）

```
操作方: IssueMergeCredential 非轮换签发(世代 10 分钟, 多节点共享准入)
        RotateMergeCredential 仅撤销/升级
发起方: ConnectMember/MergeCluster(credential)
  → transport registry 拨号 wss (join 模式证书验证: 放宽链/主机名,
    无条件验证 CertificateVerify)
  → WS 升级 (响应携带 cluster ID + generation ID 提示)
  → Connection (prelude 分帧, tls-exporter 通道绑定)
  → SessionDriver::initiate 编排 Handshake 位置 1..5:
      1 initiator hello (mode/generation/cluster/identity)
      2 responder hello
      3 responder proof  (HKDF(credential, exporter) + ed25519)
      4 initiator proof
      5 selection confirmation (双方独立重算字节精确相等)
      6 merge grant delivery (join-only, 不在认证转录内)
  → identity/merge.rs: 一笔 journaled 事务原子提交
      IdentityBinding + per-subject CredentialUse (+信任锚)
  → 会话进入 session/stream.rs 多路复用
```

认证前有 `merge_rate` 固定限速（per-source/global pending + 60s 窗口）。
接收端世代多次准入（reserve 多在途），并发 join 不再需要业务串行化；
同世代 per-subject 重放被持久使用记录拒绝。

### 4.3 反熵同步（membership / trust / resource）

```
每 anti-entropy tick，三个平面各自推进（会话承载，单向有界载荷）:
  membership: MembershipPage(描述符, cursor, 指纹 quiet / 32-tick 重发)
      接收端: 只接受严格更高 revision → member_changed 信号 +
              audit `member descriptor installed`（传播路径证据）
  trust:  TrustSnapshotPage(per-issuer revision 游标, 每 tick 一页,
          空页关 pass 才记 revision) + 墓碑车道(leave/cleanup/
          revocation/checkpoint, 独立重发节奏)
      接收端: 逐绑定 issuer-key 校验采纳, 不持久化远程快照页
  resource: per-key 水位 walk(预算 256 扫描/tick, 发射按水位过滤,
          水位推进 verdict-gated——admission ack 裁决, 失败回退页起点;
          静默窗口续 pass; 64 pass 整表刷新兜底)
投递真相（D2）: 每个分发载荷等待 SEND_ACK_WAIT=2s 的 admission 回执;
  失败 → 丢弃该对端续传状态/回退水位, 下一 tick 从头重投;
  排队 fire-and-forget, 不阻塞 tick 泵。
leave: leaver 等待 applied 回执（applied 优先、admission ack 次之）;
  peer 侧持久化 leave 记录后回执, 不重投、仅诊断。
分区愈合由 membership/recovery.rs 驱动: 完全隔离时对成员表有界扇出
退避拨号（恢复宇宙=成员表）; 任一通路存在即 Connected（any-one-route）;
Connected 后剪枝面按 cooldown 确定性回收恢复拨出的冗余边。
```

### 4.4 数据包路由

```
open_stream(target, protocol, metadata)
  → TraceId 同步分配
  → routing: Selector/精确 NodeId → LoadBalancingPolicy 选一
    （直连目的地由路由面直发; 未直连由 RouteNextHop 决策——
     默认 DefaultNextHop: 存活 peer 中最小 NodeId, 可整体替换）
    → 对照描述符存储验证选择
  → packet/wire open 帧 → 会话队列 (条数+字节双限, 恒定内存)
  → 中间节点 routing/forward.rs 逐跳转发 (RouteContext 每跳重验)
  → 目的端 open 准入入站表 → ack (当前进程准入)
  → chunk 按序 → end; 任何中断 = 显式 StreamInterrupted,
    无重放无恢复; trace 元数据入 routing/trace.rs (条件事务持久化)
```

### 4.5 存储提交（journaled 条件事务）

```
MetadataStore (进程级单写者 WriterLock, 任务可重入;
  journaled 流程全程持 permit, 同 purpose 天然串行化)
  begin → pending journal (与事务原子写入)
  → 条件检查 (期望 digest/base revision)
  → mutations → revision bump → receipt (持久化)
  → commit (fsync: redb) → reconcile by TransactionId+digest
崩溃恢复: resolve_pending_journal 对持久证据直读——
  journal 与业务事务同一 commit 原子写入, provider 收据即权威;
  Committed → 解冻继续; 残留缺席 → fail closed 冻结+corrupt;
  残留已被竞速清理 → 视为已解决继续。
Ready 态 reconcile 立即类型化拒绝（语义性拒绝无等待价值）。
崩溃矩阵按提交路径多点注入验证。
```

## 5. 设计原则（代码中可见的强约束）

1. **`unsafe` 全 crate forbid**（`[lints.rust] unsafe_code = "forbid"`）。
2. **生产代码禁 `unwrap()/expect()`**（lib.rs 对非 test 构建启用 `deny(clippy::unwrap_used, expect_used)`）。
3. **单一编码与命名来源**：确定性 CBOR、hex、分页循环、alive-peer 枚举、命名空间常量、ID 命名生成器（`{前缀}-{21 位小写字母数字}`）均单点定义。
4. **fail-closed**：未知 kind/schema/cursor/条件不匹配一律类型化拒绝，不静默跳过；journal 恢复对持久证据缺席即冻结。
5. **有界性**：所有队列/表/解析深度/帧长/水位表都有界，溢出给类型化 `Overloaded`/`ResourceExhausted` 或有界回退（水位表清空回退全量、刷新 pass 兜底）。
6. **不透明性**：核心从不解释 payload，从不持久化 payload 字节，从不重放中断流。
7. **投递真相**：反熵分发以 admission 回执裁决推进；失败不静默——续传状态回退，下一轮重投。
8. **封闭注册表 + golden 向量**：wire kind、feature 标签、schema ID 不可变且由 compatibility.rs 金样本钉死；身份记录字节由所有者模块 golden 钉死。
9. **可观测的执行路径**：语义决策点（页面收发、水位裁决、journal 恢复、拨号、剪枝）在 `audit` feature 下发结构化事件，fuzz harness 据此做状态+路径双重断言。
