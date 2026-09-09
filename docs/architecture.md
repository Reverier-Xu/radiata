# radiata 技术架构与模块职责

> 本文档由 2026-09-09 全量代码审计生成，对应 main @ `faf7833`。
> 权威 API 参考仍是 rustdoc（`cargo doc`）；本文描述实现层架构与职责边界。

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
│                  lib.rs (crate root) extension_registry          │
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
│                  endpoint,candidates,registry}                  │
├─────────────────────────────────────────────────────────────────┤
│ L1 协议域         protocol/ {cbor,envelope,tag,wire,handshake,   │
│                  offer,selection,feature,credential}            │
├─────────────────────────────────────────────────────────────────┤
│ L0 值与工具       identity/{id,value,signature} hex time label   │
│                  paging sync_common                             │
└─────────────────────────────────────────────────────────────────┘
横切（test-only）: simulation/ compatibility.rs fuzz_adapters.rs
                  identity/testing.rs storage/contract/reference.rs
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
| `identity/id.rs` | 强类型 ID（`NodeId`/`ListenerId`/`SessionId`/`TraceId`/`OperationId`/`TransactionId`），base62 带前缀校验。 |
| `identity/value.rs` | `Digest`/`PublicKey`/`Signature` 值类型。 |
| `identity/signature.rs` | ed25519 签名域分隔（domain separation）、规范签名消息组装、严格验证。 |
| `hex.rs` | 全 crate 唯一小写 hex 编解码，所有线转录/持久化文档/摘要渲染共用。 |
| `time.rs` | 挂钟时间获取（供注入）。 |
| `label.rs` | 有界规范标签（`LabelKey`/`LabelValue`/`LabelSet`），选择器求值依据。 |
| `paging.rs` | keyset-cursor 分页单一实现（membership/resource/candidate/公共视图共用），容量处仅在可证明还有下一条时才给续游标。 |

### L1 协议域（控制面语义）

| 模块 | 职责 |
| --- | --- |
| `protocol/handshake.rs` | **纯内存**认证握手状态机：消息顺序、转录组装、双端独立重算校验；无 socket/TLS 代码。 |
| `protocol/credential.rs` | join 模式凭据证明推导（HKDF-SHA256 + exporter 绑定，见模块文档的精确推导式）。 |
| `protocol/offer.rs` | 规范认证 feature offer 编码与校验（排序去重集合、强制数值上限）。 |
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
| `transport/connection.rs` | TLS-WS 流上的分帧连接（一条二进制 WS 消息 = 16B prelude + body），双重有界接收；RFC 9266 `tls-exporter` 通道绑定推导。 |
| `transport/endpoint.rs` | 公开 `Endpoint` 值类型（规范 `wss://host[:port]` 文本）。 |
| `transport/candidates.rs` | 身份限定的 endpoint 候选（挂钟过期）。 |
| `transport/registry.rs` | 开放 transport/discovery 注册表；内置 WSS 注册为默认。注册永不绕过认证与流安全。 |

### L3 会话域

| 模块 | 职责 |
| --- | --- |
| `session/driver.rs` | 在 `Connection` 上编排 `Handshake` 状态机：签名顺序（发起方 `KeyProvider::sign`）、固定 10 秒认证 deadline。 |
| `session/stream.rs` | 已建立会话的保活与包流多路复用：写半 = 有界帧通道（session queue，条数+字节双限），读循环按四 packet kind 分路；open 先验证并准入有界入站表再返回当前进程 ack；chunk 有序进入有界 body 通道；中断 = `StreamInterrupted`（不重放、不恢复）。 |

### L4 数据面（路由与包）

| 模块 | 职责 |
| --- | --- |
| `packet/wire.rs` | 包流四帧（`0x0010..=0x0013`）确定性 CBOR：open（trace/双端/协议标签/有界元数据）、chunk（序号 + ≤`MAX_CHUNK_BYTES`）、end、ack。 |
| `packet/mod.rs` | 公开流类型（`OutboundStream`/`IncomingStream`/`RouteHandle` 等）：`send_sync` 只等目的端当前进程准入 ack；`send_async` 立即返回 RouteHandle。恒定内存、恒定背压、字节序保持、从不持久化 payload、从不重放。 |
| `routing.rs` | 路由目标（精确 `NodeId` 或标签选择器 `Selector`）、`LoadBalancingPolicy` 选择、`RouteContext` 逐跳信封（每跳对会话认证对端重验证，篡改即失败关闭）。 |
| `routing/table.rs` | 节点本地有界内存路由表（仅 trace 元数据，非 payload）。 |
| `routing/forward.rs` | 中间节点逐跳转发（`ForwardingHop`：帧只过一次、序保持、中断以显式类型化 ack 上报）。 |
| `routing/trace.rs` | 持久化路由 trace 元数据（身份/目的/尝试次数/进度/终态；无 payload 字节；走条件事务，按 `TransactionId`+摘要收敛）。 |

### L5 元数据域（身份 / 成员 / 资源）

| 模块 | 职责 |
| --- | --- |
| `identity/records.rs` | 全部身份记录类型（绑定、凭据使用、信任锚、快照、意图等）的规范编码/解码/摘要脚手架。 |
| `identity/lifecycle.rs` | 本地身份打开/创建（journaled key 生命周期 + key-provider 操作协议，精确有界恢复）。 |
| `identity/merge.rs` | **原子合并记录提交**：握手验证凭据/身份证明后调用；此层永不接触凭据/证明/exporter/转录/私钥。一笔 journaled 事务原子提交不可变 `IdentityBinding`、唯一 `CredentialUse` 等。 |
| `identity/merge_rate.rs` | 固定凭据合并限速（per-source/global pending + 60s 固定窗口 + 有界 source-bucket 表 + 10 秒裁剪）。 |
| `identity/credential.rs` | join 凭据秘密（32 随机字节，`join_` 前缀 base64url）与接收方内存凭据 generation 生命周期；凭据文本/派生密钥/证明值永不持久化/复制。 |
| `identity/trust.rs` | 签发者信任快照（每个节点都是自己的快照签发者）；绑定采纳。 |
| `identity/revocation.rs` | 收敛永久撤销：任何成员可对精确 node→key 绑定签发移除墓碑；永不进检查点覆盖；仅显式本地清除。 |
| `identity/cleanup.rs` | 死节点清理墓碑（签发者签名、针对精确 subject 绑定；终态无复活）。 |
| `identity/leave.rs` | 主动退出与身份替换：journaled leave-intent → 崩溃安全地替换身份并擦除旧身份本地核心元数据。 |
| `identity/deletion.rs` | key 删除意图（目标绑定；先快照证明无已提交 generation 引用该 handle）。 |
| `membership.rs` | 所有者标记节点描述符（`NodeDescriptorV1`）：owning node 的 `NodeId` 标记 + endpoint 候选 + 严格递增 revision + 移除标志；会话信任边界（无逐条签名）。 |
| `membership/page.rs` | 有界成员反熵页（描述符列表 + 不透明 cursor，非全量分配）。 |
| `membership/sync.rs` | 会话承载成员同步：每会话每 tick 单方向两个有界载荷（`MembershipPage` + 签发者 `TrustSnapshotV1`）。 |
| `membership/neighbor.rs` | 确定性稀疏邻居规划 + 维护限流（非 test 构建中刻意 dead）。 |
| `membership/recovery.rs` | 连续恢复状态机：仅在已知在线成员互不可达时激活，按配置挂钟退避（读 `SystemTime` 处理回拨/冻结/前跳）、有界扇出、静默收敛。 |
| `resource/mod.rs` | 通用命名资源元数据：签名记录（公共名/标签/排序版本）。多写者时间戳最大值寄存器（tuple: 挂钟时间戳 → 写者 NodeId → removal rank → 记录摘要，字典序最大者胜）。 |
| `resource/store.rs` | 资源条件本地事务：寄存器键上条件提交整条记录，仅当严格胜出；败者接受但不存储（接受≠当前或未来胜出）。 |
| `resource/page.rs` / `resource/sync.rs` | 有界资源页 + 会话承载资源同步（解码时验摘要、应用时验写者签名）。 |
| `resource/retention.rs` | 签名移除保留与精确核心元数据清理（只清 `removed()` 记录，条件删除期望 = 精确存储摘要）。 |
| `resource/select.rs` | 选择器驱动的分页资源选择（对 winner 全标签空间求值，规范名序流式）。 |
| `resource/crash.rs` / `resource/e2e.rs` | 子进程崩溃矩阵 / 双组件端到端收敛（test-only）。 |

### L6 存储域

| 模块 | 职责 |
| --- | --- |
| `provider.rs` | 公开存储/key 提供者边界：`Storage`/`StorageFactory`/`KeyProvider` trait、`StoreTransaction`/`StoreOperation`/`CommitOutcome` 等类型、能力协商（`StoreCapabilities`/`KeyCapabilities`）。 |
| `storage/mod.rs` | `MetadataStore`：进程级单写者互斥（`WriterLock`，任务可重入）+ 条件提交/reconcile 的编排层。 |
| `storage/receipt.rs` | 提交回执与引用状态（live-marker/head/edge/anchor 读取、审计前奏）。 |
| `storage/pending.rs` | 挂起事务 journal（精确恢复打开：单例键、记录目标事务身份/pre-base revision/操作列表；与被描述事务原子写入）。 |
| `storage/families.rs` | 后端中立元数据族目录（所有命名空间单一定义点；all-family 合约测试遍历此目录）。 |
| `storage/migration.rs` | 事务性 schema 迁移（显式不可变边链；构造期拒绝重复边/环/歧义路径/未知端点/缺失解码器/隐式排序/降级）。 |
| `storage/json/*` | JSON 适配器（feature `json`，测试用不可变 generation 存储；别名安全排他生命周期锁；crash.rs = 子进程崩溃矩阵）。 |
| `storage/redb/*` | redb 适配器（feature `redb`，生产后端；每 commit fsync；crash.rs = 6 提交点崩溃矩阵）。 |
| `storage/contract/*` | 后端中立存储合约引擎（reference 参考实现 + 全族快照/扫描/事务/reconcile/能力合约；JSON/redb 必须逐字节等价）。 |

### L7 运行时与门面

| 模块 | 职责 |
| --- | --- |
| `runtime/supervisor.rs` | 节点核心监督者：持有 `RuntimeDependencies`，管理监听器/会话任务（JoinSet）、控制通道（`Control`/`RuntimeClient`）、包命令通道、同步轮通道；聚合所有命令/查询分派。 |
| `runtime/lifecycle.rs` | 运行时生命周期控制与快照。 |
| `runtime/recovery.rs` | 恢复面：已知在线愈合策略、转发入口选择、有界恢复 tick。 |
| `runtime/views.rs` | 纯观察分页读/点读（成员/资源/监听器/会话/拓扑/信任/可观测性），无状态迁移。 |
| `node/builder.rs` | `NodeBuilder`：存储工厂 + key provider + config + 熵 + 扩展注册表 → 派生运行时。 |
| `node/handle.rs` | `NodeHandle`：类型化命令/查询总线（sealed `Command`/`Query` trait + `async fn run`）发送端。 |
| `node/event.rs` | `EventHub`（每订阅通道、毒恢复锁、prune 语义）。 |
| `node/revision.rs` | 成员 revision 计数器（与 `MemberChanged` 事件同序；晚订阅者立即看到当前值）。 |
| `operation.rs` | 全部命令/查询类型定义（Shutdown、MergeCluster、PutResource、RunSyncRound…）。 |
| `view.rs` | 公开视图 DTO（MemberView、TopologyPage、SessionView…）。 |
| `config.rs` | `NodeConfig`（反熵间隔、会话队列条数+字节、空闲超时、keepalive、parser limits、trace 元数据限制、路由策略、回执保留、必需 features）。 |
| `error.rs` | 封闭 `ErrorKind`（秘密安全分类）+ `ProviderErrorKind` 投影。 |
| `api.rs` | `BoxFuture` 别名 + `Entropy` trait（`SystemEntropy`）。 |
| `extension_registry.rs` | 节点本地扩展注册表：`ProtocolDefinition` ↔ `PacketConsumer` 绑定、feature 定义、LB/路由策略注册。 |
| `lib.rs` | crate root：模块声明、公开 re-export、`extension`/`adapters` 子模块；`#![cfg_attr(not(test), deny(clippy::unwrap_used, expect_used))]`。 |

### 横切（test-only / 辅助）

| 模块 | 职责 |
| --- | --- |
| `simulation/*` | 种子化仿真（拓扑/网络故障矩阵/事件排序/工件捕获），`cfg(test)`。 |
| `compatibility.rs` | 冻结的 `0.1.0` 兼容性 golden 向量清单（7 格式族），`cfg(test)`。 |
| `fuzz_adapters.rs` | 规范解码器/选择器 fuzz 目标的有界适配器，`cfg(any(test, fuzzing))`。 |
| `sync_common.rs` | 同步公共（alive-peer 枚举单一来源）。 |
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
发起方: ConnectMember/MergeCluster(credential)
  → transport registry 拨号 wss (join 模式证书验证: 放宽链/主机名,
    无条件验证 CertificateVerify)
  → WS 升级 (响应携带 cluster ID + generation ID 提示)
  → Connection (prelude 分帧, tls-exporter 通道绑定)
  → SessionDriver 编排 Handshake 位置 1..5:
      1 initiator hello (mode/generation/cluster/identity)
      2 responder hello
      3 responder proof  (HKDF(credential, exporter) + ed25519)
      4 initiator proof
      5 selection confirmation (双方独立重算字节精确相等)
      6 merge grant delivery (join-only, 不在认证转录内)
  → identity/merge.rs: 一笔 journaled 事务原子提交
      IdentityBinding + CredentialUse (+信任锚)
  → 会话进入 session/stream.rs 多路复用
```

认证前有 `merge_rate` 固定限速（per-source/global pending + 60s 窗口）。

### 4.3 反熵同步（membership / resource / trust）

```
每 anti-entropy tick (每会话每方向):
  MembershipPage(描述符, cursor) + TrustSnapshotV1(本节点签发)
  + ResourcePage(资源记录, cursor)  [专用 resource-sync 协议]
接收侧: 解码时验摘要 → 应用时验签名/信任 →
  描述符: 严格更高 revision 才接受; 保留移除标记挡重放
  资源: tuple-max 寄存器, 严格胜出才条件提交
分区愈合由 membership/recovery.rs 状态机驱动 (仅拨已知在线成员)。
```

### 4.4 数据包路由

```
open_stream(target, protocol, metadata)
  → TraceId 同步分配
  → routing: Selector/精确 NodeId → LoadBalancingPolicy 选一
    → 对照描述符存储验证选择
  → packet/wire open 帧 → 会话队列 (条数+字节双限, 恒定内存)
  → 中间节点 routing/forward.rs 逐跳转发 (RouteContext 每跳重验)
  → 目的端 open 准入入站表 → ack (当前进程准入)
  → chunk 按序 → end; 任何中断 = 显式 StreamInterrupted,
    无重放无恢复; trace 元数据入 routing/trace.rs (条件事务持久化)
```

### 4.5 存储提交（journaled 条件事务）

```
MetadataStore (进程级单写者 WriterLock, 任务可重入)
  begin → pending journal (与事务原子写入)
  → 条件检查 (期望 digest/base revision)
  → mutations → revision bump → receipt (持久化)
  → commit (fsync: redb) → reconcile by TransactionId+digest
崩溃恢复: 打开时发现 pending journal → 精确重放到 Committed
  并写永久 used-ID 标记; 崩溃矩阵按提交路径多点注入验证
```

## 5. 设计原则（代码中可见的强约束）

1. **`unsafe` 全 crate forbid**（`[lints.rust] unsafe_code = "forbid"`）。
2. **生产代码禁 `unwrap()/expect()`**（lib.rs 对非 test 构建启用 `deny(clippy::unwrap_used, expect_used)`）。
3. **单一编码来源**：确定性 CBOR、hex、分页循环、alive-peer 枚举、命名空间常量均单点定义。
4. **fail-closed**：未知 kind/schema/cursor/条件不匹配一律类型化拒绝，不静默跳过。
5. **有界性**：所有队列/表/解析深度/帧长都有界，溢出给类型化 `Overloaded`/`ResourceExhausted`。
6. **不透明性**：核心从不解释 payload，从不持久化 payload 字节，从不重放中断流。
7. **封闭注册表 + golden 向量**：wire kind、feature 标签、schema ID 不可变且由 compatibility.rs 金样本钉死。
