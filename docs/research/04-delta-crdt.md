# 04 — 增量 CRDT 与版本摘要协商

> 目的：调研「收敛数据结构如何只传增量」与「对等方如何用小摘要声明自己的进度」的
> 主流做法，确认 radiata 现有 LWW/CAS 语义在新架构下如何无损承接。

## 1. Δ-CRDT：delta-state 的理论框架

- P. S. Almeida, A. Shoker, C. Baquero, "Delta State Replicated Data Types",
  Journal of Parallel and Distributed Computing 111 (2018) 162–173；
  arXiv:1603.01529。`[摘要]` https://arxiv.org/abs/1603.01529
- 核心主张（摘要原文大意）：state-based CRDT 要传整个状态、op-based CRDT 要求
  exactly-once 可靠传播；**δ-CRDT 取两者之长：像 op-based 一样传小增量，又像
  state-based 一样只依赖不可靠信道**——delta mutator 返回小 delta-state，本地与
  远端都 join；并给出两个反熵算法（最终一致 / 因果一致）。
- 对 radiata 的映射：
  - radiata 的 resources（LWW 寄存器 + CAS）与 trust 单调并集天然是 state-based
    join 半格；「行」本身就是最小 delta —— 不需要引入 op 通道或完整因果格；
  - 论文的「因果一致反熵」对应到我们这里是：**用版本/指纹摘要代替整目录比较**，
    这正是 `03` 的 RBSR 摘要（对键值目录而言，区间指纹就是集合级的状态向量替身）；
  - delta 聚合（多 delta 合并后再发）在我们的形态里自动发生：未送达的行仍在树上，
    下轮协商一并带出，无需额外状态机。

## 2. 生产级摘要协商协议 A：Yjs（state vector → 定向 diff）

- 源：y-protocols `PROTOCOL.md`（官方 wire 规范，已全文核对）：
  https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md `[全文]`
- 协议骨架（规范原文）：
  1. `SyncStep1 = stateVector` —— 连接时**双方各发自己的状态向量**（每个 clientID
     一计数的紧凑摘要）；
  2. 收到 Step1 的一方回 `SyncStep2 = encodeStateAsUpdate(doc, stateVector)` ——
     **只含对方所缺的更新**（规范原话："the updates the remote peer is missing
     relative to the received state"）；
  3. 其后的本地变更以 `Update` 推送，接收方 `applyUpdate` 幂等合并。
  - client-server 拓扑下规范明确：**服务端不应主动发起握手**（由客户端的 Step1 驱动）。
- 与 radiata 的映射：Yjs 的 stateVector≈「每属主的版本计数」摘要，SyncStep2≈定向
  diff。radiata 的多属主行集合没有 per-client 计数序列，但有 (key, row_digest) 集合
  ——RBSR 的区间指纹就是同一角色的集合版摘要（Yjs 是「按属主计数」，RBSR 是
  「按哈希分区间聚合」，后者对 owner-marked 描述符与 LWW 行同样适用）。

## 3. 生产级摘要协商协议 B：Automerge / Keyhive（heads + Bloom）

- Automerge 经典同步协议：交换文档 heads，双方各自用 **Bloom filter 摘要自己已知的
  heads**，回复对方缺失的后代变更（have/need 消息对）。`[经典·JS 时代文档，当前
  仓库路径已迁移，未在本轮重新核对全文]`
- Ink & Switch Keyhive（Automerge 的新一代同步层），设计文档
  `design/sedimentree.md`（github.com/inkandswitch/keyhive）与其 2025-03 实验室
  笔记 "05 · Syncing Keyhive"：设计原话（经搜索快照核对）——
  > "roughly speaking each peer sends the heads of its commit graph and then the
  > other end responds with any known descendants. Bloom filters are used to
  > summarize the current state…" `[片段]`
  - sedimentree：把变更历史按世代沉积成层，旧层不可变、可用小摘要代表，同步时
    「摘要（层指纹）先行，缺失层按需取」。
- 与 radiata 的映射：Bloom 表达「我有什么」同样可行，但 Bloom 是概率结构（假阳性
  → 漏传 → 需重协商兜底）；radiata 的确定性契约更亲和**精确指纹**（RBSR）。这一
  家族的价值在于验证了「摘要协商 + 幂等 apply」在真实协同编辑规模下长期服役。

## 4. 因果跟踪的增强谱系（记录，不在第一性需求内）

- Dotted Version Vectors / Interval Tree Clocks（Almeida, Baquero 等系列，
  arXiv:1011.5808 / arXiv:0905.2526）：把版本向量的成员动态性与空间开销优化到
  理论极限。`[经典·未本轮核验]`
- 适用前提是「需要因果排序的操作流」。radiata 的行语义是 LWW/CAS 的**值收敛**，
  胜者由时间戳/属主规则决定，不依赖操作因果序 —— 引入 DVV/ITC 属于过度工程。
  若未来资源泳道要升级为多写者操作日志（如聊天 example 的离线队列语义扩展），
  再回到此节。

## 5. 本方向小结

1. radiata 的合并语义已经是 δ-CRDT 意义上的 state-based 半格；缺的不是新数据结构，
   而是**摘要协商的传输形态**（Yjs/Keyhive 证明该形态可长期服役）；
2. 摘要结构应选**确定性的区间指纹**而非 Bloom（契约契合）；
3. 因果追踪谱系记录备查，当前不引入。
