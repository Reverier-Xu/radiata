# 03 — 集合和解（set reconciliation）谱系

> 目的：调研「让接收方证明自己缺什么，从而载荷只传一次」这一家族的全部主流形态，
> 以及它们在真实系统里的服役记录。这是 `06` 方案的技术主干。

## 0. 问题定义

两台机器 A、B 各持一个集合（或键值目录），要在通信量正比于**对称差 d**（而非集合
规模 n）的前提下让双方得到并集。两个子家族：

- **有先验上下文**（长期对等关系、共享键空间）：用增量摘要/范围结构协商；
- **无先验上下文**（陌生节点首次相遇）：用概率草图（IBLT / Bloom 系）估计并解码差异。

## 1. 工业反熵的常青树：Merkle / 哈希树对账

- **Dynamo**（G. DeCandia et al., "Dynamo: Amazon's Highly Available Key-value Store",
  SOSP 2007，§anti-entropy）：每个键区间维护 Merkle 树，对账双方自根向下比较哈希，
  只在分歧子树里传输键值。`[经典]`
- **Riak Active Anti-Entropy (AAE)**：周期性构建每 bucket 的 hashtree，树**定期过期
  重建**以自愈存储与树的漂移；比较仍是 merkle 式区间对账。
  https://docs.riak.com/riak/kv/2.2.3/using/reference/active-anti-entropy/ `[摘要·文档站]`
- **Cassandra** 同代同型（Lakshman & Malik, SIGMOD 2010，streaming + merkle）。`[经典]`
- 局限：树的对齐要求双方对键区间划分有一致约定；树即状态，需要过期重建的周期成本
  （与 radiata 的 watermark 清空同病）。对 radiata 的启示：**区间摘要协商是正确形态，
  但树不应是「对账时才构建的临时镜像」，而应是存储本身的索引结构**（见 RBSR）。

## 2. 无先验上下文家族：IBLT 与 Bloom 系

- **Eppstein / Goodrich / Uyeda / Varghese**, "What's the Difference? Efficient Set
  Reconciliation without Prior Context", ACM SIGCOMM 2011, DOI 10.1145/2018436.2018462。
  `[经典]` 引入 **IBLT**（invertible Bloom lookup table）与按基数分层的 strata
  estimator：先估差异规模，再用一次 IBLT 交换解码出差异键集，通信量 O(d)。
- **Graphene**（UMass Amherst；"Graphene: Efficient Interactive Set Reconciliation
  Applied to Blockchain Propagation", Proc. ACM SIGMETRICS/POMAC）：
  接收方发 Bloom filter（表达「我有什么」），发送方据此构造 IBLT 只装「你缺的」，
  论文报告大块场景下**仅用既有部署系统 12% 的带宽**。
  https://people.cs.umass.edu/~…/graphene*.pdf（UMass 作者页 PDF）`[片段·快照]`
- **Rateless 家族**（自定尺寸，免估 d）：
  - "Practical Rateless Set Reconciliation", ACM SIGCOMM 2024, arXiv:2402.02668.
    `[摘要]` https://arxiv.org/abs/2402.02668
  - "Rateless Bloom Filters: Set Reconciliation for Divergent Replicas with
    Variable-Sized Elements", arXiv:2510.27614（含 Rust 实现
    github.com/pedrogomes29/rbf）。`[摘要]`
  - "CertainSync: Rateless Set Reconciliation with Certainty", arXiv:2504.08314
    （面向区块链 mempool 同步，给出去随机性的确定性变体）。`[摘要]`
- Bloom 时钟用于因果/差异检测的谱系：A. G. et al., "The Bloom Clock",
  arXiv:2011.11744 及后续。`[摘要]`
- 评价：这族解决「第一次见面对账」与「差异极小但完全无上下文」的场景，代价是概率
  解码失败路径（rateless 家族已大幅缓解）与参数敏感性。**radiata 的会话是长期认证
  会话 + 规范键空间，先验上下文总是存在的**，因此它们在本方案里是备选加速器而非
  主干（见 `05`）。

## 3. 主干候选：Range-Based Set Reconciliation（RBSR）

- Aljoscha Meyer, "Range-Based Set Reconciliation", IEEE SRDS 2023,
  DOI 10.1109/SRDS60354.2023.00016；arXiv:2212.13567v2。`[摘要+协议全文（作者
  的非正式完整描述，见下）]`
  - https://arxiv.org/abs/2212.13567
  - 作者对协议的完整非正式描述：https://github.com/AljoschaMeyer/set-reconciliation
    `[全文]`
  - 硕士论文版（更细）：github.com/AljoschaMeyer/master_thesis
- 协议形态（按作者描述归纳，原文可查）：
  1. 集合元素按全序排列，任何**区间**可 O(log n) 算出**指纹**（元素哈希的 XOR；
     空区间指纹为 0；任意满足交换律+可消去的群运算均可，XOR 最简）；
  2. 一方发来某区间的指纹，接收方本地同区间指纹比对：相等 → 该区间已和解（回
     「无事可做」）；对方指纹为 0 → 直接回传该区间全部元素；不等 → 区间二分
     （或多分）递归；
  3. 消息可按轮打包：第 1 轮 2 个区间、第 2 轮 4 个……**O(log n) 轮**终止；
     最坏情形传 O(n) 个元素 —— 但仅当差异本身就是 O(n)，此时这是信息论下界，
     无法避免。
  4. 指纹的快速区间计算：平衡搜索树上每结点缓存子树聚合指纹，插入删除 O(log n)
     维护；区间指纹 = 两个前缀指纹之差（XOR 消去）。
- 论文贡献（相对前人）：把该技术从特定指纹方案中解放出来给出通用分析与设计空间
  （含密码学安全指纹的调研），并把本地计算复杂度优化掉一个对数因子。
- **为什么它是 radiata 的主干候选**：
  - 通信量正比于对称差 d × 对数因子，载荷只在分歧叶区间传输 —— **载荷冗余被
    结构性归零**（接收方指纹相等即不再传）；
  - 纯确定性算法：无概率解码失败路径、无参数拟合，消息只依赖两侧集合内容 ——
    与 radiata 的确定性收敛契约、canonical wire 契约、fuzz 契约完美同构；
  - 指纹树就是存储索引本身，不存在「临时树漂移需要过期重建」的问题（对比
    Dynamo/Riak）。
- 现役实现参照：
  - Rust：github.com/adriendellagaspera/set-reconciliation（`rsos`：区间可摘要
    顺序统计存储 + `rbsr` 传输无关协商）`[摘要·README]`
  - TypeScript：github.com/earthstar-project/range-reconcile（Earthstar/Willow 生态）`[摘要]`
  - Go：github.com/oftn-oswg/go-reconcile `[摘要]`

## 4. 生产线上的「接收方举证」协议：CouchDB 复制

- Apache CouchDB Replication Protocol（官方规范 2.4 节）：
  https://docs.couchdb.org/en/stable/replication/protocol.html `[全文·规范]`
- 形态：source 的**变更流按 seq 游标**增量拉取（checkpoint 断点续传）→ 对每批变更
  ID+rev 做 `_revs_diff`（target 报告自己缺哪些 revision）→ 只拉取缺失文档。
  - 规范原文要点（摘自已核对的定义节）：Replication 是单向 Source→Target 过程；
    Changes Feed 按 Sequence ID 增量；Checkpoint 是记录的中间 Sequence ID 用于
    恢复；冲突以多 leaf revision 并存（MVCC rev tree）。
- 与 radiata 的同构性：radiata 的 keyset 分页 + per-key watermark 其实已是它的
  近亲；差别在 CouchDB 由**接收方回答 diff**，radiata 现由**发送方猜 diff** —— 这
  一正一反正是本次要翻转的核心。

## 5. 本方向小结

| 场景 | 正确工具 | 载荷冗余 |
| --- | --- | --- |
| 长期对等、共享键空间、确定性要求 | **RBSR / merkle 区间协商** | 结构性 ~0 |
| 陌生节点、无上下文、差异未知 | IBLT / Graphene / rateless | 概率型，自定尺寸后近 0 |
| 单向复制、有持久游标 | CouchDB 式 seq + revs_diff | ~0 |

radiata 的三个泳道全部落在第一行 + 第三行的复合形态：会话内用 RBSR 协商，
泳道本身保留「游标/水位」语义用于 GC 与清理（checkpoint 机制不动）。
