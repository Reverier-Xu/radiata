# research — 同步冗余优化调研与架构方案

本目录是「数据同步冗余策略改良」这个工作周期的**调研资料库与决策记录**：

- `01-problem-baseline.md` — 现状基线：radiata 当前同步架构的还原与冗余来源的定量分析（全部结论落到源码证据）。
- `02-gossip-epidemic.md` — 方向一：流行病式传播（gossip）理论与优化（Demers / Karp / HyParView / Plumtree）。
- `03-set-reconciliation.md` — 方向二：集合和解（set reconciliation）谱系（Dynamo / Riak / Eppstein / Graphene / RBSR / rateless 家族 / CouchDB / 现有实现）。
- `04-delta-crdt.md` — 方向三：增量 CRDT 与版本摘要协商（Δ-CRDT / Yjs / Automerge·Keyhive / 时钟族）。
- `05-comparison.md` — 横向对比矩阵与淘汰理由：把候选技术逐条对到 radiata 的契约上。
- `06-architecture-proposal.md` — 架构改良方案（目标架构、wire 契约、调度与自适应、删除/保留清单、验收 gate 与阶段计划）。

## 阅读顺序

先读 `01`（问题是什么、有多严重、结构性根因），再按兴趣读 `02`–`04`（业内怎么做），
`05` 是决策依据的浓缩，`06` 是结论。每篇自成一体，引用可独立追溯。

## 资料留存政策

- 本目录保存**调研笔记与引用**，不提交论文 PDF 二进制：arXiv/DOI/规范文档都有稳定
  URL，仓库里放 PDF 既增重又引入再分发许可问题。
- 每条引用标注验证等级：
  - `[全文]` — 本次调研抓取并阅读了全文/完整规范；
  - `[摘要]` — 阅读了官方摘要页或权威索引条目；
  - `[片段]` — 仅经搜索快照确认了关键句（会注明）；
  - `[经典]` — 领域内公认事实的教科书级引用，未在本轮重新核验原文。
- 引用快照日期：**2026-10-01**。失效链接以 DOI 为准。

## 与 docs/ 生命周期规则的关系

按 `docs/README.md` 的约定，本目录属于「驱动即将到来的工作周期的证据与计划」：
`06-architecture-proposal.md` 中被采纳的工作项在开工时应迁入 `docs/backlog.md`
并挂上验收 gate；调研笔记本身作为决策证据保留（或在方案完全落地后随周期归档）。
