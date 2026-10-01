# 02 — 流行病式传播（gossip / epidemic broadcast）理论与优化

> 目的：搞清「push 到所有边」这类设计的冗余从理论上来讲能否调优掉，以及业界在
> **必须广播**的场景下用什么手段压冗余。结论：push 的尾部冗余是结构性的；收敛尾部
> 的正确工具是 pull/协商；广播总线的对应物是「摘要先行、载荷按需」（lazy push）。

## 1. 起点：Demers 等 1987 —— anti-entropy 这个词的出处

- A. Demers, D. Greene, J. Hauser, W. Irish, J. Larson, S. Shenker, H. Sturgis,
  D. Swinehart, D. Terry, "Epidemic Algorithms for Replicated Database Maintenance",
  ACM PODC 1987 / ACM TOCS 6(1), 1988. `[经典]`
- 贡献：把流行病学模型引入副本维护，定义了 **anti-entropy**（周期性成对对账修复）
  与 **rumor mongering**（谣言式推播）两种原语，并论证两者组合的收敛与容错性质。
- 与 radiata 的关系：当前实现正是「anti-entropy（周期 tick）+ rumor mongering（变更
  即向所有对端推）」的直接后裔，冗余特征也一脉相承。

## 2. push 的尾部冗余是数学事实：Karp 等 FOCS 2000

- R. Karp, C. Schindelhauer, S. Shenker, B. Vöcking, "Randomized Rumor Spreading",
  IEEE FOCS 2000. `[经典]`（精确常数经下文长版核对）
- B. Doerr, A. Kostrygin, "Randomized Rumor Spreading Revisited (Long Version)",
  arXiv:2303.11150, 2023. `[摘要·全文摘要页]` https://arxiv.org/abs/2303.11150
- 可核对的关键结论（引自 2303.11150 摘要）：
  - 纯 push 把一条谣言传遍 n 节点需要 n·(ln n + O(ln ln n)) 数量级的消息，尾部
    （大家都已知道还互相推）贡献了对数级的浪费；
  - **push-pull + 停止规则（median counter）可达渐近最优的 Θ(n log log n) 消息**；
    若限制每轮只能应答一个入呼（更贴近真实运行时），退化回 Θ(n log n)，但简单的
    协议变体即可恢复 Θ(n log log n)。
- 对 radiata 的含义：
  1. 「每条变更向全部 k 条出边推送」的尾部浪费不是工程失误，是 push 模型的定理级
     属性 —— 换常量、换 watermark 都不会消失；
  2. 理论最优形态是**混合**：前期用 push 抢速度，尾部用 pull 收干净。这个「push 头、
     pull 尾」的结构会直接体现在 `06` 方案的 eager-delta + 协商兜底设计里。

## 3. 成员层：HyParView —— 小活视图撑起高韧性广播

- J. Leitão, J. Pereira, L. Rodrigues, "HyParView: A Membership Protocol for Reliable
  Gossip-Based Broadcast", IEEE DSN 2007. `[摘要]`
  （IEEE Xplore 收录页见 https://ieeexplore.ieee.org/document/4273000 ；作者主页
  joaoleitao.org 与 asc.di.fct.unl.pt 提供报告版 PDF）
- 思想：symmetric partial view（小、活跃、承载消息）+ asymmetric partial view（大、
  被动、仅做候选池）双层视图，故障高发时也能快速恢复视图性质，用很小的活视图支撑
  可靠 gossip。
- 对 radiata 的含义：radiata 的度维护平面（`k(n)` 精确公式 + 均匀拨号维护）在目标上
  与 HyParView 同构且更严格（连通概率有解析保证）。**成员/连接平面无需改动**，
  本次改良应聚焦同步平面，两平面保持正交。

## 4. 广播总线的压冗余极限：Plumtree（epidemic broadcast trees）

- J. Leitão, J. Pereira, L. Rodrigues, "Epidemic Broadcast Trees", IEEE SRDS 2008,
  DOI 10.1109/SRDS.2008.9. `[摘要]`
- 机制：把「数据（GOSSIP）」与「元数据（IHAVE / lazy push）」分离 —— 稳态沿一棵按
  RTT 优化的生成树急推（eager push）数据，树外只发 **IHAVE 摘要**；发现缺件用
  GRAFT 换回急推边，多余急推边 PRUNE 掉。故障后靠摘要/graft 自愈成新树。仿真规模
  >10 000 节点，稳态消息冗余接近树形下界，同时保留流行病容错性。
- 生产出处：该协议被 Riak Core 采用，独立实现存档于
  https://github.com/helium/plumtree （2022-04 归档，README 明言「extracted from the
  implementation in Riak Core」）。`[全文·README]`
- 对 radiata 的含义：
  1. **思想可迁移**：把「载荷」与『我有新东西』的摘要分层，让重复的只是摘要 ——
     这是本方案 hint 平面的直接灵感；
  2. **形态不必照搬**：Plumtree 服务的是「每条消息必须实时广播给全体」的总线语义，
     需要维护全局生成树（graft/prune 状态机，成员变动时树震荡）。radiata 的三个泳道
     是「最终一致的收敛数据库」，没有实时广播语义，且已有 routed data plane 承载
     应用层流。用**按需协商**替代**树维护**，在成员频繁变动的集群里更简单也更稳。

## 5. 小结：本方向给出的三条定律

1. push-only 的对数级尾部冗余不可调参消除（Karp）；
2. 混合 push 头 + pull 尾是渐近最优的传播形态（Karp）；
3. 当传播不可避免有重复时，让重复的只可能是**摘要**（Plumtree 的 lazy push），
   载荷永远按需。

它们共同指向 `03` 的集合和解：pull/协商的通用实现形态。
