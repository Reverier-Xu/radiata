# 05 — 候选技术横向对比与淘汰理由

> 目的：把 `02`–`04` 的候选逐条对到 radiata 的硬契约上，给出无遗留包袱前提下的
> 干净选型。评估维度全部来自项目的实际约束，而非泛泛的优劣。

## 1. radiata 的硬约束（评估基准）

| # | 约束 | 出处 |
|---|---|---|
| C1 | 确定性收敛：相同输入集合 + 相同消息集合 ⇒ 相同结果，可仿真可 fuzz | 现有 simulation/fuzz 契约 |
| C2 | canonical wire：字节级冻结、golden vector 钉死、fail-closed 解码 | `src/protocol`、`src/sync_common.rs` |
| C3 | 有界性：每消息/每会话/每 tick 的字节与工作都有上界（反 DoS） | `MAX_SYNC_BYTES` 等纪律 |
| C4 | 认证会话承载：行信任来自会话；行自身带签名 | README 安全模型 |
| C5 | 多跳自传播：无中心协调者，任何成员都能当合并点 | any-one-route 愿景 |
| C6 | 泳道异质：descriptors / trust（单调并集）/ resources（LWW+CAS）/ tombstones（终态） | `01` §1 |
| C7 | 冗余目标：摘要可随网重复，载荷结构性不重复，且随链路质量伸缩 | `01` §5 |
| C8 | 全量重写可行：无兼容、无迁移、无存量用户 | 本周期授权 |

## 2. 对比矩阵

载荷冗余指稳态单行变更时行字节被投递次数相对必要的倍数；「摘要冗余」指为达成共识
需要交换的元数据的重复度。

| 技术 | 先验上下文 | 载荷冗余 | 确定性 | 常驻状态 | 失败/退化模式 | 生产先例 | 判定 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **现状**：push watermark 反熵 | 无 | ≈ k×（结构性） | 是 | 每对端 watermark 表 | 表漂移→周期全量重发 | — | 淘汰（C7） |
| push gossip（随机 fanout） | 无 | Θ(log n)× 尾部 | 是 | 无 | 弱网慢、尾部浪费 | Demers 系 | 淘汰（02 §2 定理级冗余） |
| Plumtree lazy-push 树 | 无 | ≈1×（树路径） | 状态复杂（树维护） | 每消息树状态 | 成员变动树震荡 | Riak Core | 淘汰（服务广播总线语义；思想吸收为 hint） |
| Merkle/hashtree AE（Dynamo/Riak） | 键区间约定 | ~0 | 是 | **临时树**需过期重建 | 树-存储漂移 | Dynamo/Riak/Cassandra | 淘汰（树漂移病与 watermark 同源；吸收区间协商思想） |
| **RBSR 区间指纹协商** | 键空间全序（有） | **~0（结构性）** | **纯确定** | 存储自身的指纹索引（全局一棵，非 per-peer） | 指纹碰撞（概率可忽略）/ 多 RTT | libp2p 生态、Earthstar/Willow | **采纳为主干** |
| IBLT / strata（Eppstein） | 无 | ~0（概率解码） | 否（解码可失败） | 无 | 解码失败→重试放大 | 研究+区块链 | 备选（陌生对端首轮加速器，非必需） |
| Graphene（Bloom+IBLT） | 无 | ~0 | 否 | 每次构造 | 参数敏感 | 区块链中继 | 备选（同上） |
| rateless / RBF / CertainSync | 无 | ~0 自定尺寸 | RBF 否 / CertainSync 近似 | 无 | — | SIGCOMM 24 线 | 备选（同上，跟踪） |
| Yjs 式 state vector | 需 per-writer 计数 | ~0 | 是 | 状态向量（O(writers)） | — | Yjs 生产 | 淘汰（radiata 行非 writer 计数模型；思想=接收方举证，已被 RBSR 覆盖） |
| Automerge/Keyhive heads+Bloom | heads 图 | ~0 | Bloom 概率 | heads 图 | 假阳性→漏传 | Automerge 生态 | 淘汰（操作日志语义我们不需要；Bloom 非确定） |
| Δ-CRDT 框架 | 因果上下文 | ~0 | 是 | 因果上下文可膨胀 | 上下文 GC 复杂 | AntidoteDB | **语义采纳**（join 半格 + delta 传播），机制不引入 |
| CouchDB seq+revs_diff | 持久游标 | ~0 | 是 | checkpoint | 游标丢失→重扫 | CouchDB 生产 | 淘汰（单向源→目标模型；多主 mesh 不适配），checkpoint 思想保留 |

## 3. 关键裁决的理由展开

### 3.1 为什么主干是 RBSR 而不是 IBLT 家族

- C1/C2：IBLT 解码是概率事件，失败路径要求重试与参数重估；RBSR 的「区间指纹相等
  ⇒ 双方一致」是确定性判定（指纹碰撞除外，64 位 + 计数联检下可忽略），消息形状
  与时序无关，fuzz 与 golden vector 契约原样保留。
- radiata 的会话永远是**长期认证会话**（C4/C5），「无先验上下文」场景不存在；IBLT
  的核心卖点（陌生节点免上下文对账）对本项目是伪需求。
- RBSR 的常驻结构就是「带聚合指纹的存储索引」：全局 O(N) 一棵（对比现状 per-peer
  watermark 表 O(N×peers)，内存反而净减）。Dynamo/Riak 的临时树漂移问题不存在。

### 3.2 为什么不用 Plumtree

- Plumtree 优化目标函数是「每条消息实时送达全体」的总线冗余；radiata 泳道是收敛
  数据库，晚几百毫秒无关紧要（C5 的收敛语义），却要为树状态机付出成员变动的震荡
  成本。
- 但其 GOSSIP/IHAVE 分层思想被完整吸收：**重复的永远只是摘要**（hint），载荷按需。

### 3.3 为什么机制上不引入完整 Δ-CRDT/因果格

- radiata 行合并 = LWW/CAS/属主标记的值收敛，胜者判定不依赖因果序（`04` §4）；
  RBSR 摘要承担了「集合级状态向量」的角色，无需 DVV/ITC。
- 语义上采纳其两条定理级结论：join 半格保证幂等收敛（重复行无害，C7 的协商重试
  因此安全）；delta 即行（增量无需专门编码）。

### 3.4 push 不是全灭：保留一个「抢跑头」

- Karp 的混合最优性（`02` §2）+ 本地回环低 RTT 场景（用户原始痛点）⇒ 保留
  **eager-delta 首跳**：变更发生时，向直接对端**顺手**携带小 delta（有界字节），
  抢一跳延迟；接收方幂等去重，尾部与一切不确定情形由协商收敛。强网下协商几乎
  不再发生（首跳已送达，指纹相等即静默），弱网下首跳丢失也只是多一轮 RTT，
  不产生任何载荷复制。

## 4. 选型结论（进入 `06`）

**单一和解原语：RBSR 风格的区间指纹协商，承载全部四个泳道；辅以 eager-delta 首跳
与轻量 hint；删除全部 per-peer watermark 状态机。**
