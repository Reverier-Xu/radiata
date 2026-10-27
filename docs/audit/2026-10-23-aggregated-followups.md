# 聚合审计后续问题报告（2026-10-23）

## 来源与方法

本报告聚合 GitHub issue #81 中两份由不同 agent 产出的审计报告：

- **报告一**（issue 正文，gpt-6-astra）：评审 `de207c5`，对比基线 `fd549c7`。
- **报告二**（issue 评论）：审计 `ad5c91b`。

验证基线为 `6183c4b`（与两个审计基线的源码完全一致）。所有条目均经人工逐项复核。

## 处理结果总览（2026-10-23 收官）

**本轮共落地 30 个修复/实施提交**（不含合并与文档提交），主线全量质量门通过
（fmt/clippy -D warnings/check/全量测试套件，41 个测试二进制全绿）。

### 已修复并删除条目的发现

| 原条目 | 修复提交（主线） | 方案要点 |
| --- | --- | --- |
| P1-1 删除证据丢弃（A02） | `b6c0bcd` | swept 判定改以留存窗口为准，新鲜删除证据保留 |
| P1-2 consumer 生命周期（A10） | `f721e56` | 节点级 consumer 生命周期预算，准入预留/终止释放 |
| P1-4 旧会话清理误伤（A15） | `cf97d10` | 转发跳点绑定确切会话代际 |
| P1-5 策略阻塞控制循环（F1） | `b7aa900` | 有界 admission worker（4 并发许可 + handoff 保 record-before-pump） |
| P1-6 扩展任务槽死锁（F2） | `b9c7091` | 扩展工作流独立 reconcile slot class |
| P1-7 origin 失败不终止远端（F4a） | `6b0e0c1` | body 失败统一投递 interrupted End |
| P1-8 ACK 归属丢失（F4b） | `1c55f97` | 准入后所有权保留在转发跳点上 |
| P1-9 慢流阻塞 reader（F4c） | `b3e85af` + `aba8faa` | 窗口满→一次性 50ms 有界宽限→过载终止 |
| P1-10 存储完成 vs shutdown（F5） | `bcda65f` | 完成屏障绑定真正的阻塞执行 |
| P1-11 吊销 vs 会话发布（F6） | `aa8242f` + `4c91a2d` | AuthorizationBoundary 短互斥段；sync 投递路径同边界 |
| P2-1 detached observer（F3） | `5adc263` + `f115910` | ObservationLanes 有界观察设施 |
| P2-2 准入积压无界（A13） | `5321a8f` | 分 slot class 的非终态积压上限 |
| P2-3 hint 重试丢失（B01） | `50ea7ae` | 未到期重试放回槽位（含变异验证） |
| P2-4 stamp 非原子（B02） | `dbfe89f` | 单次 CAS 循环完成观测+推进 |
| P2-5 转发容量竞态（B03） | （stream-lifecycle lane） | dispatch 前预留，失败/取消释放 |
| P2-6 trace 留存记账（B04） | `d7fd990` | overflow 只计新鲜终态；只报已提交删除数 |
| P2-7 WSS authority（B05） | `dcafb17` | upgrade authority 用规范端点名 |
| P2-8 pin 缓存无界（B07） | `a91fdbf` | per-peer(4) + 全局(256) LRU 驱逐，淘汰即回退 merge-trust |
| P2-9 redb 回填吞错（B08） | `ef893ee` | 迭代器错误传播，部分进度不提交 |
| P2-10 remerge 误报（B10） | `144821d` | 中止分类保留并校验 union 基线 |
| P2-11 证据替换 vs 吊销事件（#14） | `a696052` | Revoked/Replaced/Unchanged 三态结局 |
| P2-12 dial 计数器泄漏（#15） | `74ccd4d` + `fceca87` | RAII DialPermit + 两平面共享 spawn_member_dial |
| P2-13 receipt 扫描无界（#16） | `5ada982` | 旋转游标越过保留前缀 |
| P2-14 receipt 资格路径（O2） | `3ff7880` | 最终移除事务写候选标记，轮扫驱动 cleanup_receipt |
| P2-15 认证 deadline 误分类（O4） | `575d60d` | 三处 deadline 站点统一映射为可重试 NotReady |

### 维护者决定忽略

- **P1-3（A11）key 并发创建超时接管**：并发创建同一操作的 key 在本库使用场景下不会出现，修复只会引入过度设计。

### D 系列契约裁决结果

| 条目 | 裁决 | 落地 |
| --- | --- | --- |
| D-1 稀疏拓扑 densify | 现状即可 | 文档化（`416952b`） |
| D-2 资源 CAS 语义 | 文档化现状 | 文档化（`416952b`） |
| D-3 离线地平线 | 现状 + 文档化 | 文档化（`416952b`） |
| D-4 GC 后终端排除 | **完整 GC 契约**：leave/cleanup 为运营性移除（复活须 OTP 重绑），revocation 永久 | 行为修复（`522f6c8`：GC 联动退役绑定）+ 文档（`aaccb9c`） |
| D-5 传输偏好 | 文档化现状 | 文档化（`416952b`） |
| D-6 稀疏路由知识 | 先测量 | 测量落地（见下节） |
| D-7 多跳回复 | 加显式变体 | 新 API `derive_return_stream_with_hops`（`f6de0c7`） |
| D-8 任务持久性 | 文档化现状 | 文档化（`416952b`） |
| D-9 内置传输替换 | 加覆盖 API | `override_builtin_transport`（`5f76c5f`） |
| D-10 writer 锁可重入 | 现在就改 | 显式 permit 传递 + 公平异步锁（`1f3bf22`） |

### D-6 测量结论（tests/routing_sparse_measurement.rs，lean 套件常驻 / full profile 手动）

- 转发器中途走错 → 预准入分支 DFS 完全恢复；**起点首跳选错 → 单发即败**（25–35%），caller 级 fresh-trace 重试 6 次内恢复 85–95%。
- 无恢复路径的失败模式：预算低于路径长度、分区不可达、（已由 D-7 解决的 direct-only 回复）。
- 延迟由拓扑跳数决定，策略不增加延迟；oracle 与 default 延迟等价。
- 后续决策输入：是否给 origin 加首跳分支探索/可达性观察（本轮未决定）。

### 文档/证据缺口处理

- 文档项全部修复（guide-docs lane 5 提交 + contract-docs lane 6 提交 + 集成修正）。
- 测试/证据强化类（golden witness、命名空间守卫、重放测试、快照往返、分区断言、零传输证明、预算矩阵、仿真≠运行时、参考 oracle、严格 SLO）本轮暂缓；其逐项复核与处置见 [2026-10-27-followup-review.md](2026-10-27-followup-review.md)（A1/A2/A4/A7 已在该轮修复）。
- P3 维护项全部处理：kind 集中化（`0afaee9`）、三组重复 helper（`17385e8`）、fixed_bytes 去重（`a4b8920`）、infallible 构造（`a6b5bb0`）、fail_upstream（`4706026`）、dial 去重、任务等待集中（`9548485`）。广播适配/队列记账/tick 分解经评估**不改**（证据见 wave3 报告：替换会破坏取消安全/字节预算/仅重定位耦合）。

### 已知遗留（不阻塞，记录备查）

- ~~sync 路径 retire_session 不发 SessionChanged~~（2026-10-27 已修复，`ebb9a9c`）。
- ~~MemberSpkiTable 的界是内部常量而非 NodeConfig 旋钮~~（2026-10-27 已修复，`ba24c52`）。
- 两个既有 redb 临时目录/并行度 flake（单独运行均通过）。
- ~~ADMISSION_CONCURRENCY = 4 未与其他容量旋钮联合调参~~（2026-10-27 已处理，`9fa34b9`：拓扑分析确认无合法配比，两条真实结构关系以编译期断言钉死）。
- tests/admission_runtime.rs 的 deadline 断言契约已随 P2-15 更新（维护者批准）。
