# docs 目录索引

> 本目录只保留两类内容：**权威工程文档**与**归档的时点性报告**。
> 代码与注释是实现事实的唯一来源；rustdoc（`cargo doc`）是权威 API 参考。

## 权威文档

| 文档 | 内容 | 维护约定 |
| --- | --- | --- |
| [architecture.md](architecture.md) | 分层架构与模块职责（对应 `plan-0.1.0-baseline` 0.1.0 代码定稿，2026-09-15 全量重审刷新） | 代码变更触及架构语义时同步更新 |
| [plan-0.1.0.md](plan-0.1.0.md) | **0.1.0 前改进计划（唯一任务清单）**：P0/P1/P2 全部条目、根因、方案草案、验收标准、批次顺序 | 每完成一项就地更新状态；新发现的问题先入档再开工 |
| [archive/README.md](archive/README.md) | 归档说明 | — |

## archive/（时点性报告，仅供追溯，不再维护）

| 文档 | 时点 | 归档原因 |
| --- | --- | --- |
| audit-findings.md | main @ `faf7833` | 全量审计报告；P1×3、P2×22、P3×14 已全部修复（§9 台账），事项已折叠进 plan-0.1.0.md |
| example-findings.md | cluster example 战役 | 客户集成摩擦清单；#3/#4/#9/#10/#11/#12 已修，未修项已折叠进 plan-0.1.0.md（P1-4、P2-5、P2-6） |
| snapshot-analysis.md | fix-audit-findings @ `fbfaa14` | Snapshot 专项审查；未完成建议（快照刷新解耦、trust 注释、16 节点协议改造）已折叠进 plan-0.1.0.md（P0-4、P1-7、P2-1） |
| benchmark-loopback.md | 2026-09-10 | 回环基准时点数据；ack 投递语义落地后性能特征已变，P0-2 的 soak 将取代其结论 |
