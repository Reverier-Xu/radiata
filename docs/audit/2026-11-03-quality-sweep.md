# 质量审计与修复记录（2026-11-03）

## 审计方法

对 `main`（基线 `7d74948`）做了一次多维度只读审计：

- 7 条并行审查通道：协议+身份+密钥、传输+会话+包+节点、成员+资源+路由、存储+Provider+运行时+模拟、门面+跨模块重复扫描、范围/安全/SLO、扩展性/事件。
- 编排方独立复核全部 P1 结论，并用 `oracle` 产出依赖排序、文件冲突矩阵与单一来源改法。
- 质量门基线：`taplo` / nightly `rustfmt` / `check` / `clippy -D warnings` / 全量测试全绿（1087 项）。

## 维护者裁决

| 议题 | 裁决 |
| --- | --- |
| cleanup checkpoint / tombstone GC | **保留遗忘水位**，不引入保留窗口。运营者须在签发前确保全部节点在线可达、墙钟差 ≤1s；crate 只用 UNIX 时间戳，无时区语义。A4/A5 记为 wontfix-by-decision。 |
| 成员 leaf-SPKI pin | **删除**。pin 失败会回退 merge trust 并重记锚点，安全增量为零；身份证明才是权威。 |
| feature limit 协商 | **删除 limit 半边**，保留 feature 集合协商。limit 在生产代码中无消费者。 |
| 连接度桥探针 | **每节点最多一条 live probe 边**，永不被剪枝回收；探针在持有 probe 边时不再发起。稳态为 `k(n)+1` 条会话，而非满 mesh。 |
| 资源逐条签名 | **保留**；文档化其与描述符的差异：资源是经中继的用户数据，端到端验签；描述符是路由元数据，按契约依赖会话信任。 |

## 修复清单（22 个本地 commit）

| commit | 内容 |
| --- | --- |
| `6318818` | 拒绝亚秒 liveness 策略（截断为 0 会在首个 tick 关闭所有会话） |
| `f706714` | 描述符毒行上报为 refused + membership page 每节点至多一行 |
| `6e182a0` | README：cleanup checkpoint 运营前置条件与收集契约 |
| `634cfe2` | guide/cleanup/resource：checkpoint、时区、签名信任边界 |
| `4808018` | 资源毒行自愈：共享 `decode_or_absent` + 精确 CAS 覆盖 |
| `59a55f0` | 描述符毒行同样自愈（取代 refuse-only） |
| `b1d5d08` | receipt sweep 跳过坏锚点并推进 cursor，单一溢出裁决 |
| `ef09bea` | reconcile budget 常量引用 owner，消除验收 gate 漂移 |
| `2a6d69c` | 删除只写不读的 TrustSnapshot（净减 737 行） |
| `8d2be0b` | soak 阈值单一来源，4 作为显式 CI 容差发布到 ledger |
| `3bc8b8c` | 分页尾部/内存 keyset 单一来源；修正分页字节预算文档 |
| `0d0f0c8` | 移除无消费者的 `RouteContext`/`DiscoveryTag` 导出 |
| `3f4582c` | `ObservabilityCounts` 命名入参，消除 10 位置参数 |
| `212ce49` | 删除成员 SPKI pin 与两个配置旋钮 |
| `17bcbb9` | 删除 join-hint 的 SPKI 死尾巴（固定 17 字节 hint） |
| `9909326` | 删除 feature limit 协商（offer/selection 各减 100 字节） |
| `fd43bfa` | 13 处共享表锁毒构造点收敛为命名构造器 |
| `c6271bd` | `ResourceChanged` 增加 `origin`/`removal`，远端收敛发事件 |
| `46e9bf5` | event_parity 等待远端资源安装后再 drain（测试确定性） |
| `875004a` | 桥探针改为每节点一条 live probe 边，稳态 `k(n)+1` |
| `74edd55` | 复审 nits：budget 重复注释/死语句、soak 字节阈值、issuer 锁毒构造器 |
| `HEAD` | 复审 nits 文档：桥探针生命周期措辞、B2 审计行注记 |

## 未处理 / 推迟

- **P2**：资源 removal retention 与 cap 仍是硬编码常量（未加 `NodeConfig` 旋钮）。
- **P2**：`start_recovery()` 只强制一轮，不重置退避指数；CI 仍无无条件收敛上界。
- **P2**：`reconcile/plane.rs::tick`、`runtime/supervisor.rs::supervise`、`membership/sync.rs::apply_tombstone_rows` 的拆分，以及 `EventHub`/tombstone GC 的模块迁移，推迟到 0.1.0 之后。
- **已知残余**：资源毒行自愈只恢复页面活性并覆盖坏行；若坏行本身是更高版本的有效记录，写入方会在下一次发布/反熵中恢复它。

## 验证

- 全量质量门：`taplo fmt --check`、nightly `rustfmt --check`、`check`、`clippy -D warnings`、`test --workspace --all-features --locked` 全绿。
- 公开 ABI：`cargo-public-api 0.52.0` + nightly rustdoc 重新渲染，`public_abi` ignored 测试通过；基线随三次删除与一次新增更新。
- 复审：fresh reviewer 对 HEAD 产物逐缝复核，结论 approve-with-notes；其 nits 已在本轮收尾提交中处理。

## 环境注记

本机 `cargo` 不是 rustup shim，`cargo +nightly fmt` 会失败；正确写法是
`RUSTFMT=$HOME/.rustup/toolchains/nightly-*/bin/rustfmt cargo fmt --all`。
ABI 渲染需要一个把 `+nightly` 转给 `rustup run nightly cargo` 的 shim
（见本次审计使用的 `/tmp/cargo-shim/cargo`），否则 `cargo-public-api` 会以 stable rustdoc 失败。
