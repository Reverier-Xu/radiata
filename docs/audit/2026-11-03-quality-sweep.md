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
| `38356ef` | 复审 nits 文档：桥探针生命周期措辞、B2 审计行注记；新增本审计记录 |
| `b53f75e` | 第二轮复审：桥探针 dialing-side 措辞、chapter 9 矛盾、feature digest 输入、残余记录 |
| `f01ffe8` | 第二轮复审：receipt 坏值覆盖、删除空洞 cursor 断言、maintenance 测试改名 |
| `HEAD` | 验证记录：最终门禁与 ABI 结果、测试隔离注记 |

## 未处理 / 推迟

本轮登记的四条残余已在同日第二轮收尾（见下节），此处只保留仍未处理的条目。

- **P2**：`reconcile/plane.rs::tick`、`runtime/supervisor.rs::supervise`、`membership/sync.rs::apply_tombstone_rows` 的拆分，以及 `EventHub`/tombstone GC 的模块迁移，推迟到 0.1.0 之后。
- **已知残余（描述符毒行）**：坏行按 absent 处理后，一个损坏的 removal 描述符可能被更旧的 live 行覆盖（复活）。这是 "corrupt = absent" 的固有代价，未额外加墓碑保护；修复它需要为坏行写入一条墓碑，而坏行的 revision 本身不可知，等于凭空造证据。
- **已知残余（资源毒行）**：plain put 现在能本地自愈（见下节），但坏行本身仍不能被读取或删除——读取报解码错误（不伪造 absent），removal 无法从无法解码的内容构造。运营者的补救是先 plain put 覆盖。
- **无 CI 无条件收敛上界**：`start_recovery()` 现在真的强制一轮并重置节奏（见下节），但 CI 仍没有"任意配置下必收敛"的上界断言。

## 残余问题收尾（同日第二轮）

### 新发现 N1（P1，本轮修复）

原审计把该条记为"只强制一轮，不重置退避指数"，实测是**零轮**：

`RecoveryController::immediate` 只做 `last_attempt_at = now - 1`，而 `due()` 的判据是
`now >= last_attempt_at + backoff_seconds(now)`，`backoff_seconds` 在未到期时返回
`scheduled_backoff`（默认初值 2 s，加倍至 5 min）。于是命令只把 deadline 提前 1 秒，
周期不会跑。探针测试（`RecoveryPolicy::new(64, 2, 300)`，t=100 走完第一步后
`immediate(101)`）实测 `due(101)=false`、`due(102)=false`、`next_attempt_at` 仍为 104。

既有测试 `recovery_immediate_forces_one_cycle` 没暴露它：该测试的控制器从未 step 过
（`last_attempt_at == 0`），任何 due-check 都通过，所以命令看起来生效。

修复：`immediate` 重置 `attempts = 0` 并把 `scheduled_backoff` 置 0——强制周期立即到期，
后续节奏从初始退避重新加倍，运营者刚修好网络时不必等完故障期间长出来的退避。

### 修复清单（5 个 commit）

| commit | 内容 |
| --- | --- |
| `c7660a0` | `immediate` 真正强制周期并重置退避指数；补 live-schedule 回归测试（旧测试只覆盖从未 step 的控制器） |
| `34360b6` | 资源毒行本地自愈：`commit_expected_record_ctx` 对不可解码的 incumbent 走共享 `decode_or_absent`，plain put 通过 exact-CAS Put 覆盖坏行；带前置条件的写按空寄存器报 not-found |
| `b349e46` | `NodeConfig::with_resource_removal_retention(window, cap)` 取代两个硬编码常量；窗口同时穿到 `ReconcilePlane`（sweep 删除与 plane 的 reclaimed-knowledge 判据必须同一来源） |
| `3472e66` | 桥探针边改为有界寿命（120 tick = 1 小时）：到期由探针平面自己回收并在同一 tick 重探，跳过刚释放的 peer；单边上限与 `k(n)+1` 稳态不变 |
| `0e130ec` | 兼容清单新增 `Handshake` 家族，冻结 0.1.0 的 initiator feature offer 字节；`tests/mixed_versions.rs` 的模块文档改为如实说明该 lane 只证明"不同 offer 的协商"，并写明 pre-0.1.0 的 limit 协商删除是刻意的线格式破坏 |

### 设计取舍记录

- **资源毒行**：写路径采纳 page batch 的 "corrupt = absent"，读路径保持报错。理由是两者语义不同——写路径把坏行当非证据才能自愈，读路径若报 absent 就是伪造答案；removal 必须从现存内容构造，因此坏行不可删除。
- **桥探针轮换**：`k(n)+1` 的上限按时间而非永久有界。原设计的风险是"一次落在同侧就永久花掉这个节点唯一的探针"（探针边永不被剪枝，只能随会话退役）。轮换不会丢掉真桥：当探针边是该节点唯一的跨分区链路时，其余所有未直连成员都在对侧，替换探针必然落在对侧；只有同侧边才可能被同侧边接替，而那正是轮换要逃离的情形。探针边的年龄单位是**维护 tick**而非探针间隔——探针被抑制时 cadence bracket 停在触发值，所以门每 tick 都会走一次（这也是"边一退役下一 tick 就重探"的实现方式）。
- **线格式**：真实跨版本证据需要旧二进制或冻结 transcript 重放，两者都不存在；本轮改为冻结 offer 字节，使**下一次**发布可以据此断言"仍接受 0.1.0 的 offer"。这不能追溯证明 0.1.0 与更早版本互通，文档已如实写明。

### 验证

- 全量质量门（单进程）：`taplo fmt --check`、nightly `rustfmt --check`、`check --all-targets --all-features`、`clippy -D warnings`、`test --workspace --all-features --locked` 全绿（exit 0）。工作区列出 1121 个测试用例，本轮新增 10 个。
- 变异验证（每条都确认过修复前必挂）：
  - 恢复 `immediate` 的旧实现 → `recovery_immediate_pulls_a_live_schedule_forward`、`recovery_immediate_restarts_the_backoff_exponent` 失败。
  - `commit_expected_record_ctx` 改回 `decode(...)?` → `a_corrupt_register_heals_through_a_plain_put` 失败。
  - 探针寿命置 `u32::MAX`（永不回收）→ `an_aged_probe_edge_is_reclaimed_and_the_probe_rotates` 失败。
  - `probe_pool` 去掉 retired 过滤 → `the_probe_pool_excludes_the_released_peer_without_emptying` 失败；把"空池返回 `None`"改成 `Some(pool)` → 同一测试的回退断言失败。
  - 冻结 offer 十六进制改动一字节 → `manifest_vectors_reproduce_byte_for_byte` 失败。
- 公开 ABI：基线随 `NodeConfig::with_resource_removal_retention` 的加入重新渲染（唯一 diff 即该行），`public_abi` ignored 测试通过。
- 探针轮换测试的稳定性：连续 5 次全量 degree 测试套件运行全绿。首版测试曾偶发失败，根因是年龄单位搞错（按间隔算，实际按 tick 算），已修正并加了寿命常量 pin。

### 环境注记（ABI 渲染，修正上节）

仅把 `+nightly` 转发给 `rustup run nightly cargo` 的 shim **不够**：`cargo-public-api`
直接解析 `rustdoc`，而本机 PATH 中 stable 工具链的 bin 目录在前，`-Z unstable-options`
会被 stable rustdoc 拒绝（`the option Z is only accepted on the nightly compiler`）。
可用写法：

```bash
NB=$HOME/.rustup/toolchains/nightly-aarch64-apple-darwin/bin
CARGO_TARGET_DIR=/tmp/radiata-abi \
  PATH=$NB:/tmp/cargo-shim:$PATH RUSTC=$NB/rustc RUSTDOC=$NB/rustdoc \
  cargo public-api --all-features -sss
```

另需独立的 `CARGO_TARGET_DIR`：nightly 复用 stable 的 `target/` 产物会报
`E0514 found crate ... compiled by an incompatible version of rustc`。

## 验证

- 全量质量门（无并发测试进程）：`taplo fmt --check`、nightly `rustfmt --check`、`check`、`clippy -D warnings`、`test --workspace --all-features --locked` 全绿（exit 0）。
- 公开 ABI：`cargo-public-api 0.52.0` + nightly rustdoc 重新渲染，`public_abi` ignored 测试通过；基线随三次删除与一次新增更新。
- 复审：两轮 fresh reviewer。第一轮（无 shell）对 HEAD 产物逐缝复核，结论 approve-with-notes；第二轮（有 shell）逐 commit 读 diff、在 throwaway clone 复现 pre-fix 失败、并做变异验证，结论 approve-with-nits、无 blocker。其 nits 已在本轮收尾提交中处理；唯一 must-decide 是桥探针 same-side 选取的残余，已记录在“未处理 / 推迟”。
- 测试隔离注记：`storage::redb::store::followup_tests::backfill_scan_failure_fails_the_open_and_commits_nothing` 与 `storage::redb::crash::redb_crash_boundaries_recover_exact_old_or_new_state` 在**并发**跑全量套件时偶发失败（前者共享进程级 fault hook，后者重开 redb 文件），单独运行必绿；最终门禁在无并发测试进程时通过。这是既有的测试隔离问题，不属于本轮改动。

## 环境注记

本机 `cargo` 不是 rustup shim，`cargo +nightly fmt` 会失败；正确写法是
`RUSTFMT=$HOME/.rustup/toolchains/nightly-*/bin/rustfmt cargo fmt --all`。
ABI 渲染需要一个把 `+nightly` 转给 `rustup run nightly cargo` 的 shim
（见本次审计使用的 `/tmp/cargo-shim/cargo`），否则 `cargo-public-api` 会以 stable rustdoc 失败。
