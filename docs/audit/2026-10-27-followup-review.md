# 遗留项复核与后续规划（2026-10-27）

## 复核方法

对 [2026-10-23-aggregated-followups.md](2026-10-23-aggregated-followups.md) 登记的
全部暂缓/遗留条目，在当前 `main`（与 `origin/main` 完全同步）上逐条复核代码证据。
复核采用编排方直接阅读 + 两个独立子代理（glm-5.3，只读）交叉互证；上一轮的
30 个修复提交亦逐个验证真实存在于 git 历史中。

**总结论：文档登记与代码现状零漂移。** 暂缓条目无一自愈、无一失真；
14 个遗留条目经维护者逐条确认，2 个决策项已裁决。

## 维护者裁决记录（本轮新增）

| 条目 | 裁决 |
| --- | --- |
| A7 预算矩阵 | **改注释**：把矩阵表述精确化为实际 6 格，不补 cell |
| A10 严格 SLO | **保持 operator-run**，收紧文档措辞（常规绿 CI ≠ SLO 证据），不加 CI strict job |
| C1 D-6 origin 首跳探索 | **库内不做**。契约：本库不保障消息 1:1 投递，首跳选错由业务方重发恢复；需文档化 |
| C2 P1-3/A11 key 并发创建 | **维持忽略**（上一轮裁决），关闭 |

## 确认结论总表

### A. 测试/证据强化（暂缓类）

全部暂缓条目已处理完毕，见文末"已修复记录"。

### B. 已知遗留行为项

全部处理完毕，见文末"已修复记录"。本轮调查中另有新发现一项，记录备查：

- **TraceSink 强引用滞后**（B3 调查中发现，未修）：`src/routing/trace.rs` 的 detached
  持久化任务强持有 `Arc<LocalIdentityContext>`（→ 存储 → 后端锁），对 shutdown 屏障
  不可见；重路由场景下 shutdown 后任务尾巴仍可能持锁几毫秒。建议后续：改弱引用
  （镜像 `MembershipSyncConsumer`/`ReconcilePlane` 的既有模式）或关闭路径排空 trace
  队列。`tests/admission_runtime.rs` 的重启重试即针对此残留机制。

### C. 已关闭

| 条目 | 关闭理由 |
| --- | --- |
| C1 D-6 origin 首跳探索 | 维护者裁决：库内不做，契约文档化（见下） |
| C2 P1-3/A11 key 并发创建 | 维持忽略裁决 |
| admission_runtime deadline 契约 | 上轮已随 P2-15 更新（维护者批准） |

## 后续工作波次

**Wave 1（已完成，2026-10-27）**与 **Wave 2（已完成，2026-10-27）**：见文末"已修复记录"。

**Wave 3 已全部完成**：无剩余待办。新发现的 TraceSink 项见上文 B 节。

每项遵循"一个逻辑改动一个 commit + 全量质量门"；行为改动须附表达可观测
失败的回归测试。

## 已修复记录（2026-10-27，Wave 1）

四条并行 writer lane（glm-5.3，独立 worktree），编排方逐 diff 复核后集成；
合并后主线全量质量门通过（fmt/taplo/check/clippy -D warnings/全量测试
41 个二进制 1075 项全绿）。

| 条目 | 修复提交 | 方案要点 |
| --- | --- | --- |
| A1 golden witness 自比较 | `75df509` | owner 模块持有唯一冻结字面量（`pub(crate)` `cfg(test)`），manifest 直接引用；删除恒真自比较循环。意外发现：manifest 的 pending 向量与 owner golden 本就不同形（漂移实证），以 `PENDING_RECORD_COMPAT_GOLDEN` 单列 |
| A2 命名空间守卫 | `c6f4d81` | 逐处定位代替集合相等；literal 必须出现在 `*_NAMESPACE` 常量声明上；扫描覆盖 src/tests/examples/fuzz/test-support；新增常量↔registry 双向相等断言 |
| A4 快照 roundtrip | `d0761e0` | 补 `decode_store` + 全量相等断言 + 首/中/尾 binding 抽查 |
| A7 预算矩阵注释 | `1bcd284` | 注释精确化为实际 6/9 cell，注明未覆盖形态与时长取舍 |
| B1 SessionChanged 奇偶性 | `ebb9a9c` | sync 吊销路径补发 `SessionChanged`（先 SessionChanged 后 NodeRevoked，镜像本地路径）；回归测试经变异验证 |
| C1 投递契约文档化 | `d035c81` | guide 路由章节 + `derive_return_stream_with_hops` rustdoc：尽力投递、首跳无库内恢复、调用方幂等重发 |

Wave 2（2026-10-27）：四条 lane（glm-5.3 worker + fresh glm-5.3 reviewer
逐项复核），集成后主线全量质量门通过（41 个二进制 1075 项全绿）。

| 条目 | 修复提交 | 方案要点 |
| --- | --- | --- |
| A3 重放测试签名层 | `6190b4c` + `9473ec0` | `join_pair_rebound` 只改 exporter 绑定（传输层内容字节一致由断言实证）；responder 沿合法流推进后重放 proof 触发 `ProofMismatch`/`InvalidSignature`；变异验证（去 transcript 绑定即漏检） |
| A5 分区/重复断言 | `e536946` + `861cb95` | 多重性在两个原始公开面 dedup 前计数；真双分量 split + 离线写 + 冻结断言 + 恢复后 digest 一致；重拨落地改用 incarnation id 证明（发现代际重置的合法时序） |
| A6 零传输测量 | `346986b` + `9473ec0` | 实测结论：第二轮是全量重发（页字节逐字节相等）；e2e 钉死精确重发记录数（28/2554）；文档措辞如实化 |
| hint 重试 CI flake | `f10ae0f` | `settle_recorded` 固定时窗改累计计数确定性等待；归属结构性正确；tick 12-13 保留静默负检查 |

Wave 3a（2026-10-27）：四条 lane（glm-5.3 worker + fresh glm-5.3 reviewer
逐项复核均为 approve-with-nits，minor 已修复），集成后主线全量质量门通过
（41 个二进制 1077 项全绿）。

| 条目 | 修复提交 | 方案要点 |
| --- | --- | --- |
| A9 oracle 独立化 | `d7d464b` | `reference_commit_verdict`/`reference_reconcile_verdict` 按契约文本独立重写，切断对 `provider.rs` 判定函数的调用；变异验证（生产 digest 分支改错 → redb/json lane 失败而 oracle lane 绿） |
| A10 SLO 措辞 | `b884e1d` | README/verify-release/membership_sync 头注释：常规绿 CI = 功能证据非 deadline 证据；严格 profile 命令与 OCI 限定写明 |
| B2 SPKI 旋钮 | `ba24c52` | `NodeConfig::with_member_spki_anchor_limits(per_peer, global)`（非零 + per_peer≤global 校验），默认 4/256 行为不变；配置经既有构造点流入淘汰逻辑（有非恒真测试钉死） |
| B4 联合调参 | `9fa34b9` + `ae5fb8c` + `3a2e793` | 生产者/消费者拓扑分析结论：无合法配比可发明；钉住两条真实结构关系（`PUMP_HANDOFF=ADMISSION_CONCURRENCY`、`PACKET=CONTROL` 由全构建期 const assert 把守），其余旋钮各自独立性写入注释 |

Wave 3b（2026-10-27）：fresh glm-5.3 reviewer 复核（approve-with-nits，minor 已修），
集成后主线全量质量门通过（41 个二进制 1081 项全绿）。

| 条目 | 修复提交 | 方案要点 |
| --- | --- | --- |
| A8 runtime 恢复证据 | `fa55fab` | 盘点确认 R1/R2/R4/R5 已有真实 runtime 证据；R3 缺口（磁盘重开+自动重连+元数据收敛组合）扩展既有 `restarted_node_passively_reconnects` 落地，变异验证通过；E2e 分类以文档注释落地（failure-replay 设施不适用已论证） |
| B3 redb flake 根治 | `098d099` + `8d179ea` + `219798a` | 根因实证：`snapshot()` 阻塞任务克隆 `Arc<Database>` 对 commit 屏障不可见（插桩抓到 strong count=2）；SnapshotReaders 计数门纳入 flush 屏障；三处散装重试删除 + 12 轮无重试重开回归。cluster gate 升级机器级（进程内 mutex + `target/` 内核文件锁，零新外部依赖） |
