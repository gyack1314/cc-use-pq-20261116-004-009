# 星地火情事件采集与交接网关

本项目供区域应急数据值守人员处理上游已经筛选的候选火情事件。输入为本地 JSONL 观测包；它不处理遥感影像，也不判断真实火情。仓库演示数据均为合成数据。

## 运行

使用 Python 3.11 或更新版本，无第三方依赖。先在项目根目录运行 `python -m orbitbridge demo --workspace /tmp/orbitbridge-demo`，可看到接收、重复导入、交接确认和来源核对结果。演示会重建指定目录中的 `demo.sqlite3`；请仅使用专门的演示目录。

真实本地包的命令顺序为：

```text
python -m orbitbridge --db work.sqlite3 station-add sat-a "站点 A"
python -m orbitbridge --db work.sqlite3 subscribe north-watch forest-north --severity 3 --confidence 0.7
python -m orbitbridge --db work.sqlite3 ingest packet.jsonl
python -m orbitbridge --db work.sqlite3 handoffs --status pending
python -m orbitbridge --db work.sqlite3 ack 1 "值守员甲"
python -m orbitbridge --db work.sqlite3 trace 1
python -m orbitbridge --db work.sqlite3 verify
```

包第一行为 `kind=packet`、`schema=1`、`station_id`、正整数 `sequence`、带时区 `created_at`、`record_count`、`digest`。后续每行是 `kind=observation`，包含 `id`、带时区 `observed_at`、`region`、`latitude`、`longitude`、`confidence`、1–5 的 `severity` 和 `source`。`source` 可为 `infrared`、`optical`、`thermal`。摘要是每条记录按键排序、紧凑 UTF-8 JSON 表示后追加换行的 SHA-256。可参考 `orbitbridge.protocol.encode_packet` 生成测试包。

同站点序号须连续。相同包重放返回 `duplicate`，相同序号不同内容或跳号进入隔离记录。所有观测和交接项在一个 SQLite 事务中提交；无匹配订阅的观测仍被保存。订阅规则只影响后续提交的包。`verify` 检查数据库、游标、批次数与交接来源。

可用 `inspect-packet` 或 `inspect-dir` 在不改数据库的情况下诊断待收件文件。目录中存在跳号时，先用 `recovery-plan sat-a incoming/` 查看可连续提交的包，再用 `recovery-resume sat-a incoming/` 按站点序号接收。`quarantine-retry <编号> <原文件>` 只允许重检与隔离记录身份一致的包。

清单是 UTF-8 JSON，含 schema、name 和 packets 数组；每个条目含 file、station_id、sequence 和文件 SHA-256。清单与包放在同一目录。`manifest-check <清单>` 预检摘要、包身份和游标，`manifest-run <清单>` 执行可连续提交的条目。执行时再次核对文件摘要。

`quality` 检查跨表不变量，`reconcile` 核对站点和订阅数量。`batch-report <编号>` 与 `day-report YYYY-MM-DD` 分别提供批次及日期统计。`export-handoffs <订阅编号> <新文件路径>` 导出交接来源并返回摘要，`export-check <文件路径> <摘要>` 校验文件。导出不会覆盖已有文件。

测试：`python -m unittest discover -s tests -v`。语法检查：`python -m compileall -q orbitbridge`。
