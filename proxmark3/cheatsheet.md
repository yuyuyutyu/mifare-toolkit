# Proxmark3 命令速查（Mifare Classic）

以官方 RRG / Iceman 固件的命令为准。icy 分支把 `hf mf` 下的命令拆得更细，
下面按「探测 → 恢复密钥 → 读取 → 写卡」的顺序排。

## 1. 确认硬件与卡片在场

```bash
hw version
hw status
hf search
hf 14a reader
```

`hf 14a reader` 能打出 UID 与 ATQA / SAK，说明天线耦合正常。
SAK = 08 说明是 Mifare Classic 1K。

## 2. 恢复密钥

| 场景 | 命令 | 说明 |
| --- | --- | --- |
| 有一把已知密钥 | `hf mf nested 1 0 A FFFFFFFFFFFF d` | 用它扩展出其他扇区密钥 |
| 全盲，无任何密钥 | `hf mf darkside` | 恢复第一把 Key A，成功率随时间退化 |
| 已知密钥且固件较新 | `hf mf autopwn` | 自动跑 nested / darkside / hardnested |
| 密钥空间小 | `hf mf fchk 1 d` | 字典穷举，比逐把试快得多 |

`d` 参数是把结果存进设备 flash，跨命令复用，别漏。

## 3. 读取

```bash
hf mf chk --1k -f keys.dic
hf mf rdbl 0 A FFFFFFFFFFFF
hf mf dump --1k
```

`dump` 会生成 `dump.bin` + `dump.json` + `key.bin`。

## 4. 写卡

```bash
# 单块写
hf mf wrbl 0 B FFFFFFFFFFFF 11223344556677889900AABBCCDDEEFF
# 整卡还原
hf mf restore --1k --uid 11223344
```

`--uid` 只对 CUID / FUID 这类可写 UID 的卡有效，普通卡会失败，这是预期行为。

## 5. 关键区分

| 现象 | 含义 |
| --- | --- |
| 认证一直失败，换卡就正常 | 卡不是 Mifare Classic，可能是 CPU 卡或 NTAG |
| 能读不能写 | 卡片被设为只读，或者扇区尾块的访问位不允许 |
| 写 UID 报错 | 用的是普通 UID 卡，不是 CUID / FUID |
| 同一把钥匙只对一个扇区有效 | 一卡一密，需要逐扇区恢复 |
