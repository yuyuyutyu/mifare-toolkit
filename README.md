# mifare-toolkit

Mifare Classic 加密卡的分析脚本与实测笔记 —— PN532 UART 驱动 + Proxmark3 命令速查。

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Hardware](https://img.shields.io/badge/Hardware-PN532%20%7C%20Proxmark3-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## 背景

国内的门禁、水卡、洗衣卡绝大多数是 Mifare Classic 1K/4K。它用的 Crypto-1 算法
在 2008 年被破解（Nohl / Plötz），加上同一栋楼的门禁卡往往是批量写同一套密钥，
所以「同批次卡片密钥复用率极高」是常态，不是个例。

这个仓库不讨论怎么用，只提供两块东西：

1. 一个干净的 PN532 UART 驱动，能做认证 / 读块 / 写块
2. 一份实测记录：不同卡型的差异，以及哪些安卓机写不进去、为什么

## 目录

| 路径 | 说明 |
| --- | --- |
| `pn532/mifare_reader.py` | PN532 UART 驱动与命令行工具 |
| `proxmark3/cheatsheet.md` | Proxmark3 常用命令速查 |
| `docs/card-types.md` | UID / CUID / FUID / Gen2 卡型差异与手机兼容性 |

## 快速开始

```bash
pip install -r pn532/requirements.txt

# 确认硬件在线
python pn532/mifare_reader.py --port COM3 info

# 寻卡，拿 UID
python pn532/mifare_reader.py --port COM3 scan

# 用已知密钥读全部扇区
python pn532/mifare_reader.py --port COM3 dump \
    --key FFFFFFFFFFFF --key-type A --out dump.json
```

## 实测结论

| 结论 | 说明 |
| --- | --- |
| 密钥复用是真问题 | 同一栋宿舍楼批量下发的卡片，Key A 复用率通常在 90% 以上 |
| 扇区 0 的 UID 只读 | 出厂固化，改不了。要换 UID 只能用 CUID / FUID 这类可写卡 |
| 安卓写入失败多半是卡型问题 | 部分安卓机 NFC 控制器对 CUID 的写时序要求更严，换 FUID 或换机型可解 |
| 手机 NFC 不等于读卡器 | 手机只提供 13.56MHz 读写能力，供电与天线尺寸决定了它比 PN532 更容易失败 |

## 合规边界

自有的卡片、自有门禁系统、以及取得授权的测试环境。
