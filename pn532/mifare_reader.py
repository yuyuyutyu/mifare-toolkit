#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mifare_reader.py —— PN532 UART 驱动 + 命令行工具

只实现读写 Mifare Classic 需要的部分，帧结构按 PN532 User Manual UM0701 实现。

用法:
    python mifare_reader.py --port COM3 info
    python mifare_reader.py --port COM3 scan
    python mifare_reader.py --port COM3 dump --key FFFFFFFFFFFF --key-type A
    python mifare_reader.py --port /dev/ttyUSB0 dump --key FFFFFFFFFFFF --out dump.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("缺少依赖，先执行: pip install pyserial")

PREAMBLE = b"\x00\x00\xff"
POSTAMBLE = b"\x00"
ACK_FRAME = b"\x00\x00\xff\x00\xff\x00"
HOST_TO_PN532 = 0xD4
PN532_TO_HOST = 0xD5

CMD_GET_FIRMWARE_VERSION = 0x02
CMD_SAM_CONFIGURATION = 0x14
CMD_IN_LIST_PASSIVE_TARGET = 0x4A
CMD_IN_DATA_EXCHANGE = 0x40

MIFARE_AUTH_A = 0x60
MIFARE_AUTH_B = 0x61
MIFARE_READ = 0x30
MIFARE_WRITE = 0xA0

DEFAULT_KEY = bytes.fromhex("FFFFFFFFFFFF")


class PN532Error(RuntimeError):
    pass


class PN532:
    """PN532 的 UART 帧读写实现。"""

    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 1.0) -> None:
        self.serial = serial.Serial(port, baudrate=baudrate, timeout=timeout)
        self.serial.reset_input_buffer()
        self.serial.reset_output_buffer()
        self._wakeup()
        self.firmware = self.get_firmware_version()
        self._sam_configuration()

    # ---------------- 底层帧 ----------------

    def _wakeup(self) -> None:
        # UM0701 7.2.11：拉低一段时间后发 0x55 唤醒
        self.serial.write(b"\x55\x55\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        time.sleep(0.1)
        self.serial.reset_input_buffer()

    @staticmethod
    def _checksum(data: bytes) -> int:
        return (~sum(data) + 1) & 0xFF

    def _write_frame(self, command: int, params: bytes = b"") -> None:
        body = bytes([HOST_TO_PN532, command]) + params
        length = len(body)
        frame = (
            PREAMBLE
            + bytes([length, self._checksum(bytes([length]))])
            + body
            + bytes([self._checksum(body)])
            + POSTAMBLE
        )
        self.serial.write(frame)

    def _read_exact(self, size: int, timeout: float) -> bytes:
        deadline = time.time() + timeout
        buf = b""
        while len(buf) < size:
            chunk = self.serial.read(size - len(buf))
            if chunk:
                buf += chunk
                continue
            if time.time() > deadline:
                raise PN532Error("读取超时（已读 {} / {} 字节）".format(len(buf), size))
        return buf

    def _read_frame(self, timeout: float = 1.0) -> bytes:
        deadline = time.time() + timeout
        # 对齐到帧头 00 00 FF
        window = b""
        while True:
            if time.time() > deadline:
                raise PN532Error("等待 ACK 超时")
            window += self.serial.read(1)
            if len(window) >= 3 and window[-3:] == b"\x00\x00\xff":
                break

        length = self._read_exact(1, timeout)[0]
        lcs = self._read_exact(1, timeout)[0]
        if (length + lcs) & 0xFF != 0:
            raise PN532Error("LCS 校验失败")
        body = self._read_exact(length, timeout)
        dcs = self._read_exact(1, timeout)[0]
        if (sum(body) + dcs) & 0xFF != 0:
            raise PN532Error("DCS 校验失败")
        self._read_exact(1, timeout)  # postamble
        return body

    def call(self, command: int, params: bytes = b"", timeout: float = 1.0) -> bytes:
        self._write_frame(command, params)

        # 等 ACK
        deadline = time.time() + timeout
        window = b""
        while time.time() < deadline:
            window += self.serial.read(1)
            if window.endswith(ACK_FRAME):
                break
        else:
            raise PN532Error("未收到 ACK")

        body = self._read_frame(timeout)
        if not body or body[0] != PN532_TO_HOST:
            raise PN532Error("TFI 异常")
        if body[1] == command + 1:
            raise PN532Error("命令返回错误帧: {}".format(body.hex(" ")))
        return body[2:]

    # ---------------- 命令 ----------------

    def get_firmware_version(self) -> dict:
        data = self.call(CMD_GET_FIRMWARE_VERSION)
        if len(data) < 4:
            raise PN532Error("固件版本响应过短")
        ic, ver, rev, support = data[0], data[1], data[2], data[3]
        return {
            "ic": hex(ic),
            "version": "{}.{}".format(ver, rev),
            "support": hex(support),
        }

    def _sam_configuration(self) -> None:
        # 0x01 = 正常模式
        self.call(CMD_SAM_CONFIGURATION, bytes([0x01, 0x14, 0x00]))

    def in_list_passive_target(self, baud: int = 0x00, retries: int = 3) -> bytes:
        """寻卡，返回 4 字节 UID。"""
        last = None
        for _ in range(retries):
            data = self.call(CMD_IN_LIST_PASSIVE_TARGET, bytes([0x01, baud]))
            if len(data) > 0 and data[0] >= 1:
                tg = data[0]
                if len(data) >= 6:
                    uid_len = data[5]
                    return data[6:6 + uid_len]
            last = data
            time.sleep(0.1)
        raise PN532Error("未寻到卡片: {}".format(last.hex(" ") if last else "无响应"))

    def in_data_exchange(self, tg: int, payload: bytes) -> bytes:
        data = self.call(CMD_IN_DATA_EXCHANGE, bytes([tg]) + payload, timeout=1.5)
        if not data:
            raise PN532Error("InDataExchange 无返回")
        status = data[0]
        if status != 0x00:
            raise PN532Error("Mifare 操作失败，状态码 0x{:02X}".format(status))
        return data[1:]

    # ---------------- Mifare Classic ----------------

    def authenticate(self, tg: int, block: int, key: bytes,
                     key_type: str = "A", uid: bytes = b"") -> None:
        cmd = MIFARE_AUTH_A if key_type.upper() == "A" else MIFARE_AUTH_B
        if len(key) != 6:
            raise ValueError("密钥必须是 6 字节")
        payload = bytes([cmd, block & 0xFF]) + key + uid[:4]
        self.in_data_exchange(tg, payload)

    def read_block(self, tg: int, block: int) -> bytes:
        data = self.in_data_exchange(tg, bytes([MIFARE_READ, block & 0xFF]))
        if len(data) < 16:
            raise PN532Error("读块返回长度异常: {}".format(len(data)))
        return data[:16]

    def write_block(self, tg: int, block: int, payload: bytes) -> None:
        if len(payload) != 16:
            raise ValueError("写入内容必须是 16 字节")
        self.in_data_exchange(tg, bytes([MIFARE_WRITE, block & 0xFF]) + payload)

    def dump(self, tg: int, key: bytes, key_type: str, uid: bytes,
             total_blocks: int = 64) -> dict:
        """按扇区读全部块，认证失败记 null。"""
        result = {}
        current_key = key
        for block in range(total_blocks):
            # 每个扇区的第 4 块是尾块，换扇区要重新认证
            if block % 4 == 0:
                try:
                    self.authenticate(tg, block, current_key, key_type, uid)
                except PN532Error as exc:
                    result[block] = {"error": str(exc)}
                    continue
            try:
                data = self.read_block(tg, block)
                result[block] = data.hex().upper()
            except PN532Error as exc:
                result[block] = {"error": str(exc)}
        return result


def parse_key(text: str) -> bytes:
    cleaned = text.replace(" ", "").replace(":", "")
    if len(cleaned) != 12:
        raise argparse.ArgumentTypeError("密钥必须是 12 个十六进制字符")
    return bytes.fromhex(cleaned)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PN532 Mifare Classic 读写工具")
    parser.add_argument("--port", required=True, help="串口，例如 COM3 或 /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, default=115200)
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("info", help="读取固件版本")
    sub.add_parser("scan", help="寻卡并输出 UID")

    dump = sub.add_parser("dump", help="用已知密钥读全部块")
    dump.add_argument("--key", type=parse_key, default=DEFAULT_KEY)
    dump.add_argument("--key-type", choices=["A", "B", "a", "b"], default="A")
    dump.add_argument("--blocks", type=int, default=64, help="1K 卡是 64 块，4K 卡是 256 块")
    dump.add_argument("--out", help="输出 JSON 文件路径")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        card = PN532(args.port, baudrate=args.baud)
    except (serial.SerialException, PN532Error) as exc:
        print("打开设备失败: {}".format(exc), file=sys.stderr)
        return 1

    if args.action == "info":
        print(json.dumps(card.firmware, ensure_ascii=False, indent=2))
        return 0

    try:
        uid = card.in_list_passive_target()
    except PN532Error as exc:
        print("寻卡失败: {}".format(exc), file=sys.stderr)
        return 1

    print("UID: {}".format(uid.hex().upper()))

    if args.action == "scan":
        return 0

    blocks = card.dump(1, args.key, args.key_type, uid, args.blocks)
    payload = {"uid": uid.hex().upper(), "blocks": blocks}
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print("已写入 {}".format(args.out))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
