#!/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13
# Microarchitecture Exploitation - Shared Memory 1
# https://pwn.college/system-security/speculative-execution/babyarch-memflag

# 这里的 shebang 必须指向一个不带二次 execve 的 Python，也就是不能为 /run/dojo/bin/python，
# 因为在环境中它指向 /nix/store/8rkdh1mj5w4ysz03j9n5xcdamcwrdwjd-python3-3.13.11-env/bin/python3
# 而此文件又是 `makeCWrapper '/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13'
# --inherit-argv0 --set 'PYTHONNOUSERSITE' 'true'` 而来的，内部二次调用 execve 启动具体的 Python，
# 而 shared memory 会在主进程 fork + execve(child_cmd) 后注入 mmap，二次 execve 会丢失注入的 mmap
# babyarch_memflag
#     |
#     fork
#     |
#     child execve("./flag.py")
#     |
#     kernel 读取 shebang
#     |
#     execve("/usr/bin/python", ["python", "./flag.py"])
#     |
#     stop 给 ptrace
#     |
#     inject_mmap()
#     |
#     python 开始执行
# 这个文件里只能使用标准库

import ctypes

SHM_BASE = 0x1337000
FLAG_OFFSET = 0x24  # sizeof(sem_t)+4，x86_64 glibc 下 sem_t=32
FLAG_ADDR = SHM_BASE + FLAG_OFFSET
flag = ctypes.string_at(FLAG_ADDR, 0x100)

print(flag.split(b"\x00", 1)[0].decode())
