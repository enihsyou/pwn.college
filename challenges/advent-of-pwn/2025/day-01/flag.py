# Day 01
import re

import pwn
from dojotool import find_challenge, tee


def ctf() -> None:
    root_bin = find_challenge()
    elf = pwn.ELF(root_bin, checksec=False)

    entry = elf.entry
    segment = next(
        seg
        for seg in elf.segments
        if seg.header.p_type == "PT_LOAD"
        and seg.header.p_flags & 1  # PF_X，可执行
        and seg.header.p_vaddr <= entry < seg.header.p_vaddr + seg.header.p_filesz
    )
    end = segment.header.p_vaddr + segment.header.p_filesz
    size = end - entry
    asm = elf.disasm(elf.entry, size)

    data = bytearray(0x400)
    delta = [0] * 0x400
    found_cmp = False

    for line in asm.splitlines():
        m = re.search(
            r"(add|sub)\s+byte ptr \[rbp\s*-\s*(0x[0-9a-f]+)\],\s*(0x[0-9a-f]+)",
            line,
            re.IGNORECASE,
        )

        if m and not found_cmp:
            op = m.group(1)
            offset = int(m.group(2), 16)
            value = int(m.group(3), 16)
            index = 0x400 - offset

            if op == "add":
                delta[index] += value
            else:
                delta[index] -= value

            delta[index] &= 0xFF
            continue

        m = re.search(
            r"cmp\s+byte ptr \[rbp\s*-\s*(0x[0-9a-f]+)\],\s*(0x[0-9a-f]+)",
            line,
            re.IGNORECASE,
        )

        if m:
            found_cmp = True
            offset = int(m.group(1), 16)
            target = int(m.group(2), 16)
            index = 0x400 - offset

            data[index] = (target - delta[index]) & 0xFF

    with pwn.process(root_bin, level="error") as io:
        tee(io)
        io.send(data)
        io.recvrepeat()


if __name__ == "__main__":
    ctf()
