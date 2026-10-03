python
import sys, gdb
if "pwndbg" in sys.modules:
    gdb.execute("source ~/.local/share/pwndbg/pwndbg_tui.py")
    # gdb.execute("layout pwndbg_pwn")
else:
    gdb.execute("source /opt/gef/gef.py")
end

set disassembly-flavor intel
set debuginfod enabled off
set follow-fork-mode child

define print_string_array
    set $p = (char**)$arg0
        while *$p
            x/s *$p
            set $p++
    end
end

define distance
    set $a = (unsigned long)$arg0
    set $b = (unsigned long)$arg1
    set $dist_a_b = $a - $b
    set $dist_b_a = $b - $a
    printf "0x%lx - 0x%lx = 0x%lx (%ld)\n", $a, $b, $dist_a_b, $dist_a_b
    printf "0x%lx - 0x%lx = 0x%lx (%ld)\n", $b, $a, $dist_b_a, $dist_b_a
end

define psa
    document psa
    Print a NULL-terminated string array (char**) with colors.
    Usage: psa <address> [max_entries]
    end

    if $argc == 0
        printf "usage: psa <char**> [max]\n"
    else
        set $base = (char **)$arg0
        set $p = $base
        set $i = 0

        if $argc >= 2
            set $max = $arg1
        else
            set $max = 256
        end

        while *$p && $i < $max
            printf "[%02d] %p │ +0x%04x │ %p → \"%s\"\n", \
                $i, \
                $p, \
                ($p - $base) * 8, \
                *$p, \
                *$p

            set $p = $p + 1
            set $i = $i + 1
        end

        if *$p != 0
            printf "[!] Output truncated at %d entries. Use 'psa <addr> <max>' to view more.\n", $max
        end
    end
end
