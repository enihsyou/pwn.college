source /opt/gef/gef.py

set disassembly-flavor intel
set debuginfod enabled off

define print_string_array
    set $p = (char**)$arg0
        while *$p
            x/s *$p
            set $p++
    end
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
