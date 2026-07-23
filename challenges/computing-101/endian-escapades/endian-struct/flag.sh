# Cracking A Struct
# shellcheck disable=SC2016

objdump -d -M intel /challenge/reverse-me \
    | rg 'cmp.+,0x(.+)|movabs.+,0x(.+)' -or '$1$2' \
    | xargs -n1 sh -c 'echo $1 | xxd -r -p | rev' _ \
    | xargs /challenge/reverse-me
