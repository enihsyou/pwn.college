# Misc - Ping-1
# https://pwn.college/academy-ctf-v2~020f0262/misc/forensic-ping-1

dojo submit "$(
    tshark -r /challenge/challenge.pcap \
        -Y 'icmp.type == 8 && icmp.seq == 0' \
        -T fields -e ip.len \
        | python3 -c 'import sys; print("".join(chr(int(x) - 20) for x in sys.stdin))' \
        | /challenge/flagcheck
)"
