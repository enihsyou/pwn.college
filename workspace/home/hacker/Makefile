binary:
	as --64 -o flag.o flag.s
	ld -o flag flag.o
	/challenge/check ./flag | tee /dev/tty | grep 'pwn.college' | xargs dojo submit
shared:
	as --64 -o flag.o flag.s
	ld -shared -o flag.so flag.o
	/challenge/check ./flag.so | tee /dev/tty | grep 'pwn.college' | xargs dojo submit

cbinary:
	gcc -no-pie -o flag flag.c
	/challenge/check ./flag | tee /dev/tty | grep 'pwn.college' | xargs dojo submit
