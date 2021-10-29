all: harness

harness: harness.c
	gcc -o harness -masm=intel harness.c
	chown ${UID}:${GID} harness

clean:
	rm -f harness *.o
