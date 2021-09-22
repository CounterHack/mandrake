all: harness

harness: harness.c
	docker build build/ -t build-mandrake
	docker run --rm -v ${PWD}:/src --env UID=$(shell id -u) --env GID=$(shell id -g) -ti build-mandrake

indocker: harness.c
	gcc -o harness -masm=intel harness.c
	chown ${UID}:${GID} harness

clean:
	rm -f harness *.o
