all: demo demo2

demo: demo.c
	gcc -o demo -O0 -masm=intel --no-pie demo.c

demo2: demo2.c
	gcc -o demo2 -O0 -masm=intel --no-pie demo2.c

clean:
	rm -f demo demo2 *.o
