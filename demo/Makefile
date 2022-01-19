all: demo demo2 demo3

demo: demo.c
	gcc -o demo -O0 -masm=intel -fno-stack-protector --no-pie demo.c

demo2: demo2.c
	gcc -o demo2 -O0 -masm=intel -fno-stack-protector --no-pie demo2.c

demo3: demo3.c
	gcc -o demo3 -O0 -masm=intel -fno-stack-protector --no-pie demo3.c

clean:
	rm -f demo demo2 demo3 *.o
