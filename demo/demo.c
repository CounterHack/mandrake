#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int i = 0;
  char buffer[16];

  asm("int 3");

  asm("nop");
  asm("nop");
  asm("nop");

  asm("int 3");

  return 0;
}
