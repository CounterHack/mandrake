#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int i = 0;
  char buffer[16];

  gets(buffer);
  printf("%s\n", buffer);

  asm("int 3");
  asm("nop");

  return 0;
}
