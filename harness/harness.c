#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
  if(argc != 2) {
    printf("Usage: %s <hex code>\n", argv[0]);
    exit(1);
  }

  unsigned char *a = mmap((void*)0x13370000, strlen(argv[1]) / 2, PROT_EXEC |PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  int i;
  for(i = 0; i < strlen(argv[1]); i += 2) {
    sscanf(argv[1] + i, "%2hhx", (char*)&a[i / 2]);
  }

  /* Give it 10 seconds to run before killing the process with SIGALRM */
  alarm(10);
  asm("mov rax, %0\n"
      "xor rbx, rbx\n"
      "xor rcx, rcx\n"
      "xor rdx, rdx\n"
      "xor rsi, rsi\n"
      "xor rdi, rdi\n"
      "xor rbp, rbp\n"

      // This triggers the debugger
      "int 0x03\n"

      // Jump to the user's code - if they return, it'll return to the exit code
      "call rax\n"

      // This turns off the debugger
      "int 0x03\n"

      // rax (exit code) is already set to the value returned by the code
      "mov rdi, 0\n"
      "syscall\n"
      : :"r"(a));
}
