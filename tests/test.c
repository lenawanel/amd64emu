#include <unistd.h>
int main() {
  char  hello[] = "hello\n";
  write(STDOUT_FILENO, hello, sizeof(hello) - 1);
  return 0;
}
