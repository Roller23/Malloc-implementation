#include "allocator.h"
#include <string.h>
#include <unistd.h>

int main(void) {
  int len = strlen("Hello!\n");
  char *str = _calloc(len, sizeof(char));
  strncpy(str, "Hello!\n", len);
  write(1, str, len);
  _free(str);
  return 0;
}