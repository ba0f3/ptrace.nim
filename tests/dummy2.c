#include <unistd.h>

int main()
{
  int i;
  for(;;) {
    printf("My counter: %d\n", i);
    sleep(2);
    ++i;
  }
  return 0;
}
