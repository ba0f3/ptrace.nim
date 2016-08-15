#include <unistd.h>

int main()
{
  int i = 0;
  for(;;) {
    printf("My counter: %d\n", i);
    sleep(2);
    ++i;
  }
  return 0;
}
