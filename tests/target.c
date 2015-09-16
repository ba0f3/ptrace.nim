#include <stdio.h>
int main(void)
{
    int c;
    while (EOF != (c = getc(stdin)))
        putc(c, stdout);
    return 0;
}
