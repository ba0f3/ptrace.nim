#include <unistd.h>
#include <errno.h>

#static void init(void) __attribute__((constructor));

static void wrerr(const char *p)
{
    const char *q;
    int        saved_errno;

    if (!p)
        return;

    q = p;
    while (*q)
        q++;

    if (q == p)
        return;

    saved_errno = errno;

    while (p < q) {
        ssize_t n = write(STDERR_FILENO, p, (size_t)(q - p));
        if (n > 0)
            p += n;
        else
        if (n != (ssize_t)-1 || errno != EINTR)
            break;
    }

    errno = saved_errno;
}

static void init(void)
{
    wrerr("I am loaded and running.\n");
}
