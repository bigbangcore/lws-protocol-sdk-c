#include <stdlib.h>
#include "lws_protocol.h"

static int check_endian()
{
    int a = 1;
    char *p = (char *)&a;

    return (*p == 1); /*1:little-endian, 0:big-endian*/
}

int main(int argc, char **argv)
{
    int endian = check_endian();
    printf("%d\n", endian);
    return EXIT_SUCCESS;
}