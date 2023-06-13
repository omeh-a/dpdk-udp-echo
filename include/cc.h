#include <stdio.h>
#include <stdlib.h>
#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)
