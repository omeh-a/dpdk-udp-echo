#include <stdio.h>
#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)
