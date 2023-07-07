#include <stdint.h>

#define PROFILE_CONTEXT_COST 300

/* Timer data is held in a struct like this */
struct timer_buffer_t
{
	uint64_t idle;
	uint64_t total;
};

static inline uint64_t
aarch64_get_cycles(void)
{
	uint64_t tsc;
	asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
	return tsc;
}
