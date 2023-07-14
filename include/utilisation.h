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

static inline uint64_t
x86_64_get_cycles(void)
{
    unsigned int lo, hi;
    asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

/**
 * Returns the current cycle count.
 * Note that only x86 and aarch64 are supported.
 */
static inline uint64_t get_cycles(void) {
#ifdef __aarch64__
	return aarch64_get_cycles();
#endif
#ifdef __x86_64__
	return x86_64_get_cycles();
#endif
}