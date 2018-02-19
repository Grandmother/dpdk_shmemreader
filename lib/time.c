#include "time.h"

__thread uint64_t time_hz = 0;
__thread uint64_t time_100ms = 0;
__thread uint64_t random_for_time = 0;

int time_init_per_core(void)
{
    time_hz = rte_get_tsc_hz();
    time_100ms = time_hz / 10;
    if (random_for_time != 0) {
        random_for_time = rte_rand();
    }

    return 0;
}
