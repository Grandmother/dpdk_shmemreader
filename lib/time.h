#pragma once

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_random.h>

extern __thread uint64_t time_hz;
extern __thread uint64_t time_100ms;
extern __thread uint64_t random_for_time;

#define TIME_1SEC                   time_hz
#define TIME_100MSEC                time_100ms
#define T_NOW                       rte_get_tsc_cycles()
#define TIME_JIFFIE                 (random_for_time + T_NOW)

int time_init_per_core(void);
