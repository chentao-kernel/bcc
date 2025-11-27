/*
 * Create: Thu Nov 27 10:57:01 2025
 */
#ifndef __REMAP_TRACE_H
#define __REMAP_TRACE_H

#define PERF_MAX_STACK_DEPTH 127

struct event {
        int k_stack_id;
        char file[64];
        char cgroup[64];
        char comm[64];
        __u64 index;
        __u64 ts;
};

#endif