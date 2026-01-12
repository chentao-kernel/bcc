/*
 * Create: Mon Jan 12 11:29:43 2026
 */
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __OFFCPUTIME_H
#define __OFFCPUTIME_H

#define TASK_COMM_SIZE 16
#define SCHED_CACHE_SIZE 512
#define SCHED_CACHE_RECORD_ON 0
#define SCHED_CACHE_RECORD_OFF 1

#define MAX_PID_NR 32
#define MAX_TID_NR 32

struct pid_info {
        __u32 pid;
        __u32 tgid;
};

struct user_args {
        __u32 pid;
        __u32 tgid;
        __u32 min_offcpu_us;
        __u32 max_offcpu_us;
        __u32 rq_dur_us;
        int user_stack;
        int kernel_stack;
};

struct waker_t {
        __u32 pid;
        __u32 tgid;
        __u32 t_pid; /* target pid */
        __u32 pad;
        char t_comm[TASK_COMM_SIZE];
        int user_stack_id;
        int kern_stack_id;
        char comm[TASK_COMM_SIZE];
        __u64 oncpu_ns;
        __u64 offcpu_ns;
        __u64 onrq_ns;
        __u32 offcpu_id;
        __u32 oncpu_id;
        __u64 run_delay_ns;
};

struct target_t {
        __u32 pid;
        __u32 tgid;
        __u32 w_pid; /* waker pid */
        __u32 pad;
        char w_comm[TASK_COMM_SIZE];
        int user_stack_id;
        int kern_stack_id;
        char comm[TASK_COMM_SIZE];
        __u64 oncpu_ns;
        __u64 offcpu_ns;
        __u64 onrq_ns;
        __u32 offcpu_id;
        __u32 oncpu_id;
        __u64 run_delay_ns;
};

struct event_t {
        struct waker_t waker;
        struct target_t target;
        __u64 dur_us;
        __u64 rq_dur_us;
        __u64 ts_ns;
        /* 1: dump, 0: no dump */
        __u32 is_sched_cache_dump;
        __u32 cpu;
};

struct trace_event_t {
        /* waker wake target */
        struct waker_t waker;
        struct target_t target;
};

struct sched_record {
        __u32 pid;
        __u32 prio;
        char comm[TASK_COMM_SIZE];
        __u64 ts;
};

struct sched_cached {
        __u32 status;
        __u32 cpu;
        __u32 id;
        __u32 pad;
        struct sched_record records[SCHED_CACHE_SIZE];
};

#endif /* __OFFCPUTIME_H */
