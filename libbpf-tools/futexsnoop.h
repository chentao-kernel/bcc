/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __FUTEXCTN_H
#define __FUTEXCTN_H

#define TASK_COMM_LEN	16
#define MAX_SLOTS	36

struct hist_key {
	__u64 pid_tgid;
	__u64 uaddr;
	int user_stack_id;
};

struct user_args {
	__u32 targ_pid;
	__u32 targ_tid;
	__u64 targ_lock;
	bool targ_summary;
	__u32 min_dur_ms;
	__u32 max_dur_ms;
	__u32 max_lock_hold_users;
};
// for single task
struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
	__u64 pid_tgid;
	__u64 uaddr;
	int user_stack_id;
	__u64 contended;
	__u64 total_elapsed;
	__u64 min;
	__u64 max;
	__u64 max_ts;
};

// for single lock
struct lock_stat {
	uint32_t user_cnt;
	uint32_t max_user_cnt;
	__u64 uaddr;
	char comm[TASK_COMM_LEN];
	__u64 pid_tgid;
	__u64 ts;
};

#endif /* FUTEXCTN_H_ */
