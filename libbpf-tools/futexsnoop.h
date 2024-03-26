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
};

struct hist {
	__u32 slots[MAX_SLOTS];
	char comm[TASK_COMM_LEN];
	__u64 contended;
	__u64 total_elapsed;
	__u64 min;
	__u64 max;
};

struct lock_stat {
	uint32_t user_cnt;
	uint32_t max_user_cnt;
};

#endif /* FUTEXCTN_H_ */
