// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "offcpu.h"
#include "offcpu.skel.h"
#include "trace_helpers.h"

static struct env {
	pid_t pids[MAX_PID_NR];
	pid_t tids[MAX_TID_NR];
	__u64 min_offcpu_us;
	__u64 max_offcpu_us;
	__u64 rq_dur_us;
	int user_stack;
	int kernel_stack;
	bool verbose;
	int stack_map_fd;
	bool existing;
	int perf_buf_sz;
	int sample_period;
	int fd;
} env = {
	.pids[0] = -1,
	.tids[0] = -1,
	.min_offcpu_us = 10000,
	.max_offcpu_us = 100000000,
	.rq_dur_us = 0,
	.user_stack = 0,
	.kernel_stack = 0,
	.stack_map_fd = -1,
	.existing = false,
	.perf_buf_sz = 128,
	.sample_period = 100,
	.fd = -1,
};

const char *argp_program_version = "offcpu 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize off-CPU time by stack trace.\n"
"\n"
"USAGE: offcpu [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] "
"[duration]\n"
"EXAMPLES:\n"
"    offcpu             # trace off-CPU stack time until Ctrl-C\n"
"    offcpu 5           # trace for 5 seconds only\n"
"    offcpu -m 1000     # trace only events that last more than 1000 usec\n"
"    offcpu -M 10000    # trace only events that last less than 10000 usec\n"
"    offcpu -p 185,175,165 # only trace threads for PID 185,175,165\n"
"    offcpu -t 188,120,134 # only trace threads 188,120,134\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace these PIDs only, comma-separated list", 0 },
	{ "tid", 't', "TID", 0, "Trace these TIDs only, comma-separated list", 0 },
	{ "min-offcpu-us", 'm', "MIN-BLOCK-TIME", 0,
	  "the amount of time in microseconds over which we store traces (default 1)", 0 },
	{ "max-offcpu-us", 'M', "MAX-BLOCK-TIME", 0,
	  "the amount of time in microseconds under which we store traces (default U64_MAX)", 0 },
	{ "rq-dur-us", 'r', "RQ-DUR-MS", 0,
	  "task wait on the runq because of schedule latency ", 0 },
	{ "user-stack", 'U', NULL, 0,
	  "get user stack info ", 0 },
	{ "kernel-stack", 'K', NULL, 0,
	  "get kernel stack ", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int ret;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		ret = split_convert(strdup(arg), ",", env.pids, sizeof(env.pids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of pid is too big, please "
					"increase MAX_PID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid PID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 't':
		ret = split_convert(strdup(arg), ",", env.tids, sizeof(env.tids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of tid is too big, please "
					"increase MAX_TID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid TID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		env.min_offcpu_us = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_offcpu_us = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'r':
		errno = 0;
		env.rq_dur_us = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid rq duration (in ms): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stack = 1;
		break;
	case 'K':
		env.kernel_stack = 1;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	env.existing = true;
}

static int handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	char buf[8192];
	struct event_t *e = (struct event_t *)data;
	int err;

	printf("waker, pid: %d, tid:%d, comm:%s, ts: %lld(ns)\n",
		e->waker.tgid, e->waker.pid, e->waker.comm, e->ts_ns);
	printf("waker ustack:\n");
	err = symbol_resolve(env.stack_map_fd, &e->waker.user_stack_id, e->waker.tgid,
			     buf, sizeof(buf));
	if (err) {
		fprintf(stderr, "failed to resolve ustack: %s\n", strerror(errno));
	}
	printf("%s\n", buf);

	printf("waker kstack:\n");
	err = symbol_resolve(env.stack_map_fd, &e->waker.kern_stack_id, 0,
			     buf, sizeof(buf));
	if (err) {
		fprintf(stderr, "failed to resolve kstack: %s\n", strerror(errno));
	}
	printf("%s\n", buf);

	printf("target, pid: %d, tid:%d, comm:%s, dur: %lld(us), \n",
		e->target.tgid, e->target.pid, e->target.comm, e->dur_us);
	printf("target ustck:\n");
	err = symbol_resolve(env.stack_map_fd, &e->target.user_stack_id, e->target.tgid,
			     buf, sizeof(buf));
	if (err) {
		fprintf(stderr, "failed to resolve ustack: %s\n", strerror(errno));
	}
	printf("%s\n", buf);

	printf("target kstck:\n");
	err = symbol_resolve(env.stack_map_fd, &e->target.kern_stack_id, 0,
			     buf, sizeof(buf));
	if (err) {
		fprintf(stderr, "failed to resolve kstack: %s\n", strerror(errno));
	}
	printf("%s\n", buf);

	return 0;
}

static void handle_lost_event(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on cpu:%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	LIBBPF_OPTS(perf_buffer_opts, opts);
	struct offcpu_bpf *obj;
	int pids_fd, tids_fd;
	int err, i, id = 0;
	__u8 val = 0;
	struct perf_buffer *buf = NULL;
	struct user_args args;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	
	if (env.min_offcpu_us >= env.max_offcpu_us) {
		fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	symbol_new(500);

	obj = offcpu_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	err = offcpu_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	if (env.pids[0]) {
		/* User pids_fd points to the tgids map in the BPF program */
		pids_fd = bpf_map__fd(obj->maps.tgids);
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
			if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}
	if (env.tids[0]) {
		/* User tids_fd points to the pids map in the BPF program */
		tids_fd = bpf_map__fd(obj->maps.pids);
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
			if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}

	args.tgid = env.pids[0];
	args.pid = env.tids[0];
	args.min_offcpu_us = env.min_offcpu_us;
	args.max_offcpu_us = env.max_offcpu_us;
	args.rq_dur_us = env.rq_dur_us;
	args.user_stack = env.user_stack;
	args.kernel_stack = env.kernel_stack;

	err = bpf_map__update_elem(obj->maps.args_map, &id, sizeof(id), &args, sizeof(
				   struct user_args), BPF_ANY);
	if (err) {
		fprintf(stderr, "failed to init args map: %s\n", strerror(errno));
		goto cleanup;
	}

	env.stack_map_fd = bpf_map__fd(obj->maps.stack_map);

	opts.sample_period = env.sample_period;
	buf = perf_buffer__new(bpf_map__fd(obj->maps.perf_map),
			       env.perf_buf_sz, handle_event, handle_lost_event, NULL, &opts);
	if (!buf) {
		fprintf(stderr, "failed to allocate buffer\n");
		goto cleanup;
	}

	err = offcpu_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	printf("offcpu successfully started\n");

	for (;;) {
		err = perf_buffer__poll(buf, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "failed to poll perf buffer: %s\n", strerror(errno));
			goto cleanup;
		}
		if (env.existing) {
			err = 0;
			break;
		} 
	}

cleanup:
	symbol_free();
	perf_buffer__free(buf);
	offcpu_bpf__destroy(obj);
	return err != 0;
}
