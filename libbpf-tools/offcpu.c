// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
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
	pid_t pid;
	pid_t tid;
	bool user_threads_only;
	bool kernel_threads_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	__u64 min_block_time;
	__u64 max_block_time;
	long state;
	int duration;
	bool verbose;
	bool is_existing;
	int perf_buf_sz;
	struct ksyms *ksyms;
	struct sysms_cache *syms_cache;
	int stackmap_fd;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.min_block_time = 1,
	.max_block_time = -1,
	.state = -1,
	.duration = 99999999,
	.is_existing = false,
	.perf_buf_sz = 64,
	.ksyms = NULL,
	.syms_cache = NULL,
	.stackmap_fd = 0,
};

const char *argp_program_version = "offcpu 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Summarize off-CPU time by stack trace.\n"
"\n"
"USAGE: offcpu [--help] [-p PID | -u | -k] [-m MIN-BLOCK-TIME] "
"[-M MAX-BLOCK-TIME] [--state] [--perf-max-stack-depth] [--stack-storage-size] "
"[duration]\n"
"EXAMPLES:\n"
"    offcpu             # trace off-CPU stack time until Ctrl-C\n"
"    offcpu 5           # trace for 5 seconds only\n"
"    offcpu -m 1000     # trace only events that last more than 1000 usec\n"
"    offcpu -M 10000    # trace only events that last less than 10000 usec\n"
"    offcpu -p 185      # only trace threads for PID 185\n"
"    offcpu -t 188      # only trace thread 188\n"
"    offcpu -u          # only trace user threads (no kernel)\n"
"    offcpu -k          # only trace kernel threads (no user)\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_STATE			3 /* --state */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Trace this PID only" },
	{ "tid", 't', "TID", 0, "Trace this TID only" },
	{ "user-threads-only", 'u', NULL, 0,
	  "User threads only (no kernel threads)" },
	{ "kernel-threads-only", 'k', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
	{ "min-block-time", 'm', "MIN-BLOCK-TIME", 0,
	  "the amount of time in microseconds over which we store traces (default 1)" },
	{ "max-block-time", 'M', "MAX-BLOCK-TIME", 0,
	  "the amount of time in microseconds under which we store traces (default U64_MAX)" },
	{ "state", OPT_STATE, "STATE", 0, "filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE) see include/linux/sched.h" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		env.pid = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		errno = 0;
		env.tid = strtol(arg, NULL, 10);
		if (errno || env.tid <= 0) {
			fprintf(stderr, "Invalid TID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'k':
		env.kernel_threads_only = true;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'm':
		errno = 0;
		env.min_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'M':
		errno = 0;
		env.max_block_time = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid min block time (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STATE:
		errno = 0;
		env.state = strtol(arg, NULL, 10);
		if (errno || env.state < 0 || env.state > 2) {
			fprintf(stderr, "Invalid task state: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
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
	env.is_existing = true;
}

static  void print_stack(struct perf_event_t *e, int *k_stack_id, int *u_stack_id, __u32 tgid, __u32 pid)
{
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int err, i;
	unsigned long *ip;
	struct val_t val;
	char *dso_name;
	unsigned long dso_offset;
	int idx;

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

	if (bpf_map_lookup_elem(env.stackmap_fd, k_stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed Kernel Stack]\n");
			goto print_ustack;
		}

		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(env.ksyms, ip[i]);
			if (!env.verbose) {
				printf("    %s\n", ksym ? ksym->name : "unknown");
			} else {
				if (ksym)
					printf("    #%-2d 0x%lx %s+0x%lx\n", idx++, ip[i], ksym->name, ip[i] - ksym->addr);
				else
					printf("    #%-2d 0x%lx [unknown]\n", idx++, ip[i]);
			}
		}

print_ustack:
		if (bpf_map_lookup_elem(env.stackmap_fd, u_stack_id, ip) != 0) {
			fprintf(stderr, "    [Missed User Stack]\n");
			goto skip_ustack;
		}

		syms = syms_cache__get_syms(env.syms_cache, tgid);
		if (!syms) {
			if (!env.verbose) {
				fprintf(stderr, "failed to get syms\n");
			} else {
				for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++)
					printf("    #%-2d 0x%016lx [unknown]\n", idx++, ip[i]);
			}
			goto skip_ustack;
		}
		for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			if (!env.verbose) {
				sym = syms__map_addr(syms, ip[i]);
				if (sym)
					printf("    %s\n", sym->name);
				else
					printf("    [unknown]\n");
			} else {
				sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
				printf("    #%-2d 0x%016lx", idx++, ip[i]);
				if (sym)
					printf(" %s+0x%lx", sym->name, sym->offset);
				if (dso_name)
					printf(" (%s+0x%lx)", dso_name, dso_offset);
				printf("\n");
			}
		}

skip_ustack:
		printf("    %-16s %s (%d)\n", "-", val.comm, pid);

	free(ip);
}

static void handle_event(void *ctx, int cpu, void *data, __u64 lost_cnt)
{
	struct perf_event_t *e = (struct perf_event_t *)data;

	printf("waker:%s, pid:%u, tgid:%u, rq=>cpu:%d, off=>on:%d\n", e->waker.comm, e->waker.pid, e->waker.tgid, (e->waker.oncpu_ns - e->waker.onrq_ns)/1000,
			(e->waker.oncpu_ns - e->waker.offcpu_ns) / 1000);
	printf("target:%s, pid:%u, tgid:%u, rq=>cpu:%d, off=>on:%d\n", e->target.comm, e->target.pid, e->target.tgid, (e->target.oncpu_ns - e->target.onrq_ns)/1000,
			(e->target.oncpu_ns - e->target.offcpu_ns) / 1000);
	printf("ts:%llu, size:%d\n", e->ts, (int)sizeof(struct perf_event_t));
	printf("waker stack info:\n");
	print_stack(e, &e->waker.kern_stack_id, &e->waker.user_stack_id, e->waker.tgid, e->waker.pid);
	printf("woker stack info:\n");
	print_stack(e, &e->target.kern_stack_id, &e->target.user_stack_id,  e->target.tgid, e->target.pid);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct offcpu_bpf *obj;
	struct user_args args = {0};
	struct perf_buffer *pb = NULL;
	__u32 args_map_id = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_threads_only && env.kernel_threads_only) {
		fprintf(stderr, "user_threads_only and kernel_threads_only cannot be used together.\n");
		return 1;
	}
	if (env.min_block_time >= env.max_block_time) {
		fprintf(stderr, "min_block_time should be smaller than max_block_time\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	/*
	LIBBPF_OPTS(bpf_object_open_opts, opts,
					.btf_custom_path = btf);
		obj = offcpu_bpf__open_opts(&opts);
	*/
	obj = offcpu_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	args.pid = env.tid;
	args.tgid = env.pid;
	args.min_offcpu_ms = env.min_block_time;
	args.max_offcpu_ms = env.max_block_time;
	
	err = offcpu_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs\n");
		goto cleanup;
	}

	err = bpf_map__update_elem(obj->maps.args_map, &args_map_id, sizeof(args_map_id),
								&args, sizeof(struct user_args), BPF_ANY);

	env.stackmap_fd = bpf_map__fd(obj->maps.stackmap);
	env.ksyms = ksyms__load();
	if (!env.ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	env.syms_cache = syms_cache__new(0);
	if (!env.syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}
	err = offcpu_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);

	pb = perf_buffer__new(bpf_map__fd(obj->maps.perf_map), env.perf_buf_sz,
							handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "open perf buffer failed:%s\n", strerror(err));
		goto cleanup;
	}

	for (;;) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer:%s\n",strerror(err));
			goto clean_buffer;
		}
		if (env.is_existing)
			break;
	}

clean_buffer:
	perf_buffer__free(pb);
cleanup:
	offcpu_bpf__destroy(obj);
	syms_cache__free(env.syms_cache);
	ksyms__free(env.ksyms);
	return err != 0;
}
