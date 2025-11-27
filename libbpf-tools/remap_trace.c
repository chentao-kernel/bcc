/*
 * Create: Thu Nov 27 10:56:57 2025
 */

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include "blk_types.h"
#include "remap_trace.h"
#include "remap_trace.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	__u64 min_lat_ms;
	char *disk;
	int duration;
	bool timestamp;
	bool queued;
	bool verbose;
	char *cgroupspath;
	bool cg;
        int stack_fd;
        struct ksyms *ksyms;
} env = {};

static int print_kernel_stack(int fd, int *stack_id)
{
        const struct ksym *ksym;
        const char *name;
        unsigned long start_addr;
        unsigned long offset;
        __u64 ip[PERF_MAX_STACK_DEPTH] = {};

        if (bpf_map_lookup_elem(fd, stack_id, ip) == 0) {
                for (int i = 0; i < PERF_MAX_STACK_DEPTH && ip[i]; i++) {
                        ksym = ksyms__map_addr(env.ksyms, ip[i]);
                        name = ksym ? ksym->name : "[Unknown]";
                        start_addr = ksym? ksym->addr : ip[i];
                        offset = ip[i] - start_addr;
                        fprintf(stderr, "[%llx] %s+0x%lx\n", ip[i], name, offset);
                }
        }

        return 0;
}

static volatile __u64 start_ts;

const char *argp_program_version = "remap_trace 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace block I/O.\n"
"\n"
"USAGE: remap_trace [--help] [-d DISK] [-c CG] [-Q]\n"
"\n"
"EXAMPLES:\n"
"    remap_trace              # trace all block I/O\n";

static const struct argp_option opts[] = {
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time", 0 },
	{ "disk",  'd', "DISK",  0, "Trace this disk only", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "cgroup", 'c', "/sys/fs/cgroup/unified/CG", 0, "Trace process in cgroup path", 0 },
	{ "min", 'm', "MIN", 0, "Min latency to trace, in ms", 0 },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
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
	case 'Q':
		env.queued = true;
		break;
	case 'c':
		env.cg = true;
		env.cgroupspath = arg;
		break;
	case 'm':
		errno = 0;
		env.min_lat_ms = strtoll(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid latency (in us): %s\n", arg);
			argp_usage(state);
		}
		break;
	case 't':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtoll(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "invalid delay (in us): %s\n", arg);
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

static void sig_int(int signo)
{
	exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event e;
	char ts[32];

        if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
        memcpy(&e, data, sizeof(e));
        str_timestamp("%H:%M:%S", ts, sizeof(ts));
        printf("comm:%s, cgroup: %s, file:%s, time:%s, ts:%llu\n",
                        e.comm, e.cgroup, e.file, ts, e.ts);
        printf("stack:\n");
        print_kernel_stack(env.stack_fd, &e.k_stack_id);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct remap_trace_bpf *obj;
	__u64 time_end = 0;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	obj = remap_trace_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	env.ksyms = ksyms__load();
	if (!env.ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	err = remap_trace_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = remap_trace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}
        env.stack_fd = bpf_map__fd(obj->maps.stackmap);

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* setup duration */
	if (env.duration)
		time_end = get_ktime_ns() + env.duration * NSEC_PER_SEC;

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
		if (env.duration && get_ktime_ns() > time_end)
			break;
	}

cleanup:
	perf_buffer__free(pb);
	remap_trace_bpf__destroy(obj);
	ksyms__free(env.ksyms);

	return err != 0;
}

