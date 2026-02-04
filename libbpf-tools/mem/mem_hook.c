/*
 * Create: Tue Feb 03 17:42:32 2026
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>
#include <stdbool.h>
#include "mem_hook.h"

#define BUF_SIZE 1024 * 1024 * 50
#define OUTPUT_DIR "/home/dylane/mem_stat"

static void *(*real_malloc)(size_t) = NULL;
static void  (*real_free)(void *) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static void *(*real_aligned_alloc)(size_t, size_t) = NULL;
static void *(*real_memalign)(size_t, size_t) = NULL;
static size_t (*real_malloc_usable_size)(void *) = NULL;
static int (*real_posix_memalign)(void **memptr, size_t alignment, size_t size) = NULL;
static void *(*real_valloc)(size_t size) = NULL;
static void *(*real_pvalloc)(size_t size) = NULL;
static void *(*real_reallocarray)(void *ptr, size_t nmemb, size_t size) = NULL;

static atomic_long size_distribution[BUCKETS];
static atomic_long size_total;
static atomic_long id_g;
static atomic_long active_allocations = 0;

static struct mem_stat_conf *stat_g = NULL;
static pthread_t sync_thread;

__attribute__((noinline)) trace_mem_alloc(int size)
{}

static int mem_log_write(void *buf, size_t len)
{
	if (!stat_g)
		return -1;

	if (stat_g->log_buf.used + len > stat_g->log_buf.total)
		return -1;

	memcpy(stat_g->log_buf.buf, buf, len);
	stat_g->log_buf.buf += len;
	stat_g->log_buf.used += len;

	return 0;
}

void mem_stat_dump(void)
{
	char buf[2048];
	char *ptr = buf;
	int ret = 0, len = 0;
	
	atomic_fetch_add(&id_g, 1);
	for (int i = 0; i < BUCKETS; i++) {
		ret = snprintf(ptr, 2048 - len, "[2^%2d]:", i);
		if (ret > 0) {
			ptr += ret;
			len += ret;
		} else {
			return;
		}
		ret = snprintf(ptr, 2048 - len, "%12ld %12ld %12ld\n", size_distribution[i], size_total, id_g);
		if (ret) {
			ptr += ret;
			len += ret;
		}
	}
	mem_log_write(buf, len);
}

static void *mem_log_init(size)
{
	int fd;
	char file[256];
	char time_fmt[64];
	struct tm *tm_info;
	void *ptr;
	int now;

	now = time(NULL);
	tm_info = localtime(&now);
	strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%d-%H:%M:%S", tm_info);

	if (mkdir(OUTPUT_DIR, 0755) == -1) {
		if (errno != EEXIST) {
			printf("mkdir failed:%d\n", errno);
			return NULL;
		}
	}
	snprintf(file, sizeof(file), "%s/%s-%s", OUTPUT_DIR, stat_g->comm, time_fmt);
	fd = open(file, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (fd == -1) {
		printf("open failed\n");
		return NULL;
	}
	ftruncate(fd, size);
	ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		printf("mmap failed\n");
		return NULL;
	}
	close(fd);

	return ptr;
}

static int get_bucket(size_t size)
{
	int bucket = 0;
	if (size == 0)
		return 0;

	size_t temp = size >> 1;
	while (temp > 0 && bucket < BUCKETS - 1) {
		temp >>= 1;
		bucket++;
	}
	return bucket;
}

void mem_stat(void *p, size_t size, bool mem_add)
{
	size_t len;
	int bucket;

	if (!p)
		return;
	len = size ? : malloc_usable_size(p);
	bucket = get_bucket(len);

	if (mem_add) {
		atomic_fetch_add(&size_distribution[bucket], 1);
		atomic_fetch_add(&size_total, len);
		atomic_fetch_add(&active_allocations, 1);
	} else {
		atomic_fetch_sub(&size_distribution[bucket], 1);
		atomic_fetch_sub(&size_total, len);
	}
}

static struct mem_stat_conf *create_conf_with_shm()
{
	key_t key = ftok(ID_DIR, PROJ_ID);
	if (key == -1)
		return NULL;

	int shmid = shmget(key, sizeof(struct mem_stat_conf), 0666 | IPC_CREAT);
	if (shmid == -1)
		return NULL;

	void *ptr = shmat(shmid, NULL, 0);
	if (ptr == (void *)-1)
		return NULL;

	return (struct mem_stat_conf *)ptr;
}

void mem_get_comm(char *comm, int size)
{
	FILE *f = fopen("/proc/self/comm", "r");
	if (f) {
		fgets(comm, size, f);
		fclose(f);
		comm[strcspn(comm, "\n")] = 0;
		printf("comm: %s\n", comm);
	}
}

static void *sync_worker(void *arg)
{
	while (stat_g && !stat_g->stop_thread) {
		sleep(1);
		for (int i = 0; i < BUCKETS; i++) {
			stat_g->size_distribution[i] = atomic_load(&size_distribution[i]);
		}
		stat_g->active_allocations = atomic_load(&active_allocations);
		mem_stat_dump();
	}
	return NULL;
}

static int mem_stat_init()
{
	stat_g = malloc(sizeof(struct mem_stat_conf));
	if (!stat_g)
		return -1;

	stat_g->stop_thread = 0;
	pthread_create(&sync_thread, NULL, sync_worker, NULL);
	mem_get_comm(stat_g->comm, sizeof(stat_g->comm));

	stat_g->log_buf.buf = mem_log_init(BUF_SIZE);
	stat_g->log_buf.used = 0;
	stat_g->log_buf.total = BUF_SIZE;

	return 0;
}

static void __attribute__((constructor)) init_hooks()
{
	int ret;

	ret = mem_stat_init();
	if (ret) {
		printf("mem stat init failed:%d\n", ret);
		return;
	}

	real_malloc = dlsym(RTLD_NEXT, "malloc");
	real_free = dlsym(RTLD_NEXT, "free");
}

void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *p = NULL;

	if (!real_reallocarray)
		real_reallocarray = (void *(*)(void *, size_t, size_t))dlsym(RTLD_NEXT, "reallocarray");
	p = (*real_reallocarray)(ptr, nmemb, size);
	if (p)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return p;
}

void *pvalloc(size_t size)
{
	void *ptr = NULL;

	if (!real_pvalloc)
		real_pvalloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "pvalloc");

	ptr = (*real_pvalloc)(size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

void *valloc(size_t size)
{
	void *ptr = NULL;
	if (!ptr)
		real_valloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "valloc");

	ptr = (*real_valloc)(size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

void *aligned_alloc(size_t alignment, size_t size)
{
	void *ptr = NULL;

	if (!real_aligned_alloc)
		real_aligned_alloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "aligned_alloc");

	ptr = (*real_aligned_alloc)(alignment, size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;
	if (!real_posix_memalign)
		real_posix_memalign = (int (*)(void**, size_t, size_t))dlsym(RTLD_NEXT, "posix_memalign");
	ret = (*real_posix_memalign)(memptr, alignment, size);
	if (*memptr)
		mem_stat(*memptr, 0, true);

	trace_mem_alloc(size);
	return ret;
}

void *memalign(size_t alignment, size_t size)
{
	void *ptr = NULL;

	if (!real_memalign)
		real_memalign = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "memalign");

	ptr = (*real_memalign)(alignment, size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

void *calloc(size_t nr, size_t size)
{
	void *ptr = NULL;

	if (!real_calloc)
		real_calloc = dlsym(RTLD_NEXT, "calloc");
	ptr = (*real_calloc)(nr, size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

void *malloc(size_t size)
{
	if (!real_malloc)
		real_malloc = dlsym(RTLD_NEXT, "malloc");
	void *ptr =(*real_malloc)(size);
	if (ptr)
		mem_stat(ptr, 0, true);

	trace_mem_alloc(size);
	return ptr;
}

void free(void *ptr)
{
	if (!real_free)
		real_free = dlsym(RTLD_NEXT, "free");

	if (ptr)
		mem_stat(ptr, 0, false);

	real_free(ptr);
}

static void __attribute__((destructor)) report()
{
	if (stat_g) {
		stat_g->stop_thread = 1;
		pthread_join(sync_thread, NULL);
		//shmdt(stat_g);
	}
}
