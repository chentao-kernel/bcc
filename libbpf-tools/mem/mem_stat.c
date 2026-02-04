/*
 * Create: Tue Feb 03 19:17:47 2026
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include "mem_hook.h"

static struct mem_stat_conf *attach_conf(void) {
	key_t key = ftok(ID_DIR, PROJ_ID);
	if (key == -1)
		return NULL;

	int shmid = shmget(key, sizeof(struct mem_stat_conf), 0666);
	if (shmid == -1)
		return NULL;

	void *ptr = shmat(shmid, NULL, 0);
	if (ptr == (void*)-1)
		return NULL;

	return (struct mem_stat_conf*)ptr;
}

int main(void) {
	struct mem_stat_conf *conf = attach_conf();
	if (!conf) { 
		perror("attach_conf");
		return 1;
	}

	while (1) {
		long active = conf->active_allocations;

		long dist[BUCKETS];
		for (int i = 0; i < BUCKETS; i++)
			dist[i] = conf->size_distribution[i];

		printf("active=%ld  bucket0=%ld bucket1=%ld ...\n",
					active, dist[0], dist[1]);
		sleep(1);
	}

	shmdt(conf);
	return 0;
}
