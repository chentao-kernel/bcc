/*
 * Create: Tue Feb 03 17:43:48 2026
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main() {
	printf("Test: Allocating different sizes...\n");

	clock_t start, end;
    	start = clock();
	// benchmark
	for (int i = 0; i < 10000; i++) {
		void *p1 = malloc(60);
		void *p2 = malloc(1000);
		free(p1);
		free(p2);
	}
	end = clock();

	printf("benchmark, malloc/free 100000 time cost:%d ns\n", (int)(end - start));

	printf("Test: Intentional leak (256 bytes)...\n");
	malloc(256);

	for(int i = 0; i < 10; i++) {
		malloc(16);
		sleep(1);
	}

	printf("Test: Done. Exiting to trigger destructor report...\n");
	return 0;
}
