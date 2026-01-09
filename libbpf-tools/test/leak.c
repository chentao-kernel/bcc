/*
 * Create: Fri Jan 09 14:53:03 2026
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void helper_function() {
    // 故意只分配，不释放
    void *ptr = malloc(1024);
    printf("Allocated 1024 bytes at %p\n", ptr);
}

void outer_function() {
    helper_function();
}

int main() {
    printf("Starting memory leak demo (PID: %d)...\n", getpid());
    while (1) {
        outer_function();
        sleep(2); // 每2秒泄漏一次
    }
    return 0;
}
