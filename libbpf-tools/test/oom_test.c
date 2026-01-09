/*
 * Create: Thu Nov 27 16:38:43 2025
 */
// oom_test.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MB (1024 * 1024)

int main() {
    int count = 0;
    char *ptr = NULL;
    
    printf("开始分配内存...\n");
    
    sleep(10);
    while (1) {
        ptr = malloc(10 * MB);
        if (ptr == NULL) {
            printf("内存分配失败！已分配: %d MB\n", count * 100);
            break;
        }
        
        memset(ptr, 0, 10 * MB);
        
        count++;
        printf("已分配: %d MB\n", count * 10);
        sleep(1);
    }
    
    printf("程序结束\n");
    return 0;
}
