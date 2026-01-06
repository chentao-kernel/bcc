/*
 * Create: Tue Jan 06 17:47:39 2026
 */
#ifndef __BCC_SYM_API_H
#define __BCC_SYM_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

void bcc_stack_table_new(int sym_cache_size);
int bcc_stack_look_sym(int fd, uint64_t *ips, uint32_t pid, char *buf, uint32_t buf_size);
int bcc_stack_delete_sym(uint64_t addr, uint32_t pid);
void bcc_stack_table_free();

#ifdef __cplusplus
}
#endif

