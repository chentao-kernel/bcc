#include "table.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "linux/bpf.h"
#include "bcc_sym_api.h"

/*
 * stack table api for c
 */
using namespace ebpf;

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif

#define ERRBUFSZ 1024

BPFStackTable *stack_table_g = nullptr;

void bcc_stack_table_new(int sym_cache_size)
{
    TableDesc tdesc("stack_map", FileDesc(-1), BPF_MAP_TYPE_STACK_TRACE,
                        sizeof(uint32_t), sizeof(uint32_t), 1, 0);

    stack_table_g = new BPFStackTable(tdesc, true, true, sym_cache_size);
}

void bcc_stack_table_free()
{
    if (stack_table_g != nullptr) {
        /* bcc_free_symcache used when stack table destroy */
        delete stack_table_g;
    }
}

int bcc_stack_look_sym(int fd, uint64_t *ips, uint32_t pid, char *buf,
                                uint32_t buf_size)
{
    std::vector<std::string> stacks;
    const char sym_fmt[] = "%s+0x%lx;";
    uint32_t id = 0;
    int ret;

    if (stack_table_g == nullptr)
        return 0;
;
    stacks = stack_table_g->get_stack_symbol(ips, pid);

    for (auto stack : stacks) {
        ret = snprintf(buf + id, buf_size - id, sym_fmt, stack.c_str(), stack.size());

        if (ret + id + 1 > buf_size || ret < 0) {
            ret = ret < 0 ? ret : ERRBUFSZ;
            buf[id] = '\0';
            return ret;
        }
        id += ret;
    }
    return 0;
}

/*
 * Todo: delete support later.
 */
int bcc_stack_delete_sym(uint64_t addr, uint32_t pid)
{
    return 0;
}
