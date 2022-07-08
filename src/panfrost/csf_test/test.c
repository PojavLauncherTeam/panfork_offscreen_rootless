/*
 * Copyright (C) 2022 Icecream95
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util/macros.h"
#include "git_sha1.h"

#include "mali_kbase_csf_ioctl.h"
#include "mali_kbase_ioctl.h"
#include "mali_base_kernel.h"
#include "mali_base_csf_kernel.h"
#include "mali_gpu_csf_registers.h"

#define PAN_ARCH 10
#include "genxml/gen_macros.h"

#include "wrap.h"

#include "pan_shader.h"
#include "compiler/nir/nir_builder.h"
#include "bifrost/valhall/disassemble.h"

static void
dump_start(FILE *f)
{
        fprintf(f, "\x1b[90m");
}

static void
dump_end(FILE *f)
{
        fprintf(f, "\x1b[39m");
}

static void
cache_clean(volatile void *addr)
{
        __asm__ volatile ("dc cvac, %0" :: "r" (addr) : "memory");
}

static void
cache_invalidate(volatile void *addr)
{
        __asm__ volatile ("dc civac, %0" :: "r" (addr) : "memory");
}

static void
cache_barrier(void)
{
        __asm__ volatile ("dsb sy" ::: "memory");
}

typedef void (*cacheline_op)(volatile void *addr);

#define CACHELINE_SIZE 64

static void
cacheline_op_range(volatile void *start, unsigned length, cacheline_op op)
{
        volatile void *ptr = (volatile void *)((uintptr_t) start & ~((uintptr_t) CACHELINE_SIZE - 1));
        volatile void *end = (volatile void *) ALIGN_POT((uintptr_t) start + length, CACHELINE_SIZE);
        for (; ptr < end; ptr += CACHELINE_SIZE)
                op(ptr);
}

static void
cache_clean_range(volatile void *start, unsigned length)
{
        cacheline_op_range(start, length, cache_clean);
}

static void
cache_invalidate_range(volatile void *start, unsigned length)
{
        cacheline_op_range(start, length, cache_invalidate);
}

struct state;
struct test;

typedef bool (* section)(struct state *s, struct test *t);

#define CS_QUEUE_COUNT 4 /* compute / vertex / fragment / other */
#define CS_QUEUE_SIZE 65536

struct state {
        int page_size;

        int mali_fd;
        int tl_fd;
        void *tracking_region;
        void *csf_user_reg;

        uint8_t *gpuprops;
        unsigned gpuprops_size;
        uint32_t gpu_id;

        struct {
                struct panfrost_ptr normal, exec, coherent, cached;
        } allocations;

        uint64_t tiler_heap_va;
        uint64_t tiler_heap_header;

        uint8_t csg_handle;
        uint32_t csg_uid;

        struct panfrost_ptr cs_mem[CS_QUEUE_COUNT];
        void *cs_user_io[CS_QUEUE_COUNT];
        unsigned cs_last_submit[CS_QUEUE_COUNT];
        struct pan_command_stream cs[CS_QUEUE_COUNT];

        unsigned shader_alloc_offset;
        mali_ptr compute_shader;
};

struct test {
        section part;
        section cleanup;
        const char *label;

        struct test *subtests;
        unsigned sub_length;

        /* for allocation tests */
        unsigned offset;
        unsigned flags;

        /* for cs_store */
        bool add;
};

/* See STATE and ALLOC macros below */
#define DEREF_STATE(s, offset) ((void*) s + offset)

static uint64_t
pan_get_gpuprop(struct state *s, int name)
{
        int i = 0;
        uint64_t x = 0;
        while (i < s->gpuprops_size) {
                x = 0;
                memcpy(&x, s->gpuprops + i, 4);
                i += 4;

                int size = 1 << (x & 3);
                int this_name = x >> 2;

                x = 0;
                memcpy(&x, s->gpuprops + i, size);
                i += size;

                if (this_name == name)
                        return x;
        }

        fprintf(stderr, "Unknown prop %i\n", name);
        return 0;
}

static bool
open_kbase(struct state *s, struct test *t)
{
        s->mali_fd = open("/dev/mali0", O_RDWR);
        if (s->mali_fd != -1)
                return true;

        perror("open(\"/dev/mali0\")");
        return false;
}

static bool
close_kbase(struct state *s, struct test *t)
{
        int pid = getpid();
        char cmd_buffer[64] = {0};
        sprintf(cmd_buffer, "grep /dev/mali /proc/%i/maps", pid);
        system(cmd_buffer);
        sprintf(cmd_buffer, "ls -l /proc/%i/fd", pid);
        system(cmd_buffer);

        if (s->mali_fd > 0)
                return close(s->mali_fd) == 0;
        return true;
}

static bool
get_version(struct state *s, struct test *t)
{
        struct kbase_ioctl_version_check ver = { 0 };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_VERSION_CHECK, &ver);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_VERSION_CHECK)");
                return false;
        }

        printf("Major %i Minor %i: ", ver.major, ver.minor);
        return true;
}

static bool
set_flags(struct state *s, struct test *t)
{
        struct kbase_ioctl_set_flags flags = {
                .create_flags = 0
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_SET_FLAGS, &flags);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_SET_FLAGS)");
                return false;
        }
        return true;
}

static bool
mmap_tracking(struct state *s, struct test *t)
{
        s->tracking_region = mmap(NULL, s->page_size, PROT_NONE,
                                  MAP_SHARED, s->mali_fd,
                                  BASE_MEM_MAP_TRACKING_HANDLE);

        if (s->tracking_region == MAP_FAILED) {
                perror("mmap(BASE_MEM_MAP_TRACKING_HANDLE)");
                s->tracking_region = NULL;
                return false;
        }
        return true;
}

static bool
munmap_tracking(struct state *s, struct test *t)
{
        if (s->tracking_region)
                return munmap(s->tracking_region, s->page_size) == 0;
        return true;
}

static bool
get_gpuprops(struct state *s, struct test *t)
{
        struct kbase_ioctl_get_gpuprops props = { 0 };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(0))");
                return false;
        } else if (!ret) {
                fprintf(stderr, "GET_GPUPROPS returned zero size\n");
                return false;
        }

        s->gpuprops_size = ret;
        s->gpuprops = calloc(s->gpuprops_size, 1);

        props.size = s->gpuprops_size;
        props.buffer = (uint64_t)(uintptr_t) s->gpuprops;

        ret = ioctl(s->mali_fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(size))");
                return false;
        }

        return true;
}

static bool
free_gpuprops(struct state *s, struct test *t)
{
        free(s->gpuprops);
        return true;
}

static bool
get_gpu_id(struct state *s, struct test *t)
{
        uint64_t gpu_id = pan_get_gpuprop(s, KBASE_GPUPROP_PRODUCT_ID);
        if (!gpu_id)
                return false;
        s->gpu_id = gpu_id;

        uint16_t maj = gpu_id >> 12;
        uint16_t min = (gpu_id >> 8) & 0xf;
        uint16_t rev = (gpu_id >> 4) & 0xf;

        uint16_t product = gpu_id & 0xf;
        uint16_t prod = product | ((maj & 1) << 4);

        const char *names[] = {
                [1] = "TDUX",
                [2] = "G710",
                [3] = "G510",
                [4] = "G310",
                [7] = "G610",
                [16 + 2] = "G715", /* TODO: Immortalis instead of Mali? */
                [16 + 3] = "G615",
        };
        const char *name = (prod < ARRAY_SIZE(names)) ? names[prod] : NULL;
        if (!name)
                name = "unknown";

        printf("v%i.%i.%i Mali-%s (%i): ", maj, min, rev, name, product);

        if (maj < 10) {
                printf("not v10 or later: ");
                return false;
        }

        return true;
}

static bool
get_coherency_mode(struct state *s, struct test *t)
{
        uint64_t mode = pan_get_gpuprop(s, KBASE_GPUPROP_RAW_COHERENCY_MODE);

        const char *modes[] = {
                [0] = "ACE-Lite",
                [1] = "ACE",
                [31] = "None",
        };
        const char *name = (mode < ARRAY_SIZE(modes)) ? modes[mode] : NULL;
        if (!name)
                name = "Unknown";

        printf("0x%"PRIx64" (%s): ", mode, name);
        return true;
}

static bool
get_csf_caps(struct state *s, struct test *t)
{
        union kbase_ioctl_cs_get_glb_iface iface = { 0 };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_GET_GLB_IFACE, &iface);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_GET_GLB_IFACE(0))");
                return false;
        }

        printf("v%i: feature mask 0x%x, %i groups, %i total: ",
               iface.out.glb_version, iface.out.features,
               iface.out.group_num, iface.out.total_stream_num);

        unsigned group_num = iface.out.group_num;
        unsigned stream_num = iface.out.total_stream_num;

        struct basep_cs_group_control *group_data =
                calloc(group_num, sizeof(*group_data));

        struct basep_cs_stream_control *stream_data =
                calloc(stream_num, sizeof(*stream_data));

        iface = (union kbase_ioctl_cs_get_glb_iface) {
                .in = {
                        .max_group_num = group_num,
                        .max_total_stream_num = stream_num,
                        .groups_ptr = (uintptr_t) group_data,
                        .streams_ptr = (uintptr_t) stream_data,
                }
        };

        ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_GET_GLB_IFACE, &iface);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_GET_GLB_IFACE(size))");

                free(group_data);
                free(stream_data);

                return false;
        }

        for (unsigned i = 0; i < group_num; ++i) {
                if (i && !memcmp(group_data + i, group_data + i - 1, sizeof(*group_data)))
                        continue;

                fprintf(stderr, "Group %i-: feature mask 0x%x, %i streams\n",
                        i, group_data[i].features, group_data[i].stream_num);
        }

        for (unsigned i = 0; i < stream_num; ++i) {
                if (i && !memcmp(stream_data + i, stream_data + i - 1, sizeof(*stream_data)))
                        continue;

                fprintf(stderr, "Stream %i-: feature mask 0x%x\n",
                        i, stream_data[i].features);
        }

        free(group_data);
        free(stream_data);

        return true;
}

static bool
mmap_user_reg(struct state *s, struct test *t)
{
        s->csf_user_reg = mmap(NULL, s->page_size, PROT_READ,
                               MAP_SHARED, s->mali_fd,
                               BASEP_MEM_CSF_USER_REG_PAGE_HANDLE);

        if (s->csf_user_reg == MAP_FAILED) {
                perror("mmap(BASEP_MEM_CSF_USER_REG_PAGE_HANDLE)");
                s->csf_user_reg = NULL;
                return false;
        }
        return true;
}

static bool
munmap_user_reg(struct state *s, struct test *t)
{
        if (s->csf_user_reg)
                return munmap(s->csf_user_reg, s->page_size) == 0;
        return true;
}

static bool
init_mem_exec(struct state *s, struct test *t)
{
        struct kbase_ioctl_mem_exec_init init = {
                .va_pages = 0x100000,
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_MEM_EXEC_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_EXEC_INIT)");
                return false;
        }
        return true;
}

static bool
init_mem_jit(struct state *s, struct test *t)
{
        struct kbase_ioctl_mem_jit_init init = {
                .va_pages = 1 << 25,
                .max_allocations = 255,
                .phys_pages = 1 << 25,
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_MEM_JIT_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_JIT_INIT)");
                return false;
        }
        return true;
}

static bool
stream_create(struct state *s, struct test *t)
{
        struct kbase_ioctl_stream_create stream = {
                .name = "stream"
        };

        s->tl_fd = ioctl(s->mali_fd, KBASE_IOCTL_STREAM_CREATE, &stream);

        if (s->tl_fd == -1) {
                perror("ioctl(KBASE_IOCTL_STREAM_CREATE)");
                return false;
        }
        return true;

}

static bool
stream_destroy(struct state *s, struct test *t)
{
        if (s->tl_fd > 0)
                return close(s->tl_fd) == 0;
        return true;
}

static bool
tiler_heap_create(struct state *s, struct test *t)
{
        union kbase_ioctl_cs_tiler_heap_init init = {
                .in = {
                        .chunk_size = 1 << 21,
                        .initial_chunks = 5,
                        .max_chunks = 200,
                        .target_in_flight = 65535,
                }
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_TILER_HEAP_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_INIT)");
                return false;
        }

        s->tiler_heap_va = init.out.gpu_heap_va;
        s->tiler_heap_header = init.out.first_chunk_va;

        return true;
}

static bool
tiler_heap_term(struct state *s, struct test *t)
{
        if (!s->tiler_heap_va)
                return true;

        struct kbase_ioctl_cs_tiler_heap_term term = {
                .gpu_heap_va = s->tiler_heap_va
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_TILER_HEAP_TERM, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_TERM)");
                return false;
        }
        return true;
}

static bool
cs_group_create(struct state *s, struct test *t)
{
        union kbase_ioctl_cs_queue_group_create_1_6 create = {
                .in = {
                        /* Mali *still* only supports a single tiler unit */
                        .tiler_mask = 1,
                        .fragment_mask = ~0ULL,
                        .compute_mask = ~0ULL,

                        .cs_min = CS_QUEUE_COUNT,

                        .priority = 1,
                        .tiler_max = 1,
                        .fragment_max = 64,
                        .compute_max = 64,
                }
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6, &create);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6)");
                return false;
        }

        s->csg_handle = create.out.group_handle;
        s->csg_uid = create.out.group_uid;

        printf("CSG handle: %i UID: %i: ", s->csg_handle, s->csg_uid);

        /* Should be at least 1 */
        if (!s->csg_uid)
                abort();

        return true;
}

static bool
cs_group_term(struct state *s, struct test *t)
{
        if (!s->csg_uid)
                return true;

        struct kbase_ioctl_cs_queue_group_term term = {
                .group_handle = s->csg_handle
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE)");
                return false;
        }
        return true;
}

static bool
decode_init(struct state *s, struct test *t)
{
        pandecode_initialize(true);
        return true;
}

static bool
decode_close(struct state *s, struct test *t)
{
        pandecode_close();
        return true;
}

static struct panfrost_ptr
alloc_ioctl(struct state *s, union kbase_ioctl_mem_alloc *a)
{
        struct panfrost_ptr p = {0};

        uint64_t va_pages = a->in.va_pages;
        uint64_t flags = a->in.flags;

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_MEM_ALLOC, a);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_ALLOC)");
                return p;
        }

        if ((flags & BASE_MEM_SAME_VA) &&
            (!(a->out.flags & BASE_MEM_SAME_VA) ||
                a->out.gpu_va != 0x41000)) {

                fprintf(stderr, "Flags: 0x%"PRIx64", VA: 0x%"PRIx64"\n",
                        (uint64_t) a->out.flags, (uint64_t) a->out.gpu_va);
                return p;
        }

        void *ptr = mmap(NULL, s->page_size * va_pages,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         s->mali_fd, a->out.gpu_va);

        if (ptr == MAP_FAILED) {
                perror("mmap(GPU BO)");
                return p;
        }

        uint64_t gpu_va = (a->out.flags & BASE_MEM_SAME_VA) ?
                (uint64_t) ptr : a->out.gpu_va;

        pandecode_inject_mmap(gpu_va, ptr, s->page_size * va_pages, NULL);

        p.cpu = ptr;
        p.gpu = gpu_va;

        return p;
}

static struct panfrost_ptr
alloc_mem(struct state *s, uint64_t size, uint64_t flags)
{
        unsigned pages = size / s->page_size;

        union kbase_ioctl_mem_alloc a = {
                .in = {
                        .va_pages = pages,
                        .commit_pages = pages,
                        .extension = 0,
                        .flags = flags,
                }
        };

        return alloc_ioctl(s, &a);
}

static bool
alloc(struct state *s, struct test *t)
{
        struct panfrost_ptr *ptr = DEREF_STATE(s, t->offset);

        *ptr = alloc_mem(s, s->page_size, t->flags);

        volatile int *p = (volatile int *) ptr->cpu;
        *p = 0x12345;
        if (*p != 0x12345) {
                printf("Error reading from allocated memory at %p\n", p);
                return false;
        }
        *p = 0;
        cache_clean(p);

        return true;
}

static bool
dealloc(struct state *s, struct test *t)
{
        struct panfrost_ptr *ptr = DEREF_STATE(s, t->offset);

        if (ptr->cpu)
                return munmap(ptr->cpu, s->page_size) == 0;
        return true;
}

static bool
cs_queue_create(struct state *s, struct test *t)
{
        for (unsigned i = 0; i < CS_QUEUE_COUNT; ++i) {

                /* Read/write from CPU/GPU, nothing special
                 * like coherency */
                s->cs_mem[i] = alloc_mem(s, CS_QUEUE_SIZE, 0x200f);
                s->cs[i].ptr = s->cs_mem[i].cpu;

                if (!s->cs_mem[i].cpu)
                        return false;
        }

        return true;
}

static bool
cs_queue_free(struct state *s, struct test *t)
{
        bool pass = true;
        for (unsigned i = 0; i < CS_QUEUE_COUNT; ++i) {
                if (s->cs_mem[i].cpu && munmap(s->cs_mem[i].cpu, CS_QUEUE_SIZE))
                        pass = false;
        }
        return pass;
}

static bool
cs_queue_register(struct state *s, struct test *t)
{
        for (unsigned i = 0; i < CS_QUEUE_COUNT; ++i) {
                struct kbase_ioctl_cs_queue_register reg = {
                        .buffer_gpu_addr = s->cs_mem[i].gpu,
                        .buffer_size = CS_QUEUE_SIZE,
                        .priority = 1,
                };

                int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_REGISTER, &reg);

                if (ret == -1) {
                        perror("ioctl(KBASE_IOCTL_CS_QUEUE_REGISTER)");
                        return false;
                }

                union kbase_ioctl_cs_queue_bind bind = {
                        .in = {
                                .buffer_gpu_addr = s->cs_mem[i].gpu,
                                .group_handle = s->csg_handle,
                                .csi_index = i,
                        }
                };

                ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_BIND, &bind);

                if (ret == -1) {
                        perror("ioctl(KBASE_IOCTL_CS_QUEUE_BIND)");
                }

                s->cs_user_io[i] =
                        mmap(NULL,
                             s->page_size * BASEP_QUEUE_NR_MMAP_USER_PAGES,
                             PROT_READ | PROT_WRITE, MAP_SHARED,
                             s->mali_fd, bind.out.mmap_handle);

                if (s->cs_user_io[i] == MAP_FAILED) {
                        perror("mmap(CS USER IO)");
                        s->cs_user_io[i] = NULL;
                        return false;
                }
        }
        return true;
}

static bool
cs_queue_term(struct state *s, struct test *t)
{
        bool pass = true;

        for (unsigned i = 0; i < CS_QUEUE_COUNT; ++i) {
                if (s->cs_user_io[i] &&
                    munmap(s->cs_user_io[i],
                           s->page_size * BASEP_QUEUE_NR_MMAP_USER_PAGES))
                        pass = false;

                struct kbase_ioctl_cs_queue_terminate term = {
                        .buffer_gpu_addr = s->cs_mem[i].gpu,
                };

                int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_TERMINATE,
                                &term);

                if (ret == -1)
                        pass = false;
        }
        return pass;
}

#define CS_RING_DOORBELL(s, i) \
        *((uint32_t *)(s->cs_user_io[i])) = 1

#define CS_READ_REGISTER(s, i, r) \
        *((uint64_t *)(s->cs_user_io[i] + s->page_size * 2 + r))

#define CS_WRITE_REGISTER(s, i, r, v) \
        *((uint64_t *)(s->cs_user_io[i] + s->page_size + r)) = v

static void
submit_cs(struct state *s, unsigned i)
{
        uintptr_t p = (uintptr_t) s->cs[i].ptr;
        unsigned pad = (-p) & 63;
        memset(s->cs[i].ptr, 0, pad);

        unsigned last_offset = s->cs_last_submit[i];

        unsigned insert_offset = p + pad - (uintptr_t) s->cs_mem[i].cpu;
        insert_offset %= CS_QUEUE_SIZE;

        for (unsigned o = last_offset; o != insert_offset;
             o = (o + 64) % CS_QUEUE_SIZE)
                cache_clean(s->cs_mem[i].cpu + o);

        // TODO: Handle wraparound
        // TODO: Provide a persistent buffer for pandecode to use?
        dump_start(stderr);
        pandecode_cs(s->cs_mem[i].gpu + last_offset,
                     insert_offset - last_offset, s->gpu_id);
        dump_end(stderr);

        cache_barrier();

        CS_WRITE_REGISTER(s, i, CS_INSERT, insert_offset);
        s->cs[i].ptr = s->cs_mem[i].cpu + insert_offset;

        CS_RING_DOORBELL(s, i);

        s->cs_last_submit[i] = insert_offset;
}

/* Returns true if there was a timeout */
static bool
wait_event(struct state *s, unsigned timeout_ms)
{
        struct pollfd fd = {
                .fd = s->mali_fd,
                .events = POLLIN,
        };

        int ret = poll(&fd, 1, timeout_ms);

        if (ret == -1) {
                perror("poll(mali_fd)");
                return true;
        }

        /* Timeout */
        if (ret == 0)
                return true;

        struct base_csf_notification event;
        ret = read(s->mali_fd, &event, sizeof(event));

        if (ret == -1) {
                perror("read(mali_fd)");
                return true;
        }

        if (ret != sizeof(event)) {
                fprintf(stderr, "read(mali_fd) returned %i, expected %i!\n",
                        ret, (int) sizeof(event));
                return false;
        }

        switch (event.type) {
        case BASE_CSF_NOTIFICATION_EVENT:
                /* Not interesting */
                return false;

        case BASE_CSF_NOTIFICATION_GPU_QUEUE_GROUP_ERROR:
                break;

        case BASE_CSF_NOTIFICATION_CPU_QUEUE_DUMP:
                fprintf(stderr, "No event from mali_fd!\n");
                return false;

        default:
                fprintf(stderr, "Unknown event type!\n");
                return false;
        }

        struct base_gpu_queue_group_error e = event.payload.csg_error.error;

        switch (e.error_type) {
        case BASE_GPU_QUEUE_GROUP_ERROR_FATAL: {
                // See CS_FATAL_EXCEPTION_* in mali_gpu_csf_registers.h
                fprintf(stderr, "Queue group error: status 0x%x "
                        "sideband 0x%"PRIx64"\n",
                        e.payload.fatal_group.status,
                        (uint64_t) e.payload.fatal_group.sideband);
                break;
        }
        case BASE_GPU_QUEUE_GROUP_QUEUE_ERROR_FATAL: {
                // See CS_FATAL_EXCEPTION_* in mali_gpu_csf_registers.h
                fprintf(stderr, "Queue %i error: status 0x%x "
                        "sideband 0x%"PRIx64"\n",
                        e.payload.fatal_queue.csi_index,
                        e.payload.fatal_queue.status,
                        (uint64_t) e.payload.fatal_queue.sideband);
                break;
        }

        case BASE_GPU_QUEUE_GROUP_ERROR_TIMEOUT:
                fprintf(stderr, "Command stream timeout!\n");
                break;
        case BASE_GPU_QUEUE_GROUP_ERROR_TILER_HEAP_OOM:
                fprintf(stderr, "Command stream OOM!\n");
                break;
        default:
                fprintf(stderr, "Unknown error type!\n");
        }

        return false;
}

static bool
wait_cs(struct state *s, unsigned i)
{
        unsigned extract_offset = (void *) s->cs[i].ptr - s->cs_mem[i].cpu;

        unsigned timeout_ms = 100;

        while (CS_READ_REGISTER(s, i, CS_EXTRACT) != extract_offset) {
                if (wait_event(s, timeout_ms)) {
                        fprintf(stderr, "Event wait timeout!\n");

                        unsigned e = CS_READ_REGISTER(s, i, CS_EXTRACT);
                        if (e != extract_offset) {
                                fprintf(stderr, "CS_EXTRACT (%i) != %i\n",
                                        e, extract_offset);
                                return false;
                        }
                }
        }

        cache_barrier();

        return true;
}

static bool
cs_init(struct state *s, struct test *t)
{
        for (unsigned i = 0; i < CS_QUEUE_COUNT; ++i) {
                CS_WRITE_REGISTER(s, i, CS_INSERT, 0);
                pan_pack_ins(s->cs + i, CS_SET_ITERATOR, cfg) {
                        switch (i) {
                        case 0: cfg.iterator = MALI_CS_ITERATOR_COMPUTE; break;
                        case 1: cfg.iterator = MALI_CS_ITERATOR_UNK; break;
                        case 2: cfg.iterator = MALI_CS_ITERATOR_VERTEX; break;
                        case 3: cfg.iterator = MALI_CS_ITERATOR_FRAGMENT; break;
                        }
                }
                pan_pack_ins(s->cs + i, CS_SELECT_BUFFER, cfg) {
                        cfg.index = 2;
                }
                submit_cs(s, i);

                struct kbase_ioctl_cs_queue_kick kick = {
                        .buffer_gpu_addr = s->cs_mem[i].gpu
                };

                int ret = ioctl(s->mali_fd, KBASE_IOCTL_CS_QUEUE_KICK, &kick);

                if (ret == -1) {
                        perror("ioctl(KBASE_IOCTL_CS_QUEUE_KICK)");
                        return false;
                }
        }

        return true;
}

static bool
cs_simple(struct state *s, struct test *t)
{
        pan_command_stream *c = s->cs;

        pan_emit_cs_32(c, 0x48, 0x1234);
        submit_cs(s, 0);
        return wait_cs(s, 0);
}

static bool
cs_store(struct state *s, struct test *t)
{
        pan_command_stream *c = s->cs;

        uint32_t *dest = s->allocations.cached.cpu + 240;
        mali_ptr dest_va = s->allocations.cached.gpu + 240;
        uint32_t value = 1234;
        uint32_t add = 4320000;

        *dest = 0;
        cache_clean(dest);

        unsigned addr_reg = 0x48;
        unsigned value_reg = 0x4a;

        pan_pack_ins(c, CS_STATE, cfg) { cfg.state = 2; }
        pan_emit_cs_48(c, addr_reg, dest_va);
        pan_emit_cs_32(c, value_reg, value);

        if (t->add) {
                pan_pack_ins(c, CS_ADD_IMM, cfg) {
                        cfg.value = add;
                        cfg.src = value_reg;
                        cfg.dest = value_reg;
                }
                value += add;
        }

        pan_pack_ins(c, CS_STR_32, cfg) {
                cfg.addr = addr_reg;
                cfg.value = value_reg;
        }

        submit_cs(s, 0);
        wait_cs(s, 0);

        cache_invalidate(dest);
        uint32_t result = *dest;

        if (result != value) {
                printf("Got %i, expected %i: ", result, value);
                return false;
        }

        return true;
}

static void
emit_cs_call(pan_command_stream *c, mali_ptr va, void *start, void *end)
{
        cache_clean_range(start, end - start);

        pan_emit_cs_48(c, 0x48, va);
        pan_emit_cs_32(c, 0x4a, end - start);
        pan_pack_ins(c, CS_CALL, cfg) {
                cfg.address = 0x48;
                cfg.length = 0x4a;
        }
}

static bool
cs_sub(struct state *s, struct test *t)
{
        pan_command_stream *c = s->cs;
        pan_command_stream _i = { .ptr = s->allocations.cached.cpu }, *i = &_i;
        mali_ptr cs_va = s->allocations.cached.gpu;

        uint32_t *dest = s->allocations.normal.cpu;
        mali_ptr dest_va = s->allocations.normal.gpu;
        uint32_t value = 4321;

        *dest = 0;
        cache_clean(dest);

        unsigned addr_reg = 0x48;
        unsigned value_reg = 0x4a;

        void *start = i->ptr;

        pan_pack_ins(i, CS_SELECT_BUFFER, cfg) { cfg.index = 3; }
        pan_pack_ins(i, CS_STATE, cfg) { cfg.state = 8; }

        pan_emit_cs_48(i, addr_reg, dest_va);
        pan_emit_cs_32(i, value_reg, value);
        pan_pack_ins(i, CS_STR_32, cfg) {
                cfg.addr = addr_reg;
                cfg.value = value_reg;
        }

        emit_cs_call(c, cs_va, start, i->ptr);

        submit_cs(s, 0);
        wait_cs(s, 0);

        cache_invalidate(dest);
        uint32_t result = *dest;

        if (result != value) {
                printf("Got %i, expected %i: ", result, value);
                return false;
        }

        return true;
}

static mali_ptr
upload_shader(struct state *s, struct util_dynarray binary)
{
        assert(s->shader_alloc_offset + binary.size < s->page_size);

        mali_ptr va = s->allocations.exec.gpu + s->shader_alloc_offset;

        memcpy(s->allocations.exec.cpu, binary.data, binary.size);

        /* Shouldn't be needed, but just in case... */
        cache_clean_range(s->allocations.exec.cpu, binary.size);

        s->shader_alloc_offset += binary.size;

        return va;
}

static bool
compute_compile(struct state *s, struct test *t)
{
        nir_builder _b =
                nir_builder_init_simple_shader(MESA_SHADER_COMPUTE,
                                               GENX(pan_shader_get_compiler_options)(),
                                               "mem_store"), *b = &_b;

        nir_ssa_def *ptr =
                nir_load_push_constant(b, 1, 64, nir_imm_int(b, 0));

        nir_ssa_def *value = nir_imm_int(b, 123);

        nir_store_global(b, ptr, 8, value, 1);

        struct panfrost_compile_inputs inputs = {
                .gpu_id = s->gpu_id,
                .no_ubo_to_push = true,
        };

        struct util_dynarray binary = {0};
        struct pan_shader_info shader_info = {0};

        GENX(pan_shader_compile)(b->shader, &inputs, &binary, &shader_info);

        dump_start(stderr);
        disassemble_valhall(stderr, binary.data, binary.size, true);
        dump_end(stderr);

        s->compute_shader = upload_shader(s, binary);

        util_dynarray_fini(&binary);
        ralloc_free(b->shader);

        return true;
}

static struct panfrost_ptr
mem_offset(struct panfrost_ptr ptr, unsigned offset)
{
        ptr.cpu += offset;
        ptr.gpu += offset;
        return ptr;
}

static bool
compute_execute(struct state *s, struct test *t)
{
        pan_command_stream *c = s->cs;
        pan_command_stream _i = { .ptr = s->allocations.cached.cpu }, *i = &_i;
        mali_ptr cs_va = s->allocations.cached.gpu;

        struct panfrost_ptr dest = s->allocations.normal;
        uint32_t value = 123;

        *(uint32_t *) dest.cpu = 0;
        cache_clean(dest.cpu);

        struct panfrost_ptr fau = mem_offset(dest, 64);
        *(uint64_t *) fau.cpu = dest.gpu;
        cache_clean(fau.cpu);

        struct panfrost_ptr local_storage = mem_offset(dest, 128);
        pan_pack(local_storage.cpu, LOCAL_STORAGE, _);
        cache_clean(local_storage.cpu);

        struct panfrost_ptr shader_program = mem_offset(dest, 192);
        pan_pack(shader_program.cpu, SHADER_PROGRAM, cfg) {
                cfg.stage = MALI_SHADER_STAGE_COMPUTE;
                cfg.primary_shader = true;
                cfg.register_allocation =
                        MALI_SHADER_REGISTER_ALLOCATION_32_PER_THREAD;
                cfg.binary = s->compute_shader;
        }
        cache_clean(shader_program.cpu);

        void *start = i->ptr;

        pan_pack_ins(i, CS_SELECT_BUFFER, cfg) { cfg.index = 3; }
        pan_pack_ins(i, CS_STATE, cfg) { cfg.state = 8; }

        pan_pack_cs(i, COMPUTE_PAYLOAD, cfg) {
                cfg.workgroup_size_x = 1;
                cfg.workgroup_size_y = 1;
                cfg.workgroup_size_z = 1;

                cfg.workgroup_count_x = 1;
                cfg.workgroup_count_y = 1;
                cfg.workgroup_count_z = 1;

                cfg.compute.shader = shader_program.gpu;
                cfg.compute.thread_storage = local_storage.gpu;

                cfg.compute.fau = fau.gpu;
                cfg.compute.fau_count = 1;
        }

        pan_pack_ins(i, COMPUTE_LAUNCH, _);

        pan_pack_ins(c, CS_STATE, cfg) { cfg.state = 255; }
        emit_cs_call(c, cs_va, start, i->ptr);

        submit_cs(s, 0);
        wait_cs(s, 0);

        cache_invalidate(dest.cpu);
        uint32_t result = *(uint32_t *)dest.cpu;

        if (result != value) {
                printf("Got %i, expected %i: ", result, value);
                return false;
        }

        return true;
}

#define SUBTEST(s) { .label = #s, .subtests = s, .sub_length = ARRAY_SIZE(s) }

#define STATE(item) .offset = offsetof(struct state, item)

#define ALLOC(item) .offset = offsetof(struct state, allocations.item)
#define ALLOC_TEST(label, item, f) { alloc, dealloc, label, ALLOC(item), .flags = f }

struct test kbase_main[] = {
        { open_kbase, close_kbase, "Open kbase device" },
        { get_version, NULL, "Check version" },
        { set_flags, NULL, "Set flags" },
        { mmap_tracking, munmap_tracking, "Map tracking handle" },
        { get_gpuprops, free_gpuprops, "Get GPU properties" },
        { get_gpu_id, NULL, "GPU ID" },
        { get_coherency_mode, NULL, "Coherency mode" },
        { get_csf_caps, NULL, "CSF caps" },
        { mmap_user_reg, munmap_user_reg, "Map user register page" },
        { init_mem_exec, NULL, "Initialise EXEC_VA zone" },
        { init_mem_jit, NULL, "Initialise JIT allocator" },
        { stream_create, stream_destroy, "Create synchronisation stream" },
        { tiler_heap_create, tiler_heap_term, "Create chunked tiler heap" },
        { cs_group_create, cs_group_term, "Create command stream group" },
        { decode_init, decode_close, "Initialize pandecode" },

        /* Flags are named in mali_base_csf_kernel.h, omitted for brevity */
        ALLOC_TEST("Allocate normal memory", normal, 0x200f),
        ALLOC_TEST("Allocate exectuable memory", exec, 0x2017),
        ALLOC_TEST("Allocate coherent memory", coherent, 0x280f),
        ALLOC_TEST("Allocate cached memory", cached, 0x380f),

        /* These three tests are run for every queue, but later ones are not */
        { cs_queue_create, cs_queue_free, "Create command stream queues" },
        { cs_queue_register, cs_queue_term, "Register command stream queues" },
        { cs_init, NULL, "Initialise and start command stream queues" },

        { cs_simple, NULL, "Execute MOV command" },
        { cs_store, NULL, "Execute STR command" },
        { cs_store, NULL, "Execute ADD command", .add = true },
        { cs_sub, NULL, "Execute STR on iterator" },

        { compute_compile, NULL, "Compile a compute shader" },
        { compute_execute, NULL, "Execute a compute shader" },
};

static void
do_test_list(struct state *s, struct test *tests, unsigned length);

static void
cleanup_test_list(struct state *s, struct test *tests, unsigned length)
{
        for (unsigned i = length; i > 0; --i) {
                unsigned n = i - 1;

                struct test *t = &tests[n];
                if (!t->cleanup)
                        continue;

                printf("[CLEANUP %i] %s: ", n, t->label);
                if (t->cleanup(s, t)) {
                        printf("PASS\n");
                } else {
                        printf("FAIL\n");
                }
        }
}

static unsigned
interpret_test_list(struct state *s, struct test *tests, unsigned length)
{
        for (unsigned i = 0; i < length; ++i) {
                struct test *t = &tests[i];

                printf("[TEST %i] %s: ", i, t->label);
                if (t->part) {
                        if (t->part(s, t)) {
                                printf("PASS\n");
                        } else {
                                printf("FAIL\n");
                                if (!getenv("TEST_KEEP_GOING"))
                                        return i + 1;
                        }
                }
                if (t->subtests)
                        do_test_list(s, t->subtests, t->sub_length);
        }

        return length;
}

static void
do_test_list(struct state *s, struct test *tests, unsigned length)
{
        unsigned ran = interpret_test_list(s, tests, length);
        cleanup_test_list(s, tests, ran);
}

int
main(void)
{
        struct state s = {
                .page_size = sysconf(_SC_PAGE_SIZE),
        };

        printf("Running Valhall CSF tests" MESA_GIT_SHA1 "\n");

        do_test_list(&s, kbase_main, ARRAY_SIZE(kbase_main));
}
