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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util/macros.h"

#include "mali_kbase_csf_ioctl.h"
#include "mali_kbase_ioctl.h"
#include "mali_base_kernel.h"
#include "mali_base_csf_kernel.h"

struct state;
struct test;

// todo; swop args?
typedef bool (* section)(struct state *s, struct test *t);

struct state {
        int page_size;

        int mali_fd;
        int tl_fd;
        void *tracking_region;
        void *csf_user_reg;

        uint8_t *gpuprops;
        unsigned gpuprops_size;

        struct {
                void *normal, *exec, *coherent, *cached;
        } allocations;

        uint64_t tiler_heap_va;
        uint64_t tiler_heap_header;
};

struct test {
        section part;
        section cleanup;
        const char *label;
        struct test *subtests;
        unsigned sub_length;

        unsigned offset;
        unsigned flags;
};

#define DEREF_STATE(s, offset) ((void*)s + offset)

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
                return false;
        }
        return true;
}

static bool
munmap_tracking(struct state *s, struct test *t)
{
        if (s->tracking_region && s->tracking_region != MAP_FAILED)
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
        uint16_t maj = gpu_id >> 12;
        uint16_t min = (gpu_id >> 8) & 0xf;
        uint16_t rev = (gpu_id >> 4) & 0xf;
        uint16_t product = gpu_id & 0xf;

        const char *names[] = {
                [0] = "G610",
                [8] = "G710",
                [10] = "G510",
                [12] = "G310",
        };
        const char *name = (min < ARRAY_SIZE(names)) ? names[min] : NULL;
        if (!name)
                name = "unknown";

        printf("v%i.%i r%ip%i (Mali-%s): ", maj, min, rev, product, name);

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
                return false;
        }
        return true;
}

static bool
munmap_user_reg(struct state *s, struct test *t)
{
        if (s->csf_user_reg && s->csf_user_reg != MAP_FAILED)
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
alloc(struct state *s, struct test *t)
{
        void **ptr = DEREF_STATE(s, t->offset);
        unsigned flags = t->flags;

        union kbase_ioctl_mem_alloc a = {
                .in = {
                        .va_pages = 1,
                        .commit_pages = 1,
                        .extension = 0,
                        .flags = flags,
                }
        };

        int ret = ioctl(s->mali_fd, KBASE_IOCTL_MEM_ALLOC, &a);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_ALLOC)");
                return false;
        }

        if ((flags & BASE_MEM_SAME_VA)
            && (!(a.out.flags & BASE_MEM_SAME_VA) ||
                a.out.gpu_va != 0x41000)) {

                fprintf(stderr, "Flags: 0x%"PRIx64", VA: 0x%"PRIx64"\n",
                        (uint64_t) a.out.flags, (uint64_t) a.out.gpu_va);
                return false;
        }

        *ptr = mmap(NULL, s->page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    s->mali_fd, a.out.gpu_va);

        if (*ptr == MAP_FAILED) {
                perror("mmap(GPU BO)");
                return false;
        }

        int *p = (int *)*ptr;
        *p = 0x12345;
        if (*p != 0x12345) {
                printf("Error reading from allocated memory at %p\n", p);
                return false;
        }
        *p = 0;

        return true;
}

static bool
dealloc(struct state *s, struct test *t)
{
        void **ptr = DEREF_STATE(s, t->offset);

        if (*ptr && *ptr != MAP_FAILED)
                return munmap(*ptr, s->page_size) == 0;
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

        /* Flags are named in mali_base_csf_kernel.h, omitted for brevity */
        ALLOC_TEST("Allocate normal memory", normal, 0x200f),
        ALLOC_TEST("Allocate exectuable memory", exec, 0x2017),
        ALLOC_TEST("Allocate coherent memory", coherent, 0x280f),
        ALLOC_TEST("Allocate cached memory", cached, 0x380f),

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
                                continue;
                        } else {
                                printf("FAIL\n");
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

        do_test_list(&s, kbase_main, ARRAY_SIZE(kbase_main));
}
