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
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util/macros.h"
#include "pan_base.h"

#if PAN_BASE_API >= 2
#define MALI_USE_CSF 1
#endif

#if PAN_BASE_API >= 1
#include "mali_base_kernel.h"
#include "mali_kbase_ioctl.h"

#define kbase_ioctl ioctl
#else

#include <errno.h>
#include <stdarg.h>

#include "old/mali-ioctl.h"
#include "old/mali-ioctl-midgard.h"
#include "old/mali-props.h"

static int
kbase_ioctl(int fd, unsigned long request, ...)
{
        int ioc_size = _IOC_SIZE(request);

        assert(ioc_size);

        va_list args;

        va_start(args, request);
        int *ptr = va_arg(args, void *);
        va_end(args);

        *ptr = (_IOC_TYPE(request) - 0x80) * 256 + _IOC_NR(request);

        int ret = ioctl(fd, request, ptr);
        if (ret)
                return ret;

        int r = *ptr;
        switch (r) {
        case MALI_ERROR_OUT_OF_GPU_MEMORY:
                errno = ENOSPC;
                return -1;
        case MALI_ERROR_OUT_OF_MEMORY:
                errno = ENOMEM;
                return -1;
        case MALI_ERROR_FUNCTION_FAILED:
                errno = EINVAL;
                return -1;
        default:
                return 0;
        }
}
#endif

#include "mali_kbase_gpuprops.h"

#if PAN_BASE_API >= 1
static uint64_t
pan_get_gpuprop(kbase k, int name)
{
        int i = 0;
        uint64_t x = 0;
        while (i < k->gpuprops_size) {
                x = 0;
                memcpy(&x, k->gpuprops + i, 4);
                i += 4;

                int size = 1 << (x & 3);
                int this_name = x >> 2;

                x = 0;
                memcpy(&x, k->gpuprops + i, size);
                i += size;

                if (this_name == name)
                        return x;
        }

        fprintf(stderr, "Unknown prop %i\n", name);
        return 0;
}
#else
static uint64_t
pan_get_gpuprop(kbase k, int name)
{
        switch (name) {
        default:
                fprintf(stderr, "Unknown prop %i\n", name);
                return 0;
        }
}
#endif

#if PAN_BASE_API >= 1
static bool
get_version(kbase k)
{
        struct kbase_ioctl_version_check ver = { 0 };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_VERSION_CHECK, &ver);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_VERSION_CHECK)");
                return false;
        }

        return ver.major == 11;
}
#endif

static bool
set_flags(kbase k)
{
        struct kbase_ioctl_set_flags flags = {
                .create_flags = 0
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_SET_FLAGS, &flags);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_SET_FLAGS)");
                return false;
        }
        return true;
}

static bool
mmap_tracking(kbase k)
{
        k->tracking_region = mmap(NULL, k->page_size, PROT_NONE,
                                  MAP_SHARED, k->fd,
                                  BASE_MEM_MAP_TRACKING_HANDLE);

        if (k->tracking_region == MAP_FAILED) {
                perror("mmap(BASE_MEM_MAP_TRACKING_HANDLE)");
                k->tracking_region = NULL;
                return false;
        }
        return true;
}

static bool
munmap_tracking(kbase k)
{
        if (k->tracking_region)
                return munmap(k->tracking_region, k->page_size) == 0;
        return true;
}

#if PAN_BASE_API >= 1
static bool
get_gpuprops(kbase k)
{
        struct kbase_ioctl_get_gpuprops props = { 0 };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(0))");
                return false;
        } else if (!ret) {
                fprintf(stderr, "GET_GPUPROPS returned zero size\n");
                return false;
        }

        k->gpuprops_size = ret;
        k->gpuprops = calloc(k->gpuprops_size, 1);

        props.size = k->gpuprops_size;
        props.buffer = (uint64_t)(uintptr_t) k->gpuprops;

        ret = kbase_ioctl(k->fd, KBASE_IOCTL_GET_GPUPROPS, &props);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GET_GPUPROPS(size))");
                return false;
        }

        return true;
}
#else
static bool
get_gpuprops(kbase k)
{
        k->gpuprops = calloc(1, sizeof(struct kbase_ioctl_gpu_props_reg_dump));

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_GPU_PROPS_REG_DUMP, k->gpuprops);
        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_GPU_PROPS_REG_DUMP)");
                return false;
        }

        return true;
}
#endif

static bool
free_gpuprops(kbase k)
{
        free(k->gpuprops);
        return true;
}

static bool
get_gpu_id(kbase k)
{
        uint64_t gpu_id = pan_get_gpuprop(k, KBASE_GPUPROP_PRODUCT_ID);
        if (!gpu_id)
                return false;
        //k->info.gpu_id = gpu_id;

        uint16_t maj = gpu_id >> 12;
        return maj >= 10;
}

#if PAN_BASE_API >= 2
static bool
mmap_user_reg(kbase k)
{
        k->csf_user_reg = mmap(NULL, k->page_size, PROT_READ,
                               MAP_SHARED, k->fd,
                               BASEP_MEM_CSF_USER_REG_PAGE_HANDLE);

        if (k->csf_user_reg == MAP_FAILED) {
                perror("mmap(BASEP_MEM_CSF_USER_REG_PAGE_HANDLE)");
                k->csf_user_reg = NULL;
                return false;
        }
        return true;
}

static bool
munmap_user_reg(kbase k)
{
        if (k->csf_user_reg)
                return munmap(k->csf_user_reg, k->page_size) == 0;
        return true;
}
#endif

#if PAN_BASE_API >= 1
static bool
init_mem_exec(kbase k)
{
        struct kbase_ioctl_mem_exec_init init = {
                .va_pages = 0x100000,
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_EXEC_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_EXEC_INIT)");
                return false;
        }
        return true;
}

static bool
init_mem_jit(kbase k)
{
        struct kbase_ioctl_mem_jit_init init = {
                .va_pages = 1 << 25,
                .max_allocations = 255,
                .phys_pages = 1 << 25,
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_JIT_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_JIT_INIT)");
                return false;
        }
        return true;
}
#endif

#if PAN_BASE_API >= 2
static bool
tiler_heap_create(kbase k)
{
        union kbase_ioctl_cs_tiler_heap_init init = {
                .in = {
                        .chunk_size = 1 << 21,
                        .initial_chunks = 5,
                        .max_chunks = 200,
                        .target_in_flight = 65535,
                }
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_TILER_HEAP_INIT, &init);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_INIT)");
                return false;
        }

        k->tiler_heap_va = init.out.gpu_heap_va;
        k->tiler_heap_header = init.out.first_chunk_va;

        return true;
}

static bool
tiler_heap_term(kbase k)
{
        if (!k->tiler_heap_va)
                return true;

        struct kbase_ioctl_cs_tiler_heap_term term = {
                .gpu_heap_va = k->tiler_heap_va
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_TILER_HEAP_TERM, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_TERM)");
                return false;
        }
        return true;
}
#endif

#if PAN_BASE_API >= 2
static bool
cs_group_create(kbase k)
{
        union kbase_ioctl_cs_queue_group_create_1_6 create = {
                .in = {
                        /* Mali *still* only supports a single tiler unit */
                        .tiler_mask = 1,
                        .fragment_mask = ~0ULL,
                        .compute_mask = ~0ULL,

                        .cs_min = k->cs_queue_count,

                        .priority = 1,
                        .tiler_max = 1,
                        .fragment_max = 64,
                        .compute_max = 64,
                }
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6, &create);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6)");
                return false;
        }

        k->csg_handle = create.out.group_handle;
        k->csg_uid = create.out.group_uid;

        /* Should be at least 1 */
        assert(k->csg_uid);

        return true;
}

static bool
cs_group_term(kbase k)
{
        if (!k->csg_uid)
                return true;

        struct kbase_ioctl_cs_queue_group_term term = {
                .group_handle = k->csg_handle
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE)");
                return false;
        }
        return true;
}
#endif

typedef bool (* kbase_func)(kbase k);

struct kbase_op {
        kbase_func part;
        kbase_func cleanup;
        const char *label;
};

struct kbase_op kbase_main[] = {
#if PAN_BASE_API >= 1
        { get_version, NULL, "Check version" },
#endif
        { set_flags, NULL, "Set flags" },
        { mmap_tracking, munmap_tracking, "Map tracking handle" },
        { get_gpuprops, free_gpuprops, "Get GPU properties" },
        { get_gpu_id, NULL, "GPU ID" },
#if PAN_BASE_API >= 2
        { mmap_user_reg, munmap_user_reg, "Map user register page" },
#endif
#if PAN_BASE_API >= 1
        { init_mem_exec, NULL, "Initialise EXEC_VA zone" },
        { init_mem_jit, NULL, "Initialise JIT allocator" },
#endif
#if PAN_BASE_API >= 2
        { tiler_heap_create, tiler_heap_term, "Create chunked tiler heap" },
        { cs_group_create, cs_group_term, "Create command stream group" },
#endif
};

static void
kbase_close(kbase k)
{
        while (k->setup_state) {
                unsigned i = k->setup_state - 1;
                kbase_main[i].cleanup(k);
                --k->setup_state;
        }
}

#if PAN_BASE_API >= 2
static struct kbase_cs
kbase_cs_bind(kbase k, base_va va, unsigned size)
{
        struct kbase_cs cs = {0};

        struct kbase_ioctl_cs_queue_register reg = {
                .buffer_gpu_addr = va,
                .buffer_size = size,
                .priority = 1,
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_REGISTER, &reg);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_REGISTER)");
                return cs;
        }

        union kbase_ioctl_cs_queue_bind bind = {
                .in = {
                        .buffer_gpu_addr = va,
                        .group_handle = k->csg_handle,
                        .csi_index = k->num_csi++,
                }
        };

        ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_BIND, &bind);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_BIND)");
        }

        cs.user_io =
                mmap(NULL,
                     k->page_size * BASEP_QUEUE_NR_MMAP_USER_PAGES,
                     PROT_READ | PROT_WRITE, MAP_SHARED,
                     k->fd, bind.out.mmap_handle);

        if (cs.user_io == MAP_FAILED) {
                perror("mmap(CS USER IO)");
                cs.user_io = NULL;
        }

        return cs;
}

/* TODO: Free up the CSI to be reused by another CS? */
static void
kbase_cs_term(kbase k, struct kbase_cs *cs, base_va va)
{
        if (cs->user_io)
            munmap(cs->user_io,
                   k->page_size * BASEP_QUEUE_NR_MMAP_USER_PAGES);

        struct kbase_ioctl_cs_queue_terminate term = {
                .buffer_gpu_addr = va,
        };

        kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_TERMINATE, &term);
}
#endif

bool
#if PAN_BASE_API == 0
kbase_open_old
#elif PAN_BASE_API == 1
kbase_open_new
#elif PAN_BASE_API == 2
kbase_open_csf
#endif
(kbase k)
{
        k->close = kbase_close;

#if PAN_BASE_API >= 2
        k->cs_bind = kbase_cs_bind;
        k->cs_term = kbase_cs_term;
#endif

        for (unsigned i = 0; i < ARRAY_SIZE(kbase_main); ++i) {
                ++k->setup_state;
                if (!kbase_main[i].part(k)) {
                        k->close(k);
                        return false;
                }
        }
        return true;
}
