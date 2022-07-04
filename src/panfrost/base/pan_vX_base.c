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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util/macros.h"
#include "util/u_atomic.h"
#include "pan_base.h"

#include "drm-uapi/panfrost_drm.h"

#if PAN_BASE_API >= 2
#define MALI_USE_CSF 1
#endif

#if PAN_BASE_API >= 1
#include "mali_base_kernel.h"
#include "mali_kbase_ioctl.h"

#define kbase_ioctl ioctl
#else

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
static bool
kbase_get_mali_gpuprop(kbase k, unsigned name, uint64_t *value)
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

                if (this_name == name) {
                        *value = x;
                        return true;
                }
        }

        return false;
}
#else
static bool
kbase_get_mali_gpuprop(kbase k, unsigned name, uint64_t *value)
{
        struct kbase_ioctl_gpu_props_reg_dump *props = k->gpuprops;

        switch (name) {
        case KBASE_GPUPROP_PRODUCT_ID:
                *value = props->core.product_id;
                return true;
        case KBASE_GPUPROP_RAW_SHADER_PRESENT:
                *value = props->raw.shader_present;
                return true;
        case KBASE_GPUPROP_RAW_TEXTURE_FEATURES_0:
                *value = props->raw.texture_features[0];
                return true;
        case KBASE_GPUPROP_RAW_TILER_FEATURES:
                *value = props->raw.tiler_features;
                return true;
        case KBASE_GPUPROP_RAW_GPU_ID:
                *value = props->raw.gpu_id;
                return true;
        default:
                return false;
        }
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

static struct kbase_op kbase_main[] = {
#if PAN_BASE_API >= 1
        { set_flags, NULL, "Set flags" },
#endif
        { mmap_tracking, munmap_tracking, "Map tracking handle" },
#if PAN_BASE_API == 0
        { set_flags, NULL, "Set flags" },
#endif
        { get_gpuprops, free_gpuprops, "Get GPU properties" },
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
                if (kbase_main[i].cleanup)
                        kbase_main[i].cleanup(k);
                --k->setup_state;
        }
}

static bool
kbase_get_pan_gpuprop(kbase k, unsigned name, uint64_t *value)
{
        unsigned conv[] = {
                [DRM_PANFROST_PARAM_GPU_PROD_ID] = KBASE_GPUPROP_PRODUCT_ID,
                [DRM_PANFROST_PARAM_SHADER_PRESENT] = KBASE_GPUPROP_RAW_SHADER_PRESENT,
                [DRM_PANFROST_PARAM_TEXTURE_FEATURES0] = KBASE_GPUPROP_RAW_TEXTURE_FEATURES_0,
                [DRM_PANFROST_PARAM_THREAD_TLS_ALLOC] = KBASE_GPUPROP_TLS_ALLOC,
                [DRM_PANFROST_PARAM_TILER_FEATURES] = KBASE_GPUPROP_RAW_TILER_FEATURES,
        };

        if (name < ARRAY_SIZE(conv) && conv[name])
                return kbase_get_mali_gpuprop(k, conv[name], value);

        switch (name) {
        case DRM_PANFROST_PARAM_AFBC_FEATURES:
                *value = 0;
                return true;
        case DRM_PANFROST_PARAM_GPU_REVISION: {
                if (!kbase_get_mali_gpuprop(k, KBASE_GPUPROP_RAW_GPU_ID, value))
                        return false;
                *value &= 0xffff;
                return true;
        }
        default:
                return false;
        }
}

static struct base_ptr
kbase_alloc(kbase k, size_t size, unsigned pan_flags, unsigned mali_flags)
{
        struct base_ptr r = {0};

        unsigned pages = size / k->page_size;

        union kbase_ioctl_mem_alloc a = {
                .in = {
                        .va_pages = pages,
                        .commit_pages = pages,
                }
        };

        size_t alloc_size = size;
        unsigned flags = mali_flags;
        bool exec_align = false;

        if (!flags) {
                flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                        BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                        BASE_MEM_SAME_VA;

                /* ++difficulty_level */
                if (PAN_BASE_API >= 1)
                        flags |= BASE_MEM_COHERENT_LOCAL | BASE_MEM_CACHED_CPU;
        }

        if (pan_flags & PANFROST_BO_HEAP) {
                size_t align_size = 2 * 1024 * 1024 / k->page_size; /* 2 MB */

                a.in.va_pages = ALIGN_POT(a.in.va_pages, align_size);
                a.in.commit_pages = 0;
                a.in.extension = align_size;
                flags |= BASE_MEM_GROW_ON_GPF;
        }

        if (!(flags & PANFROST_BO_NOEXEC)) {
                flags |= BASE_MEM_PROT_GPU_EX;
                flags &= ~BASE_MEM_PROT_GPU_WR;

                if (PAN_BASE_API == 0) {
                        /* Assume 4K pages */
                        a.in.va_pages = 0x1000; /* Align shader BOs to 16 MB */
                        size = 1 << 26; /* Four times the alignment */
                        exec_align = true;
                }
        }

        a.in.flags = flags;

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_ALLOC, a);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_ALLOC)");
                return r;
        }

        if (PAN_BASE_API == 0)
                a.out.gpu_va = 0x41000;

        if ((flags & BASE_MEM_SAME_VA) &&
            (!(a.out.flags & BASE_MEM_SAME_VA) ||
             a.out.gpu_va != 0x41000)) {

                fprintf(stderr, "Flags: 0x%"PRIx64", VA: 0x%"PRIx64"\n",
                        (uint64_t) a.out.flags, (uint64_t) a.out.gpu_va);
                return r;
        }

        void *ptr = mmap(NULL, size,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         k->fd, a.out.gpu_va);

        if (ptr == MAP_FAILED) {
                perror("mmap(GPU BO)");
                return r;
        }

        uint64_t gpu_va = (a.out.flags & BASE_MEM_SAME_VA) ?
                (uint64_t) ptr : a.out.gpu_va;

        if (exec_align) {
                gpu_va = ALIGN_POT(gpu_va, 1 << 24);

                ptr = mmap(NULL, alloc_size,
                           PROT_READ | PROT_WRITE, MAP_SHARED,
                           k->fd, gpu_va);

                if (ptr == MAP_FAILED) {
                        perror("mmap(GPU EXEC BO)");
                        return r;
                }
        }

        r.cpu = ptr;
        r.gpu = gpu_va;

        return r;
}

static void
kbase_free(kbase k, base_va va)
{
        struct kbase_ioctl_mem_free f = {
                .gpu_addr = va
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_FREE, &f);

        if (ret == -1)
                perror("ioctl(KBASE_IOCTL_MEM_FREE)");
}

#if PAN_BASE_API < 2
static void
kbase_handle_events(kbase k)
{
        struct base_jd_event_v2 event;

        int ret = read(k->fd, &event, sizeof(event));

        if (ret == -1) {
                if (errno == EAGAIN)
                        return;

                perror("read(mali fd)");
                return;
        }

        if (event.event_code != BASE_JD_EVENT_DONE)
                fprintf(stderr, "Atom %i reported event %i!\n",
                        event.atom_number, event.event_code);

        struct util_dynarray *handles = k->atom_bos + event.atom_number;
}
#else
static void
kbase_handle_events(kbase k)
{
        // todo
}
#endif

#if PAN_BASE_API < 2
static int
kbase_submit(kbase k, uint64_t va, unsigned req,
             struct kbase_syncobj *o,
             struct util_dynarray ext_res,
             int32_t *handles, unsigned num_handles)
{
        struct util_dynarray buf;
        util_dynarray_init(&buf, NULL);

        memcpy(util_dynarray_resize(&buf, int32_t, num_handles),
               handles, num_handles * sizeof(int32_t));

        // TODO: Just use a lock rather than many atomic operations....

        struct base_jd_atom_v2 atom = {
                .jc = va,
                .atom_number = p_atomic_add_return(&k->atom_number, 1),
        };

        /* Make sure that we haven't taken an atom that's already in use. */
        assert(!p_atomic_cmpxchg(&k->atom_bos[atom.atom_number].data,
                                 NULL, buf.data));

        /* Now we know it's safe, copy the whole buffer */
        k->atom_bos[atom.atom_number] = buf;

        unsigned handle_buf_size = util_dynarray_num_elements(&k->gem_handles, uint32_t);
        uint32_t *handle_buf = util_dynarray_begin(&k->gem_handles);

        /* Mark the BOs as in use */
        // TODO: Have an 8-bit use counter rather than this...
        for (unsigned i = 0; i < num_handles; ++i) {
                assert(handles[i] < handle_buf_size);
                handle_buf[i] |= 3U << 30;
        }

        atom.nr_extres = util_dynarray_num_elements(&ext_res, base_va);

        if (atom.nr_extres) {
                atom.core_req |= BASE_JD_REQ_EXTERNAL_RESOURCES;
                atom.extres_list = (uintptr_t) util_dynarray_begin(&ext_res);
        }

        if (req & PANFROST_JD_REQ_FS)
                atom.core_req |= BASE_JD_REQ_FS;
        else
                atom.core_req |= BASE_JD_REQ_CS | BASE_JD_REQ_T;

        struct kbase_ioctl_job_submit submit = {
                .nr_atoms = 1,
                .stride = sizeof(atom),
                .addr = (uintptr_t) &atom,
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_JOB_SUBMIT, &submit);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_JOB_SUBMIT)");
                return -1;
        }

        return atom.atom_number;
}

#else
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
        k->api = PAN_BASE_API;

        /* For later APIs, we've already checked the version in pan_base.c */
#if PAN_BASE_API == 0
        struct kbase_ioctl_get_version ver = { 0 };
        kbase_ioctl(k->fd, KBASE_IOCTL_GET_VERSION, &ver);
#endif

        k->close = kbase_close;

        k->get_pan_gpuprop = kbase_get_pan_gpuprop;
        k->get_mali_gpuprop = kbase_get_mali_gpuprop;

        k->alloc = kbase_alloc;
        k->free = kbase_free;

        k->handle_events = kbase_handle_events;

#if PAN_BASE_API < 2
        k->submit = kbase_submit;
#else
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
