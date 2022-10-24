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
#include <poll.h>
#include <pthread.h>

#include "util/macros.h"
#include "util/u_atomic.h"
#include "util/os_file.h"

#include "pan_base.h"

#include "drm-uapi/panfrost_drm.h"

#if PAN_BASE_API >= 2
#include "csf/mali_gpu_csf_registers.h"

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
#endif

#include "mali_kbase_gpuprops.h"

#define LOG(fmt, ...) do { \
                if (k->verbose) { \
                        struct timespec tp; \
                        clock_gettime(CLOCK_MONOTONIC_RAW, &tp); \
                        printf("%li.%09li\t" fmt, tp.tv_sec, tp.tv_nsec __VA_OPT__(,) __VA_ARGS__); \
                } \
        } while (0)

#if PAN_BASE_API == 0
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
static struct base_ptr
kbase_alloc(kbase k, size_t size, unsigned pan_flags, unsigned mali_flags);

static bool
alloc_event_mem(kbase k)
{
        k->event_mem = kbase_alloc(k, k->page_size,
                                   PANFROST_BO_NOEXEC,
                                   BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
                                   BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
                                   BASE_MEM_SAME_VA | BASE_MEM_CSF_EVENT);
        return k->event_mem.cpu;
}

static bool
free_event_mem(kbase k)
{
        if (k->event_mem.cpu)
                return munmap(k->event_mem.cpu, k->page_size) == 0;
        return true;
}
#endif

#if PAN_BASE_API >= 2
static bool
cs_group_create(kbase k, struct kbase_context *c)
{
        /* TODO: What about compute-only contexts? */
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

        c->csg_handle = create.out.group_handle;
        c->csg_uid = create.out.group_uid;

        /* Should be at least 1 */
        assert(c->csg_uid);

        return true;
}

static bool
cs_group_term(kbase k, struct kbase_context *c)
{
        if (!c->csg_uid)
                return true;

        struct kbase_ioctl_cs_queue_group_term term = {
                .group_handle = c->csg_handle
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE)");
                return false;
        }
        return true;
}
#endif

#if PAN_BASE_API >= 2
static bool
tiler_heap_create(kbase k, struct kbase_context *c)
{
        c->tiler_heap_chunk_size = 1 << 21; /* 2 MB */

        union kbase_ioctl_cs_tiler_heap_init init = {
                .in = {
                        .chunk_size = c->tiler_heap_chunk_size,
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

        c->tiler_heap_va = init.out.gpu_heap_va;
        c->tiler_heap_header = init.out.first_chunk_va;

        return true;
}

static bool
tiler_heap_term(kbase k, struct kbase_context *c)
{
        if (!c->tiler_heap_va)
                return true;

        struct kbase_ioctl_cs_tiler_heap_term term = {
                .gpu_heap_va = c->tiler_heap_va
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_TILER_HEAP_TERM, &term);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_TILER_HEAP_TERM)");
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
        { alloc_event_mem, free_event_mem, "Allocate event memory" },
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

        pthread_mutex_destroy(&k->handle_lock);
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

static void
kbase_free_ioctl(kbase k, base_va va)
{
        struct kbase_ioctl_mem_free f = {
                .gpu_addr = va
        };

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_FREE, &f);

        if (ret == -1)
                perror("ioctl(KBASE_IOCTL_MEM_FREE)");
}

static struct base_ptr
kbase_alloc(kbase k, size_t size, unsigned pan_flags, unsigned mali_flags)
{
        struct base_ptr r = {0};

        unsigned pages = DIV_ROUND_UP(size, k->page_size);

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

                /* Add COHERENT_LOCAL to keep GPU cores coherent with each
                 * other. */
                if (PAN_BASE_API >= 1)
                        flags |= BASE_MEM_COHERENT_LOCAL;

                /* TODO: ++difficulty_level */
                //if (PAN_BASE_API >= 1)
                //        flags |= BASE_MEM_CACHED_CPU;
        }

        if (pan_flags & PANFROST_BO_HEAP) {
                size_t align_size = 2 * 1024 * 1024 / k->page_size; /* 2 MB */

                a.in.va_pages = ALIGN_POT(a.in.va_pages, align_size);
                a.in.commit_pages = 0;
                a.in.extension = align_size;
                flags |= BASE_MEM_GROW_ON_GPF;
        }

        if (!(pan_flags & PANFROST_BO_NOEXEC)) {
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

        int ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_ALLOC, &a);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_ALLOC)");
                return r;
        }

        // TODO: Is this always true, even in the face of multithreading?
        if (PAN_BASE_API == 0)
                a.out.gpu_va = 0x41000;

        if ((flags & BASE_MEM_SAME_VA) &&
            !((a.out.flags & BASE_MEM_SAME_VA) &&
              a.out.gpu_va < 0x80000)) {

                fprintf(stderr, "Flags: 0x%"PRIx64", VA: 0x%"PRIx64"\n",
                        (uint64_t) a.out.flags, (uint64_t) a.out.gpu_va);
                errno = EINVAL;
                return r;
        }

        void *ptr = mmap(NULL, size,
                         PROT_READ | PROT_WRITE, MAP_SHARED,
                         k->fd, a.out.gpu_va);

        if (ptr == MAP_FAILED) {
                perror("mmap(GPU BO)");
                kbase_free_ioctl(k, a.out.gpu_va);
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
                        kbase_free_ioctl(k, gpu_va);
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
        /* BOs are freed on munmap, no need to do anything special. */
}

static int
kbase_import_dmabuf(kbase k, int fd)
{
        int ret;

        pthread_mutex_lock(&k->handle_lock);

        unsigned size = util_dynarray_num_elements(&k->gem_handles, kbase_handle);

        kbase_handle *handles = util_dynarray_begin(&k->gem_handles);

        for (unsigned i = 0; i < size; ++i) {
                kbase_handle h = handles[i];

                if (h.fd < 0)
                        continue;

                ret = os_same_file_description(h.fd, fd);

                if (ret == 0) {
                        pthread_mutex_unlock(&k->handle_lock);
                        return i;
                } else if (ret < 0) {
                        printf("error in os_same_file_description(%i, %i)\n", h.fd, fd);
                }
        }

        int dup = os_dupfd_cloexec(fd);

        union kbase_ioctl_mem_import import = {
                .in = {
                        .phandle = (uintptr_t) &dup,
                        .type = BASE_MEM_IMPORT_TYPE_UMM,
                        /* Usage flags: CPU/GPU reads/writes */
                        .flags = 0xf,
                }
        };

        ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_IMPORT, &import);

        int handle;

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_MEM_IMPORT)");
                handle = -1;
        } else {
                assert(import.out.flags & BASE_MEM_NEED_MMAP);

                uint64_t va = (uintptr_t) mmap(NULL, import.out.va_pages * k->page_size,
                                               PROT_READ | PROT_WRITE,
                                               MAP_SHARED, k->fd, import.out.gpu_va);

                handle = kbase_alloc_gem_handle_locked(k, va, dup);
        }

        pthread_mutex_unlock(&k->handle_lock);

        return handle;
}

struct kbase_syncobj {
        /* Use kbase_syncobj_ref / kbase_syncobj_unref */
        unsigned ref_count;

        /* syncobjs which are dup'd from this one */
        pthread_mutex_t child_mtx;
        unsigned child_count;
        struct kbase_syncobj **children;

        /* How many jobs are still executing? */
        unsigned job_count;
};

static struct kbase_syncobj *
kbase_syncobj_create(kbase k)
{
        struct kbase_syncobj *o = calloc(1, sizeof(*o));

        o->ref_count = 1;

        pthread_mutex_init(&o->child_mtx, NULL);

        return o;
}

static void
kbase_syncobj_ref(struct kbase_syncobj *o)
{
        ASSERTED unsigned ret = p_atomic_inc_return(&o->ref_count);
        /* We need to have at least one existing reference to be able to call
         * this function */
        assert(ret > 1);
}

static void
kbase_syncobj_unref(struct kbase_syncobj *o)
{
        unsigned ret = p_atomic_dec_return(&o->ref_count);

        if (!ret) {
                for (unsigned i = 0; i < o->child_count; ++i)
                        kbase_syncobj_unref(o->children[i]);

                pthread_mutex_destroy(&o->child_mtx);
                free(o->children);
                free(o);
        }
}

static void
kbase_syncobj_destroy(kbase k, struct kbase_syncobj *o)
{
        kbase_syncobj_unref(o);
}

static struct kbase_syncobj *
kbase_syncobj_dup(kbase k, struct kbase_syncobj *o)
{
        struct kbase_syncobj *dup = kbase_syncobj_create(k);

        /* Updates are passed from older to newer syncobjs, so reference the
         * new object */
        kbase_syncobj_ref(dup);

        pthread_mutex_lock(&o->child_mtx);

        ++o->child_count;
        o->children = reallocarray(o->children, o->child_count,
                                   sizeof(*o->children));

        o->children[o->child_count - 1] = dup;

        dup->job_count = o->job_count;

        pthread_mutex_unlock(&o->child_mtx);

        return dup;
}

static bool
kbase_handle_events(kbase k);

static bool
kbase_syncobj_wait(kbase k, struct kbase_syncobj *o)
{
        unsigned try_count = 0;

        while (p_atomic_read(&o->job_count)) {

                /* There are currently-executing jobs which reference this
                 * syncobj, wait for an event. */

                struct pollfd pfd[1] = {
                        {
                                .fd = k->fd,
                                .events = POLLIN,
                        },
                };

                int ret = poll(pfd, 1, 200);
                if (ret == -1)
                        perror("poll(syncobj)");

                if (ret == 0 && try_count > 10) {
                        fprintf(stderr, "syncobj wait timeout, %p returning\n", o);
                        return false;
                }

                if (ret == 0) {
                        ++try_count;
                        fprintf(stderr, "syncobj wait timeout %p\n", o);
                        continue;
                }

                if (pfd[0].revents || try_count > 10)
                        kbase_handle_events(k);
        }

        return true;
}

static void
kbase_syncobj_inc_jobs(struct kbase_syncobj *o)
{
        /* TODO: Avoid taking so many locks */
        pthread_mutex_lock(&o->child_mtx);

        /* Might as well not bother with the atomic, given the locking... */
        p_atomic_inc_return(&o->job_count);

        for (unsigned i = 0; i < o->child_count; ++i)
                kbase_syncobj_inc_jobs(o->children[i]);

        pthread_mutex_unlock(&o->child_mtx);
}

static void
kbase_syncobj_dec_jobs(struct kbase_syncobj *o)
{
        /* TODO: Avoid taking so many locks */
        pthread_mutex_lock(&o->child_mtx);

        /* Might as well not bother with the atomic, given the locking... */
        p_atomic_dec_return(&o->job_count);

        for (unsigned i = 0; i < o->child_count; ++i)
                kbase_syncobj_dec_jobs(o->children[i]);

        pthread_mutex_unlock(&o->child_mtx);
}

static void
kbase_poll_event(kbase k, int64_t timeout_ns)
{
        struct pollfd pfd = {
                .fd = k->fd,
                .events = POLLIN,
        };

        struct timespec t = {
                .tv_sec = timeout_ns / 1000000000,
                .tv_nsec = timeout_ns % 1000000000,
        };

        int ret = ppoll(&pfd, 1, &t, NULL);

        if (ret == -1 && errno != EINTR)
                perror("poll(mali fd)");

        LOG("poll returned %i\n", pfd.revents);

        return;
}

#if PAN_BASE_API < 2
static bool
kbase_handle_events(kbase k)
{
        struct base_jd_event_v2 event;
        bool ret = true;

        for (;;) {
                int ret = read(k->fd, &event, sizeof(event));

                if (ret == -1) {
                        if (errno == EAGAIN) {
                                return true;
                        } else {
                                perror("read(mali fd)");
                                return false;
                        }
                }

                struct kbase_syncobj *o = (void *)event.udata.blob[0];

                if (o) {
                        kbase_syncobj_dec_jobs(o);
                        kbase_syncobj_unref(o);
                }

                if (event.event_code != BASE_JD_EVENT_DONE) {
                        fprintf(stderr, "Atom %i reported event 0x%x!\n",
                                event.atom_number, event.event_code);
                        ret = false;
                }

                pthread_mutex_lock(&k->handle_lock);

                unsigned size = util_dynarray_num_elements(&k->gem_handles,
                                                           kbase_handle);
                kbase_handle *handle_data = util_dynarray_begin(&k->gem_handles);

                struct util_dynarray *handles = k->atom_bos + event.atom_number;

                util_dynarray_foreach(handles, int32_t, h) {
                        if (*h >= size)
                                continue;
                        assert(handle_data[*h].use_count);
                        --handle_data[*h].use_count;
                }
                util_dynarray_fini(handles);

                pthread_mutex_unlock(&k->handle_lock);
        }

        return ret;
}

#else

static bool
kbase_read_event(kbase k)
{
        struct base_csf_notification event;
        int ret = read(k->fd, &event, sizeof(event));

        if (ret == -1) {
                if (errno == EAGAIN) {
                        return true;
                } else {
                        perror("read(mali_fd)");
                        return false;
                }
        }

        if (ret != sizeof(event)) {
                fprintf(stderr, "read(mali_fd) returned %i, expected %i!\n",
                        ret, (int) sizeof(event));
                return false;
        }

        switch (event.type) {
        case BASE_CSF_NOTIFICATION_EVENT:
                LOG("Notification event!\n");
                return true;

        case BASE_CSF_NOTIFICATION_GPU_QUEUE_GROUP_ERROR:
                break;

        case BASE_CSF_NOTIFICATION_CPU_QUEUE_DUMP:
                fprintf(stderr, "No event from mali_fd!\n");
                return true;

        default:
                fprintf(stderr, "Unknown event type!\n");
                return true;
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
                unsigned queue = e.payload.fatal_queue.csi_index;

                // See CS_FATAL_EXCEPTION_* in mali_gpu_csf_registers.h
                fprintf(stderr, "Queue %i error: status 0x%x "
                        "sideband 0x%"PRIx64"\n",
                        queue, e.payload.fatal_queue.status,
                        (uint64_t) e.payload.fatal_queue.sideband);

                /* TODO: Decode the instruct that it got stuck at */

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

static void
kbase_update_syncobjs(kbase k,
                      struct kbase_event_slot *slot,
                      uint64_t seqnum)
{
        struct kbase_sync_link **list = &slot->syncobjs;
        struct kbase_sync_link **back = slot->back;

        while (*list) {
                struct kbase_sync_link *link = *list;

                LOG("seq %lx %lx\n", seqnum, link->seqnum);

                /* Remove the link if the syncobj is now signaled */
                if (seqnum > link->seqnum) {
                        LOG("syncobj %p done!\n", link->o);
                        kbase_syncobj_dec_jobs(link->o);
                        kbase_syncobj_unref(link->o);
                        *list = link->next;
                        if (&link->next == back)
                                slot->back = list;
                        free(link);
                } else {
                        // TODO: Assume that later syncobjs will have higher
                        // values and so skip checking?
                        list = &link->next;
                }
        }
}

static bool
kbase_handle_events(kbase k)
{
        /* This will clear the event count, so there's no need to do it in a
         * loop. */
        bool ret = kbase_read_event(k);

        uint64_t *event_mem = k->event_mem.cpu;

        /* TODO: Locking? */
        for (unsigned i = 0; i < k->event_slot_usage; ++i) {
                uint64_t seqnum = event_mem[i * 2];
                uint64_t cmp = k->event_slots[i].last;

                LOG("MAIN SEQ %lx > %lx?\n", seqnum, cmp);

                if (seqnum < cmp) {
                        if (false)
                                fprintf(stderr, "seqnum at offset %i went backward "
                                        "from %"PRIu64" to %"PRIu64"!\n",
                                        i, cmp, seqnum);
                } else /*if (seqnum > cmp)*/ {
                        kbase_update_syncobjs(k, &k->event_slots[i], seqnum);
                }

                /* TODO: Atomic operations? */
                k->event_slots[i].last = seqnum;
        }

        return ret;
}

static bool
kbase_wait_all_syncobjs(kbase k)
{
        bool ret = true;

        for (unsigned i = 0; i < 5; ++i) {
                bool all = true;

                for (unsigned i = 0; i < k->event_slot_usage; ++i) {
                        if (k->event_slots[i].syncobjs) {
                                LOG("slot %i has syncobjs\n", i);
                                all = false;
                        }
                }

                if (all)
                        return ret;

                LOG("waiting for syncobjs\n");

                kbase_poll_event(k, 200 * 1000000);
                ret &= kbase_handle_events(k);
        }

        return ret;
}

#endif

#if PAN_BASE_API < 2
static uint8_t
kbase_latest_slot(uint8_t a, uint8_t b, uint8_t newest)
{
        /* If a == 4 and newest == 5, a will become 255 */
        a -= newest;
        b -= newest;
        a = MAX2(a, b);
        a += newest;
        return a;
}

static int
kbase_submit(kbase k, uint64_t va, unsigned req,
             struct kbase_syncobj *o,
             int32_t *handles, unsigned num_handles)
{
        struct util_dynarray buf;
        util_dynarray_init(&buf, NULL);

        if (o) {
                kbase_syncobj_ref(o);
                kbase_syncobj_inc_jobs(o);
        }

        memcpy(util_dynarray_resize(&buf, int32_t, num_handles),
               handles, num_handles * sizeof(int32_t));

        pthread_mutex_lock(&k->handle_lock);

        unsigned slot = (req & PANFROST_JD_REQ_FS) ? 0 : 1;
        unsigned dep_slots[KBASE_SLOT_COUNT];

        uint8_t nr = k->atom_number++;

        struct base_jd_atom_v2 atom = {
                .jc = va,
                .atom_number = nr,
                .udata.blob[0] = (uintptr_t) o,
        };

        for (unsigned i = 0; i < KBASE_SLOT_COUNT; ++i)
                dep_slots[i] = nr;

        /* Make sure that we haven't taken an atom that's already in use. */
        assert(!k->atom_bos[nr].data);
        k->atom_bos[atom.atom_number] = buf;

        unsigned handle_buf_size = util_dynarray_num_elements(&k->gem_handles, kbase_handle);
        kbase_handle *handle_buf = util_dynarray_begin(&k->gem_handles);

        struct util_dynarray extres;
        util_dynarray_init(&extres, NULL);

        /* Mark the BOs as in use */
        for (unsigned i = 0; i < num_handles; ++i) {
                int32_t h = handles[i];
                assert(h < handle_buf_size);
                assert(handle_buf[h].use_count < 255);

                /* Implicit sync */
                if (handle_buf[h].use_count)
                        for (unsigned s = 0; s < KBASE_SLOT_COUNT; ++s)
                                dep_slots[s] =
                                        kbase_latest_slot(dep_slots[s],
                                                          handle_buf[h].last_access[s],
                                                          nr);

                handle_buf[h].last_access[slot] = nr;
                ++handle_buf[h].use_count;

                if (handle_buf[h].fd != -1)
                        util_dynarray_append(&extres, base_va, handle_buf[h].va);
        }

        pthread_mutex_unlock(&k->handle_lock);

        assert(KBASE_SLOT_COUNT == 2);
        if (dep_slots[0] != nr) {
                atom.pre_dep[0].atom_id = dep_slots[0];
                /* TODO: Use data dependencies?  */
                atom.pre_dep[0].dependency_type = BASE_JD_DEP_TYPE_ORDER;
        }
        if (dep_slots[1] != nr) {
                atom.pre_dep[1].atom_id = dep_slots[1];
                atom.pre_dep[1].dependency_type = BASE_JD_DEP_TYPE_ORDER;
        }

        if (extres.size) {
                atom.core_req |= BASE_JD_REQ_EXTERNAL_RESOURCES;
                atom.nr_extres = util_dynarray_num_elements(&extres, base_va);
                atom.extres_list = (uintptr_t) util_dynarray_begin(&extres);
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

        util_dynarray_fini(&extres);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_JOB_SUBMIT)");
                return -1;
        }

        return atom.atom_number;
}

#else
static struct kbase_context *
kbase_context_create(kbase k)
{
        struct kbase_context *c = calloc(1, sizeof(*c));

        if (!cs_group_create(k, c)) {
                free(c);
                return NULL;
        }

        if (!tiler_heap_create(k, c)) {
                cs_group_term(k, c);
                free(c);
                return NULL;
        }

        return c;
}

static void
kbase_context_destroy(kbase k, struct kbase_context *ctx)
{
        tiler_heap_term(k, ctx);
        cs_group_term(k, ctx);
        free(ctx);
}

static bool
kbase_context_recreate(kbase k, struct kbase_context *ctx)
{
        tiler_heap_term(k, ctx);
        cs_group_term(k, ctx);

        if (!cs_group_create(k, ctx)) {
                free(ctx);
                return false;
        }

        if (!tiler_heap_create(k, ctx)) {
                free(ctx);
                return false;
        }

        return true;
}

static struct kbase_cs
kbase_cs_bind_noevent(kbase k, struct kbase_context *ctx,
                      base_va va, unsigned size, unsigned csi)
{
        struct kbase_cs cs = {
                .ctx = ctx,
                .va = va,
                .size = size,
                .csi = csi,
                .latest_flush = (uint32_t *)k->csf_user_reg,
        };

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
                        .group_handle = ctx->csg_handle,
                        .csi_index = csi,
                }
        };

        ret = kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_BIND, &bind);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_BIND)");
                // hack
                cs.user_io = (void *)1;
                return cs;
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

static struct kbase_cs
kbase_cs_bind(kbase k, struct kbase_context *ctx,
              base_va va, unsigned size)
{
        struct kbase_cs cs = kbase_cs_bind_noevent(k, ctx, va, size, ctx->num_csi++);

        // TODO: This is a misnomer... it isn't a byte offset
        cs.event_mem_offset = k->event_slot_usage++;
        k->event_slots[cs.event_mem_offset].back =
                &k->event_slots[cs.event_mem_offset].syncobjs;
        *((uint64_t *)(k->event_mem.cpu + cs.event_mem_offset * 16)) = 1;

        return cs;
}

static void
kbase_cs_term(kbase k, struct kbase_cs *cs)
{
        if (cs->user_io)
            munmap(cs->user_io,
                   k->page_size * BASEP_QUEUE_NR_MMAP_USER_PAGES);

        struct kbase_ioctl_cs_queue_terminate term = {
                .buffer_gpu_addr = cs->va,
        };

        kbase_ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_TERMINATE, &term);

        /* Clean up old syncobjs so we don't keep waiting for them */
        kbase_update_syncobjs(k, &k->event_slots[cs->event_mem_offset], ~0ULL);
}

static void
kbase_cs_rebind(kbase k, struct kbase_cs *cs)
{
        struct kbase_cs new;
        new = kbase_cs_bind_noevent(k, cs->ctx, cs->va, cs->size, cs->csi);

        cs->user_io = new.user_io;

        fprintf(stderr, "bound csi %i again\n", cs->csi);
}

static bool
kbase_cs_kick(kbase k, struct kbase_cs *cs)
{
        struct kbase_ioctl_cs_queue_kick kick = {
                .buffer_gpu_addr = cs->va,
        };

        int ret = ioctl(k->fd, KBASE_IOCTL_CS_QUEUE_KICK, &kick);

        if (ret == -1) {
                perror("ioctl(KBASE_IOCTL_CS_QUEUE_KICK)");
                return false;
        }

        return true;
}

#define CS_RING_DOORBELL(cs) \
        *((uint32_t *)(cs->user_io)) = 1

#define CS_READ_REGISTER(cs, r) \
        *((uint64_t *)(cs->user_io + 4096 * 2 + r))

#define CS_WRITE_REGISTER(cs, r, v) \
        *((uint64_t *)(cs->user_io + 4096 + r)) = v

static bool
kbase_cs_submit(kbase k, struct kbase_cs *cs, uint64_t insert_offset,
                struct kbase_syncobj *o, uint64_t seqnum)
{
        LOG("submit %p, seq %li, insert %li -> %li\n", cs, seqnum,
            cs->last_insert, insert_offset);

        if (!cs->user_io)
                return false;

        if (insert_offset == cs->last_insert)
                return true;

        if (o) {
                kbase_syncobj_ref(o);
                kbase_syncobj_inc_jobs(o);
                // TODO: Don't add multiple links to one queue
                struct kbase_sync_link *link = malloc(sizeof(*link));
                *link = (struct kbase_sync_link) {
                        .o = o,
                        // TODO: Adjust this?
                        .seqnum = seqnum,
                        .next = NULL,
                };

                struct kbase_event_slot *slot =
                        &k->event_slots[cs->event_mem_offset];

                // TODO: Atomic operations?
                struct kbase_sync_link **list = slot->back;
                slot->back = &link->next;

                assert(!*list);
                *list = link;
        }

        __asm__ volatile ("dmb sy" ::: "memory");

        bool active = CS_READ_REGISTER(cs, CS_ACTIVE);
        LOG("active is %i\n", active);

        CS_WRITE_REGISTER(cs, CS_INSERT, insert_offset);
        cs->last_insert = insert_offset;

        if (false /*active*/) {
                __asm__ volatile ("dmb sy" ::: "memory");
                CS_RING_DOORBELL(cs);
                __asm__ volatile ("dmb sy" ::: "memory");

                active = CS_READ_REGISTER(cs, CS_ACTIVE);
                LOG("active is now %i\n", active);
        } else {
                kbase_cs_kick(k, cs);
        }

        {
                int ret = ioctl(k->fd, KBASE_IOCTL_CS_EVENT_SIGNAL);
                ret = ioctl(k->fd, KBASE_IOCTL_CS_EVENT_SIGNAL);

                if (ret == -1) {
                        perror("ioctl(KBASE_IOCTL_CS_EVENT_SIGNAL)");
                        return false;
                }
        }

        return true;
}

static bool
kbase_cs_wait(kbase k, struct kbase_cs *cs, uint64_t extract_offset)
{
        bool ret = true;
        unsigned count = 0;

        if (!cs->user_io)
                return false;

        // TODO: This only works for waiting for the latest job
        while (CS_READ_REGISTER(cs, CS_EXTRACT) != extract_offset) {
                LOG("extract: %p %li (want %li)\n", cs, CS_READ_REGISTER(cs, CS_EXTRACT),
                    extract_offset);

                // TODO: Reduce timeout
                kbase_poll_event(k, 200 * 1000000);
                ret &= kbase_handle_events(k);
                ++count;

                if (count > 10) {
                        uint64_t e = CS_READ_REGISTER(cs, CS_EXTRACT);
                        unsigned a = CS_READ_REGISTER(cs, CS_ACTIVE);

                        fprintf(stderr, "CSI %i CS_EXTRACT (%li) != %li, "
                                "CS_ACTIVE (%i)\n",
                                cs->csi, e, extract_offset, a);

                        cs->last_extract = e;

                        return false;
                }
        }

        cs->last_extract = extract_offset;

        ret &= kbase_handle_events(k);

        // everything is broken, let's avoid fixing it by waiting for every
        // syncobj!
        kbase_wait_all_syncobjs(k);

        return ret;
}
#endif

static void
kbase_mem_sync(kbase k, base_va gpu, void *cpu, unsigned size,
               bool invalidate)
{
        struct kbase_ioctl_mem_sync sync = {
                .handle = gpu,
                .user_addr = (uintptr_t) cpu,
                .size = size,
                .type = invalidate + (PAN_BASE_API == 0 ? 1 : 0),
        };

        int ret;
        ret = kbase_ioctl(k->fd, KBASE_IOCTL_MEM_SYNC, &sync);
        if (ret == -1)
                perror("ioctl(KBASE_IOCTL_MEM_SYNC)");
}

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

        pthread_mutex_init(&k->handle_lock, NULL);

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
        k->import_dmabuf = kbase_import_dmabuf;

        k->poll_event = kbase_poll_event;
        k->handle_events = kbase_handle_events;

#if PAN_BASE_API < 2
        k->submit = kbase_submit;
#else
        k->context_create = kbase_context_create;
        k->context_destroy = kbase_context_destroy;
        k->context_recreate = kbase_context_recreate;

        k->cs_bind = kbase_cs_bind;
        k->cs_term = kbase_cs_term;
        k->cs_rebind = kbase_cs_rebind;
        k->cs_submit = kbase_cs_submit;
        k->cs_wait = kbase_cs_wait;
#endif

        k->syncobj_create = kbase_syncobj_create;
        k->syncobj_destroy = kbase_syncobj_destroy;
        k->syncobj_dup = kbase_syncobj_dup;
        k->syncobj_wait = kbase_syncobj_wait;

        k->mem_sync = kbase_mem_sync;

        for (unsigned i = 0; i < ARRAY_SIZE(kbase_main); ++i) {
                ++k->setup_state;
                if (!kbase_main[i].part(k)) {
                        k->close(k);
                        return false;
                }
        }
        return true;
}
