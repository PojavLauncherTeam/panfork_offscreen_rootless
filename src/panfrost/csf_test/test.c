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
        void *tracking_region;
        void *csf_user_reg;

        uint8_t *gpuprops;
        unsigned gpuprops_size;
};

struct test {
        section part;
        section cleanup;
        const char *label;
};

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

        // todo: macro for error-checked ioctls
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
        s->csf_user_reg = mmap(NULL, s->page_size, PROT_NONE,
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
};

int main()
{
        struct state s = {
                .page_size = sysconf(_SC_PAGE_SIZE),
        };

        for (int i = 0; i < ARRAY_SIZE(kbase_main); ++i) {
                struct test *t = &kbase_main[i];
                printf("[TEST %i] %s: ", i, t->label);
                if (t->part(&s, t)) {
                        printf("PASS\n");
                } else {
                        printf("FAIL\n");
                }
        }

        for (int i = ARRAY_SIZE(kbase_main) -1; i >= 0; --i) {
                struct test *t = &kbase_main[i];
                if (!t->cleanup)
                        continue;

                printf("[CLEANUP %i] %s: ", i, t->label);
                if (t->cleanup(&s, t)) {
                        printf("PASS\n");
                } else {
                        printf("FAIL\n");
                }
        }
}
