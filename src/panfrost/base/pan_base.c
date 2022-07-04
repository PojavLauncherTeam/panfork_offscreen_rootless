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

#include "mali_kbase_ioctl.h"

bool
kbase_open(kbase k, int fd, unsigned cs_queue_count)
{
        *k = (struct kbase) {0};
        k->fd = fd;
        k->cs_queue_count = cs_queue_count;
        k->page_size = sysconf(_SC_PAGE_SIZE);

        struct kbase_ioctl_version_check ver = { 0 };
        int ret = ioctl(k->fd, KBASE_IOCTL_VERSION_CHECK, &ver);
        int ret2 = ioctl(k->fd, KBASE_IOCTL_VERSION_CHECK_RESERVED, &ver);

        if (ret == 0) {
                if (ver.major == 3)
                        return kbase_open_old(k);
                else
                        return kbase_open_new(k);
        } else if (ret2 == 0) {
                return kbase_open_csf(k);
        }

        return false;
}

int
kbase_alloc_gem_handle(kbase k, int fd)
{
        unsigned size = util_dynarray_num_elements(&k->gem_handles, int);

        int *handles = util_dynarray_begin(&k->gem_handles);

        for (unsigned i = 0; i < size; ++i) {
                if (handles[i] == -2) {
                        handles[i] = fd;
                        return i;
                }
        }

        util_dynarray_append(&k->gem_handles, int, fd);
        return size;
}

void
kbase_free_gem_handle(kbase k, int handle)
{
        unsigned size = util_dynarray_num_elements(&k->gem_handles, int);

        int fd = -1;

        if (handle >= size)
                return;

        if (handle + 1 < size) {
                int *ptr = util_dynarray_element(&k->gem_handles, int, handle);
                fd = *ptr;
                *ptr = -2;
        } else {
                fd = util_dynarray_pop(&k->gem_handles, int);
        }

        if (fd != -1)
                close(fd);
}
