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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

#include "util/macros.h"
#include "pan_base.h"

#include "mali_kbase_ioctl.h"

bool
kbase_open(kbase k, int fd, unsigned cs_queue_count, bool verbose)
{
        *k = (struct kbase) {0};
        k->fd = fd;
        k->cs_queue_count = cs_queue_count;
        k->page_size = sysconf(_SC_PAGE_SIZE);
        k->verbose = verbose;

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

/* If fd != -1, ownership is passed in */
int
kbase_alloc_gem_handle_locked(kbase k, base_va va, int fd)
{
        kbase_handle h = {
                .va = va,
                .fd = fd
        };

        unsigned size = util_dynarray_num_elements(&k->gem_handles, kbase_handle);

        kbase_handle *handles = util_dynarray_begin(&k->gem_handles);

        for (unsigned i = 0; i < size; ++i) {
                if (handles[i].fd == -2) {
                        handles[i] = h;
                        return i;
                }
        }

        util_dynarray_append(&k->gem_handles, kbase_handle, h);

        return size;
}

int
kbase_alloc_gem_handle(kbase k, base_va va, int fd)
{
        pthread_mutex_lock(&k->handle_lock);

        int ret = kbase_alloc_gem_handle_locked(k, va, fd);

        pthread_mutex_unlock(&k->handle_lock);

        return ret;
}

void
kbase_free_gem_handle(kbase k, int handle)
{
        pthread_mutex_lock(&k->handle_lock);

        unsigned size = util_dynarray_num_elements(&k->gem_handles, kbase_handle);

        int fd;

        if (handle >= size) {
                pthread_mutex_unlock(&k->handle_lock);
                return;
        }

        if (handle + 1 < size) {
                kbase_handle *ptr = util_dynarray_element(&k->gem_handles, kbase_handle, handle);
                fd = ptr->fd;
                ptr->fd = -2;
        } else {
                fd = (util_dynarray_pop(&k->gem_handles, kbase_handle)).fd;
        }

        if (fd != -1)
                close(fd);

        pthread_mutex_unlock(&k->handle_lock);
}

kbase_handle
kbase_gem_handle_get(kbase k, int handle)
{
        kbase_handle h = { .fd = -1 };

        pthread_mutex_lock(&k->handle_lock);

        unsigned size = util_dynarray_num_elements(&k->gem_handles, kbase_handle);

        if (handle < size)
                h = *util_dynarray_element(&k->gem_handles, kbase_handle, handle);

        pthread_mutex_unlock(&k->handle_lock);

        return h;
}

int
kbase_wait_bo(kbase k, int handle, int64_t timeout_ns, bool wait_readers)
{
        for (;;) {
                pthread_mutex_lock(&k->handle_lock);
                if (handle >= util_dynarray_num_elements(&k->gem_handles, kbase_handle)) {
                        errno = EINVAL;
                        pthread_mutex_unlock(&k->handle_lock);
                        return -1;
                }
                kbase_handle *ptr = util_dynarray_element(&k->gem_handles, kbase_handle, handle);
                if (!ptr->use_count) {
                        pthread_mutex_unlock(&k->handle_lock);
                        return 0;
                }

                pthread_mutex_unlock(&k->handle_lock);

                /* TODO: We can't just keep waiting against the timeout... */
                k->poll_event(k, timeout_ns);
                k->handle_events(k);
        }
}
