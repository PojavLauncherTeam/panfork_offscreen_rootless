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

struct mali_ioctl_get_version_new {
        uint16_t major;
        uint16_t minor;
};

#define MALI_IOCTL_GET_VERSION_NEW (_IOWR(0x80, 0, struct mali_ioctl_get_version_new))

bool kbase_open_old(kbase k);
bool kbase_open_csf(kbase k);

bool
kbase_open(kbase k, int fd, unsigned cs_queue_count)
{
        *k = (struct kbase) {0};
        k->fd = fd;
        k->cs_queue_count = cs_queue_count;
        k->page_size = sysconf(_SC_PAGE_SIZE);

        /* First try a new-style GET_VERSION */
        struct mali_ioctl_get_version_new ver = { 0 };
        int ret = ioctl(k->fd, MALI_IOCTL_GET_VERSION_NEW, &ver);

        if (ret == 0) {
                return kbase_open_csf(k);
        } else {
                return kbase_open_old(k);
        }
}
