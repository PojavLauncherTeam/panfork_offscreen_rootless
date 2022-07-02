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
 *
 */

/* Library for interfacing with kbase */
#ifndef PAN_BASE_H
#define PAN_BASE_H

struct util_dynarray;

struct kbase_syncobj;

typedef struct kbase_context {
        /* Set these before calling kbase_open */
        struct {
        } params;
        struct {
                unsigned gpu_id;
                unsigned arch;
        } info;
} *kbase;

bool kbase_open(kbase k);
void kbase_close(kbase k);

uint64_t kbase_get_pan_gpuprop(kbase k, unsigned name);
uint64_t kbase_get_mali_gpuprop(kbase k, unsigned name);

struct panfrost_ptr kbase_alloc(kbase k, size_t size,
                                unsigned pan_flags,
                                unsigned mali_flags);
void kbase_free(kbase k, struct panfrost_ptr va);

void kbase_cache_clean(void *ptr, size_t size);
void kbase_cache_invalidate(void *ptr, size_t size);

/* <= v9 GPUs */
bool kbase_submit(kbase k, uint64_t va, unsigned req,
                  struct kbase_syncobj *o,
                  struct util_dynarray *ext_res);

/* >= v10 GPUs */
bool kbase_cs_submit(kbase k, unsigned cs, unsigned insert_offset,
                     struct kbase_syncobj *o);
bool kbase_cs_wait(kbase k, unsigned cs, unsigned extract_offset);

/* syncobj functions */

struct kbase_syncobj *kbase_syncobj_create(kbase k);
struct kbase_syncobj *kbase_syncobj_free(kbase k);
struct kbase_syncobj *kbase_syncobj_dup(kbase k, struct kbase_syncobj *o);

/* TODO: timeout? (and for cs_wait) */
bool kbase_syncobj_wait(kbase k, struct kbase_syncobj *o);

struct mpanfrost_ptr kbase_import(kbase k, int fd, size_t *size);

void kbase_ctr_open(kbase k);
void kbase_ctr_set_enabled(kbase k, bool enable);
void kbase_ctr_dump(kbase k);

#endif
