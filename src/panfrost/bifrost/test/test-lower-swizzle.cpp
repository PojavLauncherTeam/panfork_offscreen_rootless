/*
 * Copyright (C) 2022 Collabora, Ltd.
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

#include "compiler.h"
#include "bi_test.h"
#include "bi_builder.h"

#include <gtest/gtest.h>

#define CASE(instr, expected) INSTRUCTION_CASE(instr, expected, bi_lower_swizzle)
#define NEGCASE(instr) CASE(instr, instr)

class LowerSwizzle : public testing::Test {
protected:
   LowerSwizzle() {
      mem_ctx = ralloc_context(NULL);

      reg     = bi_register(0);
      x       = bi_register(1);
      y       = bi_register(2);
      z       = bi_register(3);
      w       = bi_register(4);
   }

   ~LowerSwizzle() {
      ralloc_free(mem_ctx);
   }

   void *mem_ctx;

   bi_index reg, x, y, z, w;
};

TEST_F(LowerSwizzle, Csel16)
{
   CASE(bi_csel_v2f16_to(b, reg, bi_half(x, 0), y, z, w, BI_CMPF_NE),
        bi_csel_v2f16_to(b, reg, bi_swz_v2i16(b, bi_half(x, 0)), y, z, w, BI_CMPF_NE));
}

TEST_F(LowerSwizzle, Fma16)
{
   NEGCASE(bi_fadd_v2f16_to(b, reg, bi_half(x, 0), y));
   NEGCASE(bi_fma_v2f16_to(b, reg, bi_half(x, 0), y, z));
}

