#!/usr/bin/env python3

import os
import re
import subprocess
import sys

try:
    py_path = os.path.dirname(os.path.realpath(__file__)) + "/../bifrost/valhall"
except:
    py_path = "../bifrost/valhall"

if py_path not in sys.path:
    sys.path.insert(0, py_path)

import asm
import struct

shaders = {
    "compute":
    """
IADD_IMM.i32.reconverge r0, 0x0, #0x0
NOP.wait0
ICMP.u32.ge.m1 r1, r0, u2, 0x0
BRANCHZ.eq.reconverge ^r1.h0, offset:1
BRANCHZ.eq 0x0, offset:3
ATOM1_RETURN.i32.slot0.ainc @r1, u0, offset:0x0
IADD_IMM.i32 r0, ^r0, #0x1
BRANCHZ.eq.reconverge 0x0, offset:-7
NOP.end
"""
}

template = """
!cs 0
!alloc x 4096
!alloc y 4096
!alloc ev 4096

endpt 0
mov x48, $x

mov w21, 0x80000000
mov w25, 1
mov w26, 1
mov w27, 1

add x0e, x48, 64
mov x50, $ev
str x50, [x0e]
mov x30, 10
str x30, [x0e, 8]
add w0f, w0f, 0x02000000

add x16, x48, 128
mov x30, 0x118
str x30, [x16]
mov x30, $compute
str x30, [x16, 8]

add x1e, x48, 192

mov x30, $y
@regdump x30
mov x30, 0

mov w40, 100
1: add w40, w40, -1
str cycles, [x50, 32]
b.ne w40, 1b

@ 1 560 560
@ 5 686 681
@ 10 822
@ 15 958
mov w42, 200
mov w40, 100
1: add w40, w40, -1
endpt 1
UNK 0400ff0000008001
UNK 2501504200000004
@UNK 3 24, #0x4a0000000211

@wait all
b.ne w40, 1b

UNK 2601504200000004

str cycles, [x50, 40]
str cycles, [x50, 48]
UNK 02 24, #0x4a0000000211
wait 0

add x5c, x50, 64
UNK 25015c5e00fd0004
UNK 25015c5e00fd0001

!dump x 0 4096
!dump y 0 384
!delta ev 0 4096
"""

atemplate = """
!cs 0
!alloc x 4096
!alloc ev 4096 0x8200f
!alloc ev2 4096 0x8200f

mov x10, $x
UNK 00 30, #0x100000000000
add x12, x10, 256
str cycles, [x12]
mov x5a, $ev2
mov x48, 0
mov w4a, 0
slot 3
wait 3
UNK 00 31, 0
mov x48, $ev
mov w4a, 0x4321
add x46, x48, 64
mov w42, 0

str cycles, [x12, 8]
UNK 01 26, 0x484a00000005
str cycles, [x12, 16]
UNK 01 26, 0x484a00000005
str cycles, [x12, 24]

nop

mov w10, 10000
1:
UNK 01 26, 0x484a00000005
add w10, w10, -1
b.ne w10, 1b
str cycles, [x12, 32]

mov w10, 10000
1:
UNK 01 26, 0x484a00000005
@UNK 02 24, #0x420000000211
add w10, w10, -1
b.ne w10, 1b
str cycles, [x12, 40]

ldr x16, [x48, 0]
wait 0
str x16, [x48, 16]

UNK 00 31, 0x100000000

mov w4a, #0x0
UNK 02 24, #0x4a0000000211

mov w5e, 1
add x5c, x5a, 0x100
UNK 01 25, 0x5c5e00f80001

!delta x 0 4096
!dump ev 0 4096
!dump ev2 0 4096
"""

atemplate = """
!cs 0
!alloc x 4096
!alloc ev 4096 0x8200f

iter vertex
slot 2

mov x40, $x
mov w10, 1
mov x48, 0
mov w4a, 0
call w4a, x48
  nop
  nop
  nop
  mov x20, $.
@  movp x22, 0x0126000011223344
  movp x22, 0x1600000060000001
  str x22, [x20, 56]
  1: nop
  b 1b
  nop
  add x40, x40, #256
  regdump x40

mov x5a, #0x5ff7fd6000
mov x48, $ev
mov x40, #0x5ff7fd6000
mov w54, #0x1
UNK 00 24, #0x540000000233
wait 0
slot 6
@UNK 00 31, #0x0
UNK 00 09, #0x0
wait 6
@UNK 00 31, #0x100000000
mov x4a, x40
UNK 01 26, 0x484a00040001

!dump x 0 4096
@!dump ev 0 4096
@!delta x 0 4096
"""

cycletest = """
1:
mov w10, 10
str cycles, [x5c]
add x5c, x5c, 8
add w10, w10, -1
mov w11, 100000

inner:
add w11, w11, -1
b.ne w11, inner

b.ne w10, 1b
"""

def get_cmds(cmd):
    return template.format(cmd=cmd)

def assemble_shader(text):
    lines = text.strip().split("\n")
    lines = [l for l in lines if len(l) > 0 and l[0] not in "#@"]
    return [asm.parse_asm(ln) for ln in lines]

class Buffer:
    id = 0

    def __init__(self):
        self.id = Buffer.id
        Buffer.id += 1

def resolve_rel(to, branch):
    return (to - branch) // 8 - 1

def to_int16(value):
    assert(value < 36768)
    assert(value >= -32768)
    return value & 0xffff

class Level(Buffer):
    def __init__(self, indent):
        super().__init__()

        self.indent = indent
        self.buffer = []
        self.call_addr_offset = None
        self.call_len_offset = None

        self.labels = {}
        self.label_refs = []
        # Numeric labels can be reused, so have to be handled specially.
        self.num_labels = {}
        self.num_refs = {}

    def offset(self):
        return len(self.buffer) * 8

    def __repr__(self):
        buf = " ".join(hex(x) for x in self.buffer)
        return f"buffer {self.id} {self.offset()} 0x200f {buf}"

    def buffer_add_value(self, offset, value):
        self.buffer[offset // 8] += value

    def process_relocs(self, refs, to=None):
        for ref, offset, type_ in refs:
            assert(type_ == "rel")

            if to is None:
                goto = self.labels[ref]
            else:
                goto = to

            value = to_int16(resolve_rel(goto, offset))
            self.buffer_add_value(offset, value)

    def finish(self):
        self.process_relocs(self.label_refs)

class Alloc(Buffer):
    def __init__(self, size, flags=0x200f):
        super().__init__()

        self.size = size
        self.flags = flags
        self.buffer = []

    def __repr__(self):
        buf = " ".join(hex(x) for x in self.buffer)
        return f"buffer {self.id} {self.size} {hex(self.flags)} {buf}"

def fmt_reloc(r):
    dst, offset, src, src_offset = r
    return f"reloc {dst}+{offset} {src}+{src_offset}"

def fmt_exe(e):
    return " ".join(str(x) for x in e)

class Context:
    def __init__(self):
        self.levels = []
        self.l = None

        self.allocs = {}
        self.completed = []
        self.reloc = []

        self.exe = []
        self.last_exe = None

        self.is_call = False

    def set_l(self):
        if len(self.levels):
            self.l = self.levels[-1]

    def pop_until(self, indent):
        while self.l.indent != indent:
            l = self.levels.pop()
            self.completed.append(l)

            self.set_l()
            if not len(self.levels):
                return

            buf_len = l.offset()

            r = self.l
            self.reloc.append((r.id, r.call_addr_offset * 8, l.id, 0))
            r.buffer[r.call_len_offset] = (
                (r.buffer[r.call_len_offset] & (0xffff << 48)) +
                buf_len)
            r.buffer[r.call_addr_offset] &= (0xffff << 48)

            r.call_addr_offset = None
            r.call_len_offset = None

    def flush_exe(self):
        ind = self.levels[0].indent

        self.pop_until(ind)
        if len(self.levels[0].buffer):
            l = self.levels.pop()
            l.finish()
            self.completed.append(l)

            self.levels.append(Level(ind))
            self.set_l()

        if not len(self.exe):
            return

        if self.last_exe is None:
            print("# Trying to add multiple CSs to an exe line, becoming confused")
            return

        if len(self.completed):
            p = self.completed[-1]
            assert(p.indent == ind)

            self.exe[self.last_exe] += [p.id, p.offset()]

        self.last_exe = None

    def add_shaders(self, shaders):
        for sh in shaders:
            qwords = assemble_shader(shaders[sh])
            sh = sh.lower()

            a = Alloc(len(qwords) * 8, flags=0x2017)
            a.buffer = qwords
            self.allocs[sh] = a

    def interpret(self, text):
        text = text.split("\n")

        old_indent = None

        for orig_line in text:
            #print(orig_line, file=sys.stderr)

            line = orig_line.split("@")[0].expandtabs().rstrip().lower()
            if not line:
                continue

            indent = len(line) - len(line.lstrip())
            line = line.lstrip()

            if old_indent is None:
                self.levels.append(Level(indent))
            elif indent != old_indent:
                if indent > old_indent:
                    assert(self.is_call)

                    self.levels.append(Level(indent))
                else:
                    self.pop_until(indent)

            self.set_l()

            old_indent = indent
            self.is_call = False

            given_code = None

            # TODO: Check against this to test the disassembler?
            if re.match(r"[0-9a-f]{16} ", line):
                given_code = int(line[:16], 16)
                line = line[16:].lstrip()

            s = [x.strip(",") for x in line.split()]

            for i in range(len(s)):
                if s[i].startswith("$"):
                    if s[i] == "$.":
                        buf = self.l
                    else:
                        alloc_id = s[i][1:]
                        buf = self.allocs[alloc_id]
                    self.reloc.append((self.l.id, self.l.offset(),
                                       buf.id, 0))
                    s[i] = "#0x0"

            def is_num(str):
                return re.fullmatch(r"[0-9]+", str)

            if s[0].endswith(":") or (len(s) == 1 and is_num(s[0])):
                label = s[0]
                if s[0].endswith(":"):
                    label = label[:-1]

                if is_num(label):
                    label = int(label)
                    if label in self.l.num_refs:
                        self.l.process_relocs(self.l.num_refs[label], self.l.offset())
                        del self.l.num_refs[label]
                    self.l.num_labels[label] = self.l.offset()
                else:
                    if label in self.l.labels:
                        print("Label reuse is not supported for non-numeric labels")
                    self.l.labels[label] = self.l.offset()

                s = s[1:]
                if not len(s):
                    continue

            def hx(word):
                return int(word, 16)

            def reg(word):
                return hx(word[1:])

            def val(word):
                value = int(word.strip("#"), 0)
                assert(value < (1 << 48))
                return value

            sk = True

            if s[0] == "!cs":
                assert(len(s) == 2)
                self.flush_exe()
                self.last_exe = len(self.exe)
                self.exe.append(["exe", int(s[1])])
                continue
            elif s[0] == "!parallel":
                assert(len(s) == 2)
                self.flush_exe()
                self.last_exe = len(self.exe) - 1
                self.exe[-1] += [int(s[1])]
                continue
            elif s[0] == "!alloc":
                assert(len(s) == 3 or len(s) == 4)
                alloc_id = s[1]
                size = int(s[2])
                flags = val(s[3]) if len(s) == 4 else 0x200f
                self.allocs[alloc_id] = Alloc(size, flags)
                continue
            elif s[0] in ("!dump", "!delta"):
                assert(len(s) == 4)
                alloc_id = s[1]
                offset = val(s[2])
                size = val(s[3])
                mode = "hex" if s[0] == "!dump" else "delta"
                self.exe.append(("dump", self.allocs[alloc_id].id,
                                 offset, size, mode))
                continue
            elif s[0] == "movp":
                assert(len(s) == 3)
                assert(s[1][0] == "x")
                addr = reg(s[1])
                # Can't use val() as that has a max of 48 bits
                value = int(s[2].strip("#"), 0)

                self.l.buffer.append((2 << 56) | (addr << 48) | (value & 0xffffffff))
                self.l.buffer.append((2 << 56) | ((addr + 1) << 48)
                                       | ((value >> 32) & 0xffffffff))
                continue
            elif s[0] == "regdump":
                assert(len(s) == 2)
                assert(s[1][0] == "x")
                dest = reg(s[1])

                # Number of registers to write per instruction
                regs = 16

                cmd = 21
                value = (dest << 40) | (((1 << regs) - 1) << 16)

                for i in range(0, 0x60, regs):
                    code = (cmd << 56) | (i << 48) | value | (i << 2)
                    self.l.buffer.append(code)

                del cmd, value
                continue

            elif s[0] == "unk":
                if len(s) == 2:
                    h = hx(s[1])
                    cmd = h >> 56
                    addr = (h >> 48) & 0xff
                    value = h & 0xffffffffffff
                else:
                    assert(len(s) == 4)
                    cmd = hx(s[2])
                    addr = hx(s[1])
                    value = val(s[3])
            elif s[0] == "nop":
                if len(s) == 1:
                    addr = 0
                    value = 0
                    cmd = 0
                else:
                    assert(len(s) == 3)
                    addr = hx(s[1])
                    value = val(s[2])
                    cmd = 0
            elif s[0] == "mov" and s[2][0] in "xw":
                # This is actually an addition command
                assert(len(s) == 3)
                assert(s[1][0] == s[2][0])
                cmd = { "x": 17, "w": 16 }[s[1][0]]
                addr = reg(s[1])
                value = reg(s[2]) << 40
            elif s[0] == "mov":
                assert(len(s) == 3)
                cmd = { "x": 1, "w": 2 }[s[1][0]]
                addr = reg(s[1])
                value = val(s[2])
            elif s[0] == "add":
                assert(len(s) == 4)
                assert(s[1][0] == s[2][0])
                assert(s[1][0] in "wx")
                cmd = 16 if s[1][0] == "w" else 17
                addr = reg(s[1])
                value = (reg(s[2]) << 40) | (val(s[3]) & 0xffffffff)
            elif s[0] == "endpt":
                assert(len(s) == 2)
                types = {"compute": 1, "fragment": 2, "blit": 3, "vertex": 13}
                name = s[1]
                cmd = 34
                addr = 0
                value = types[name] if name in types else int(name, 0)
            elif s[0] == "wait":
                assert(len(s) == 2)
                cmd = 3
                addr = 0
                if s[1] == "all":
                    value = 255
                else:
                    value = sum(1 << int(x) for x in s[1].split(","))
                value <<= 16
            elif s[0] == "slot":
                assert(len(s) == 2)
                cmd = 23
                addr = 0
                value = int(s[1], 0)
            elif s[0] == "add":
                # TODO: unk variant
                assert(len(s) == 4)
                assert(s[1][0] == "x")
                assert(s[2][0] == "x")
                cmd = 17
                addr = reg(s[1])
                v = val(s[3])
                assert(v < (1 << 32))
                assert(v >= (-1 << 31))
                value = (reg(s[2]) << 40) | (v & 0xffffffff)
            elif s[0] == "idvs":
                assert(len(s) == 7)
                r1 = reg(s[1])
                r2 = reg(s[2])
                assert(s[3] == "mode")
                mode = int(s[4])
                assert(s[5] == "index")
                index = int(s[6])

                cmd = 6
                addr = 0
                value = (r2 << 40) | (r1 << 32) | (index << 8) | mode
            elif s[0] == "str" and s[1] in ("cycles", "timestamp"):
                assert(len(s) == 3 or len(s) == 4)
                assert(s[2][0] == "[")
                assert(s[-1][-1] == "]")
                s = [x.strip("[]") for x in s]
                assert(s[2][0] == "x")

                type_ = 1 if s[1] == "cycles" else 0
                dest = reg(s[2])
                if len(s) == 4:
                    offset = val(s[3])
                else:
                    offset = 0

                cmd = 40
                addr = 0
                value = (dest << 40) | (type_ << 32) | to_int16(offset)
            elif s[0] in ("ldr", "str"):
                assert(len(s) == 3 or len(s) == 4)
                assert(s[2][0] == "[")
                assert(s[-1][-1] == "]")
                s = [x.strip("[]") for x in s]
                assert(s[1][0] in "xw")
                assert(s[2][0] == "x")

                mask = 3 if s[1][0] == "x" else 1

                # Names are correct for str, but inverted for ldr
                src = reg(s[1])
                dest = reg(s[2])
                if len(s) == 4:
                    offset = val(s[3])
                else:
                    offset = 0

                cmd = 20 if s[0] == "ldr" else 21
                addr = src
                value = (dest << 40) | (mask << 16) | to_int16(offset)
            elif s[0] == "b" or s[0].startswith("b."):
                # For unconditional jumps, use w00 as a source register if it
                # is not specified
                if s[0] == "b" and (len(s) == 2 or
                                    (len(s) == 3 and
                                     s[1] in ("back", "skip"))):
                    s = [s[0], "w00", *s[1:]]

                assert(len(s) == 3 or (len(s) == 4 and s[2] in ("back", "skip")))
                assert(s[1][0] == "w")

                ops = {
                    "b.gt": 0, "b.le": 1,
                    "b.eq": 2, "b.ne": 3,
                    "b.lt": 4, "b.ge": 5,
                    "b": 6, "b.al": 6,
                }

                src = reg(s[1])
                if len(s) == 4:
                    offset = val(s[3])
                    if s[2] == "back":
                        offset = -1 - offset
                else:
                    label = s[2]
                    if re.fullmatch(r"[0-9]+b", label):
                        label = int(label[:-1])
                        assert(label in self.l.num_labels)
                        offset = resolve_rel(self.l.num_labels[label],
                                             self.l.offset())
                    elif re.fullmatch(r"[0-9]+f", label):
                        label = int(label[:-1])
                        if label not in self.l.num_refs:
                            self.l.num_refs[label] = []
                        self.l.num_refs[label].append((label, self.l.offset(), "rel"))
                        offset = 0
                    else:
                        assert(not re.fullmatch(r"[0-9]+", label))
                        self.l.label_refs.append((label, self.l.offset(), "rel"))
                        offset = 0

                cmd = 22
                addr = 0
                value = (src << 40) | (ops[s[0]] << 28) | to_int16(offset)

            elif s[0] == "strev(unk)":
                s = [x.strip("[]()") for x in s]
                unk = int(s[2])
                val = reg(s[3])
                dest = reg(s[4])
                unk2 = hx(s[6])

                cmd = 37
                addr = unk
                value = (dest << 40) | (val << 32) | unk2
            elif s[0] in ("evwait.ls", "evwait.hi"):
                assert(len(s) == 3)
                assert(s[1][0] in "wx")
                assert(s[2][0] == "[")
                assert(s[-1][-1] == "]")
                s = [x.strip("[]()") for x in s]
                src = reg(s[2])
                val = reg(s[1])
                cond = 1 if s[0] == "evwait.hi" else 0

                cmd = 53 if s[1][0] == "x" else 39
                addr = 0
                value = (src << 40) | (val << 32) | (cond << 28)
            elif s[0] == "call":
                ss = [x for x in s if x.find('(') == -1 and x.find(')') == -1]
                assert(len(ss) == 3)
                assert(ss[1][0] == "w")
                assert(ss[2][0] == "x")
                cmd = 32
                addr = 0
                num = reg(ss[1])
                target = reg(ss[2])
                value = (num << 32) | (target << 40)

                l = self.l

                cur = len(l.buffer)
                for ofs in range(cur - 2, cur):
                    if l.buffer[ofs] >> 48 == 0x148:
                        l.call_addr_offset = ofs
                    if l.buffer[ofs] >> 48 == 0x24a:
                        l.call_len_offset = ofs
                assert(l.call_addr_offset is not None)
                assert(l.call_len_offset is not None)

                self.is_call = True
            else:
                print("Unknown command:", orig_line, file=sys.stderr)
                # TODO remove
                cmd = 0
                addr = 0
                value = 0
                sk = False
                pass

            code = (cmd << 56) | (addr << 48) | value

            if given_code and code != given_code:
                print(f"Mismatch! {hex(code)} != {hex(given_code)}, {orig_line}")

            self.l.buffer.append(code)

            del cmd, addr, value

            if False and not sk:
                print(orig_line, file=sys.stderr)
                print(indent, s, hex(code) if sk else "", file=sys.stderr)

        self.pop_until(self.levels[0].indent)
        self.flush_exe()

    def __repr__(self):
        r = []
        r += [str(self.allocs[x]) for x in self.allocs]
        r += [str(x) for x in self.completed]
        r += [fmt_reloc(x) for x in self.reloc]
        r += [fmt_exe(x) for x in self.exe]
        return "\n".join(r)

def interpret(text):
    c = Context()
    c.add_shaders(shaders)
    c.interpret(text)
    print(c)

def run(text):
    c = Context()
    c.add_shaders(shaders)
    c.interpret(text)
    #print(c)

    p = subprocess.run(["csf_test", "/dev/stdin"],
                       input=str(c), text=True)

def rebuild():
    try:
        p = subprocess.run(["rebuild-mesa"])
        if p.returncode != 0:
            return False
    except FileNotFoundError:
        pass
    return True

def go(text):
    if not rebuild():
        return

    run(text)

os.environ["CSF_QUIET"] = "1"

go(get_cmds(""))

#rebuild()
#for c in range(256):
#    print(c, end=":")
#    sys.stdout.flush()
#    cmd = f"UNK 00 {hex(c)[2:]} 0x00000000"
#    run(get_cmds(cmd))

#interpret(cmds)
#go(cmds)
