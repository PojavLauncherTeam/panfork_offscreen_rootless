#!/usr/bin/env python3

import os
import re
import subprocess
import sys

cmds = """
!cs 2
!alloc x 4096
!alloc ev 4096 0x8200f

mov x50, $x
add x52, x50, 0x200

slot 2
mov x5a, $ev

wait 1
add x48, x5a, 0x400
mov x4a, #0x112233445566

mov x5e, 0x605040302010

mov x00, 10
mov x10, 1
mov x20, 2
mov x30, 3
mov x40, 4

@mov x4a, 0x100000000

@mov x4a, 0xff000000
@mov x4a, 0x100000
@mov x4a, 0

regdump x50

mov w22, 5
add x24, x52, 0x200

str w22, [x24]
add x24, x24, 4
add w22, w22, -1
b.ne w22, back 3

regdump x52

!dump x 0 4096
!dump ev 0 4096
"""

class Buffer:
    id = 0

    def __init__(self):
        self.id = Buffer.id
        Buffer.id += 1

class Level(Buffer):
    def __init__(self, indent):
        super().__init__()

        self.indent = indent
        self.buffer = []
        self.call_addr_offset = None
        self.call_len_offset = None

    def __repr__(self):
        buf = " ".join(hex(x) for x in self.buffer)
        return f"buffer {self.id} {len(self.buffer) * 8} {buf}"

class Alloc(Buffer):
    def __init__(self, size, flags=0x200f):
        super().__init__()

        self.size = size
        self.flags = flags

    def __repr__(self):
        return f"alloc {self.id} {self.size} {hex(self.flags)}"

def fmt_reloc(r):
    dst, offset, src = r
    return f"reloc {dst}+{offset} {src}"

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

            buf_len = len(l.buffer) * 8

            r = self.l
            self.reloc.append((r.id, r.call_addr_offset * 8, l.id))
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

            self.exe[self.last_exe] = (
                *self.exe[self.last_exe], p.id, len(p.buffer) * 8)

        self.last_exe = None

    def interpret(self, text):
        text = text.split("\n")

        old_indent = None

        for orig_line in text:
            #print(orig_line, file=sys.stderr)

            line = orig_line.split("@")[0].expandtabs().rstrip()
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
            if re.match(r"[0-9a-fA-F]{16} ", line):
                given_code = int(line[:16], 16)
                line = line[16:].lstrip()

            s = [x.strip(",") for x in line.split()]

            for i in range(len(s)):
                if s[i].startswith("$"):
                    alloc_id = s[i][1:]
                    self.reloc.append((self.l.id, len(self.l.buffer) * 8,
                                       self.allocs[alloc_id].id))
                    s[i] = "#0x0"

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
                self.exe.append(("exe", int(s[1])))
                continue
            elif s[0] == "!alloc":
                assert(len(s) == 3 or len(s) == 4)
                alloc_id = s[1]
                size = int(s[2])
                flags = val(s[3]) if len(s) == 4 else 0x200f
                self.allocs[alloc_id] = Alloc(size, flags)
                continue
            elif s[0] == "!dump":
                assert(len(s) == 4)
                alloc_id = s[1]
                offset = val(s[2])
                size = val(s[3])
                self.exe.append(("dump", self.allocs[alloc_id].id,
                                 offset, size))
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

            elif s[0] == "UNK":
                assert(len(s) == 4)
                cmd = hx(s[2])
                addr = hx(s[1])
                value = val(s[3])
            elif s[0] == "nop":
                if len(s) == 1:
                    code = 0
                else:
                    assert(len(s) == 3)
                    addr = hx(s[1])
                    value = val(s[2])
                    code = (addr << 48) | value
            elif s[0] == "mov" and s[2][0] == "x":
                # This is actually an addition command
                assert(len(s) == 3)
                assert(s[1][0] == "x")
                cmd = 17
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
            elif s[0] == "iter":
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
            elif s[0] in ("ldr", "str"):
                assert(len(s) == 3 or len(s) == 4)
                assert(s[2][0] == "[")
                assert(s[-1][-1] == "]")
                s = [x.strip("[]") for x in s]
                assert(s[1][0] in "xw")
                assert(s[2][0] == "x")

                mask = 3 if s[1][0] == "x" else 1

                src = reg(s[1])
                dest = reg(s[2])
                if len(s) == 4:
                    offset = val(s[3])
                else:
                    offset = 0

                cmd = 20 if s[0] == "ldr" else 21
                addr = src
                value = (dest << 40) | (offset & 0xffff) | (mask << 16)
            elif s[0] == "b" or s[0].startswith("b."):
                assert(len(s) == 4)
                assert(s[1][0] == "w")
                assert(s[2] in ("back", "skip"))

                ops = {
                    "b.gt": 0, "b.le": 1,
                    "b.eq": 2, "b.ne": 3,
                    "b.lt": 4, "b.ge": 5,
                    "b": 6, "b.al": 6,
                }

                src = reg(s[1])
                offset = val(s[3])
                if s[2] == "back":
                    offset = -1 - offset
                assert(offset < 36768)
                assert(offset >= -32768)

                cmd = 22
                addr = 0
                value = (src << 40) | (ops[s[0]] << 28) | (offset & 0xffff)

            elif s[0] == "strev(unk)":
                s = [x.strip("[]()") for x in s]
                unk = int(s[2])
                val = reg(s[3])
                dest = reg(s[4])
                unk2 = hx(s[6])

                cmd = 37
                addr = unk
                value = (dest << 40) | (val << 32) | unk2
            elif s[0] == "evwait":
                assert(len(s) == 3)
                assert(s[2][0] == "[")
                assert(s[-1][-1] == "]")
                s = [x.strip("[]()") for x in s]
                src = reg(s[2])
                val = reg(s[1])

                cmd = 39
                addr = 0
                value = (src << 40) | (val << 32) | 0x10000000
            elif s[0] == "job":
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
                print("unk", orig_line, file=sys.stderr)
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
    c.interpret(text)
    print(c)

def go(text):
    try:
        p = subprocess.run(["rebuild-mesa"])
        if p.returncode != 0:
            return
    except FileNotFoundError:
        pass

    c = Context()
    c.interpret(text)

    p = subprocess.run(["csf_test", "/dev/stdin"],
                       input=str(c), text=True)

os.environ["CSF_QUIET"] = "1"

#interpret(cmds)
go(cmds)
