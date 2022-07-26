#!/usr/bin/env python3

import re
import sys

cmds = """
!cs 0
mov x48, #0x5ffba00040
mov w4a, #0xc8
job w4a (25 instructions), x48 (0x5ffba00040)
  mov x56, #0x5fffa3d5c0
  mov x48, #0x5fffa3d5c0
  str x56, [x48, 18]
"""

class Level:
    id = 0

    def __init__(self, indent):
        self.id = Level.id
        Level.id += 1
        self.indent = indent
        self.buffer = []
        self.call_addr_offset = None
        self.call_len_offset = None

    def __repr__(self):
        buf = " ".join(hex(x) for x in self.buffer)
        return f"buffer {self.id} {len(self.buffer) * 8} {buf}"

def fmt_reloc(r):
    dst, offset, src = r
    return f"reloc {dst}+{offset} {src}"

def fmt_cs(c):
    buf, len = c
    return f"cs {buf} {len}"

levels = []
completed = []
reloc = []
cs = []

def pop_until(indent):
    while levels[-1].indent != indent:
        l = levels.pop()
        completed.append(l)

        if len(levels):
            buf_len = len(l.buffer) * 8

            r = levels[-1]
            reloc.append([r.id, r.call_addr_offset * 8, l.id])
            r.buffer[r.call_len_offset] = (
                r.buffer[r.call_len_offset] & (0xffff << 48) +
                buf_len)
            r.buffer[r.call_addr_offset] &= (0xffff << 48)

            r.call_addr_offset = None
            r.call_len_offset = None

def add_cs():
    l = levels.pop()
    completed.append(l)
    cs.append([l.id, len(l.buffer) * 8])

def interpret(text):
    old_indent = None

    for orig_line in text:
        #print(orig_line, file=sys.stderr)

        line = orig_line.split("@")[0].expandtabs().rstrip()
        if not line:
            continue

        indent = len(line) - len(line.lstrip())
        line = line.lstrip()

        if old_indent is None:
            levels.append(Level(indent))
        elif indent != old_indent:
            if indent > old_indent:
                levels.append(Level(indent))
            else:
                pop_until(indent)

        old_indent = indent

        given_code = None

        # TODO: Check against this to test the disassembler?
        if re.match(r"[0-9a-fA-F]{16} ", line):
            given_code = int(line[:16], 16)
            line = line[16:].lstrip()

        s = [x.strip(",") for x in line.split()]

        def hx(word):
            return int(word, 16)

        def reg(word):
            return hx(word[1:])

        def val(word):
            value = int(word.strip("#"), 0)
            assert(value < (1 << 48))
            return value

        sk = True

        if s[0] == "UNK":
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
        elif s[0] == "str":
            assert(len(s) == 4)
            assert(s[2][0] == "[")
            assert(s[3][-1] == "]")
            s = [x.strip("[]") for x in s]
            assert(s[1][0] == "x")
            assert(s[2][0] == "x")

            val = reg(s[1])
            dest = reg(s[2])
            offset = hx(s[3])

            cmd = 21
            addr = val
            value = (dest << 40) | (offset & 0xffffffff) | (3 << 16)
        elif s[0] == "strev(unk)":
            s = [x.strip("[]()") for x in s]
            unk = int(s[2])
            val = reg(s[3])
            dest = reg(s[4])
            unk2 = hx(s[6])

            cmd = 37
            addr = unk
            value = (dest << 40) | (val << 32) | unk2
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

            l = levels[-1]

            cur = len(l.buffer)
            for ofs in range(cur - 2, cur):
                if l.buffer[ofs] >> 48 == 0x148:
                    l.call_addr_offset = ofs
                if l.buffer[ofs] >> 48 == 0x24a:
                    l.call_len_offset = ofs
            assert(l.call_addr_offset is not None)
            assert(l.call_len_offset is not None)
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

        levels[-1].buffer.append(code)

        del cmd, addr, value

        if False and not sk:
            print(orig_line, file=sys.stderr)
            print(indent, s, hex(code) if sk else "", file=sys.stderr)

interpret(cmds.split("\n"))
pop_until(levels[0].indent)
add_cs()

print("\n".join(str(x) for x in completed))
print("\n".join(fmt_reloc(x) for x in reloc))
print("\n".join(fmt_cs(c) for c in cs))
