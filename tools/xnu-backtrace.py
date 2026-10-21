#!/usr/bin/env python3
"""Backtrace of a stopped QEMU guest from qemu-sweet.py --stack-words output.

usage: xnu-backtrace.py OUTDIR KERNEL

Reads OUTDIR/regs.txt (PC, X29, X30) and OUTDIR/stack.txt (`x /Ngx SP` dump),
follows the AArch64 frame-pointer chain (frame record = [previous fp, lr]) and
symbolizes each return address with llvm-nm.
"""
import bisect, re, subprocess, sys

out, kernel = sys.argv[1], sys.argv[2]
regs = open(f'{out}/regs.txt').read()
reg = lambda n: int(re.search(rf'\b{n}=([0-9a-f]{{16}})', regs).group(1), 16)

mem = {}
for line in open(f'{out}/stack.txt'):
    m = re.match(r'([0-9a-f]+):((?:\s+0x[0-9a-f]+)+)', line.strip())
    if m:
        base = int(m.group(1), 16)
        for i, w in enumerate(m.group(2).split()):
            mem[base + 8 * i] = int(w, 16)

syms = []
for line in subprocess.run(['llvm-nm', '-n', kernel], capture_output=True, text=True).stdout.splitlines():
    p = line.split()
    if len(p) == 3 and p[1] in 'tTsS':
        syms.append((int(p[0], 16), p[2]))
addrs = [a for a, _ in syms]


def name(a):
    i = bisect.bisect_right(addrs, a) - 1
    return f'{syms[i][1]}+0x{a - syms[i][0]:x}' if i >= 0 else hex(a)


print(f'pc  {reg("PC"):#018x} {name(reg("PC"))}')
print(f'lr  {reg("X30"):#018x} {name(reg("X30"))}')
fp, seen = reg('X29'), set()
for depth in range(64):
    if fp in seen or fp not in mem or fp + 8 not in mem:
        if fp:
            print(f'(frame {fp:#x} outside the dumped stack)')
        break
    seen.add(fp)
    prev, lr = mem[fp], mem[fp + 8]
    if not lr:
        break
    print(f'#{depth:<2} {lr:#018x} {name(lr)}')
    fp = prev
