#!/usr/bin/env python

import sys, re
import subprocess as sp

def read_sym(exe):
    syms = []
    p = sp.Popen(['nm', '-n', '-C', '--defined-only', exe], stdout=sp.PIPE)
    for line in p.communicate()[0].decode().split('\n'):
        try:
            (_addr, _type, _name) = line.split()
            if _type not in (u'T', u't', u'W', u'w'):
                continue
            syms.append([_name, int(_addr, 16)])
        except:
            pass
    return syms

insns = {}

def check_insn(exe, sym, start, stop, patt):
    # function blacklist
    if sym in ('_init', '_fini', '__libc_csu_init', '__libc_csu_fini', 'frame_dummy'):
        return

    args = ['objdump', '-d', '-C', '--start-address', '0x%x' % start]
    if stop > start:
        args.extend(['--stop-address', '0x%x' % stop])
    args.append(exe)
    p = sp.Popen(args, stdout=sp.PIPE, stderr=None)

    found = False
    for line in p.communicate()[0].decode().split('\n'):
        if line.endswith('<%s>:' % sym):
            found = True
            continue
        if not found:
            continue

        m = patt.match(line)
        if m is None:
            continue

        ofs = int(m.group(1), 16)
        insn = m.group(3)

        # we only check first 5 insns (for mcount patching)
        if ofs > start + 5:
            break

        # unsupported insns
        if insn[0] == 'j' or insn in ('callq', 'repz'):
            print("%s has %s" % (sym, insn))

        if insn in insns:
            insns[insn] += 1
        else:
            insns[insn] = 1

if len(sys.argv) < 2:
    print("Usage: %s <objfile>" % sys.argv[0])
    sys.exit(0)

exe  = sys.argv[1]
syms = read_sym(exe)

# objdump re pattern:  offset         raw opcode        insn     args
patt = re.compile('\s*([0-9a-f]+):\s*([0-9a-f]{2} )*\s+([^ ]+)\s*(.*)')
i = 0
for s in syms:
    try:
        check_insn(exe, s[0], s[1], syms[i+1][1], patt)
    except:
        check_insn(exe, s[0], s[1], 0, patt)
    i += 1

for i in sorted(insns, key=lambda x:insns[x]):
    print("insn: %-7s  count:%4d" % (i, insns[i]))
