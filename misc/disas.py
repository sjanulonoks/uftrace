#!/usr/bin/env python

import sys
import subprocess as sp

start = 0
stop  = 0

def objdump(exe, sym):
    global start, stop
    syms = []
    p1 = sp.Popen(['nm', '-n', '-C', '--defined-only', exe], stdout=sp.PIPE)
    p2 = sp.Popen(['grep', '-A', '1', sym], stdin=p1.stdout, stdout=sp.PIPE)
    for line in p2.communicate()[0].decode().split('\n'):
        if start == 0:
            start = int(line.split()[0], 16)
        elif stop == 0:
            stop  = int(line.split()[0], 16)
        
    arg = ['objdump', '-d', '-C', '--start-address', '0x%x' % start]
    if stop != 0:
        arg.extend(['--stop-address', '0x%x' % stop])
    arg.append(exe)
    sp.call(arg)

if len(sys.argv) < 3:
    print("Usage: %s <objfile> <func>" % sys.argv[0])
    sys.exit(0)

objdump(sys.argv[1], sys.argv[2])
