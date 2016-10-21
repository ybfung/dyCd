#!/usr/bin/env python

import angr
import sys

def execute(file):
    print 'Provide binary: ' + file 
    proj = angr.Project(file, load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFG()
    b_funcs = dict(proj.kb.functions)
    for f in b_funcs:
        s = b_funcs[f]
        print 'Address [%#x] \t%s ' % ( s.addr, s.name)






if __name__ == '__main__':
    if( len(sys.argv) < 2):
        print "Please provide a binary file"
    else:
        execute(sys.argv[1])
