#!/usr/bin/env python

import angr
import sys


class Menu():
    def __init__(self):
        self.menuItems = {0: 'exit'}

    def add_item(self,key,value):
        self.menuItems[key] = value

    def get_choice(self):
        for f in self.menuItems:
            print '%d : %s' % ( f, self.menuItems[f])
        return int( raw_input("Please enter : " )) 


class Target(Menu):
    def __init__(self,pBinary):
        self._mBinary = pBinary
        self._mProj = angr.Project(pBinary, load_options={'auto_load_libs': False})
        self._mCfg = self._mProj.analyses.CFG()
        self._mFuncList = dict(self._mProj.kb.functions)
        Menu.__init__(self)
        self.add_item(1,'list functions')
        self.add_item(2,'analyse a function paths')

    def analyse_func_paths(self):
        addr = 0
        try:
            addr = hex(int( raw_input("Please enter a function address in hex format: " ),16))  
            print 'Start analyzing for %d ...' % (addr)
        except ValueError, e :
            print ("'%s' is not a valid function address" % e.args[0].split(": ")[1])
        return True

    def display_functions(self):
        for f in self._mFuncList:
            s = self._mFuncList[f]
            print 'Address [%#x] \t%s ' % ( s.addr, s.name)

    def execute_cmd(self,cmd):
        if cmd == 0:
            return False
        if cmd == 1:
            self.display_functions()
            return True
        if cmd == 2:
            self.analyse_func_paths()
            return True
        else:
            print 'unsupport cmd '
            return True


def show_menu(pTarget):
    is_valid = 0
    while not is_valid:
        try:
            choice = pTarget.get_choice()
            is_valid = 1
        except ValueError, e :
            print ("'%s' is an invalid input" % e.args[0].split(": ")[1])
    return pTarget.execute_cmd(choice) 
    

        
def execute(file):
    print 'Provide binary: ' + file 
    #proj = angr.Project(file, load_options={'auto_load_libs': False})
    #cfg = proj.analyses.CFG()
    #b_funcs = dict(proj.kb.functions)

    rc = True
    target = Target(file)

    while rc == True:
        #if menu(b_funcs) < 0:
        rc = show_menu(target)
    print 'Good bye!'


if __name__ == '__main__':
    if( len(sys.argv) < 2):
        print "Please provide a binary file"
    else:
        execute(sys.argv[1])
