#!/usr/bin/env python

import sys
import angr

def exit_false():
    """Simple exit function returning False"""
    return False


class Menu(object):
    """Class for showing the menu item"""
    def __init__(self):
        self.m_menuitems = {}
        self.add_item(0, 'exit', exit_false)

    def add_item(self, key, value, func):
        """Method to add a menu item. to the Dictionary"""
        l_func_obj = (value, func)
        self.m_menuitems[key] = l_func_obj

    def get_choice(self):
        """Method to get the user input from the list of menu items"""
        for item in self.m_menuitems:
            print '%d : %s' % (item, self.m_menuitems[item][0])
        return int(raw_input("Please enter : "))


class FuncPaths(object):  # pylint: disable=too-few-public-methods
    """Class for Function Paths"""
    def __init__(self):
        self.m_paths = []

    def find_paths(self, path):
        """Method to recursively identify paths"""
        l_path = path.step()
        if len(l_path) == 0:
            self.m_paths.append(path)
        else:
            for pth in l_path:
                self.find_paths(pth)

    def get_paths(self):
        """Method to get analysed paths"""
        return self.m_paths


class Target(Menu):
    """Main Class for binary function paths analysis"""
    def __init__(self, pBinary):
        self._mBinary = pBinary
        self._mProj = angr.Project(pBinary, load_options={'auto_load_libs': False})
        self._mCfg = self._mProj.analyses.CFG()
        self._mFuncList = dict(self._mProj.kb.functions)
        self.paths = []
        Menu.__init__(self)
        self.add_item(1, 'list functions', self.display_functions)
        self.add_item(2, 'analyse a function paths', self.analyse_func_paths)
        self.add_item(3, 'compare two functions', self.analyse_func_paths)

    def _findPaths_(self, p):
        pp = p.step()
        if len(pp) == 0:
            self.paths.append(p)
        else:
            for i in pp:
                self._findPaths_(i)

    def analyse_func_paths(self):
        del self.paths[:]
        f_addr = 0
        try:
            f_addr = int(raw_input("Please enter a function address in hex format: "), 16)
            print 'Start analyzing for 0x%x ...' % (f_addr)
        except ValueError, e:
            print "'%s' is not a valid function address" % e.args[0].split(": ")[1]
            return True

        state = self._mProj.factory.blank_state(addr=f_addr)
        print 'Processing...'

        path = self._mProj.factory.path(state)
        if path.addr != f_addr:
            print 'for some reason, the path address is not correct.'

        paths_obj = FuncPaths()

        self._findPaths_(path)
        print 'Number of paths found: %d' % len(self.paths)
        for s in self.paths:
            print 'Constrant: %s' % s.state.se.constraints

        return True

    def compare_two_functins(self):
        return True

    def display_functions(self):
        for f in self._mFuncList:
            s = self._mFuncList[f]
            print 'Address [%#x] \t%s ' % (s.addr, s.name)
        return True

    def execute_cmd(self, cmd):
        if cmd in self.m_menuitems:
            return self.m_menuitems[cmd][1]()
        else:
            print 'unsupport cmd '
            return True

def show_menu(pTarget):
    is_valid = 0
    while not is_valid:
        try:
            choice = pTarget.get_choice()
            is_valid = 1
        except ValueError, e:
            print "'%s' is an invalid input" % e.args[0].split(": ")[1]
    return pTarget.execute_cmd(choice)

def execute(file):
    print 'Provide binary: ' + file

    rc = True
    target = Target(file)

    while rc:
        rc = show_menu(target)
    print 'Good bye!'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "Please provide a binary file"
    else:
        execute(sys.argv[1])
