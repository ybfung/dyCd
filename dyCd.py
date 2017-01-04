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
        self.add_item(3, 'compare two functions', self.compare_two_functins)

    def analyse_func_paths(self):
        """Perform a path analysis for a function address"""
        del self.paths[:]
        f_addr = 0
        try:
            f_addr = int(raw_input("Please enter a function address in hex format: "), 16)
            print 'Start analyzing for 0x%x ...' % (f_addr)
        except ValueError, ex:
            print "'%s' is not a valid function address" % ex.args[0].split(": ")[1]
            return True

        state = self._mProj.factory.blank_state(addr=f_addr)
        print 'Processing...'

        path = self._mProj.factory.path(state)
        if path.addr != f_addr:
            print 'for some reason, the path address is not correct.'

        paths_obj = FuncPaths()
        paths_obj.find_paths(path)
        found_paths = paths_obj.get_paths()
        print 'Number of paths found: %d' % len(found_paths)
        for pths in found_paths:
            print 'Constrant: %s' % pths.state.se.constraints

        return True

    def compare_two_functins(self):
        """Analyse two functions based on their paths similarities"""
        f_addr_a = 0
        f_addr_b = 0
        try:
            f_addr_a = int(raw_input("Please enter first function address in hex format: "), 16)
            #print 'Start analyzing for 0x%x ...' % (f_addr)
        except ValueError, ex:
            print "'%s' is not a valid function address" % ex.args[0].split(": ")[1]
            return True

        try:
            f_addr_b = int(raw_input("Please enter second function address in hex format: "), 16)
            #print 'Start analyzing for 0x%x ...' % (f_addr)
        except ValueError, ex:
            print "'%s' is not a valid function address" % ex.args[0].split(": ")[1]
            return True

        state_a = self._mProj.factory.blank_state(addr=f_addr_a)
        print 'Processing for 0x%x...' % (f_addr_a)
        path_a = self._mProj.factory.path(state_a)

        paths_obj_a = FuncPaths()
        paths_obj_a.find_paths(path_a)
        found_paths_a = paths_obj_a.get_paths()
        print 'Number of paths found : %d' % len(found_paths_a)
        for pths_a in found_paths_a:
            print 'Constrant: %s' % pths_a.state.se.constraints

        state_b = self._mProj.factory.blank_state(addr=f_addr_b)
        print 'Processing for 0x%x...' % (f_addr_b)
        path_b = self._mProj.factory.path(state_b)
        paths_obj_b = FuncPaths()
        paths_obj_b.find_paths(path_b)
        found_paths_b = paths_obj_b.get_paths()
        print 'Number of paths found: %d' % len(found_paths_b)
        for pths_b in found_paths_b:
            print 'Constrant: %s' % pths_b.state.se.constraints

        return True

    def display_functions(self):
        """List functions"""
        for func in self._mFuncList:
            func_obj = self._mFuncList[func]
            print 'Address [%#x] \t%s ' % (func_obj.addr, func_obj.name)
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
