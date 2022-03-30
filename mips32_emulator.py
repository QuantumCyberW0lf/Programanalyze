#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pexpect, re, sys, os, argparse, sys, time

class Emulating(object):
    def __init__(self:object,db=False)->None:
        self.db=db
        self.spawn=pexpect.spawn('spim',encoding="utf-8")
        self._pexpect('\(spim\)')
        if not '(spim)' in self.spawn.after:
            print("[!] Spim is not installed: {}".format(self.spawn.after))
            sys.exit(-1)

    def _send_cmd(self:object,line:str)->None:
        if not self.spawn.isalive():
            print("[-] Child process is not alive")
            sys.exit(-1)
        if self.db:
            print("[*] === Sending === [*] {}".format(line))
        self.spawn.sendline(line)

    def _pexpect(self:object,pattern:str,timeout=-1,size=None)->int:
        if not self.spawn.isalive():
            print("[-] Child process is not alive")
            sys.exit(-1)
        if self.db:
            print("[*] === Expecting === [*] {}".format(pattern))
        ind = self.spawn.expect(pattern,timeout=timeout,searchwindowsize=size)
        if self.db:
            print("[*] === Before === [*] {}".format(self.spawn.before))
            print("[*] === After  === [*] {}".format(self.spawn.after))
        return ind

    def load_file(self:object,file_name:str)->None:
        self._send_cmd("load \"{}\"".format(file_name))
        ind = self._pexpect(['Cannot open file.*\(spim\) ','\(spim\)',pexpect.EOF,
            pexpect.TIMEOUT],timeout=10)
        if ind == 0:
            print("[-] Could not load assembly file {}".format(file_name))
            sys.exit(-1)
        elif ind == 1: pass #not implemented
        elif ind == 2:
            print("[-] End of File")
            sys.exit(-1)
        elif ind == 3:
            print("[-] Time out")
            sys.exit(-1)
        else:
            print("[-] Something went wrong")
            sys.exit(-1)

    def run_spim(self:object,timeout=10,timeoutfatal=False)->str:
        self._send_cmd('run')
        ind = self._pexpect(['.*\(spim\) ',pexpect.EOF,pexpect.TIMEOUT],timeout=timeout)
        if ind == 0: pass
        elif ind == 1:
            print("[-] End of File")
            sys.exit(-1)
        elif ind == 2:
            ind = self._pexpect(['.*',pexpect.EOF,pexpect.TIMEOUT],timeout = .1)
            if ind == 0 or ind == 1:
                return self.spawn.before + self.spawn.after
            else:
                return ""
        else:
            print('[-] Something went wrong')
            sys.exit(-1)

    def reg_eval(self:object,register:str,timeout=10)->hex:
       self._send_cmd('print {}'.format(register))
       ind = self._pexpect(['.*Reg.*0x([0-9a-f])+.*\(spim\) ',
           '.*Unkown label:.*\(spim\) ',pexpect.EOF,pexpect.TIMEOUT],timeout=timeout)
       if ind == 0:
           match = re.search('.*Reg.* = (0x[0-9a-f]+) .*\(spim\) ',self.spawn.after,
                   re.DOTALL)
           val = hex(int(match.group(1),0))
           return val
       elif ind == 1:
           print("[-] Unknown label: {}".format(repr(register)))
           sys.exit(-1)
       elif ind == 2:
           print("[-] End of File")
           sys.exit(-1)
       elif ind == 3:
           print("[-] Time out")
           sys.exit(-1)
       else:
           print('[-] Something went wrong')
           sys.exit(-1)

    def quit_prog(self:object,timeout=10)->None:
        self._send_cmd('quit')
        ind = self._pexpect([pexpect.EOF,pexpect.TIMEOUT],timeout=timeout)
        if ind == 0: pass
        elif ind == 1:
            print("[-] Time out")
            sys.exit(-1)
        else:
            print('[-] Something went wrong')
            sys.exit(-1)

def main()->None:
    des="MIPS32 Emulator with Python3."
    epi="Built by Qu@ntumCyb3rW01f/Qu@ntumH@ck3r Thi Altenschmidt"
    parser=argparse.ArgumentParser(description=des,epilog=epi)
    parser.add_argument("--file","-f",action="store",type=str,dest="ass_file",
            help="Specify an assembly file to load.",required=True)
    given_args = parser.parse_args()
    ass_file = given_args.ass_file

    if not os.path.exists(ass_file):
        print("[-] File {} doesn't exist".format(repr(ass_file)))
        sys.exit(-1)

    emul = Emulating(db=False)
    emul.load_file(ass_file)
    emul.run_spim()

    register_list = ["$s0","$s1","$s2","$s3","$s4"]
    for register in register_list:
        print("Register {}  has value: {}".format(register,emul.reg_eval(register)))

    time.sleep(0.5)
    print("[*] Quitting program...")
    time.sleep(0.5)
    emul.quit_prog()

if __name__ == "__main__":
    main()
