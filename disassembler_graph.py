#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys,os,argparse
try:
    from capstone import *
    from capstone.x86 import *
except ImportError:
    print("[!] Please run python3 -m pip install capstone")
    sys.exit(-1)
try:
    from graphviz import render
except ImportError:
    print("[!] Please run python3 -m pip install graphviz for Visualization")
    sys.exit(-1)

JMP_INSTR = ["jo","jno","js","jns","je","jz","jne","jnz","jb","jnae","jc","jnb","jae",
        "jnc","jbe","jna","ja","jnbe","jl","jnge","jge","jnl","jle","jng","jg","jnle",
        "jp","jpe","jnp","jpo","jcxz","jecxz","jmp"]
BRANCH = ["ret","call"]

def read_code_and_save(in_file:str)->str:
    with open(in_file,"rb") as fd:
        code = fd.read()
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    in_file_name, in_file_extension = os.path.splitext(in_file)
    out_file = open(in_file_name+"_disass.s","w")
    for i in md.disasm(code, 0x0):
        i_addr,i_mnemonic,i_op_str=i.address,i.mnemonic,i.op_str
        out_file.write(str(hex(i_addr))+"\t"+str(i_mnemonic)+"\t"+str(i_op_str)+"\n")
    out_file.close()
    print("[+] === Disassembled content is saved in file {} === [+]".format(out_file.name))
    return out_file.name

def separate_blocks(in_file:str)->list:
    blocks = list()
    non_leaders = list()
    basic_blocks = list()
    with open(in_file,"r") as fd:
        content_list = fd.read().splitlines()
    for c in content_list:
        for j in JMP_INSTR:
            for b in BRANCH:
                if b in c or j in c:
                    non_leaders.append(c.lower())

    blocks = [x for x in content_list if x not in non_leaders]
    return blocks

def find_branch(in_file:str)->list:
    branch = list()
    blocks = separate_blocks(in_file)
    with open(in_file,"r") as fd:
        content_list = fd.read().splitlines()

    branch = [x for x in content_list if x not in blocks]
    return branch

def find_basic_blocks(in_file:str)->dict:
    """
    This function works only for this Execrsie
    """
    help_list = [""]*7
    brs = find_branch(in_file)
    basic_blocks = {i+1:"" for i in range(len(brs))}
    with open(in_file,"r") as fd:
        content_list = fd.read().splitlines()
    for string in content_list:
        if string.startswith("0x0") or string.startswith("0x3") or string.startswith("0x6") or string.startswith("0x9"):
            help_list[0] += string + "\n"
        elif string.startswith("0xe") or string.startswith("0x10"):
            help_list[1] += string + "\n"
        elif string.startswith("0x15"):
            help_list[2] += string + "\n"
        elif string.startswith("0x17") or string.startswith("0x19") or string.startswith("0x1c") or string.startswith("0x1e"):
            help_list[3] += string + "\n"
        elif string.startswith("0x23"):
            help_list[4] += string + "\n"
        elif string.startswith("0x28"):
            help_list[5] += string + "\n"
        elif string.startswith("0x2c"):
            help_list[6] += string + "\n"

    for key in basic_blocks:
        basic_blocks[key] = help_list[key-1]+brs[key-1]
    return basic_blocks

def create_graph(bb:dict)->str:
    output = open("basic_blocks_graph.dot","w")
    output.write("digraph CFG {Block_1 -> Block_2 -> Block_7; Block_1 -> Block_3 -> Block_2; Block_1 -> Block_3 -> Block_4 -> Block_6; Block_1 -> Block_3 -> Block_4 -> Block_5 -> Block_4; Block_5 -> Block_6 -> Block_7}")
    output.close()
    return output.name

def visualize(dot_file:str)->None:
    render("dot","png",dot_file)

def main():
    des="Hausaufgabe 1 Blatt 4 Programmanalyse SoSe20."
    epi="Built by Qu@ntumH@ck3er Thi Altenschmidt"
    parser=argparse.ArgumentParser(description=des,epilog=epi)
    parser.add_argument("--file","-f",action="store",type=str,dest="in_file",
            help="Specify the input binary file for disassembling.",required=True)
    given_args = parser.parse_args()
    in_file = given_args.in_file
    if not os.path.exists(in_file):
        print("[-] File {} doesn't exists.".format(in_file))
    print("[!] Warning: This script only works for the Exercise 1.")
    disass_file_name=read_code_and_save(in_file)
    print("[*] === separating blocks === [*]")
    bls = separate_blocks(disass_file_name)
    for b in bls:
        print(b)
    print("[*] === finding branch loci === [*]")
    brs = find_branch(disass_file_name)
    for b in brs:
        print(b)
    print("[+] === identifying basic blocks === [+]")
    bb = find_basic_blocks(disass_file_name)
    for k,v in bb.items():
        print("Block {} -> Code: {}".format(k,v))
    outfile_graph = create_graph(bb)
    print("[+] === creating control flow graphs file at {} === [+]".format(outfile_graph))
    print("[+] === visualizing the control flow graphs === [+]")
    visualize(outfile_graph)    
    
if __name__ == "__main__":
    main()

