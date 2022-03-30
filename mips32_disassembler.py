#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ctypes, struct, os, sys, argparse

REGISTERS_DICT = {
        0:"$zero", #Hardware constant 0
        1:"$at", #Reserved for Assembler
        2:"$v0", #return values
        3:"$v1",
        4:"$a0", #args
        5:"$a1",
        6:"$a2",
        7:"$a3",
        8:"$t0", #tmp
        9:"$t1",
        10:"$t2",
        11:"$t3",
        12:"$t4",
        13:"$t5",
        14:"$t6",
        15:"$t7",
        16:"$s0", #saved values
        17:"$s1",
        18:"$s2",
        19:"$s3",
        20:"$s4",
        21:"$s5",
        22:"$s6",
        23:"$s7",
        24:"$t8", #cont. saved values
        25:"$t9",
        26:"$k0", #reserved for operating system
        27:"$k1",
        28:"$gp", #global ptr
        29:"$sp", #stack ptr
        30:"$fp", #framed ptr
        31:"$ra", #return adress
        }

REGISTERS_RT_DICT = {
        0:["bltz","bgez"],
        1:["tgei","tgeiu","tlti","tltiu","teqi",None,"tnei"],
        2:["bltzal","bgezal"],
        }

REGISTERS_C_DICT = {
        0:["madd","maddu","mul",None,"msub","msubu"],
        1:list(),
        2:list(),
        3:list(),
        4:["clz","clo"],
        }

REGISTERS_INSTR_DICT = {
        0:["sll",None,"srl","sra","sllv",None,"srlv","srav"],
        1:["jr","jalr"],
        2:["mfhi","mthi","mflo","mtlo"],
        3:["mult","multu","div","divu"],
        4:["add","addu","sub","subu","and","or","xor","nor"],
        5:[None,None,"slt","sltu"],
        }
ROOT_DICT = {
        0:[None,None,"j","jal","beq","bne","blez","bgtz"],
        1:["addi","addiu","slti","sltiu","andi","ori","xori","lui"],
        2:list(),
        3:["llo","lhi","trap"],
        4:["lb","lh","lwl","lw","lbu","lhu","lwr"],
        5:["sb","sh","swl","sw",None,None,"swr"],
        6:["ll"],
        7:["sc"],
        }
TYPE_R, TYPE_J, TYPE_I = "R","J","I"
REG_C_TYPE_MULT, REG_C_TYPE_COUNT = 0, 4
REG_TYPE_SHIFT_OR_SHIFTV = 0
REG_TYPE_JMPR = 1
REG_TYPE_MOV = 2
REG_TYPE_DIVMULT = 3
REG_TYPE_ARITHLOG_GTE = 4
R_TYPE_JMP_OR_BR = 0
R_TYPE_ARITHLOGI = 1
R_TYPE_LI_OR_TRAP = 3
R_TYPE_LSTR_GTE = 4

def bit_mask(n:int)->int:
    return (1 << n)-1

def mips_disass(num:ctypes.c_uint32)->str:
    op_code = ctypes.c_uint8(num.value >> 26)
    op_code_u = ctypes.c_uint8((op_code.value >> 3) & bit_mask(3))
    op_code_l = ctypes.c_uint8(op_code.value & bit_mask(3))

    rs = ctypes.c_uint8((num.value >> 21) & bit_mask(5)) #First Source Register

    rt = ctypes.c_uint8((num.value >> 16) & bit_mask(5)) #Second Source Register
    rt_u = ctypes.c_uint8(rt.value >> 3)
    rt_l = ctypes.c_uint8(rt.value & bit_mask(3))

    rd = ctypes.c_uint16((num.value >> 11) & bit_mask(5)) #Destination Register
    sa = ctypes.c_uint8((num.value >> 6) & bit_mask(5)) #Shift amount

    func_code = ctypes.c_uint8(num.value & bit_mask(6)) #Function
    func_code_u = ctypes.c_uint8((func_code.value >> 3) & bit_mask(3))
    func_code_l = ctypes.c_uint8(func_code.value & bit_mask(3))

    imm = ctypes.c_uint8(num.value & bit_mask(16)) #immediate value
    tgt = ctypes.c_uint32(num.value & bit_mask(26)) #target of branch locus
    instr_dict = {'name':None,'type':None,'args':[None]*32}

    if (tgt.value > bit_mask(25)):
        tgt.value |= int(0xfc000000)

    if(op_code.value==0):
        for key, val in instr_dict.items():
            if key == "name":
                instr_dict[key]=REGISTERS_INSTR_DICT[func_code_u.value][func_code_l.value]
                #print(instr_dict[key])
            if key == "type":
                instr_dict[key] = TYPE_R
    elif(op_code.value==int(0x1c)):
        for key, val in instr_dict.items():
            if key == "name":
                instr_dict[key]=REGISTERS_C_DICT[func_code_u.value][func_code_l.value]
                #print(instr_dict[key])
            if key == "type":
                instr_dict[key] = TYPE_R
    elif(op_code.value == 1):
        for key, val in instr_dict.items():
            if key == "name":
                instr_dict[key]=REGISTERS_RT_DICT[rt_u.value][rt_l.value]
                #print(instr_dict[key])
            if key == "type":
                instr_dict[key] = TYPE_I
    else:
        for key, val in instr_dict.items():
            if key == "name":
                instr_dict[key] = ROOT_DICT[op_code_u.value][op_code_l.value]
                #print(instr_dict[key])
            if key == "type":
                instr_dict[key] = TYPE_I

    #if(instr_dict["name"]==None):
        #print("[-] Error: Not implemented opcode")
    if(num.value == 0):
        for key, val in instr_dict.items():
            if key == "name":
                instr_dict[key] = "nop"
                #print(instr_dict[key])
            if key == "args":
                instr_dict[key][0] = 0
    elif(op_code.value == 0):
        if func_code_u.value == REG_TYPE_SHIFT_OR_SHIFTV:
            if(func_code_l.value < 4):
                instr_dict["args"]="{}, {}, {}".format(
                    REGISTERS_DICT[rd.value],REGISTERS_DICT[rt.value],sa.value
                    )
                print(instr_dict["name"]+" "+instr_dict["args"])
            else:
                instr_dict["args"]="{}, {}, {}".format(
                    REGISTERS_DICT[rd.value],REGISTERS_DICT[rt.value],
                    REGISTERS_DICT[rs.value]
                    )
                print(instr_dict["name"]+" "+instr_dict["args"])
        elif func_code_u.value == REG_TYPE_JMPR:
            if(func_code_l.value < 1):
                instr_dict["args"]="{}".format(REGISTERS_DICT[rs.value])
            else:
                instr_dict["args"]="{}, {}".format(
                    REGISTERS_DICT[rd.value],REGISTERS_DICT[rs.value]
                    )
                print(instr_dict["name"]+" "+instr_dict["args"])
        elif func_code_u.value == REG_TYPE_MOV:
            if(func_code_l % 2 == 0):
                instr_dict["args"]="{}".format(REGISTERS_DICT[rd.value])
                print(instr_dict["name"]+" "+instr_dict["args"])
            else:
                instr_dict["args"]="{}".format(REGISTERS_DICT[rs.value])
                print(instr_dict["name"]+" "+instr_dict["args"])
        elif func_code_u.value == REG_TYPE_DIVMULT:
            instr_dict["args"]="{}, {}".format(
                REGISTERS_DICT[rs.value],REGISTER_DICT[rt.value]
                )
            print(instr_dict["name"]+" "+instr_dict["args"])

        elif (func_code_u.value == REG_TYPE_ARITHLOG_GTE) or (func_code.value == REG_TYPE_ARITHLOG_GTE+1):
            instr_dict["args"]="{}, {}, {}".format(REGISTERS_DICT[rd.value],REGISTERS_DICT[rs.value],REGISTERS_DICT[rt.value])
            print(instr_dict["name"]+" "+instr_dict["args"])
    elif(op_code.value == int(0x1c)):
        if func_code_u.value == REG_C_TYPE_MULT:
            if(func_code_u.value == 2):
                instr_dict["args"]="{}, {}, {}".format(
                    REGISTERS_DICT[rd.value],REGISTERS_DICT[rs.value],
                    REGISTERS_DICT[rt.value]
                    )
                print(instr_dict["name"]+" "+instr_dict["args"])
            else:
                instr_dict["args"]="{}, {}".format(
                    REGISTERS_DICT[rs.value],REGISTERS_DICT[rt.value]
                    )
                print(instr_dict["name"]+" "+instr_dict["args"])
        elif func_code_u.value == REG_C_TYPE_COUNT:
            instr_dict["args"]="{}, {}".format(
                REGISTERS_DICT[rd.value],REGISTERS_DICT[rs.value]
                )
            print(instr_dict["name"]+" "+instr_dict["args"])
    elif(op_code.value == 1):
        instr_dict["args"]="{}, {}".format(REGISTERS_DICT[rs.value],imm.value)
        print(instr_dict["name"]+" "+instr_dict["args"])

    else:
        if op_code_u.value == R_TYPE_JMP_OR_BR:
            if(op_code_l.value < 4):
                instr_dict["args"]="{}".format(tgt.value)
                instr_dict["type"]=TYPE_J
                print(instr_dict["name"]+" "+instr_dict["args"])
            else:
                if(op_code_l.value < 6):
                    instr_dict["args"]="{}, {}, {}".format(
                            REGISTERS_DICT[rs.value],REGISTERS_DICT[rt.value],
                            hex(imm.value
                            ))
                    print(instr_dict["name"]+" "+instr_dict["args"])
                else:
                    instr_dict["args"]="{}, {}".format(
                            REGISTERS_DICT[rs.value],hex(imm.value)
                            )
                    print(instr_dict["name"]+" "+instr_dict["args"])
        elif op_code_u.value == R_TYPE_ARITHLOGI:
            if(op_code_l.value < 7):
                instr_dict["args"]="{}, {}, {}".format(
                        REGISTERS_DICT[rt.value],REGISTERS_DICT[rs.value],hex(imm.value)
                        )
                print(instr_dict["name"]+" "+instr_dict["args"])
            else:
                instr_dict["args"]="{}, {}".format(
                        REGISTERS_DICT[rt.value],hex(imm.value)
                        )
                print(instr_dict["name"]+" "+instr_dict["args"])
        elif (op_code_u.value == R_TYPE_LSTR_GTE) or (op_code_u.value == R_TYPE_LSTR_GTE+1) or (op_code_u.value == R_TYPE_LSTR_GTE+2) or (op_code_u.value == R_TYPE_LSTR_GTE+3):
            instr_dict["args"]="{}, {}({})".format(
                    REGISTERS_DICT[rt.value],hex(imm.value),
                    REGISTERS_DICT[rs.value]
                    )
            print(instr_dict["name"]+" "+instr_dict["args"])
    return instr_dict["name"]+" "+instr_dict["args"]

def read_input_and_save(file_name:object,out_file:object)->None:
    with open(file_name,"rb") as fd:
        file_content = fd.read()

    reg_ip = 0
    entry_addr = 0

    file = open(out_file,"w")
    file.write(".text\n")
    file.write(".globl main\n")
    file.write("main:\n")
    while(reg_ip-entry_addr < len(file_content)):
        num = struct.unpack("<I",file_content[reg_ip-entry_addr:reg_ip+4-entry_addr])[0]
        c_num = ctypes.c_uint32(num)
        result = mips_disass(c_num)+"\n"
        file.write(result)
        reg_ip += 4
    file.write("li $v0, 10\n")
    file.write("syscall")
    file.close()

def main():
    des="MIPS32-Disassembler with Python3."
    epi="Built by Qu@ntumCyb3rW01f/Qu@ntumH@ck3r Thi Altenschmidt."
    parser=argparse.ArgumentParser(description=des,epilog=epi)
    parser.add_argument("--file","-f",action="store",dest="bin_file",type=str,help="Specify a MIPS32 bin file to disassembly.",required=True)
    parser.add_argument("--save","-s",action="store",dest="out_file",type=str,help="Specify file name to save the output result.",default="mips32_disass_output.s")
    given_args=parser.parse_args()
    bin_file,out_file=given_args.bin_file,given_args.out_file

    if not os.path.exists(bin_file):
        print("[-] File {} doesn't exist.".format(bin_file))
        sys.exit(-1)
    file_name, file_extension = os.path.splitext(bin_file)
    if file_extension != ".bin":
        print("[-] File {} ist not a binary file.".format(bin_file))
        sys.exit(-1)
    read_input_and_save(bin_file,out_file)

if __name__ == "__main__":
    main()
