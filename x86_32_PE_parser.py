#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct, argparse, os, sys
from binascii import hexlify, unhexlify

def read_file(fname:str)->str:
    with open(fname,"rb") as f_ptr:
        fcontent = f_ptr.read()
    return fcontent


def read_dos_hdr(dos_hdr:str)->str:
    if dos_hdr[0:2] == b'MZ':
        mag_num = struct.unpack('H',dos_hdr[0:2])[0]
        print("Magic-Byte of DOS-Header: {}".format(mag_num))
        bytes_last_page = struct.unpack('H',dos_hdr[2:4])[0]
        print("bytes of last page: {}".format(bytes_last_page))
        pg_file = struct.unpack('H',dos_hdr[4:6])[0]
        print("pages in file: {}".format(pg_file))
        num_rel = struct.unpack("H",dos_hdr[6:8])[0]
        print("number of relocations: {}".format(num_rel))
        dos_hdr_sz = struct.unpack('H',dos_hdr[8:10])[0]
        print("DOS header size: {}".format(dos_hdr_sz))
        min_par = struct.unpack("H",dos_hdr[10:12])[0]
        print("minimum paragraphs: {}".format(min_par))
        max_par = struct.unpack("H",dos_hdr[12:14])[0]
        print("maximum paragraphs: {}".format(max_par))
        st_mod = struct.unpack("H",dos_hdr[14:16])[0]
        print("stack modul: {}".format(st_mod))
        sp_reg = struct.unpack("H",dos_hdr[16:18])[0]
        print("stack pointer register: {}".format(sp_reg))
        chk_sum = struct.unpack("H",dos_hdr[18:20])[0]
        print("check sum: {}".format(chk_sum))
        ip_reg = struct.unpack("H",dos_hdr[20:22])[0]
        print("instruction pointer register: {}".format(ip_reg))
        code_mod = struct.unpack("H",dos_hdr[22:24])[0]
        print("code modul: {}".format(code_mod))
        off_rel = struct.unpack("H",dos_hdr[24:26])[0]
        print("offset first relocation: {}".format(off_rel))
        pe_hdr_off = struct.unpack("I",dos_hdr[60:64])[0]
        print("Portable Excutable Header offset: {}".format(pe_hdr_off))
    return pe_hdr_off

def read_sec_hdr(sec_hdr:str)->None:
    name = b"".join(struct.unpack('8c',sec_hdr[0:8])).decode("ascii")
    phys_addr = struct.unpack("I",sec_hdr[8:12])[0]
    virt_sz = struct.unpack("I",sec_hdr[8:12])[0]
    virt_addr = struct.unpack("I",sec_hdr[12:16])[0]
    sz_raw_dat = struct.unpack("I",sec_hdr[16:20])[0]
    char = struct.unpack("I",sec_hdr[36:40])[0]
    print("Section name: {}".format(name))
    print("Physical Address: {}, in hex: {}".format(phys_addr,hex(phys_addr)))
    print("Virtual Size: {}, in hex: {}".format(virt_sz,hex(virt_sz)))
    print("Size of Raw Data: {}, in hex: {}".format(sz_raw_dat,hex(sz_raw_dat)))
    print("Virtual Address: {}, in hex: {}".format(virt_addr,hex(virt_addr)))
    print("Characteristics: {}, in hex: {}".format(char,hex(char)))

def read_pe_hdr(pe_hdr:str)->int:
    machine = hexlify(pe_hdr[0:2]).decode("ascii")
    if machine == "4c01":
        print("Machine: i386 32 bit (0x014c)")
    elif machine == "6486":
        print("Machine: i386 64 bit (0x8664)")
    else:
        print("Machine type not found!")
    num_sec = struct.unpack("h",pe_hdr[2:4])[0]
    print("Number of sections: {}".format(num_sec))
    time_date_stamp = struct.unpack("i",pe_hdr[4:8])[0]
    print("time date stampe: {}".format(time_date_stamp))
    sym_tab = struct.unpack('I',pe_hdr[8:12])[0]
    print("Symbol table: {}".format(sym_tab))
    num_sym = struct.unpack('I',pe_hdr[12:16])[0]
    print("Number of symbols: {}".format(num_sym))
    sizeopthdr = struct.unpack('h',pe_hdr[16:18])[0]
    chars = bin(int(hex(struct.unpack('H',pe_hdr[18:20])[0]),16))
    print("Size of optional header: {}".format(sizeopthdr))
    return sizeopthdr

def read_import_func():
    dll_dict = {}

def read_peopt_hdr(peopt_hdr:str)->str:
    resource_rva = None
    opt_hdr_magic = peopt_hdr[0:2].decode("ascii")
    if opt_hdr_magic == "\x0b\x01":
        opt_hdr_magic = "PE32"
    elif opt_hdr_magic == "\x0b\x02":
        opt_hdr_magic = "PE32+"
    else:
        print("optional header magic not found")

    last_idx = fill_opt_hdr(peopt_hdr)
    image_data_dir = {}
    init_1 = last_idx
    init_2 = last_idx+4
    data_dir = {}
    data_dir[0] = "Export symbols table"
    data_dir[1] = "Import symbols table"
    data_dir[2] = "Resource table"
    data_dir[3] = "Exception table"
    data_dir[4] = "Certificate table"
    data_dir[5] = "Base relocation table"
    data_dir[6] = "Debugging information"
    data_dir[7] = "Architecture-specific data"
    data_dir[8] = "Global pointer register"
    data_dir[9] = "Thread local storage table"
    data_dir[10] = "Load configuration table"
    data_dir[11] = "Bound import table"
    data_dir[12] = "Import address table"
    data_dir[13] = "Delay import descriptor"
    data_dir[14] = "CLR header"
    data_dir[16] = "Reserved"

    for i in range(0,16):
        try:
            rva = struct.unpack('I',peopt_hdr[init_1:init_2])[0]
            size = struct.unpack('I',peopt_hdr[init_1:int_2+4])[0]
            image_data_dir[data_dir[i]] = (rva,size)
            if data_dir[i] == "Resource table":
                resource_rva = rva
        except:
            pass #We are not going to handle execeptional case here
        init_1 += 8
        init_2 += 8

    return resource_rva

def fill_opt_hdr(peopt_hdr:str)->int:
    last_idx = 96
    major_lnkv = struct.unpack('b',bytes([peopt_hdr[2]]))[0]
    minor_lnkv = struct.unpack('b',bytes([peopt_hdr[3]]))[0]
    code_size = struct.unpack('i',peopt_hdr[4:8])[0]
    init_size = struct.unpack('i',peopt_hdr[8:12])[0]
    uninit_size = struct.unpack('i',peopt_hdr[12:16])[0]
    entry_point = struct.unpack('i',peopt_hdr[16:20])[0]
    baseofcode = struct.unpack('i',peopt_hdr[20:24])[0]
    baseofdata = struct.unpack('i',peopt_hdr[24:28])[0]
    image_base = struct.unpack('i',peopt_hdr[28:32])[0]
    sec_alignment = struct.unpack('i',peopt_hdr[32:36])[0]
    f_alignment = struct.unpack('i',peopt_hdr[36:40])[0]
    major_op = struct.unpack('h',peopt_hdr[40:42])[0]
    minor_op = struct.unpack('h',peopt_hdr[42:44])[0]
    major_im = struct.unpack('h',peopt_hdr[44:46])[0]
    minor_im = struct.unpack('h',peopt_hdr[46:48])[0]
    major_subver = struct.unpack('h',peopt_hdr[48:50])[0]
    minor_subver = struct.unpack('h',peopt_hdr[50:52])[0]
    win32_verval = struct.unpack('i',peopt_hdr[52:56])[0]
    sizeofimage = struct.unpack('i',peopt_hdr[56:60])[0]
    sizeofhdr = struct.unpack('i',peopt_hdr[60:64])[0]
    chk_sum = struct.unpack('i',peopt_hdr[64:68])[0]
    sub_sys = struct.unpack('h',peopt_hdr[68:70])[0]
    dll_chr = bin(int(hex(struct.unpack('h',peopt_hdr[70:72])[0]),16))[2:]
    sz_stack_reserve = struct.unpack('i',peopt_hdr[72:76])[0]
    sz_stack_commit = struct.unpack('i',peopt_hdr[76:80])[0]
    return last_idx

def main():
    description="PE file parsing with Python3"
    epilog="Built by Thi Altenschmidt"
    parser=argparse.ArgumentParser(description=description,epilog=epilog)
    parser.add_argument("--file","-f",action="store",dest="fname",type=str,
            help="Specify a PE file for parsing",required=True)
    given_args = parser.parse_args()
    fname = given_args.fname
    if not os.path.exists(fname):
        print("[-] File {} doesn't exist!".format(repr(fname)))
        sys.exit(-1)
    f_content = read_file(fname)
    dos_hdr = f_content[:64]
    read_dos_hdr(dos_hdr)
    pe_hdr_off = read_dos_hdr(dos_hdr)
    pe_hdr = f_content[pe_hdr_off+4:pe_hdr_off+4+20]
    read_pe_hdr(pe_hdr)
    sizeopthdr = read_pe_hdr(pe_hdr)
    peopt_hdr = f_content[pe_hdr_off+4+20:pe_hdr_off+4+20+sizeopthdr]
    resource_rva = read_peopt_hdr(peopt_hdr)
    begin_sec = pe_hdr_off+4+20+sizeopthdr
    end_sec = pe_hdr_off+4+20+sizeopthdr+40
    num_sec = struct.unpack('h',pe_hdr[2:4])[0]

    #Read section header
    for i in range(0,num_sec):
        sec_hdr = f_content[begin_sec:end_sec]
        read_sec_hdr(sec_hdr)
        begin_sec += 40
        end_sec += 40

    #Entry point pe optional header:
    read_peopt_hdr(peopt_hdr)
    entry_point = struct.unpack('i',peopt_hdr[16:20])[0]
    print("Entry point: {} in hex: {}".format(entry_point,hex(entry_point)))

    #Size of code = #size of raw data in section .text


if __name__ == "__main__":
    main()



