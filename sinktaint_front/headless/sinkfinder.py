#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import sys
# import ghidra.ghidra_builtins
import angr
import re
import pickle
import pyvex
import archinfo
import func_timeout
from func_timeout import func_set_timeout
import networkx as nx
from collections import OrderedDict

debug = False

x86_regname_unify = {
    "al": "eax", "ah": "eax", "ax": "eax", "eax": "eax", "rax": "eax",
    "bl": "ebx", "bh": "ebx", "bx": "ebx", "ebx": "ebx", "rbx": "ebx",
    "cl": "ecx", "ch": "ecx", "cx": "ecx", "ecx": "ecx", "rcx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx", "edx": "edx", "rdx": "edx",
    "si": "esi", "sil": "esi", "esi": "esi",
    "di": "edi", "dil": "edi", "edi": "edi",
    "ip": "eip", "eip": "eip",
    "bp": "ebp", "bpl": "ebp", "ebp": "ebp",
    "sp": "esp", "spl": "esp", "esp": "esp"
}
ret_reg_dict = OrderedDict([
    ('x86', 'eax'),
    ('x64', 'rax'),
    ('mipsbe', 'v0'),   #twe return reg, UC_MIPS_REG_V0, UC_MIPS_REG_V1
    ('mipsle', 'v0'),
    ('mips64be', 'v0'),
    ('mips64le', 'v0'),
    ('armbe', 'r0'),
    ('armle', 'r0'),
    ('arm64be', 'x0'),
    ('arm64le', 'x0'),
    ('ppcbe', 'r3'),
    ('ppcle', 'r3'),
    ('ppc64be', 'r3'),
    ('ppc64le', 'r3')
    ])
arg_reg_dict = OrderedDict([
    ('x86', []),
    ('x64', []),
    ('mipsbe', ['a0', 'a1', 'a2', 'a3']),
    ('mipsle', ['a0', 'a1', 'a2', 'a3']),
    ('mips64be', ['a0', 'a1', 'a2', 'a3']),
    ('mips64le', ['a0', 'a1', 'a2', 'a3']),
    ('armbe', ['R0', 'R1', 'R2', 'R3']),
    ('armle', ['R0', 'R1', 'R2', 'R3']),
    ('arm64be', ['X0', 'X1', 'X2', 'X3']),
    ('arm64le', ['X0', 'X1', 'X2', 'X3']),
    ('ppcbe', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppcle', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppc64be', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10']),
    ('ppc64le', ['gpr3', 'gpr4', 'gpr5', 'gpr6', 'gpr7', 'gpr8', 'gpr9', 'gpr10'])
    ])


def get_arch_reg_names(proj):
    reg_names = list(proj.arch.register_names.values())

    return reg_names

def reg_used_loop(proj, loop_path):
    reg_name_list = set()
    if 'mips' in proj.arch.name.lower():
        pattern=re.compile("\$..")
        for node in loop_path:
            block = proj.factory.block(node.addr)
            insns = block.capstone.insns
            for ins in insns:
                regs = pattern.findall(str(ins))
                for r in regs:
                    reg_name_list.add(r.strip('$'))
    else:
        for node in loop_path:
            block = proj.factory.block(node.addr)
            insns = block.capstone.insns
            for ins in insns:
                reg_access_id_tupple = ins.insn.regs_access()
                for id_list in reg_access_id_tupple:
                    for reg_id in id_list:
                        reg_name = ins.insn.reg_name(reg_id)
                        reg_name_list.add(reg_name)

    return list(reg_name_list)

# def filter_vex_str(vex_str):
#     ret_str = None
#     if '(' in vex_str:
#         pattern = r'\((.*?)\)'
#         res = re.findall(pattern, vex_str)
#         if len(res) != 1:
#             print("[-] Found more than one '()' %s" % vex_str)
#             return ret_str
#         else:
#             res = res[0]
#             if ',' in res:
#                 ret_str = res.split(',')[0].strip(' ')
#             else:
#                 ret_str = res
#             return ret_str
#     else:
#         ret_str = vex_str
#         return ret_str
def filter_vex_str(vex_str):
    #t7 = if (t58) ILGop_Ident32(LDbe(t23)) else t27
    # if (t60) STbe(t35) = t7
    if "ST" in vex_str:
        pattern = r'ST.*?\((.*?)\)'
        res = re.findall(pattern, vex_str)
        ret_str = res[0]
        return ret_str
    if "LD" in vex_str:
        pattern = r'LD.*?\((.*?)\)'
        res = re.findall(pattern, vex_str)
        ret_str = res[0]
        return ret_str
    ret_str = None
    if '(' in vex_str:
        pattern = r'\((.*?)\)'
        res = re.findall(pattern, vex_str)
        if len(res) != 1:
            print("[-] Found more than one '()' %s" % vex_str)
            return ret_str
        else:
            res = res[0]
            if ',' in res:
                ret_str_0 = res.split(',')[0].strip(' ')
                ret_str_1 = res.split(',')[1].strip(' ')
                if "t" in ret_str_1:
                    ret_str = (ret_str_0, ret_str_1)
                else:
                    ret_str = ret_str_0
            else:
                ret_str = res
            return ret_str
    else:
        ret_str = vex_str
        return ret_str

def is_ld_st_in_loop(loop_irsb):
    ST_Flag = False
    LD_Flag = False
    if debug:
        print("[+] Judging load and store in loop...")
    for _, stmt in enumerate(loop_irsb.statements):
        if 'ST' in str(stmt):
            ST_Flag = True
        if 'LD' in str(stmt):
            LD_Flag = True
        if ST_Flag and LD_Flag:

            return ST_Flag, LD_Flag
    return ST_Flag, LD_Flag

def get_input_output_loop_irsb(irsb, regs_list):
    input = set()
    output = set()
    CMP_flag = False
    for _, stmt in enumerate(irsb.statements):
        if isinstance(stmt, pyvex.stmt.Put):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.Exit):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offsIP, irsb.arch.bits // 8))
        else:
            stmt_str = stmt.__str__()
        if "IMark" in stmt_str:
            CMP_flag = False
        if 'Cmp' in stmt_str:
            CMP_flag = True
        if CMP_flag:
            continue
        if "cc_" in stmt_str or "pc" in stmt_str or "ip" in stmt_str or 'ra' in stmt_str:
            continue
        if '=' in stmt_str:
            #print(stmt_str)
            dst_str, src_str = [x.strip(' ') for x in stmt_str.split('=')]
            #print(dst_str, src_str)
            dst = filter_vex_str(dst_str)
            if 'PUT' in stmt_str and dst in regs_list and dst not in input:
                output.add(dst)
            if dst != None :
                src = filter_vex_str(src_str)
                if src in regs_list and src not in output:
                    input.add(src)
    return input, output

@func_set_timeout(5)
def generate_loop_irsb(proj, loop_path):
    if debug:
        print("[+] Generating loop irsb...")
    loop_start = loop_path[0].addr
    loop_irsb = pyvex.IRSB(None, loop_start, arch = proj.arch)
    if debug:
        print(loop_path)
    prev_addrs = []
    inst_arch = proj.arch
    for node in loop_path:
        block = proj.factory.block(node.addr)
        for addr in block.instruction_addrs:
            if addr in prev_addrs:
                break
        prev_addrs += block.instruction_addrs
        if addr != block.instruction_addrs[-1]:
            bb_start = block.addr
            block_size = addr - bb_start   # if block_size == 0
            block_bytes = block.bytes[:block_size]
            block_irsb = pyvex.IRSB(block_bytes, mem_addr=bb_start, arch=inst_arch, opt_level=1, strict_block_end = True)
            loop_irsb.extend(block_irsb)
        else:
            try:
                block_irsb = block.vex
                loop_irsb.extend(block_irsb)
            except:
                return loop_irsb
    #print(loop_irsb)
    return loop_irsb

def split_irsb_dst_src(proj, irsb):
    data_pairs = []
    LD_node  = []
    ST_node = []
    ADD_node = []
    LD_first_flag = False
    CMP_flag = False
    LD_ST_order = []

    for _, stmt in enumerate(irsb.statements):
        
        #print(type(stmt))
        if isinstance(stmt, pyvex.stmt.Put):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.data.offset, stmt.data.result_size(irsb.tyenv) // 8))
        elif isinstance(stmt, pyvex.stmt.Exit):
            stmt_str = stmt.__str__(reg_name=irsb.arch.translate_register_name(stmt.offsIP, irsb.arch.bits // 8))
        else:
            stmt_str = stmt.__str__()
        #print(stmt_str)
        if "IMark" in stmt_str:
            CMP_flag = False
        if 'Cmp' in stmt_str:
            CMP_flag = True
        if CMP_flag:
            continue
        if "cc_" in stmt_str or "pc" in stmt_str or "ip" in stmt_str or 'ra' in stmt_str:
            continue
        if '=' in stmt_str and 'Cond' not in stmt_str:
            #print(stmt_str)
            dst_str, src_str = [x.strip(' ') for x in stmt_str.split('=')]
            #print(dst_str, src_str)
            arch  = proj.arch
            
            dst = filter_vex_str(dst_str)
            if dst != None:
                src = filter_vex_str(src_str)
                if arch == 'x86':
                    try:
                        dst = x86_regname_unify[dst]
                    except:
                        pass
                    try:
                        src = x86_regname_unify[src]
                    except:
                        pass
                if "0x" in src:
                    continue
                if "(" not in stmt_str:
                    data_pairs.append((src, dst))
                else:
                    data_pairs.append((dst, src))
            if "ST" in stmt_str:
                ST_node.append(dst)
                LD_ST_order.append(dst)
            if "LD" in stmt_str:
                if len(ST_node) == 0:
                    LD_first_flag = True
                LD_node.append(src)
                LD_ST_order.append(src)
            if "Add" in stmt_str or "Sh" in stmt_str:
                ADD_node.append(dst)
        else:
            continue
    return data_pairs, ST_node, LD_node, ADD_node, LD_first_flag, LD_ST_order

def total_insn_loop(proj, loop_path):
    total_insn = 0
    for node in loop_path:
        block = proj.factory.block(node.addr)
        total_insn += block.instructions

    return total_insn

def total_insn_func(func):
    total_insn = 0
    for block in func.blocks:
        total_insn += block.instructions
    
    return total_insn

def call_in_loop(proj, loop_path):
    call_times = 0
    for node in loop_path:
        block = proj.factory.block(node.addr)
        block_irsb = block.vex
        if block_irsb.jumpkind == 'Ijk_Call':
            call_times += 1

    return call_times


def is_copy_loop_with_vex(proj, loop_path):
    flag = 0
    start_block_ea = loop_path[0].addr
    res = []
    global debug
    #print(succs)
    #arch = idaapi.get_inf_structure().procName.lower()
    # load mode and store mode in vex

    #loads, stores, branch, arithmetic= get_insts_set()
    order_flag = True   
    #order_flag = False   
    path_thresh = 10    
    call_thresh = 2     
    inst_thresh = 50    
    loose = True
    if loose:
        store_thresh =  8  
        load_thresh = 8    
    else:
        store_thresh = 3   
        load_thresh = 3     

    
    add_flag = 0
    ADD_node_loop = []
    
    inst_nums = total_insn_loop(proj, loop_path)
    if debug:
        print("[+] total instruction in loop: %s" % inst_nums)

    if len(loop_path) > path_thresh and inst_nums > inst_thresh:
        return 0

    loop_irsb = generate_loop_irsb(proj, loop_path)
    if debug:
        print(loop_irsb)
    call_times = call_in_loop(proj, loop_path)
    if debug:
        print("call:", call_times)
    if call_times > call_thresh:
        return 0

    
    data_pairs, ST_node, LD_node, ADD_node, LD_first_flag, LD_ST_order = split_irsb_dst_src(proj,loop_irsb)
    if debug:
        print("Loop:", res)
        print(data_pairs, ST_node, LD_node, ADD_node)
    
    if call_times != 0:
        arch = proj.arch
        args_reg_list = arg_reg_dict[arch]
        ret_reg = ret_reg_dict[arch]
        for arg_reg in args_reg_list:
            data_pairs.append((ret_reg, arg_reg))
    if LD_first_flag == False and order_flag:
        return 0
    if ST_node == [] or LD_node == [] or ADD_node == []:
        return 0      #not sat
    if len(ST_node) > store_thresh or len(LD_node) > load_thresh:
        return 0
    data_flow = nx.DiGraph()
    for (dst, src) in data_pairs:
        if isinstance(src, tuple):
            data_flow.add_edge(src[0], dst)
            data_flow.add_edge(src[1], dst)
        else:

            data_flow.add_edge(src, dst)
    try:
        res = list(nx.simple_cycles(data_flow)) # find the loop paths
        #res = list(nx.cycle_basis(G, 0))
    except:
        return 0
    #
    
    #if res == []:   # no loop
    #    continue
    for path in res:
        for nd in path:
            if nd in ADD_node:
                ADD_node_loop.append(nd)
    if debug:
        print("Add loop:", ADD_node_loop)
    for start in LD_node:
        for end in ST_node:
            if order_flag and LD_ST_order.index(start) >= LD_ST_order.index(end):
                continue
            start_prev = set(data_flow.predecessors(start))
            
            end_prev = set(data_flow.predecessors(end))
            if debug:
                print("start: %s prev: %s" % (start, start_prev))
                print("end: %s prev: %s" % (end, end_prev))
            if start_prev & end_prev != set() and (len(start_prev) == 1 or len(end_prev) == 1):
                continue
            ld_st_path_ger = nx.all_simple_paths(data_flow, start, end)
            st_ld_path_ger = nx.all_simple_paths(data_flow, end, start)
            st_ld_path = list(st_ld_path_ger)
            ld_st_path = list(ld_st_path_ger)
            if ld_st_path != [] and st_ld_path == []:
                #
                if debug:
                    print("Load: %s, Store: %s" % (start, end), ld_st_path)

                if ADD_node_loop == []:
                    for nd in ADD_node:
                        if nd in ld_st_path[0]:
                            flag = 1
                            return 1

                for nd in ADD_node_loop:
                    add_st_path_ger = nx.all_simple_paths(data_flow, nd, end)
                    
                    add_st_path = list(add_st_path_ger)
                    if debug:
                        print("Add node: %s to store: %s, path: " % (nd, end), add_st_path)
                    #print(add_st_path == [])
                    if add_st_path != [] or nd == end:
                        flag = 1
                        return 1
                        
    return flag

def analyze_loop_path(proj, loop_path):
    try:
        loop_irsb = generate_loop_irsb(proj, loop_path)
        
        ST_Flag, LD_Flag = is_ld_st_in_loop(loop_irsb)
        if ST_Flag and LD_Flag:
            reg_name_list = reg_used_loop(proj, loop_path)
            input, output = get_input_output_loop_irsb(loop_irsb, reg_name_list)
            print("[+] loop input: ", input)
            print("[+] loop output: ", output)
    except:
        print("[-] Error in analyzing loop...")

def reorder_loop_path(loop, cfg):
    loop_rela = {}
    loop_path = []
    loop_nodes = loop.body_nodes
    entry_node = loop.entry
    func = cfg.functions.floor_func(entry_node.addr)
    loop_thresh = 10
    if len(loop_nodes) > loop_thresh:
        return loop_path
    for node in loop_nodes:
        for succ in node.successors():
            if succ in loop_nodes:
                loop_rela[node] = succ
    curr = entry_node
    if debug:
        print("[+] Reorder loop path...")
    loop_path.append(curr)
    
    for i in range(len(loop_nodes) - 1):
        curr = loop_rela[curr]
        loop_path.append(curr)
    
    return loop_path

'''
find loops in function level 
'''
def get_func_loop(cfg, addr):
    func = cfg.functions.floor_func(addr)
    func_cfg = func.graph
    loop_paths = list(nx.simple_cycles(func_cfg))

    return loop_paths



def analyze_bin(binary_file, outputfile):
    proj = angr.Project(binary_file, auto_load_libs=False, use_sim_procedures=True)
    if 'ARM' in proj.arch.name:
        cfg = proj.analyses.CFG(force_complete_scan=False)
    else:
        cfg = proj.analyses.CFG()
    # pk_file = binary_file + '.pk'
    # try:
    #     print("[+] read file@" + pk_file)
    #     with open(pk_file,'rb') as f:
    #         (proj,cfg)=pickle.load(f)
    #     print("[+] read file@%s is ok..." % pk_file)
    # except:
    #     print("[+] Constructing CFG...")
    #     proj = angr.Project(binary_file, auto_load_libs=False, use_sim_procedures=True)
    #     if 'ARM' in proj.arch.name:
    #         cfg = proj.analyses.CFG(force_complete_scan=False)
    #     else:
    #         cfg = proj.analyses.CFG()
    #     print("[+] write file@" + pk_file)
    #     with open(pk_file,'wb') as f:
    #         pickle.dump((proj,cfg),f)
    #     print("[+] write file@%s is ok..." % pk_file)
    if debug:
        print("[+] Finding loops...")
    loops_found = proj.analyses.LoopFinder()
    flag = 0
    cp_like = []

    for loop in loops_found.loops:
        try:
            entry_node = loop.entry
            func = cfg.functions.floor_func(entry_node.addr)
            func_name = func.name
            # if total_insn_func(func) > 300:
            #     continue
            if debug:
                print("[+] Analyzeing loop....")
            loop_path = reorder_loop_path(loop, cfg)
            if len(loop_path) > 10:
                continue
            print("[+] Loop in function '%s': loop start @0x%x" % (func_name, entry_node.addr))
            print("[+] is '%s' a copy function?" % func_name)
            flag = is_copy_loop_with_vex(proj, loop_path)
            if flag == 0:
                print("[-] False (0).")
            else:
                print("[+] True (1).")
            func_addr = func.addr
            loop_addr = entry_node.addr
            
            if flag:
                loop_irsb = generate_loop_irsb(proj, loop_path)
                reg_name_list = reg_used_loop(proj, loop_path)
                input, output = get_input_output_loop_irsb(loop_irsb, reg_name_list)
                print("[+] loop input: ", input) # check all input, if input is tainted, give a warning
                print("[+] loop output: ", output)
                cp_like.append((func_addr,loop_addr, input))
        except:
            if debug:
                print("[-] Error in analyzing loop...")
            pass
            


    # for func_addr in proj.kb.functions:

    func_out = open(outputfile + '-funcaddr','w')
    loop_out = open(outputfile + '-loopaddr', 'w')
    for func, loop, input in cp_like:
        func_out.write("0x%08x\n" % func)
        loop_out.write("0x%08x:" % loop)
        for i in input:
            loop_out.write(" %s" % i)
        loop_out.write("\n")

    func_out.close()
    loop_out.close()
    

if __name__ == '__main__':
    debug = False
    binary_file = sys.argv[1]
    # binary_file = '/home/sinktaint/wr940nv4-httpd'
    analyze_bin(binary_file, binary_file)
    