#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Find path to sink functions from reference of given strings. Different output format for the function calling certain check functions. Find more params heuristicly.
# @author tkmk, Gh0stZero
# @category Analysis


import time
import sys

try:
    from ghidra.ghidra_builtins import toAddr, currentProgram, currentAddress, getReferencesTo
    from ghidra.ghidra_builtins import getFunctionContaining, getInstructionAt, getFunctionAt, getByte, getDataAt, getScriptArgs, createFunction
    from ghidra.ghidra_builtins import getInt, getMonitor
except:
    pass
from ghidra.util.classfinder import ClassSearcher
from ghidra.app.plugin.core.analysis import ConstantPropagationAnalyzer
from ghidra.app.decompiler import DecompileOptions, DecompInterface, ClangStatement
from ghidra.program.model.pcode import PcodeOp, Varnode, VarnodeAST, HighParam, HighLocal, PcodeOpAST
from ghidra.program.model.data import PointerDataType, ArrayDataType, Undefined4DataType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import SymbolicPropogator
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.address import GenericAddress
from ghidra.util.exception import CancelledException
from collections import Counter, defaultdict
import re
import struct

#import ghidra.ghidra_builtins
from ghidra import *

DEBUG = False

WRITE_FILE = False
name = str(currentProgram.name)
if WRITE_FILE:
    result_write = open(name + "_sink_log.txt", 'w')
    
ifc = None

syms = {}
newParam = defaultdict(set)
analyzer = None
searchStrArgDone = set()
funcPosCounter = Counter()
callMap = {}
safeFuncs = set()
referenced = set()
monitor = ConsoleTaskMonitor()
addr_sink_flag = {} #{addr: (sink, flag)}
sinks_dict ={}
sinks_size = {}
risky_sink = {}
secure_sink = {}

decompile_function_cache = {}

is_big_endian = False
process_is_64bit = False

endian = currentProgram.metadata[u'Endian']
if endian == u'Big':
    is_big_endian = True
else:
    is_big_endian = False

process_type = currentProgram.metadata['Processor']
if process_type.endswith(u'64'):
    process_is_64bit = True
# sinks = ["strcpy", "strcat", "strncat","strlcpy", "memcpy", "strncpy", "sprintf", "snprintf", 'system']
sinks = ["strcpy", "sprintf"] #, "memcpy", "strncpy",  "snprintf"]

heurist_filte_func = ['acosNvramConfig_set', 'acosNvramConfig_get', 'acosNvramConfig_match', 
                'acosNvramConfig_unset', 'acosNvramConfig_match', "strcpy", "strcat", 
                "strncat","strlcpy", "memcpy", "strncpy", "sprintf", "snprintf", 'system',
                "strcmp", 'strncmp', 'printf', 'strchr', 'strrchr', 'strspn', 'strncasecmp',
                'strsep', 'strcspn', 'stricmp', 'strerror', 'strlcat', 'strlwr', 'fprintf', 
                'strtok', 'fopen', 'strtok_r', 'strcasecmp'] #'strstr',
needCheckLength = {
    'strncpy': 2,
    'strncat': 2,
    'strlcpy': 2,
    'memcpy': 2,
    "snprintf": 1
}

heuristicMin = 4
# sinks = ['strcpy']
digest = ['strcpy', 'sprintf', 'memcpy', 'strcat']

heuristicIgnoreFunctions = ['strcpy', 'strncpy', 'strcat', 'memcpy']

#comment: 表示数据来源的位置
needCheckConstantStr = {
    'system': 0,
    'fwrite': 0,
    '___system': 0,
    'bstar_system': 0,
    'popen': 0,
    'execve': 0,
    'strcpy': 1,
    'strcat': 1,
    'strncpy': 1,
    'memcpy': 1,
    'twsystem': 0
}
needCheckFormat = {
    'sprintf': 1,
    'doSystemCmd': 0,
    'doShell': 0
}


def a2h(address):
    return '0x' + str(address)

def a2i(addr):
    return int(a2h(addr), 16)

def getAnalyzer():
    global analyzer
    for a in ClassSearcher.getInstances(ConstantPropagationAnalyzer):
        if a.canAnalyze(currentProgram):
            analyzer = a
            break
    else:
        assert 0

def getCallingArgs(addr, pos):
    if not 0 <= pos <= 3:
        return
    arch = str(currentProgram.language.processor)
    if arch == 'ARM':
        reg = currentProgram.getRegister('r%d' % pos)
    elif arch == 'MIPS':
        nextInst = getInstructionAt(addr).next
        if len(nextInst.pcode):  # not NOP
            addr = addr.add(8)
        reg = currentProgram.getRegister('a%d' % pos)
    else:
        return
    return getRegister(addr, reg)


def getRegister(addr, reg):
    if analyzer is None:
        getAnalyzer()

    func = getFunctionContaining(addr)
    if func is None:
        return

    if func in syms:
        symEval = syms[func]
    else:
        symEval = SymbolicPropogator(currentProgram)
        symEval.setParamRefCheck(True)
        symEval.setReturnRefCheck(True)
        symEval.setStoredRefCheck(True)
        analyzer.flowConstants(currentProgram, func.entryPoint, func.body, symEval, monitor)
        syms[func] = symEval

    return symEval.getRegisterValue(addr, reg)


def getStr(addr):
    ad = addr
    ret = ''
    try:
        while not ret.endswith('\0'):
            ret += chr(getByte(ad) % 256)
            ad = ad.add(1)
    except MemoryAccessException:
        return
    return ret[:-1]

def getString(addr):
    mem = currentProgram.getMemory()
    core_name_str = ""
    while True:
        try:
            byte = mem.getByte(addr.add(len(core_name_str)))
            if byte == 0:
                return core_name_str
            if ((byte < 0x7F and byte > 0x1F) or byte in (0x9, 0xD, 0xA)):
                core_name_str += chr(byte)
            else:
                if core_name_str == '':
                    core_name_str = None
                return core_name_str
        except:
            return None

def getStrArg(addr, argpos=0):
    rv = getCallingArgs(addr, argpos)
    if rv is None:
        return
    return getStr(toAddr(rv.value))

#comment: 判断源数据是否来源于常量
def checkConstantStr(addr, argpos=0):
    # empty string is not considered as constant, for it may be uninitialized global variable
    return bool(getStrArg(addr, argpos))

#comment: 判断跟格式化字符串相关的函数
def checkSafeFormat(addr, offset=0):
    data = getStrArg(addr, offset)
    if data is None:
        return False

    fmtIndex = offset
    for i in range(len(data) - 1):
        if data[i] == '%' and data[i + 1] != '%':
            fmtIndex += 1
            if data[i + 1] == 's':
                if fmtIndex > 3:
                    return False
                if not checkConstantStr(addr, fmtIndex):
                    return False
    return True


def getCallee(inst):
    callee = None
    if len(inst.pcode):
        if inst.pcode[-1].mnemonic == 'CALL':
            callee = getFunctionAt(inst.getOpObjects(0)[0])
        elif inst.pcode[-1].mnemonic == 'CALLIND':
            regval = getRegister(inst.address, inst.getOpObjects(0)[0])
            if regval is not None:
                callee = getFunctionAt(toAddr(regval.value))
    return callee

def print_symbol(symbol):
    try:     
        print("  name:         {}".format(symbol.name))
        print("  dataType:     {}".format(symbol.dataType))
        print("  getPCAddress: 0x{}".format(symbol.getPCAddress()))
        print("  size:         {}".format(symbol.size))
        print("  storage:      {}".format(symbol.storage))
        print("  parameter:    {}".format(symbol.parameter))
        print("  readOnly:     {}".format(symbol.readOnly))
        print("  typeLocked:   {}".format(symbol.typeLocked))
        print("  nameLocked:   {}".format(symbol.nameLocked))
    except:
        print("not a symbol...:", symbol)

def is_address_in_current_program(address):
    for block in currentProgram.memory.blocks:
        if address.offset in range(block.getStart().offset,block.getEnd().offset):
            return True
    return False

def get_signed_value(input_data):
    pack_format = ""
    if is_big_endian:
        pack_format += ">"
    else:
        pack_format += "<"
        
    if process_is_64bit:
        pack_format += "L"
    else:
        pack_format += "I"

    data = struct.pack(pack_format.upper(), input_data.offset)
    signed_data = struct.unpack(pack_format.lower(), data)[0]

    return signed_data

class FlowNode(object):
    def __init__(self, var_node):
        """ Used to get VarNode value
        :param var_node:
        """
        self.var_node = var_node

    def get_value(self):
        """ Get VarNode value depend on it's type.
        :return:
        """
        if self.var_node.isAddress():
            return self.var_node.getAddress()
        
        elif self.var_node.isConstant():
            return self.var_node.getAddress()
        
        elif self.var_node.isUnique():
            return calc_pcode_op(self.var_node.getDef())
        
        elif self.var_node.isRegister():
            return calc_pcode_op(self.var_node.getDef())

        # https://github.com/NationalSecurityAgency/ghidra/issues/2283
        elif self.var_node.isPersistent():
            print("TODO: Var_node isPersistent")
            # TODO: Handler this later
            return
        elif self.var_node.isAddrTied():
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isUnaffected():
            print("TODO: Var_node isUnaffected")
            # TODO: Handler this later
            return

def calc_pcode_op(pcode):
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        if opcode == PcodeOp.PTRSUB:
            var_node_1 = FlowNode(pcode.getInput(0))
            var_node_2 = FlowNode(pcode.getInput(1))
            value_1 = var_node_1.get_value()
            value_2 = var_node_2.get_value()
            if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                return value_1.offset + value_2.offset
            else:
                return None
        elif opcode == PcodeOp.CAST:
            var_node_1 = FlowNode(pcode.getInput(0))
            value_1 = var_node_1.get_value()
            if isinstance(value_1, GenericAddress):
                return value_1.offset
            else:
                return None

        elif opcode == PcodeOp.PTRADD:
            var_node_0 = FlowNode(pcode.getInput(0))
            var_node_1 = FlowNode(pcode.getInput(1))
            var_node_2 = FlowNode(pcode.getInput(2))
            try:
                value_0_point = var_node_0.get_value()
                if not isinstance(value_0_point, GenericAddress):
                    return
                value_0 = toAddr(getInt(value_0_point))
                value_1 = var_node_1.get_value()
                if not isinstance(value_1, GenericAddress):
                    
                    return
                value_1 = get_signed_value(value_1.offset)
                # TODO: Handle input2 later
                value_2 = var_node_2.get_value()
               
                if not isinstance(value_2, GenericAddress):
                    return
                output_value = value_0.add(value_1)
                return output_value.offset

            except Exception as err:
                return None

            except:
                print("Got something wrong with calc PcodeOp.PTRADD")
                return None

        elif opcode == PcodeOp.INDIRECT:
            print("TODO: INDIRECT")
            # TODO: Need find a way to handle INDIRECT operator.
            return None

        elif opcode == PcodeOp.MULTIEQUAL:
            print("TODO: MULTIEQUAL")
            # TODO: Add later
            return None

        elif opcode == PcodeOp.COPY:
            var_node_0 = FlowNode(pcode.getInput(0))
            value_0 = var_node_0.get_value()
            return value_0
    else:
        print("Found Unhandled opcode: {}".format(pcode))
        return None

def analyze_call_parms(pcodeOpAST):
    parms = {}
    # TODO: Check call_addr is in function.
    if pcodeOpAST:
        # opcode = pcodeOpAST.getOpcode()
        # if opcode == PcodeOp.CALL:
        #     target_call_addr = pcodeOpAST.getInput(0).getAddress()

        # elif opcode == PcodeOp.CALLIND:
        #     target_call_addr = FlowNode(pcodeOpAST.getInput(0)).get_value()
        inputs = pcodeOpAST.getInputs()
        for i in range(len(inputs))[1:]:
            parm = inputs[i]
            parm_node = FlowNode(parm)

            parm_value = parm_node.get_value()

            if isinstance(parm_value, GenericAddress):
                parm_value = parm_value.offset
            parms[i] = parm_value
        return parms
    return
    
def get_all_call_pcode(high_func):
    ops = get_function_pcode(high_func)
    call_pcodes = {}
    if not ops:
        return
    while ops.hasNext():
        pcodeOpAST = ops.next()
        opcode = pcodeOpAST.getOpcode()
        if opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
            op_call_addr = pcodeOpAST.getInput(0).PCAddress
            call_pcodes[op_call_addr] = pcodeOpAST
    return call_pcodes

def get_call_pcode(call_addr, call_pcodes):
    # TODO: Check call_addr is in function.
    if call_addr in call_pcodes:
        return call_pcodes[call_addr]
    return
    
def get_call_parm_value(call_addr, call_pcodes):
    parms_value = {}
    if not call_addr in call_pcodes:
        return
    pcodeOpAST = get_call_pcode(call_addr, call_pcodes)
    parms = analyze_call_parms(pcodeOpAST)

    if not parms:
        return

    for i in parms:
        parm_value = parms[i]

        parm_data = None
        if parm_value:
            if is_address_in_current_program(toAddr(parm_value)):
                if getDataAt(toAddr(parm_value)):
                    parm_data = getString(toAddr(parm_value))
                elif getInstructionAt(toAddr(parm_value)):
                    parm_data = getFunctionAt(toAddr(parm_value))
        # print(parm_data)
        parms_value["param_{}".format(i)] = {'param_value': parm_value,
                                            'param_data': parm_data}

    return parms_value
    
def get_constant_val(varnode):
    if not varnode.isConstant():
        print("not a constant...")
        return None
    varnode_string = str(varnode.toString())
    val_str = varnode_string.split(', ')
    val = val_str[1] # ['(const', '0x800', '4)']
    val = int(val, 16)
    return val

def get_str_data(args_addr):
    val_data = getDataAt(args_addr)
    if val_data != None and isinstance(val_data, type(u'') ):
        val = val_data.value
        temp = getString(val)
        if temp == None:
            return False, val
        else:
            val = temp
        return True, val
    else:
        val = None
        args_string = getString(args_addr)
        if args_string != None:
            return True, args_string
        else:
            return False, val
    
def get_string_val(varnode):
    if varnode.isUnique():
        args_def = varnode.getDef()
        try:
            args_addr = toAddr(args_def.getInput(0).getOffset())
            return get_str_data(args_addr)
        except:
            return False, None
    if varnode.isAddress():
        pass
    return False, None
        
def args_is_constOrstr(varnode):
    '''
    @param: VarnodeAST
    @return: is constant or string, True or False
    '''
    val = None
    if varnode.isUnique():
        return get_string_val(varnode)
    if varnode.isConstant():
        val = get_constant_val(varnode)
        return True, val
    else:   # fathe node is a constant or str?
        args_def = varnode.getDef()
        if args_def == None:
            return False, val
        MAX_LEN = len(args_def.getInputs())
        for i in range(MAX_LEN):
            temp_var = args_def.getInput(i)
            temp_def = temp_var.getDef()
            if temp_def == None:
                return False, None
            def_val = temp_def.getInput(0)
            if not def_val.isConstant() and not def_val.isUnique() and not def_val.isAddress():
                return False, None
        if def_val.isConstant():
            if def_val.getDef() == None:
                return False, val
            val = get_constant_val(def_val)
            val_str = getString(toAddr(val))
            if val_str != None:
                val = val_str
        elif def_val.isUnique():
            _, val = get_string_val(def_val)
        elif def_val.isAddress():
            _, val = get_str_data(def_val.getAddress())
        
        return True, val
            
def init_sink_dict():
    var_dict = {}
    for func in sinks:
        var_dict[func] = {}
    return var_dict
        
def get_call_pcodeOpAST(high_func, entry_point_dict):
    
    sink_func_pcodeAST = init_sink_dict()
    if high_func == None:
        return sink_func_pcodeAST
    ops = high_func.getPcodeOps()
    #all_pcodeOpAST = {}
    while(ops.hasNext() and not monitor.isCancelled()):
        pcodeOpAST = ops.next()
        if (pcodeOpAST.getOpcode() != PcodeOp.CALL):
            continue
        #args_list = pcodeOpAST.getInputs()
        call_target = pcodeOpAST.getInput(0)
        for name, addr in entry_point_dict.items():
            if call_target.getAddress() == addr:
                sink_func_pcodeAST[name][call_target.PCAddress] =pcodeOpAST
    return sink_func_pcodeAST
    
def get_all_args_varnode(pcodeOpAST):
    args_varnode = {}
    args_array = pcodeOpAST.getInputs()
    for i in range(0, len(args_array)-1):
        args = pcodeOpAST.getInput(i+1)
        args_varnode[i] = args
    return args_varnode
    
def get_all_args_symbol(local_symbol, stack_symbol, args_varnode):
    args_symbols = {}
    for i, args in args_varnode.items():
        symbol_args = get_param_var_from_varnode(args) # is parameter or local (pcvar)
        if symbol_args == None:
            symbol_args = get_stackvar_from_varnode(local_symbol, stack_symbol, args) # is stack
        if symbol_args == None:
            
            flag, val = args_is_constOrstr(args)
            if flag:
                symbol_args = val
        args_symbols[i] = symbol_args
    return args_symbols

def get_all_call_parm_value(call_addr, search_funcs=None):
    """
    :param call_addr:
    :param search_funcs: function name list to search
    :return:
    """
    target_func = getFunctionContaining(call_addr)
    parms_data = {}
    if target_func:
        target_refs = getReferencesTo(target_func.getEntryPoint())
        for ref in target_refs:
            # Filter reference type
            ref_type = ref.getReferenceType()
            if not ref_type.isCall():
                print("skip! Not a calll type")
                continue

            call_addr = ref.getFromAddress()
            func = getFunctionContaining(call_addr)
            if DEBUG:
                print("call_addr: {}".format(call_addr), "function: {}".format(func))
            if not func:
                continue
            # search only targeted function
            if search_funcs:
                if func.name not in search_funcs:
                    continue

            func_addr = func.getEntryPoint()
            if func_addr in decompile_function_cache:
                (_, call_pcodes) = decompile_function_cache[func_addr]
            else:
                ifc = decompile_config()
                high_func = decompile_func(ifc, func)
                call_pcodes = get_all_call_pcode(high_func)
                decompile_function_cache[func_addr] = (high_func, call_pcodes)

            parms_data[call_addr] = {
                'call_addr': call_addr,
                'ref_func_addr': func.getEntryPoint(),
                'ref_func_name': func.name,
                'params': {}
            }

            parms_value = get_call_parm_value(call_addr, call_pcodes)
            if not parms_value:
                continue

            trace_data = parms_data[call_addr]
            trace_data['params'] = parms_value

        return parms_data

def get_parent_def(args_Varnode):
    mul_parent  = []
    if args_Varnode.isUnique() and args_Varnode.getDef().getOpcode() == PcodeOp.COPY:
        flag, _ = get_string_val(args_Varnode)
        return flag
    if args_Varnode.isConstant():
        return True
    else:   # fathe node is a constant or str?
        args_def = args_Varnode.getDef()
        # print(args_def)
        if args_def == None: #or args_def.getOpcode() == PcodeOp.MULTIEQUAL: # todo
            return False
        MAX_LEN = len(args_def.getInputs())
        for i in range(MAX_LEN):
            temp_var = args_def.getInput(i)
            temp_def = temp_var.getDef()
            # print(temp_def)
            if temp_def == None:
                return False
            if temp_def.getOpcode() == PcodeOp.CALL: # var comes from function call
                call_site = temp_def.getSeqnum().getTarget().getOffset()
                target = temp_def.getInput(0).getAddress()
                return call_site, target
            if temp_def.getOpcode() == PcodeOp.LOAD:
                return False
            def_val = temp_def.getInput(0)
            # print(def_val)
            mul_parent.append(def_val)
        for val in mul_parent:
            if val.isConstant() or val.isAddress():
                return True
            elif val.isUnique() and val.getDef().getOpcode() == PcodeOp.COPY:
                return True
                
        return False
    
def get_bitmask():
    bitness_masks = {
        '16': 0xffff,
        '32': 0xffffffff,
        '64': 0xffffffffffffffff,
    }
    bitmask = 0xffffffff
    try:
        addr_size = currentProgram.getMetadata()['Address Size']
        bitmask = bitness_masks[addr_size]
    except KeyError:
        raise Exception("Unsupported bitness: {}. Add a bit mask for this target.".format(addr_size))
    return bitmask

def construct_varnode_symbol(func, high_func):
    local_symbol = {}
    stack_symbol = {}
    bitmask = get_bitmask()
    if high_func == None:
        return local_symbol, stack_symbol
    local_variables = func.getAllVariables()
    for lv in local_variables:
        unsigned_lv_offset = lv.getMinAddress().getUnsignedOffset() & bitmask
        local_symbol[unsigned_lv_offset] = lv
    
    lsm = high_func.getLocalSymbolMap()
    for symbol in lsm.getSymbols():
        if symbol.isParameter(): 
            continue
        defop_input_offset = symbol.getStorage().getFirstVarnode().getOffset() & bitmask
        stack_symbol[defop_input_offset] = symbol
    return local_symbol, stack_symbol

def get_stackvar_from_varnode(local_symbol, stack_symbol, varnode):
    bitmask = get_bitmask()
    vndef = varnode.getDef()
    if vndef:
        vndef_inputs = vndef.getInputs()
        for defop_input in vndef_inputs:
            defop_input_offset = defop_input.getAddress().getOffset() & bitmask
            if defop_input_offset in local_symbol:
                return local_symbol[defop_input_offset]
            if defop_input_offset in stack_symbol:
                return stack_symbol[defop_input_offset]
        
    return None

def get_param_var_from_varnode(varnode):
    var_high = varnode.getHigh()
    if type(var_high) == HighParam:
        param_symbol = var_high.getSymbol()
        return param_symbol
    if type(var_high) == HighLocal:
        pvar_symbol = var_high.getSymbol()
        return pvar_symbol
    return None

def get_clang_statements(func): 
    
    def token_walker(node,list):
        if type(node) == ClangStatement:
            list.append(node)
        else:
            for i in range(node.numChildren()):
                token_walker(node.Child(i),list)

    statement_nodes = list()
    statement_entry = dict()
    try:
        ifc = decompile_config()
        decres = ifc.decompileFunction(func, 60, monitor)
        token_walker(decres.getCCodeMarkup(),statement_nodes)
    except:
        return statement_entry
    
    for node in statement_nodes:
        if node.getMinAddress() is not None:
            if node.getPcodeOp().getOpcode() == PcodeOp.CALL:
                addr = node.getMaxAddress().getOffset()
            else:
                addr = node.getMinAddress().getOffset()
            statement_entry[addr]  = node   # ClangStatement
    ifc.closeProgram()
    return statement_entry


def trans_clang_state(statement_entry):
    pcodeAST_entry = {}
    for addr, clang_state in statement_entry.items():
        pcodeAST = clang_state.getPcodeOp()
        #addr = pcodeAST.getSeqnum().target
        pcodeAST_entry[addr] = pcodeAST
    
    return pcodeAST_entry
    
def get_prev_clang_code(pcodeAST, pcodeAST_entry):
    prev_addr = None
    if pcodeAST in pcodeAST_entry.values():
        for addr, ast in pcodeAST_entry.items():
            if ast == pcodeAST:
                return prev_addr
            else:
                prev_addr = addr
    return prev_addr

def label_varnode(pcodeAST_entry):
    #todo
    '''
    label:
    contant: 1
    call: 2
    other: 0
    '''
    varnode_label_dict = {}
    
    for addr, pcodeAST in sorted(pcodeAST_entry.items()):
        output = pcodeAST.getOutput()  # none, function call with no return
        if output == None and pcodeAST.getOpcode() == PcodeOp.CALL:
            callee = str(getFunctionContaining(pcodeAST.getInput(0).getAddress()).name)
            label = 0
            if callee in ['strcpy']: # needCheckConstantStr:
                print(pcodeAST)
                arg_inputs = pcodeAST.getInputs()[2:]
                
                print(varnode_label_dict)
                for arg in arg_inputs:
                    print(arg.getPCAddress())
                    if arg in varnode_label_dict:
                        label = label + varnode_label_dict[arg][arg.getPCAddress().getOffset()]
                    elif arg.isConstant() or arg.isUnique():
                        label = label + 1
                    else:
                        label = 0
                        break
                if label > 1:
                    label = 1
                output = str(pcodeAST.getInputs()[1].toString())
                addr = pcodeAST.getInputs()[1].getPCAddress().getOffset()
                print(output, label)
            else:
                output = 'None'
        elif output!= None and pcodeAST.getOpcode() == PcodeOp.CALL:
            output = str(output.toString())
            label = 2
        else:
            input = pcodeAST.getInput(0)
            if output == None:
                output = 'None'
            else:
                output = str(output.toString())
            if input.isConstant():
                label = 1
            else:
                label = 0
        if output in varnode_label_dict:
            varnode_label_dict[output][addr] = label
        else:
            varnode_label_dict[output] = {}
            varnode_label_dict[output][addr] = label
             
    return varnode_label_dict
    
def get_var_label(func):
    statement_entry = get_clang_statements(func)
    pcodeAST_entry = trans_clang_state(statement_entry)
    varnode_label_dict = label_varnode(pcodeAST_entry)
    
    return varnode_label_dict
        
def decompile_config():
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    return ifc

def decompile_func(ifc, func):
    if func == None:
        return None
    res = ifc.decompileFunction(func, 60, monitor)
    high_func = res.getHighFunction()
    return high_func

def get_function_pcode(high_func):
    if high_func:
        try:
            ops = high_func.getPcodeOps()
        except:
            return None
        return ops

def get_func_start_end_int(func):
    func_body = func.getBody().toList()
    start = a2i(func_body[0].minAddress)
    end = a2i(func_body[-1].maxAddress)
    return start, end

def get_func_start_end_addr(func):
    func_body = func.getBody().toList()
    start = func_body[0].minAddress
    end = func_body[-1].maxAddress
    return start, end
def get_sink_func_addr():
    global sinks_dict
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.getName() in sinks:
            entry_point = func.getEntryPoint()
            if DEBUG:
                print("Found %s @ 0x%08x" % (func.getName(), a2i(entry_point)))
            if func.body.minAddress == func.body.maxAddress:
                continue
            sinks_dict[str(func.getName())] = entry_point
    return sinks_dict

def check_strcpy(func, all_pcodeOpAST, local_symbol, stack_symbol):
    global sinks_dict
    global sinks_size
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check 'strcpy' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        varnodes = get_all_args_varnode(opAST)
        args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
        # print_symbol(args_symbol[0])
        # print_symbol(args_symbol[1])
        try:
            if isinstance(args_symbol[0].dataType, ArrayDataType):
                size = args_symbol[0].size
                sinks_size[a2i(addr)] = size
            if isinstance(args_symbol[0].dataType, ArrayDataType) and isinstance(args_symbol[1].dataType, ArrayDataType):
                size_flag = args_symbol[0].size >= args_symbol[1].size
            else:
                size_flag = False
        except:
            size_flag = False
        # try:
        #     para_flag = True
        #     if 'param' in args_symbol[1].name:
        #         parms_data = get_all_call_parm_value(addr)
        #         for ref_addr, info in parms_data.items():
        #             if info['params'][args_symbol[1].name]['param_data'] == None:
        #                 para_flag = False
        #                 break
        #         if para_flag:
        #             if DEBUG:
        #                 print("Call strcpy @ 0x%08x : not vulnerable..." % a2i(addr))
        #             if WRITE_FILE:
        #                 result_write.write("Call strcpy @ 0x%08x : not vulnerable...\n" % a2i(addr))
                    
        #         else:
        #             if DEBUG:
        #                 print("Call strcpy @ 0x%08x : may be vulnerable...." % a2i(addr))
        #             if WRITE_FILE:
        #                 result_write.write("Call strcpy @ 0x%08x : may be vulnerable....\n" % a2i(addr))
        #         continue
        # except:
        #     pass
        const_flag = get_parent_def(varnodes[1])
        # print(const_flag, size_flag)
        if const_flag == True or size_flag:
            addr_sink_flag[addr] = (sinks_dict['strcpy'], False)
            if DEBUG:
                print("Call strcpy @ 0x%08x : not vulnerable..." % a2i(addr))
            if WRITE_FILE:
                result_write.write("Call strcpy @ 0x%08x : not vulnerable...\n" % a2i(addr))
        else:
            if const_flag != False:
                try:
                    call_site, func_addr = const_flag
                    callee = getFunctionContaining(func_addr)
                    func_name = str(callee.name)
                    if DEBUG:
                        print("parameter 'src' comes @ 0x%08x call: %s" % (call_site, func_name))
                    if WRITE_FILE:
                        result_write.write("parameter 'src' comes @ 0x%08x call: %s\n" % (call_site, func_name))
                except:
                    pass
            addr_sink_flag[addr] = (sinks_dict['strcpy'], True)
            if DEBUG:
                print("Call strcpy @ 0x%08x : may be vulnerable...." % a2i(addr))
            if WRITE_FILE:
                result_write.write("Call strcpy @ 0x%08x : may be vulnerable....\n" % a2i(addr))
            
def check_memcpy(func, all_pcodeOpAST, local_symbol, stack_symbol):
    global sinks_dict
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check 'memcpy' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        is_vuln = _check_strncpy(opAST, local_symbol, stack_symbol, func.getEntryPoint())
        if is_vuln:
            addr_sink_flag[addr] = (sinks_dict['memcpy'], True)
            if DEBUG:
                print("Call memcpy @ 0x%08x : may be vulnerable...." % a2i(addr))
        else:
            addr_sink_flag[addr] = (sinks_dict['memcpy'], False)
            if DEBUG:
                print("Call memcpy @ 0x%08x : not vulnerable..." % a2i(addr))
            
def check_strncpy(func, all_pcodeOpAST, local_symbol, stack_symbol):
    global sinks_dict
    if all_pcodeOpAST != {}:
        print("Check 'strncpy' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        is_vuln = _check_strncpy(opAST, local_symbol, stack_symbol, func.getEntryPoint())
        if is_vuln:
            addr_sink_flag[addr] = (sinks_dict['strncpy'], True)
            if DEBUG:
                print("Call strncpy @ 0x%08x : may be vulnerable...." % a2i(addr))
        else:
            addr_sink_flag[addr] = (sinks_dict['strncpy'], False)
            if DEBUG:
                print("Call strncpy @ 0x%08x : not vulnerable..." % a2i(addr))
                
def check_strlcpy(func, all_pcodeOpAST, local_symbol, stack_symbol):
    global sinks_dict
    if all_pcodeOpAST != {}:
        print("Check 'strlcpy' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        is_vuln = _check_strncpy(opAST, local_symbol, stack_symbol, func.getEntryPoint())
        if is_vuln:
            addr_sink_flag[addr] = (sinks_dict['strlcpy'], True)
            if DEBUG:
                print("Call strlcpy @ 0x%08x : may be vulnerable...." % a2i(addr))
        else:
            addr_sink_flag[addr] = (sinks_dict['strlcpy'], False)
            if DEBUG:
                print("Call strlcpy @ 0x%08x : not vulnerable..." % a2i(addr))
                        
def _check_strncpy(opAST, local_symbol, stack_symbol, addr):
    '''
    strncpy, memcpy
    '''
    varnodes = get_all_args_varnode(opAST)
    args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
    try:
        para_flag = True
        if 'param' in args_symbol[1].name:
            parms_data = get_all_call_parm_value(addr)
            for ref_addr, info in parms_data.items():
                if info['params'][args_symbol[1].name]['param_data'] == None:
                    para_flag = False
                    break
            if para_flag:
                return False
                
            else:
                return True
    except:
        pass
    try:
        # if isinstance(args_symbol[0].dataType, ArrayDataType) and isinstance(args_symbol[2], int):
        if isinstance(args_symbol[2], int):
            size_flag = True  #511, 512
        elif isinstance(args_symbol[0].dataType, ArrayDataType) and isinstance(args_symbol[1].dataType, ArrayDataType):
            size_flag = args_symbol[0].size >= args_symbol[1].size
        else:
            size_flag = False
    except:
        size_flag = False
    const_flag = get_parent_def(varnodes[1])
    if const_flag or size_flag:
        return False
    else:
        return True

format_char = ['c','d','i', 'e', 'E', 'f', 'g', 'G', 'o', 'u', 'x', 'X', 'p', 'n', '%']
format_num = ['0', '1', '2', '3,', '4', '5', '6', '7', '8', '9']
def parse_format(format_str, start = 2):
    '''
    sprintf: start from arg2
    snprintf: start from arg3
    '''
    s_index = format_str.find('%s')
    num_para = start
    para_dict = {}  #index: True/Flase
    if s_index == -1:
        return para_dict
    
    for s in range(0, len(format_str) - 1, 1):
        char = format_str[s]
        if char == '%':
            if format_str[s+1] == 's':
                para_dict[num_para] = True
                num_para += 1
                s = s + 2
            elif format_str[s+1] in format_char:
                para_dict[num_para] = False
                num_para += 1
                s = s + 2
            elif format_str[s+1] in format_num:
                try:
                    if format_str[s+2] in format_char:
                        para_dict[num_para] = False
                        num_para += 1
                        s = s + 3
                    elif format_str[s+2] in format_num and format_str[s+3] in format_char:
                        para_dict[num_para] = False
                        num_para += 1
                        s = s + 4
                except:
                    pass
                        
    return para_dict     

def check_format(format_str, args_symbol, varnodes, addr):
    
    # try:
    #     para_flag = True
    #     if 'param' in args_symbol[2].name:
    #         parms_data = get_all_call_parm_value(addr)
    #         for ref_addr, info in parms_data.items():
    #             if info['params'][args_symbol[2].name]['param_data'] == None:
    #                 para_flag = False
    #                 break
    #         if para_flag:
    #             if DEBUG:
    #                 print("Call sprintf @ 0x%08x : not vulnerable..." % a2i(addr))
    #             if WRITE_FILE:
    #                 result_write.write("Call sprintf @ 0x%08x : not vulnerable...\n" % a2i(addr))
    #         else:
    #             if DEBUG:
    #                 print("Call sprintf @ 0x%08x : may be vulnerable...." % a2i(addr))
    #             if WRITE_FILE:
    #                 result_write.write("Call sprintf @ 0x%08x : may be vulnerable....\n" % a2i(addr))
    #         return True
    # except:
    #     pass
    format_len = len(format_str) - len(args_symbol) + 2
    # for i in range(1, len(args_symbol)):
    #     print_symbol(args_symbol[i])
    para_dict = parse_format(format_str)
    if len(para_dict) != len(args_symbol) - 2:
        addr_sink_flag[addr] = (sinks_dict['sprintf'], True)
        if DEBUG:
            print("Parse formate string error...")
            print("Call sprintf @ 0x%08x : may be vulnerable...." % a2i(addr))
        return False
    str_symbol = []
    for index, flag in para_dict.items():
        if flag == True:
            str_symbol.append(args_symbol[index])
    try:
        if isinstance(args_symbol[0].dataType, ArrayDataType):
            dst_max_size = args_symbol[0].size
            src_size = format_len
            for sym in str_symbol:
                if isinstance(sym, str):
                    src_size = src_size + len(sym)
                else:
                    try:
                        if isinstance(sym.dataType, ArrayDataType):
                            src_size = src_size + sym.size
                        else:
                            src_size = 0xffffffff
                            break 
                    except:
                        pass
            size_flag = dst_max_size >= src_size
        else:
            size_flag = False
    except:
        size_flag = False
    var_num = 0
    for index, flag in para_dict.items():
        if flag == True:
            const_flag = get_parent_def(varnodes[index])

            try:
                call_site, func_addr = const_flag
                callee = getFunctionContaining(func_addr)
                func_name = str(callee.name)
                var_num += 1
                if DEBUG:
                    print("parameter 'src' comes @ 0x%08x call: %s" % (call_site, func_name))
                if WRITE_FILE:
                    result_write.write("parameter 'src' comes @ 0x%08x call: %s\n" % (call_site, func_name))
            except:
                if const_flag == False:
                    var_num = 1
    if var_num == 0 or size_flag:
        addr_sink_flag[addr] = (sinks_dict['sprintf'], False)
        if DEBUG:
            print("Call sprintf @ 0x%08x : not vulnerable..." % a2i(addr))
    else:
        addr_sink_flag[addr] = (sinks_dict['sprintf'], True)
        if DEBUG:
            print("Call sprintf @ 0x%08x : may be vulnerable...." % a2i(addr))
    return True

def check_sprintf(func, all_pcodeOpAST, local_symbol, stack_symbol):
    '''
    args0: destination,
    args1: format       if '%s' in args1
    args2: source
    args.: source
    '''
    global sinks_dict
    global sinks_size
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check 'sprintf' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        varnodes = get_all_args_varnode(opAST)
        args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
        if isinstance(args_symbol[1], str) and '%s' in args_symbol[1]:
            check_format(args_symbol[1], args_symbol, varnodes, addr)
        else:
            if isinstance(args_symbol[1], str):
                addr_sink_flag[addr] = (sinks_dict['sprintf'], False)
                if DEBUG:
                    print("Call sprintf @ 0x%08x : not vulnerable..." % a2i(addr))
            else:
                const_flag = get_parent_def(varnodes[1])
                _, val = args_is_constOrstr(varnodes[1])
                if const_flag and isinstance(val, str) and '%s' not in val:
                    addr_sink_flag[addr] = (sinks_dict['sprintf'], False)
                    if DEBUG:
                        print("Call sprintf @ 0x%08x : not vulnerable..." % a2i(addr))
                elif const_flag and isinstance(val, str) and '%s' in val:
                    if check_format(val, args_symbol, varnodes, addr) == False:
                        continue
                else:
                    addr_sink_flag[addr] = (sinks_dict['sprintf'], True)
                    if DEBUG:
                        print("Call sprintf @ 0x%08x : may be vulnerable...." % a2i(addr))

def check_snprintf(func, all_pcodeOpAST, local_symbol, stack_symbol):
    '''
    args0: destination,
    args1: format       if '%s' in args1
    args2: source
    args.: source
    '''
    global sinks_dict
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check 'snprintf' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        varnodes = get_all_args_varnode(opAST)
        args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
        if isinstance(args_symbol[0].dataType, ArrayDataType):
            dst_max_size = args_symbol[0].size
            if isinstance(args_symbol[1], int):
                size_thresh = args_symbol[1]
                if dst_max_size >= size_thresh:
                    addr_sink_flag[addr] = (sinks_dict['snprintf'], False)
                    if DEBUG:
                        print("Call snprintf @ 0x%08x : not vulnerable..." % a2i(addr))
                    continue
        if isinstance(args_symbol[2], str) and '%s' in args_symbol[2]:
            format_str = args_symbol[2]
            format_len = len(format_str) - len(args_symbol) + 2
            
            para_dict = parse_format(format_str, start = 3)
            if len(para_dict) != len(args_symbol) - 3:
                addr_sink_flag[addr] = (sinks_dict['snprintf'], True)
                if DEBUG:
                    print("Parse formate string error...")
                    print("Call snprintf @ 0x%08x : may be vulnerable...." % a2i(addr))
                continue
            str_symbol = []
            for index, flag in para_dict.items():
                if flag == True:
                    str_symbol.append(args_symbol[index])
            try:
                if isinstance(args_symbol[0].dataType, ArrayDataType):
                    dst_max_size = args_symbol[0].size

                    src_size = format_len
                    for sym in str_symbol:
                        if isinstance(sym, str):
                            src_size = src_size + len(sym)
                        else:
                            try:
                                if isinstance(sym.dataType, ArrayDataType):
                                    src_size = src_size + sym.size
                                else:
                                   src_size = 0xffffffff
                                   break 
                            except:
                                pass
                    size_flag = dst_max_size >= src_size
                else:
                    size_flag = False
            except:
                size_flag = False
            for index, flag in para_dict.items():
                if flag == True:
                    const_flag = get_parent_def(varnodes[index])
                    if const_flag == False:
                        break
            if const_flag or size_flag:
                addr_sink_flag[addr] = (sinks_dict['snprintf'], False)
                if DEBUG:
                    print("Call snprintf @ 0x%08x : not vulnerable..." % a2i(addr))
            else:
                addr_sink_flag[addr] = (sinks_dict['sprintf'], True)
                if DEBUG:
                    print("Call snprintf @ 0x%08x : may be vulnerable...." % a2i(addr))
        else:
            if isinstance(args_symbol[2], str):
                addr_sink_flag[addr] = (sinks_dict['sprintf'], False)
                if DEBUG:
                    print("Call snprintf @ 0x%08x : not vulnerable..." % a2i(addr))
            else:
                const_flag = get_parent_def(varnodes[2])
                _, val = args_is_constOrstr(varnodes[2])
                if const_flag and '%s' not in val:
                    addr_sink_flag[addr] = (sinks_dict['sprintf'], False)
                    if DEBUG:
                        print("Call snprintf @ 0x%08x : not vulnerable..." % a2i(addr))
                else:
                    addr_sink_flag[addr] = (sinks_dict['sprintf'], True)
                    if DEBUG:
                        print("Call snprintf @ 0x%08x : may be vulnerable...." % a2i(addr))


def check_system(func, all_pcodeOpAST, local_symbol, stack_symbol):
    
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check 'system' in function @ 0x%08x" % a2i(func.getEntryPoint()))
    for addr, opAST in all_pcodeOpAST.items():
        varnodes = get_all_args_varnode(opAST)
        args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
        if isinstance(args_symbol[0], str):
            addr_sink_flag[addr] = (sinks_dict['system'], False)
            if DEBUG:
                print("Call system @ 0x%08x : not vulnerable..." % a2i(addr))
        else:
            const_flag = get_parent_def(varnodes[0])
            _, val = args_is_constOrstr(varnodes[0])
            if const_flag:
                addr_sink_flag[addr] = (sinks_dict['system'], False)
                if DEBUG:
                    print("Call system @ 0x%08x : not vulnerable..." % a2i(addr))
            else:
                addr_sink_flag[addr] = (sinks_dict['system'], True)
                if DEBUG:
                    print("Call system @ 0x%08x : may be vulnerable...." % a2i(addr))


def get_risky_sinks():
    global sinks_dict
    global addr_sink_flag
    global risky_sink
    global secure_sink
    
    name = str(currentProgram.name)
    for call_addr, sink_info in addr_sink_flag.items():
        sink_func_addr, flag = sink_info
        call_addr = a2i(call_addr)
        sink_func_addr = a2i(sink_func_addr)
        if flag:
            risky_sink[call_addr] = sink_func_addr
        else:
            secure_sink[call_addr] = sink_func_addr
            
    risky_info_file = open(name + "_risky_sink.txt", 'w')
    for call_addr, sink_func_addr in risky_sink.items():
        sink_func_name = getFunctionContaining(toAddr(sink_func_addr)).name
        line_info = "0x%08x 0x%08x %s\n" % (call_addr, sink_func_addr, sink_func_name)
        risky_info_file.write(line_info)
    risky_info_file.close
    
    secure_info_file = open(name + "_secure_sink.txt", 'w')
    for call_addr, sink_func_addr in secure_sink.items():
        sink_func_name = getFunctionContaining(toAddr(sink_func_addr)).name
        line_info = "0x%08x 0x%08x %s\n" % (call_addr, sink_func_addr, sink_func_name)
        secure_info_file.write(line_info)
    secure_info_file.close
    
    return risky_sink

def check_all_sink():
    fm = currentProgram.getFunctionManager()
    total_strcpy = 0
    not_vulnerable = 0
    funcs = fm.getFunctions(True)
    sinks_entry_dict = get_sink_func_addr()
    ifc = decompile_config()
    for func in funcs:
        high_func = decompile_func(ifc, func)
        local_symbol, stack_symbol = construct_varnode_symbol(func, high_func)
        sink_func_pcodeAST = get_call_pcodeOpAST(high_func, sinks_entry_dict)
        # all_pcodeOpAST = sink_func_pcodeAST["strcpy"]
        # check_strcpy(func, all_pcodeOpAST, local_symbol, stack_symbol)
        all_pcodeOpAST = sink_func_pcodeAST["system"]
        check_system(func, all_pcodeOpAST, local_symbol, stack_symbol)
        
        # all_pcodeOpAST = sink_func_pcodeAST["memcpy"]
        # check_memcpy(func, all_pcodeOpAST, local_symbol, stack_symbol)
        # all_pcodeOpAST = sink_func_pcodeAST["sprintf"]
        # check_sprintf(func, all_pcodeOpAST, local_symbol, stack_symbol)
    ifc.closeProgram()
    #print("Total %d strcpy calls, %d is not vulnerable..." % (total_strcpy, not_vulnerable/ total_strcpy))

def get_secure_sink(filename):
    global sinks_dict
    global addr_sink_flag
    global risky_sink

    fm = currentProgram.getFunctionManager()

    funcs = fm.getFunctions(True)
    sinks_entry_dict = get_sink_func_addr()
    ifc = decompile_config()
    for func in funcs:
        high_func = decompile_func(ifc, func)
        local_symbol, stack_symbol = construct_varnode_symbol(func, high_func)
        sink_func_pcodeAST = get_call_pcodeOpAST(high_func, sinks_entry_dict)
        for name, all_pcodeOpAST in sink_func_pcodeAST.items():
            # all_pcodeOpAST = sink_func_pcodeAST["strcpy"]
            sinks_size = get_dst_size(name, func, all_pcodeOpAST, local_symbol, stack_symbol)
        all_pcodeOpAST = sink_func_pcodeAST["strcpy"]
        check_strcpy(func, all_pcodeOpAST, local_symbol, stack_symbol)
        # all_pcodeOpAST = sink_func_pcodeAST["system"]
        # check_system(func, all_pcodeOpAST, local_symbol, stack_symbol)
        
        # all_pcodeOpAST = sink_func_pcodeAST["memcpy"]
        # check_memcpy(func, all_pcodeOpAST, local_symbol, stack_symbol)
        all_pcodeOpAST = sink_func_pcodeAST["sprintf"]
        check_sprintf(func, all_pcodeOpAST, local_symbol, stack_symbol)
    ifc.closeProgram()
    secure_sink_addr = []
    for call_addr, sink_info in addr_sink_flag.items():
        sink_func_addr, flag = sink_info
        call_addr = a2i(call_addr)
        sink_func_addr = a2i(sink_func_addr)

        if not flag:
            secure_sink_addr.append(call_addr)

    # name = str(currentProgram.name)
    size_info = open(filename + "_sink_size.txt", 'w')
    for addr, size in sinks_size.items():
        size_info.write("0x%08x:%d\n" % (addr, size))
    size_info.close()

    return secure_sink_addr
   
def searchStrArg(func):
    if func in searchStrArgDone:
        return
    if DEBUG:
        print ('start search', func, '(heuristic)')
    searchStrArgDone.add(func)
    start = func.entryPoint
    end = func.body.maxAddress

    global funcPosCounter
    # funcPosCounter = Counter()
    inst = getInstructionAt(start)
    while inst is not None and inst.address < end:
        callee = getCallee(inst)
        if callee is not None:
            if str(callee.name) in heurist_filte_func or 'thunk' in str(callee.name):
                inst = inst.next
                continue
            maxpos = 4
            if callee.parameterCount > 0: #donot consider only one para, the result of callee.parameterCount is not always correct.
                                        # need to implement it by ourselves
                maxpos = min(maxpos, callee.parameterCount)
            for pos in range(maxpos):
                if getStrArg(inst.address, pos) in paramTargets:
                    # if pos == 0:
                    #     inst = inst.next
                    #     continue
                    funcPosCounter[callee, pos] += 1
        inst = inst.next

def get_implicit_para(func):

    start = func.entryPoint
    end = func.body.maxAddress

    global funcPosCounter
    # newParamCount = 0
    inst = getInstructionAt(start)
    while inst is not None and inst.address < end:
        callee = getCallee(inst)
        if callee is not None and callee.name not in heurist_filte_func and 'thunk' not in str(callee.name):
            for pos in range(4):
                if funcPosCounter[callee, pos] >= heuristicMin:
                    s = getStrArg(inst.address, pos)
                    if s and re.search(r'[a-zA-Z_]{4}', s) and s not in paramTargets:
                        if DEBUG:
                            print ('new param', s)
                        if '<' in s or '>' in s or '\r' in s or '\n' in s or '\t' in s or ' 'in s or '.' in s or \
                            '[' in s or ']' in s or "'" in s or '=' in s or '!' in s or '{' in s or '}' in s or '(' in s or \
                                ')' in s or '*' in s or '$' in s or '@' in s or '$' in s or '+' in s or '\\' in s or '/' in s or \
                                    '%' in s or ':' in s:
                            pass
                        else:
                            newParam[s].add(func)
                        # newParamCount += 1

        inst = inst.next
    if DEBUG:
        print ('finish search', func, '(heuristic)')
    return

def findSinkPath(refaddr, stringaddr, stringval):
    pending = []

    def search(func, start=None):
        if func in callMap:
            return
        callMap[func] = {}

        start = start or func.entryPoint
        end = func.body.maxAddress

        inst = getInstructionAt(start)
        while inst is not None and inst.address < end:  #comment: find all callee
            callee = getCallee(inst)
            if callee is not None:
                callMap[func][inst.address] = callee
                if callee not in callMap:
                    pending.append(callee)
            inst = inst.next

    def printpath(path):
        print >>f, '[Param "%s"(%s), Referenced at %s : %s]' % (stringval, a2h(stringaddr), startFunc, a2h(refaddr)),
        for i in range(len(path)):
            addr, callee = path[i][:2]
            if i == len(path) - 1:
                print >>f, '>>', a2h(addr), '->', callee,
            else:
                calleeCallDigestFunc = path[i + 1][-1]
                if calleeCallDigestFunc:
                    print >>f, '>>', a2h(addr), '>>', callee,
                else:
                    print >>f, '>>', a2h(addr), '->', callee,

        print >>f

    def dfs(func, path, start=None):
        '''path: list of (addr of call, callee, callDigestFunc)'''
        if len(path) > 5:
            return False
        if func.name in sinks and len(path): #comment: 函数在sink中，
            if func.name in needCheckConstantStr and checkConstantStr(path[-1][0], needCheckConstantStr[func.name]):
                return False
            if func.name in needCheckFormat and checkSafeFormat(path[-1][0], needCheckFormat[func.name]):
                return False
            printpath(path)
            return True
        callDigestFunc = False
        vulnerable = False
        for addr, callee in sorted(callMap[func].items()):
            if start is not None and addr < start:
                continue
            if not callDigestFunc and callee.name in digest:
                if callee.name in needCheckConstantStr and checkConstantStr(addr, needCheckConstantStr[callee.name]):
                    pass
                elif callee.name in needCheckFormat and checkSafeFormat(addr, needCheckFormat[callee.name]):
                    pass
                else:
                    callDigestFunc = True
            if callee in [x[1] for x in path] + [startFunc] or callee in safeFuncs:
                continue
            vulnerable = dfs(callee, path + [(addr, callee, callDigestFunc)]) or vulnerable
        if not vulnerable and func != startFunc:
            safeFuncs.add(func)
        return vulnerable

    startFunc = getFunctionContaining(refaddr)
    assert startFunc is not None

    pending.append(startFunc)
    while len(pending):
        search(pending.pop())

    vulnerable = dfs(startFunc, [], refaddr)
    # if vulnerable:
    #     searchStrArg(startFunc)
    return vulnerable


def searchParam(target, refstart=None, refend=None):
    if DEBUG:
        print ('start searching "%s" ...' % target)
    curAddr = currentProgram.minAddress
    end = currentProgram.maxAddress
    haveWayToSink = False
    checkedRefAddr = set()
    while curAddr < end:
        curAddr = find(curAddr, target)
        if curAddr is None:
            break
        if getByte(curAddr.add(len(target))) != 0: #查找到当前字符串结尾，因为target可能是一个字符串的子串
            curAddr = curAddr.add(1)
            continue
        for ref in getReferencesTo(curAddr):
            if refstart is not None and refstart > ref.fromAddress:
                continue
            if refend is not None and refend < ref.fromAddress:
                continue
            if target not in newParam:
                referenced.add(target)
            caller = getFunctionContaining(ref.fromAddress)
            if caller is None:
                continue
            _, func_end = get_func_start_end_addr(caller)
            inst = getInstructionAt(ref.fromAddress)
            callee_name = None
            while inst is not None and inst.address < func_end:
                callee = getCallee(inst)
                if callee is not None:
                    callee_name = callee.name
                    break
                inst = inst.next
            if callee_name in heurist_filte_func or 'thunk' in str(callee_name):
                continue
            if caller is not None:
                if DEBUG:
                    print ('Reference From', a2h(ref.fromAddress), '(%s)' % caller,)
                    print ('To', a2h(curAddr), '("%s")' % target)
                if ref.fromAddress in checkedRefAddr:
                    continue
                haveWayToSink = findSinkPath(ref.fromAddress, curAddr, target) or haveWayToSink
                checkedRefAddr.add(ref.fromAddress)
            else:
                for ref2 in getReferencesTo(ref.fromAddress):
                    caller = getFunctionContaining(ref2.fromAddress)
                    if caller is None:
                        if DEBUG:
                            print ('Ignore', getSymbolAt(ref2.fromAddress), 'at', a2h(ref2.fromAddress))
                        continue
                    if DEBUG:
                        print ('Reference From', a2h(ref2.fromAddress), '(%s)' % caller,)
                        print ('To', a2h(ref.fromAddress), '(%s)' % getSymbolAt(ref.fromAddress),)
                        print ('To', a2h(curAddr), '("%s")' % target)
                    if ref2.fromAddress in checkedRefAddr:
                        continue
                    haveWayToSink = findSinkPath(ref2.fromAddress, curAddr, target) or haveWayToSink
                    checkedRefAddr.add(ref2.fromAddress)

        curAddr = curAddr.add(1)
    if DEBUG:
        print ('finish searching "%s"' % target)
    return haveWayToSink

def a2i(addr):
    return int(a2h(addr), 16)

def fix_undefinefunction():
    listing = currentProgram.getListing()
    initer = listing.getInstructions(currentProgram.getMemory(), True)
    while (initer.hasNext() and not monitor.isCancelled()):
        inst = initer.next()
        inst_addr = inst.address
        if listing.isInFunction(inst_addr):
            pass
        else:
            inst_ref = getReferencesTo(inst_addr)
            if inst_ref.tolist() == []:
                inst_string = str(inst_addr.toString())
                try:
                    if DEBUG:
                        print("Creat function @ 0x%08x ..." % a2i(inst_addr))
                    createFunction(inst_addr, "FUN_" + inst_string)
                except:
                    print("Creat function error @ 0x%08x ..." % a2i(inst_addr))
                continue
            
            for ref in inst_ref:
                if ref.getReferenceType().isData():
                    ref_from = ref.fromAddress
                    if not listing.isInFunction(ref_from):
                        inst_string = str(inst_addr.toString())
                        try:
                            if DEBUG:
                                print("Creat function @ 0x%08x ..." % a2i(inst_addr))
                            createFunction(inst_addr, "FUN_" + inst_string)
                            # print("Creat function @ 0x%08x ..." % a2i(inst_addr))
                            break
                        except:
                            print("Creat function error @ 0x%08x ..." % a2i(inst_addr))

def heurist_para():
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        searchStrArg(func)
    funcs = fm.getFunctions(True)

    for func in funcs:
        get_implicit_para(func)

def read_sinks(filename):
    global sinks
    addr_in = open(filename + '-funcaddr', 'r')
    for line in addr_in.readlines():
        addr = int(line.strip(), 16)
        try:
            func_name = str(getFunctionContaining(toAddr(addr)).name)
            sinks.append(func_name)
        except:
            pass
    sinks = list(set(sinks))

def get_dst_size(name, func, all_pcodeOpAST, local_symbol, stack_symbol):
    global sinks_size
    if all_pcodeOpAST != {}:
        if DEBUG:
            print("Check '%s' in function @ 0x%08x" % (name, a2i(func.getEntryPoint())))
    for addr, opAST in all_pcodeOpAST.items():
        varnodes = get_all_args_varnode(opAST)
        args_symbol = get_all_args_symbol(local_symbol, stack_symbol, varnodes)
        # print_symbol(args_symbol[0])
        # print_symbol(args_symbol[1])
        try:
            if isinstance(args_symbol[0].dataType, ArrayDataType):
                size = args_symbol[0].size
                sinks_size[a2i(addr)] = size
                if DEBUG:
                    print("0x%08x : %d" % (a2i(addr), size))
                
        except:
            continue

    return sinks_size

def filter_secure_sink(filename, secure_sink_addrs):
    with open(filename,'r') as f:
        cont = f.read()
    cont = cont.split('\n')
    pattern = re.compile("0x[0-9a-fA-F]+")
    out = open(filename +'-filte','w')

    func_file_name = open(filename.replace("_ref2sink_bof.result", "-funcaddr"), 'r')
    func_addrs = set()
    for line in func_file_name.readlines():
        addr = int(line.strip(), 16)
        try:
            func_addrs.add(addr)
        except:
            pass
    
    ori_sink_addr = set()
    after_sink_addr = set()
    for i in cont:
        try:
            findlist = pattern.findall(i)
            sink_addr = int(findlist[-1], 16)
            ori_sink_addr.add(sink_addr)
            if sink_addr in secure_sink_addrs:
                continue
            else:
                after_sink_addr.add(sink_addr)
                out.write(i + '\n')  
        except:
            out.write(i + '\n')
            print ("The following line parse error:",i)
    out.write("original: %d\n" %len(ori_sink_addr))
    out.write("after: %d\n" %len(after_sink_addr))
    out.write("after-loop: %d\n" %len(after_sink_addr.difference(func_addrs)))
    for addr in secure_sink_addrs:
        out.write("0x%08x " % addr)
    out.write("\n")
    out.close()

if __name__ == '__main__':
    args = getScriptArgs()
    fix_undefinefunction()
    paramTargets = set(open(args[0]).read().strip().split())
    filename = args[1].replace('_ref2sink_bof.result','')
    read_sinks(filename)
    f = None
    if len(args) > 1:
        f = open(args[1], 'w')

    numOfParam = len(paramTargets)
    heurist_para()
    t = time.time()
    cnt = 0
    for i, param in enumerate(paramTargets):
        monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, numOfParam))
        cnt += searchParam(param)

    new_cnt = 0
    flag = False
    for i, param in enumerate(newParam):
        monitor.setMessage('Searching for "%s": %d of %d' % (param, i + 1, len(newParam)))
        for func in newParam[param]:
            if searchParam(param, func.body.minAddress, func.body.maxAddress) == True:
                flag = True
        new_cnt += flag

    t = time.time() - t
    print ('Time Elapsed:', t)
    print ('%d of %d parameters are referenced' % (len(referenced), numOfParam))
    print ('%d of %d parameters have way to sink function' % (cnt, numOfParam))
    print ('Find %d new params heuristicly:' % len(newParam))
    print ('%d of %d parameters have way to sink function' % (new_cnt, len(newParam)))
    print (', '.join(newParam))

    if f is not None:
        print >>f, 'Time Elapsed:', t
        print >>f, '%d of %d parameters are referenced' % (len(referenced), numOfParam)
        print >>f, '%d of %d parameters have way to sink function' % (cnt, numOfParam)
        print >>f, 'Find %d new params heuristicly:' % len(newParam)
        print >>f, '%d of %d parameters have way to sink function' % (new_cnt, len(newParam))
        print >>f, ', '.join(newParam)
        f.close()
    secure_sink_addrs = get_secure_sink(filename)
    filter_secure_sink(args[1], secure_sink_addrs)
