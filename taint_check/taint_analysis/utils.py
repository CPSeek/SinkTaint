import angr
import archinfo

bugFindingFlag=False
current_cfg=None
arm_registers = {
        'r0': (8, 4),
        'r1': (12, 4),
        'r2': (16, 4),
        'r3': (20, 4),
        'r4': (24, 4),
        'r5': (28, 4),
        'r6': (32, 4),
        'r7': (36, 4),
        'r8': (40, 4),
        'r9': (44, 4),
        'r10': (48, 4),
        'r11': (52, 4),
        'r12': (56, 4),
        'lr': (64, 4)
    }
aarch_registers = {
        'x0': (16, 8),
        'x1': (24, 8),
        'x2': (32, 8),
        'x3': (40, 8),
        'x4': (48, 8),
        'x5': (56, 8),
        'x6': (64, 8),
        'x7': (72, 8),
        'x30': (256, 8)
    }
mips_registers = {
        'v0': (16, 4),
        'a0': (24, 4),
        'a1': (28, 4),
        'a2': (32, 4),
        'a3': (36, 4),
        'lr': (132, 4),
        'ra': (132, 4)
    }
def setBugFindingFlag(bo,cfg=None):
    global bugFindingFlag,current_cfg
    bugFindingFlag=bo
    if bo:
        current_cfg=cfg
def getBugFindingFlag():
    global bugFindingFlag
    return bugFindingFlag
def getBugFindingCFG():
    global current_cfg
    return current_cfg
ordered_argument_regs = {
    'ARMEL': [
        arm_registers['r0'][0],
        arm_registers['r1'][0],
        arm_registers['r2'][0],
        arm_registers['r3'][0],
        arm_registers['r4'][0],
        arm_registers['r5'][0],
        arm_registers['r6'][0],
        arm_registers['r7'][0],
        arm_registers['r8'][0],
        arm_registers['r9'][0],
        arm_registers['r10'][0],
        arm_registers['r11'][0],
        arm_registers['r12'][0]
    ],
    'AARCH64': [
        aarch_registers['x0'][0],
        aarch_registers['x1'][0],
        aarch_registers['x2'][0],
        aarch_registers['x3'][0],
        aarch_registers['x4'][0],
        aarch_registers['x5'][0],
        aarch_registers['x6'][0],
        aarch_registers['x7'][0],
    ],
    'MIPS32': [
        mips_registers['a0'][0],
        mips_registers['a1'][0],
        mips_registers['a2'][0],
        mips_registers['a3'][0],
    ],
}


return_regs = {
    'ARMEL': arm_registers['r0'][0],
    'AARCH64': aarch_registers['x0'][0],
    'MIPS32': mips_registers['v0'][0]
}

link_regs = {
    'ARMEL': arm_registers['lr'][0],
    'AARCH64': aarch_registers['x30'][0],
    'MIPS32': mips_registers['ra'][0]
}

_ordered_argument_regs_names = {
    'ARMEL': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
    'AARCH64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
    'MIPS32': ['a0', 'a1', 'a2', 'a3'],
}

_archinfo_by_string = {
    'ARMEL': archinfo.ArchARMEL,
    'AARCH64': archinfo.ArchAArch64,
    'MIPS32': archinfo.ArchMIPS32,
}


def arg_reg_name(p, idx):
    """
    Gets a register name by the argument register index
    :param p: the project
    :param idx: the index of the argument register
    :return: the name of the register
    """
    return _ordered_argument_regs_names[p.arch.name][idx]


def arg_reg_names(p, n=-1):
    """
    Gets the first n argument register names. If n=-1, it will return all argument registers
    :param p: the project
    :param n: the number of elements to retrieve
    :return: the name of the register
    """
    if n < 0:
        return _ordered_argument_regs_names[p.arch.name]
    return _ordered_argument_regs_names[p.arch.name][:n]


def arg_reg_off(p, idx):
    """
    Gets a register offset by the argument register index
    :param p: the project
    :param idx: the index of the argument register
    :return: the offset in vex
    """
    return next(x.vex_offset for x in p.arch.register_list if x.name == arg_reg_name(p, idx))

def arg_reg_id(p, name):
    """
    Gets an argument register index by the argument register name
    :param p: the project
    :param name: the name of the register
    :return: the index of the register
    """
    return _ordered_argument_regs_names[p.arch.name].index(name)


def arg_reg_id_by_off(p, off):
    """
    Gets an argument register index by the argument register offset
    :param p: the project
    :param off: the offset of the register
    :return: the index of the register
    """
    return arg_reg_id(p, p.arch.register_names[off])


def ret_reg_name(p):
    """
    Returns the name of the return register
    :param p: the project
    :return: the name of the return register
    """
    return p.arch.register_names[p.arch.ret_offset]


def get_arguments_call_with_instruction_address(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call with the corresponding function address.
    It checks the arguments in order so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b_addr: basic block address
    :return: a list of (instruction_address and the arguments of a function call)
    """
    set_params = []
    b = p.factory.block(b_addr)
    for reg_name in arg_reg_names(p):
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and p.arch.register_names[s.offset] == reg_name]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        # find the address of this instruction
        stmt_idx = b.vex.statements.index(put_stmt)
        inst_addr = [x.addr for x in b.vex.statements[:stmt_idx] if hasattr(x, 'addr')][-1]

        set_params.append((inst_addr, put_stmt))

    return set_params


# FIXME: so far we only consider arguments passed through registers
# if arg is passed in the previous block?
# two ways to fix this: travese the net function check the arg register used.
# check multiple blocks
def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """
    set_params = []
    b = p.factory.block(b_addr)
    for reg_name in arg_reg_names(p):
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and p.arch.register_names[s.offset] == reg_name]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params


def get_any_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call.

    :param p: angr project
    :param b_addr: basic block address
    :return: instructions setting arguments
    """
    set_params = []
    b = p.factory.block(b_addr)
    # fix for newer version of angr to only include argument registers
    argument_registers_offset = [x.vex_offset for x in p.arch.register_list if x.argument]
    put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put']
    for stmt in put_stmts:
        if stmt.offset in argument_registers_offset:
            set_params.append(stmt)
    return set_params


def get_arity(p, b_addr):
    """
    Retrieves the arity by inspecting a funciton call
    :param p: angr project
    :param b_addr: basic block address
    :return: arity of the function
    """

    return len(get_ord_arguments_call(p, b_addr))


def get_initial_state(p, ct, addr):
    """
    Sets and returns the initial state of the analysis
    :param p: the angr project
    :param ct: the coretaint object
    :param addr: entry point
    :return: the state
    """

    s = p.factory.blank_state(
        remove_options={
            angr.options.LAZY_SOLVES
        }
    )

    # set a bogus return at the end of this function and in the link register (if applicable)
    s.callstack.ret_addr = ct.bogus_return
    if hasattr(s.regs, 'lr'):
        setattr(s.regs, 'lr', ct.bogus_return)

    s.ip = addr
    return s
