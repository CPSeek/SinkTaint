from binary_dependency_graph.utils import are_parameters_in_registers, get_string
from taint_analysis.utils import ordered_argument_regs, arg_reg_name
from bug_finder.config import checkcommandinjection, checkbufferoverflow


exe_funcs = ["system", "popen", "execve", "___system", "bstar_system", "doSystemCmd", "twsystem"]
findflag = False
retaddr = []

checkfwrite = False

# checkcommandinjection = True
# checkbufferoverflow = True
# loop_sink_inputs = {}
# sink_dst_size = {}

# def init_sink_dst_size(dst_size_dict):
#     # global sink_dst_size
#     sink_dst_size = dst_size_dict

# def init_loop_sinks(sink_input_dict):
#     # global loop_sink_inputs
#     loop_sink_inputs = sink_input_dict

# def get_loop_sinks():
#     # global loop_sink_inputs
#     sink_addrs = []
#     for addr, _ in loop_sink_inputs.items():
#         sink_addrs.append(addr)
#     return sink_addrs

def init_flag():
    global findflag, retaddr
    findflag = 0
    retaddr = []

def setfindflag(bo, addr=None):
    global findflag, retaddr
    findflag = bo
    # print("[-]"*20)
    # print("findflag:", findflag)
    if addr:
        # print("addr: 0x%x" % addr)
        # print("Addr:", retaddr)
        with open("./tmp/"+hex(addr), 'w') as f:
            f.write('')
    if bo:
        retaddr.append(addr)
    else:
        retaddr = []
    #print("Addr:", retaddr)


def getfindflag():
    global findflag, retaddr
    #print("getfindflag:", findflag, retaddr)
    return findflag, retaddr


def checkstringtainted(p, core_taint, state, name, plt_path):
    reg = getattr(state.regs, name)
    # print "checkstringtainted",name,reg,plt_path.active[0]
    idx = 0
    if False:
        # print core_taint.safe_load(plt_path,reg.args[0]+idx),'is_tainted',core_taint.is_tainted(core_taint.safe_load(plt_path,reg.args[0]+idx),path=plt_path)
        while not core_taint.is_tainted(core_taint.safe_load(plt_path, reg.args[0] + idx), path=plt_path):
            byt = state.memory.load(reg.args[0] + idx, 1).args[0]
            # print idx,':',byt
            if byt == 0 or idx >= 0x200:  # consider implement this
                return False
            idx += 1
        return True
    else:
        return core_taint.is_final_or_points_to_tainted_data(reg, plt_path, unconstrained=False)


def doSystemCmd(p, core_taint, plt_path, *_, **__):
    """
    doSystemCmd function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("dosystemcmd:.......................")
    if not checkcommandinjection:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 0))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%')
        for i in range(1, 1 + n_vargs):
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
            reg = getattr(plt_state.regs, name)
            #print (name, ':', reg)
            if (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                                plt_path)):
                print ("doSystemCmd return True")
                setfindflag(1, plt_state.regs.lr.args[0])
                print("doSystemCmd is True: 0x%x" % plt_state.regs.lr.args[0])
                return True
        print ("doSystemCmd return False")
        return False
    else:
        raise Exception("implement me")


def system(p, core_taint, plt_path, *_, **__):
    """
    system function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("system:.......................")
    if not checkcommandinjection:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        state = plt_path.active[0]
        if core_taint.is_final_tainted(reg, path=plt_path):
            setfindflag(1, plt_state.regs.lr.args[0])
            print("System is True: 0x%x" % plt_state.regs.lr.args[0])
            return True
        ret = checkstringtainted(p, core_taint, state, name, plt_path)
        print ("SYSTEM return ", ret)
        if ret:
            setfindflag(1, plt_state.regs.lr.args[0])
            print("System is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def popen(p, core_taint, plt_path, *_, **__):
    """
    popen function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("popen:.......................")
    if not checkcommandinjection:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        if (core_taint.is_final_tainted(reg, path=plt_path)):
            setfindflag(1, plt_state.regs.lr.args[0])
            print("Popen is True: 0x%x" % plt_state.regs.lr.args[0])
            return True
        ret = checkstringtainted(p, core_taint, plt_state, name, plt_path)
        if ret:
            setfindflag(1, plt_state.regs.lr.args[0])
            print("Popen is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def execve(p, core_taint, plt_path, *_, **__):
    """
    execve function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("execve:.......................")
    if not checkcommandinjection:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name0 = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg0 = getattr(plt_state.regs, name0)
        name1 = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg1 = getattr(plt_state.regs, name1)
        ret = (core_taint.is_final_tainted(reg0, path=plt_path) or
               checkstringtainted(p, core_taint, plt_state, name0, plt_path) or
               core_taint.is_final_tainted(reg1, path=plt_path) or
               checkstringtainted(p, core_taint, plt_state, name1, plt_path))
        if ret:
            print ("execve return True")
            setfindflag(1, plt_state.regs.lr.args[0])
            print("execve is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")

def cpyfunc(p, core_taint, plt_path, size_con=None):
    print("cpyfunc:.......................")
    plt_state = plt_path.active[0]
    sink_addr = plt_path.active[0].addr
    if sink_addr in core_taint.loop_sink_inputs:
        reg_names = core_taint.loop_sink_inputs[sink_addr]
    else:
        return False
    for name_reg_src in reg_names:
        reg_src = getattr(plt_state.regs, name_reg_src) # TODO Only by judging whether it is tainted data, not the length
        tainted = checkstringtainted(p, core_taint, plt_state, name_reg_src, plt_path)
        if core_taint.is_final_tainted(reg_src, plt_path) or tainted: # TODO duplicate checkstringtainted
            # if core_taint.is_or_points_to_tainted_data(reg_src, plt_path, unconstrained=False):
            # print ('1', reg_src)
            # setfindflag(1, plt_state.regs.lr.args[0])
            core_taint._vulnerable_addrs.add(sink_addr)
            print("*"*80)
            print ("cpyfunc return True: 0x%x" % sink_addr)
            return True

def strcpy(p, core_taint, plt_path, size_con=None):
    """
    strcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return:  None
    """
    print("strcpy:.......................")
    if not checkbufferoverflow:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    sink_addr = plt_path.mp_active.history.jump_source
    sink_addr = sink_addr.mp_first
    if sink_addr in core_taint.sink_dst_size:
        dst_size = core_taint.sink_dst_size[sink_addr]
    else:
        dst_size = 0x80
    if are_parameters_in_registers(p):
        name_reg_src = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg_src = getattr(plt_state.regs, name_reg_src) # TODO Only by judging whether it is tainted data, not the length
        src = core_taint.safe_load(plt_path, reg_src, estimate_size = True)

        tainted = checkstringtainted(p, core_taint, plt_state, name_reg_src, plt_path)
        try:
            ret = not tainted or (src.length <= dst_size and src.size() != 32)
            if ret:
                return False          
        except:
            pass

        if core_taint.is_final_tainted(reg_src, plt_path) or tainted: # TODO duplicate checkstringtainted
            # if core_taint.is_or_points_to_tainted_data(reg_src, plt_path, unconstrained=False):
            # print ('1', reg_src)
            # setfindflag(1, plt_state.regs.lr.args[0])
            core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
            print("*"*80)
            print ("strcpy return True: 0x%x" % plt_state.regs.lr.args[0])
            return True
        # check the size of the two buffers
        name_reg_dst = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg_dst = getattr(plt_state.regs, name_reg_dst)

        src = core_taint.safe_load(plt_path, reg_src)
        dst = core_taint.safe_load(plt_path, reg_dst)
        # tainted = checkstringtainted(p, core_taint, plt_state, name_reg_src, plt_path)

        # we raise alerts also for equal size of src and dst, as the analysis might be under-constrained.
        # TODO do not know the accurate size

        # ret = tainted and size_con >= (src.cardinality - 1) >= (dst.cardinality - 1)
        try:
            ret = tainted and src.size() > dst_size
            if ret:
                #print ("strcpy return True")
                # setfindflag(1, plt_state.regs.lr.args[0])
                core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
                print("*"*80)
                print ("strcpy return True: 0x%x" % plt_state.regs.lr.args[0])
            return ret
        except:
            return False
    else:
        raise Exception("implement me")


def memcpy(p, core_taint, plt_path, *_, **__):
    """
    memcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("memcpy:.......................")
    if not checkbufferoverflow:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    sink_addr = plt_path.mp_active.history.jump_source
    sink_addr = sink_addr.mp_first
    if sink_addr in core_taint.sink_dst_size:
        dst_size = core_taint.sink_dst_size[sink_addr]
    else:
        dst_size = 0x100
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][2]]
        reg = getattr(plt_state.regs, name)
        if not reg.symbolic:
            thresh_size = reg.args[0]
            if dst_size >= thresh_size:
                return False

        reg_loaded = core_taint.safe_load(plt_path, reg, estimate_size = True)
        
        ret = (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                               plt_path))
        # TODO check size
        if ret and dst_size <= int(reg_loaded.length / 8):
            # setfindflag(1, plt_state.regs.lr.args[0])
            core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
            print("memcpy is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def strncpy(p, core_taint, plt_path, *_, **__):
    """
    memcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("strncpy:.......................")
    if not checkbufferoverflow:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    sink_addr = plt_path.mp_active.history.jump_source
    sink_addr = sink_addr.mp_firstsink_addr = plt_path.active[0].addr
    if sink_addr in core_taint.sink_dst_size:
        dst_size = core_taint.sink_dst_size[sink_addr]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][2]]
        reg = getattr(plt_state.regs, name)
        ret = (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                               plt_path))
        # TODO check size
        if ret:
            # setfindflag(1, plt_state.regs.lr.args[0])
            core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
            print("memcpy is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")

def fwrite(p, core_taint, plt_path, *_, **__):
    """
    fwrite function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("fwrite:.......................")
    if not checkfwrite:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg = getattr(plt_state.regs, name)
        ret = (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                               plt_path))
        if ret:
            setfindflag(1, plt_state.regs.lr.args[0])
            print("fwrite is True: 0x%x" % plt_state.regs.lr.args[0])
        return ret
    else:
        raise Exception("implement me")


def sprintf(p, core_taint, plt_path, *_, **__):
    """
    sprintf function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("sprintf:.......................")
    if not checkbufferoverflow:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    sink_addr = plt_path.mp_active.history.jump_source
    sink_addr = sink_addr.mp_first

    if sink_addr in core_taint.sink_dst_size:
        dst_size = core_taint.sink_dst_size[sink_addr]
    else:
        dst_size = 0x80
    if are_parameters_in_registers(p):
        dst = getattr(plt_state.regs, arg_reg_name(p, 0))
        dst_loaded = core_taint.safe_load(plt_path, dst, estimate_size = True)
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 1))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%s') + str_val.count('%d')
        total_size = len(str_val) - n_vargs * 2
        s_index = []
        j = 2
        for i in range(len(str_val)-1):
            if str_val[i] == '%':
                if str_val[i+1] == 's':
                    s_index.append(j)
                else:
                    pass
                j += 1

        for i in range(2, 2 + n_vargs):
            if i not in s_index:
                total_size += 4
                continue
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
            reg = getattr(plt_state.regs, name)
            reg_loaded = core_taint.safe_load(plt_path, reg, estimate_size = True)
            total_size += int(reg_loaded.length / 8)
            if (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                                plt_path)):
                if dst_size <= total_size:
                    # setfindflag(1, plt_state.regs.lr.args[0])
                    core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
                    print("sprintf is True: 0x%x" % plt_state.regs.lr.args[0])
                    return True
        return False
    else:
        raise Exception("implement me")


def snprintf(p, core_taint, plt_path, *_, **__):
    """
    sprintf function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """
    print("snprintf:.......................")
    if not checkbufferoverflow:
        print ("return due to filtered")
        return False
    plt_state = plt_path.active[0]
    sink_addr = plt_path.active[0].addr
    if sink_addr in core_taint.sink_dst_size:
        dst_size = core_taint.sink_dst_size[sink_addr]
    else:
        dst_size = 0x100    
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg = getattr(plt_state.regs, name)
        if not reg.symbolic:
            thresh_size = reg.args[0]
            if dst_size >= thresh_size:
                return False
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 2))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%s') + str_val.count('%d')
        for i in range(3, 3 + n_vargs):
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
            reg = getattr(plt_state.regs, name)
            if (core_taint.is_final_tainted(reg, path=plt_path) or checkstringtainted(p, core_taint, plt_state, name,
                                                                                plt_path)):
                print ("SNPRINTF return True")
                # setfindflag(1, plt_state.regs.lr.args[0])
                core_taint._vulnerable_addrs.add(plt_state.regs.lr.args[0])
                print("snprintf is True: 0x%x" % plt_state.regs.lr.args[0])
                return True
        return False
    else:
        raise Exception("implement me")
