import logging
import pickle
import time
import angr
from angr.sim_options import LAZY_SOLVES
import os
import sys

import size_analysis
from bar_logger import bar_logger
from binary_dependency_graph.binary_dependency_graph import BinaryDependencyGraph, Role, RoleInfo
from binary_dependency_graph.utils import get_ord_arguments_call, get_any_arguments_call, are_parameters_in_registers, \
    get_mem_string, STR_LEN, get_memcpy_like, get_sizeof_like, get_heap_alloc, get_env, get_memcmp_like_unsized, \
    get_memcmp_like_sized, get_dyn_sym_addr, find_memcpy_like, get_reg_used, get_addrs_similar_string, \
    get_indirect_str_refs, get_atoi, get_nvram, get_cJSON, TIMEOUT_TAINT, TIMEOUT_TRIES
#from bug_finder import sinks
#from bug_finder.utils import SINK_FUNCS, HTTP_KEYWORDS
from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
from taint_analysis.utils import get_arity, link_regs, ordered_argument_regs, setBugFindingFlag
from .utils import *
from sinks import exe_funcs

angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)

summary_functions.simplify_memcpy = True

log = logging.getLogger("BugFinder")
log.setLevel("DEBUG")

sinkTarget = []

regr4 = None
loop_sink_inputs = {}
# sink_dst_size = {}

# def init_sink_dst_size(dst_size_dict):
#     global sink_dst_size
#     sink_dst_size = dst_size_dict

def init_loop_sinks(sink_input_dict):
    global loop_sink_inputs
    loop_sink_inputs = sink_input_dict

def get_loop_sinks():
    global loop_sink_inputs
    sink_addrs = []
    for addr, _ in loop_sink_inputs.items():
        sink_addrs.append(addr)
    return sink_addrs

def setr4(intt):
    global regr4
    regr4 = intt


def clearsinktarget():
    global sinkTarget
    sinkTarget = []


def setSinkTarget(lit):
    global sinkTarget
    sinkTarget = lit


class BugFinder:
    def __init__(self, config, analyze_parents=True, analyze_children=True, logger_obj=None):
        global log

        if logger_obj:
            log = logger_obj

        self._config = config
        self._bdg = None
        # self._bdg = bdg
        self._ct = None
        self._current_seed_addr = None
        self._current_p = None
        self._current_max_size = 0
        self._current_role_info = {
            RoleInfo.ROLE: Role.UNKNOWN,
            RoleInfo.DATAKEY: '',
            RoleInfo.CPF: None,
            RoleInfo.X_REF_FUN: None,
            RoleInfo.CALLER_BB: None,
            RoleInfo.ROLE_FUN: None,
            RoleInfo.ROLE_INS: None,
            RoleInfo.ROLE_INS_IDX: None,
            RoleInfo.COMM_BUFF: None,
            RoleInfo.PAR_N: None
        }

        self._analyze_parents = analyze_parents
        self._analyze_children = analyze_children
        self._analysis_starting_time = time.time()
        self._taint_names_applied = []
        self._sink_addrs = []
        self._current_cfg = None
        self._raised_alert = False
        self._report_alert_fun = None

        # stats
        self._stats = {}
        self._visited_bb = 0
        self._current_cpf_name = 'Unknown'
        self._start_time = None
        self._end_time = None
        self._report_stats_fun = None

    @property
    def stats(self):
        return self._stats

    def _apply_taint(self, addr, current_path, next_state, taint_key=False):
        """
        Applies the taint to the role function call

        :param addr: address of the role function
        :param current_path: current angr's path
        :param next_state: state at the entry of the function
        :param taint_key: taint the used data key
        :return:
        """

        # print "_apply_taint",addr
        def is_arg_key(arg):
            return hasattr(arg, 'args') and isinstance(arg.args[0], int) and arg.args[0] == self._current_seed_addr

        p = self._current_p
        ins_args = get_ord_arguments_call(p, addr)
        if not ins_args:
            ins_args = get_any_arguments_call(p, addr)

        if not are_parameters_in_registers(p):
            raise Exception("Parameters not in registers: Implement me")
        # print current_path.active,taint_key
        for stmt in ins_args:
            reg_off = stmt.offset
            reg_name = p.arch.register_names[reg_off]
            val_arg = getattr(next_state.regs, reg_name)
            size = None
            if is_arg_key(val_arg):
                if not taint_key:
                    continue
                n_bytes = p.loader.memory.load(val_arg.args[0], STR_LEN)
                size = len(get_mem_string(n_bytes)) * 8
                if val_arg.concrete and val_arg.args[0] < p.loader.main_object.min_addr:
                    continue
                # print('taint applied to %s:%s' % (reg_name, str(val_arg)))
                self._ct.apply_taint(current_path, val_arg, reg_name, size)

    def _get_function_summaries(self):
        """
        Set and returns a dictionary of function summaries
        :return: function summaries
        """

        p = self._current_p

        mem_cpy_summ = get_memcpy_like(p)
        size_of_summ = get_sizeof_like(p)
        heap_alloc_summ = get_heap_alloc(p)
        env_summ = get_env(p)
        memcmp_like_unsized = get_memcmp_like_unsized(p)
        memcmp_like_sized = get_memcmp_like_sized(p)
        atoi_like = get_atoi(p)
        nvram_summ = get_nvram(p)
        cJSON_get_summ = get_cJSON(p)

        summaries = mem_cpy_summ
        summaries.update(size_of_summ)
        summaries.update(heap_alloc_summ)
        summaries.update(env_summ)
        summaries.update(memcmp_like_unsized)
        summaries.update(memcmp_like_sized)
        summaries.update(atoi_like)
        summaries.update(nvram_summ)
        summaries.update(cJSON_get_summ)
        return summaries

    def _get_initial_state(self, info):
        """
        Sets and returns the initial state of the analysis

        :param info: info
        :return: the state
        """
        global regr4
        p = self._current_p
        s = p.factory.blank_state(
            remove_options={
                LAZY_SOLVES
            }
        )
        addr = info[RoleInfo.X_REF_FUN]
        gp_addr = info[RoleInfo.GP]
        lr = p.arch.register_names[link_regs[p.arch.name]]
        setattr(s.regs, lr, self._ct.bogus_return)
        s.ip = addr
        if regr4:
            if 'ARM' in p.arch.name:
                s.regs.r4 = regr4
            elif 'MIPS' in p.arch.name:
                s.regs.gp = regr4
        else:
            if 'ARM' in p.arch.name:
                # s.regs.r4 = 1044168
                pass
            elif 'MIPS' in p.arch.name:
                s.regs.gp = gp_addr
                pass
        if 'ARM' in p.arch.name:
            s.regs.r11 = s.regs.sp + 8
        elif 'MIPS' in p.arch.name:
            s.regs.fp = s.regs.sp
        return s

    def _find_sink_addresses(self):
        """
        Sets the sink addresses in the current binary's project

        :return: None
        """

        p = self._current_p

        self._sink_addrs = [(get_dyn_sym_addr(p, func[0]), func[1]) for func in SINK_FUNCS]
        self._sink_addrs += [(m, sinks.memcpy) for m in find_memcpy_like(p)]

        self._sink_addrs += [(m, sinks.cpyfunc) for m in get_loop_sinks()]
    def insinkList(self, addr):
        global sinkTarget
        # print "insinkList",sinkTarget,addr
        if addr in sinkTarget:
            return True
        return False

    def _jump_in_sink(self, current_path):
        """
        Checks whether a basic block contains a jump into a sink

        :param current_path: angr current path
        :return: True if the basic block contains a jump into a sink, and the Sink. False and None otherwise
        """

        if self._current_p.loader.find_object_containing(current_path.active[0].addr) != \
                self._current_p.loader.main_object:
            return False, None

        next_path = current_path.copy(deep=True).step()
        try:
            for entry in self._sink_addrs:
                if next_path.active[0].addr == entry[0] and self.insinkList(current_path.active[0].addr):
                    return True, entry[1]
        except:
            log.error(
                "Unable to find successors for %s, perhaps uncontrainted call?" % hex(current_path.active[0].addr))
        return False, None

    def _is_sink_and_tainted(self, current_path):
        """
        Checks if the current basic block contains a call to a sink and uses tainted data

        :param current_path: angr current path
        :return: The sink if the basic block contains a call to a sink and uses tainted data, False otherwise
        """

        p = self._current_p

        is_sink, check_taint_func = self._jump_in_sink(current_path)
        if not is_sink:
            return False

        # print "_is_sink_and_tainted",current_path.active
        plt_path = current_path.copy(deep=True).step()
        return check_taint_func(p, self._ct, plt_path, size_con=self._current_max_size)

    def _is_any_taint_var_bounded(self, guards_info):
        """
        Checks whether tainted data is bounded

        :param guards_info: guards info (ITE)
        :return: True if bounded (False otherwise), and the tainted data.
        """
        if not guards_info:
            return False, None

        bounded = False
        tainted = None
        last_guard = guards_info[-1][1]
        if last_guard.op in ('__eq__', '__le__', '__ne__', 'SLE', 'SGT', '__ge__'):
            op1 = last_guard.args[0]
            op2 = last_guard.args[1]
            if (self._ct.is_tainted(op1) and not self._ct.is_tainted(op2)) or \
                    (self._ct.is_tainted(op2) and not self._ct.is_tainted(op1)):

                # First check if the var si a constant and NULL, as they are mostly used to check whether an address
                # is not NUll.

                if self._ct.is_tainted(op1):
                    tainted = op1
                    var = op2
                else:
                    tainted = op2
                    var = op1

                if last_guard.op in ('__eq__', '__ne__') and var.concrete and var.args[0] == 0:
                    return False, None

                # Then check whether is un-tainting the whole memory region or just a part of it
                # FIXME: do soemthing better
                bounded = True
                for c in tainted.recursive_children_asts:
                    if self._ct.is_tainted(c):
                        if c.op == 'BVS':
                            break
                        if c.op == 'Extract':
                            bounded = False
                            break
        return bounded, tainted

    def is_address(self, val):
        """
        Checks if value is a valid address.

        :param val: value
        :return:  True if value is a valid address
        """

        p = self._current_p
        if val.concrete and val.args[0] < p.loader.main_object.min_addr:
            return False
        return True

    def bv_to_hash(self, v):
        """
        Calculates the hash of a bitvector

        :param v: bit vector
        :return: hash
        """

        args_str = map(str, v.recursive_leaf_asts)
        new_v_str = ''
        for a_str in args_str:
            if '_' in a_str:
                splits = a_str.split('_')
                a_str = '_'.join(splits[:-2] + splits[-1:])
                new_v_str += a_str
        return new_v_str

    def is_tainted_by_us(self, tainted_val):
        """
        Checks if a variable is tainted by us, or the results of the taint propagation

        :param tainted_val: variable
        :return: True if tainted by us, False otherwise
        """

        hash_val = self.bv_to_hash(tainted_val)
        if hash_val in self._taint_names_applied:
            return True
        return False

    def _check_sink(self, current_path, guards_info, *_, **__):
        """
        Checks whether the taint propagation analysis lead to a sink, and performs the necessary actions
        :param current_path: angr current path
        :param guards_info:  guards (ITE) information
        :return: None
        """

        try:
            p = self._current_p
            current_state = current_path.active[0]
            current_addr = current_state.addr
            cfg = self._current_cfg

            self._visited_bb += 1

            next_path = current_path.copy(deep=True).step()
            info = self._current_role_info
            # check constant comparisons and untaint if necessary
            bounded, var = self._is_any_taint_var_bounded(guards_info)
            if bounded:
                self._ct.do_recursive_untaint(var, current_path)

            # If the taint is not applied yet, apply it
            if not self._ct.taint_applied and current_addr == info[RoleInfo.CALLER_BB]:
                next_state = next_path.active[0]
                self._apply_taint(current_addr, current_path, next_state, taint_key=True)

            try:
                if len(next_path.active) and self._config['eg_source_addr']:
                    if next_path.active[0].addr == int(self._config['eg_source_addr'], 16):
                        next_state = next_path.active[0]
                        self._apply_taint(current_addr, current_path, next_state, taint_key=True)
            except TimeOutException as to:
                raise to
            except:
                pass

            if self._is_sink_and_tainted(current_path):
                delta_t = time.time() - self._analysis_starting_time
                self._raised_alert = True
                name_bin = self._ct.p.loader.main_object.binary
                print("Found a tainted sink! Reporting alert!")
                self._report_alert_fun('sink', name_bin, current_path, current_addr,
                                       self._current_role_info[RoleInfo.DATAKEY],
                                       pl_name=self._current_cpf_name, report_time=delta_t)

            # tainted call address and tainted parameters
            bl = self._current_p.factory.block(current_addr)
            if not len(next_path.active) and len(next_path.unconstrained) and bl.vex.jumpkind == 'Ijk_Call':
                if p.arch.name != "MIPS32":
                    cap = bl.capstone.insns[-1]
                    vb = bl.vex
                    reg_jump = cap.insn.op_str
                    val_jump_reg = getattr(next_path.unconstrained[0].regs, reg_jump)
                else:
                    cap = bl.capstone.insns[-2]
                    vb = bl.vex
                    reg_jump = cap.insn.op_str.strip("$") # mips is wrong, jal $t9, need to remove '$'
                    val_jump_reg = getattr(next_path.unconstrained[0].regs, reg_jump)
                if not hasattr(vb.next, 'tmp'):
                    return
                val_jump_tmp = next_path.unconstrained[0].scratch.temps[vb.next.tmp]

                if not self.is_tainted_by_us(val_jump_reg) and not self.is_tainted_by_us(val_jump_tmp):
                    if self._ct.is_or_points_to_tainted_data(val_jump_reg, next_path, unconstrained=True):
                        nargs = get_arity(self._current_p, current_path.active[0].addr)
                        for ord_reg in ordered_argument_regs[self._current_p.arch.name][:nargs]:
                            reg_name = self._current_p.arch.register_names[ord_reg]
                            if reg_name == reg_jump:
                                continue

                            reg_val = getattr(next_path.unconstrained[0].regs, reg_name)
                            if self._ct.is_or_points_to_tainted_data(reg_val, next_path,
                                                                     unconstrained=True) and self.is_address(reg_val):
                                delta_t = time.time() - self._analysis_starting_time
                                self._raised_alert = True
                                name_bin = self._ct.p.loader.main_object.binary
                                print("Found a tainted call with tainted parameters! Reporting alert!")
                                self._report_alert_fun('sink', name_bin, current_path, current_addr,
                                                       self._current_role_info[RoleInfo.DATAKEY],
                                                       pl_name=self._current_cpf_name, report_time=delta_t)

                        next_state = next_path.unconstrained[0]
                        hash_val = self.bv_to_hash(val_jump_tmp)
                        self._taint_names_applied.append(hash_val)
                        hash_val = self.bv_to_hash(val_jump_reg)
                        self._taint_names_applied.append(hash_val)
                        self._apply_taint(current_addr, current_path, next_state)

            # eventually if we are in a loop guarded by a tainted variable
            next_active = next_path.active
            if len(next_active) > 1:
                history_addrs = [t for t in current_state.history.bbl_addrs]
                seen_addr = [a.addr for a in next_active if a.addr in history_addrs]

                if len(seen_addr) == 0:
                    return

                back_jumps = [a for a in seen_addr if a < current_addr]
                if len(back_jumps) == 0:
                    return

                bj = back_jumps[0]
                node_s = cfg.model.get_any_node(bj)
                node_f = cfg.model.get_any_node(current_addr)

                if not node_s or not node_f:
                    return

                fun_s = node_s.function_address
                fun_f = node_f.function_address

                if fun_s != fun_f:
                    return

                idx_s = history_addrs.index(bj)
                for a in history_addrs[idx_s:]:
                    n = cfg.model.get_any_node(a)
                    if not n:
                        continue

                    if n.function_address != fun_s:
                        return

                # if we have a back-jump satisfiying all the conditions
            #     cond_guard = [g for g in next_active[0].guards][-1]
            # SaTC
            #     if hasattr(cond_guard, 'args') and len(cond_guard.args) == 2 and \
            #             self._ct.taint_buf in str(cond_guard.args[0]) and \
            #             self._ct.taint_buf in str(cond_guard.args[1]):
            #         delta_t = time.time() - self._analysis_starting_time
            #         self._raised_alert = True
            #         name_bin = self._ct.p.loader.main_object.binary
            #         print("Found a loop guarded by a tainted variable. Reporting Alert!")
            #         self._report_alert_fun('loop', name_bin, current_path, current_addr, cond_guard,
            #                                pl_name=self._current_cpf_name, report_time=delta_t)
            #
                # Karonte
                # if we have a back-jump satisfiying all the conditions
                cond_guard = [g for g in next_active[0].history.jump_guards][-1]

                for node in cond_guard.recursive_leaf_asts:
                    if self._ct._taint_buf in str(node):
                        print("Found a loop guarded by a tainted variable. Reporting Alert!")
                        log.info("Found a loop guarded by a tainted variable. Reporting Alert!")
                        delta_t = time.time() - self._analysis_starting_time
                        self._raised_alert = True
                        name_bin = self._ct.p.loader.main_object.binary
                        self._report_alert_fun('loop', name_bin, current_path, current_addr, cond_guard,
                                               pl_name=self._current_cpf_name, report_time=delta_t)
            
            # clean up the copied state to prevent possible memory leaks
            for state in next_path.active + next_path.unconstrained:
                state.history.trim()
                state.downsize()
                state.release_plugin('solver')
        except TimeOutException as to:
            raise to
        except Exception as e:
            log.error("Something went terribly wrong: %s" % str(e))

    # FIXME: where did max_size go?
    def _vuln_analysis(self, p, cfg, cpf_name, seed_addr, info, loop_sinks_addr_input, sink_dst_size, max_size):
        """
        Run the analysis for children (i.e, slave binaries)

        :param bdg_node:  BDG node
        :param seed_addr: address of the seed of taint
        :param info: binary's info
        :return:
        """

        self._current_p = p
        self._current_cfg = cfg
        self._current_cpf_name = cpf_name
        self._current_seed_addr = seed_addr
        self._current_role_info = info
        self._taint_names_applied = []
        self._visited_bb = 0
        self._current_max_size = max_size

        ana_start_time = time.time()

        # prepare the under-contrainted-based initial state
        setBugFindingFlag(True, self._current_cfg)
        self._ct = coretaint.CoreTaint(self._current_p, interfunction_level=1, smart_call=True,
                                       follow_unsat=True, black_calls=(info[RoleInfo.ROLE_FUN],),
                                       try_thumb=True, shuffle_sat=True,
                                       exit_on_decode_error=True, force_paths=True,
                                       taint_returns_unfollowed_calls=True, allow_untaint=True,
                                       logger_obj=log, loop_sink = loop_sinks_addr_input, sink_dst = sink_dst_size)
        summarized_f = self._get_function_summaries()
        s = self._get_initial_state(info)
        self._find_sink_addresses()
        self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
        try:
            self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, check_func=self._check_sink,
                         init_bss=False)
        except TimeOutException:
            log.warning("Hard timeout triggered")
        except Exception as e:
            log.error("Something went terribly wrong: %s" % str(e))

        self._ct.unset_alarm()
        print("return vulnerable address:", self._ct._vulnerable_addrs)
        return self._ct._vulnerable_addrs
        '''
            # stats
            self._stats[bdg_node.bin]['to'] += 1 if self._ct.triggered_to() else 0
            self._stats[bdg_node.bin]['visited_bb'] += self._visited_bb
            self._stats[bdg_node.bin]['n_paths'] += self._ct.n_paths
            self._stats[bdg_node.bin]['ana_time'] += (time.time() - ana_start_time)
            self._stats[bdg_node.bin]['n_runs'] += 1
        '''

    @staticmethod
    def find_ref_http_strings(n, keywords):
        """
        Finds HTTP related strings

        :param n: BDG node
        :param keywords: keywords to look for
        :return: None
        """

        cfg = n.cfg
        p = n.p

        # get all the string references we are looking for
        for key_str in keywords:
            strs_info = get_addrs_similar_string(p, key_str)
            for s_info in strs_info:
                str_addr = s_info[1]
                current_string = s_info[0]
                direct_refs = [s for s in cfg.memory_data.items() if s[0] == str_addr]
                indirect_refs = get_indirect_str_refs(p, cfg, [str_addr])

                for a, s in direct_refs + indirect_refs:
                    if not s.irsb:
                        continue

                    if not BinaryDependencyGraph.is_call(s):
                        continue

                    for (irsb_addr, stmt_idx, insn_addr) in list(s.refs):
                        if are_parameters_in_registers(p):
                            reg_used = get_reg_used(p, cfg, irsb_addr, stmt_idx, a, [str_addr])
                            if not reg_used:
                                continue

                            par_n = ordered_argument_regs[p.arch.name].index(p.arch.registers[reg_used][0])

                            # in this way we filter out sub-functions (angr's mistakes)
                            x_ref_fun = min([f for f in cfg.functions.values() if
                                             min(f.block_addrs) <= s.irsb_addr <= max(f.block_addrs)],
                                            key=lambda x: x.addr)

                            info = {
                                RoleInfo.ROLE: n.role,
                                RoleInfo.DATAKEY: current_string,
                                RoleInfo.CPF: None,
                                RoleInfo.X_REF_FUN: x_ref_fun.addr,
                                RoleInfo.CALLER_BB: s.irsb_addr,
                                RoleInfo.ROLE_FUN: None,
                                RoleInfo.ROLE_INS: None,
                                RoleInfo.ROLE_INS_IDX: None,
                                RoleInfo.COMM_BUFF: None,
                                RoleInfo.PAR_N: par_n
                            }
                            n.add_role_info(s.address, info)
                        else:
                            log.error("_find_str_xref_in_call: arch doesn t use registers to set function parameters."
                                      "Implement me!")

    def _discover_http_strings(self, strs):
        """
        Discover the HTTP strings in the binaries of a BDG
        :param strs: HTTP strings
        :return: None
        """

        for n in self._bdg.nodes:
            n.clear_role_info()
            log.info("Discovering HTTP strings for %s" % str(n))
            BugFinder.find_ref_http_strings(n, strs)
            log.info("Done.")

    def _register_next_elaboration(self):
        """
        Register next elaboration with the bar logger
        :return:
        """

        if log.__class__ == bar_logger.BarLogger:
            log.new_elaboration()

    def _setup_progress_bar(self):
        """
        Setup the bar logger with the total number of analysis to perform
        :return:
        """

        if log.__class__ == bar_logger.BarLogger:
            tot_dk = sum([len(x.role_data_keys) for x in self._bdg.nodes])
            etc = tot_dk * TIMEOUT_TAINT * TIMEOUT_TRIES / 2
            log.set_etc(etc)
            log.set_tot_elaborations(tot_dk)

    def _analyze(self):
        """
        Runs the actual vulnerability detection analysis

        :return:
        """

        roots = [x for x in self._bdg.nodes if x.root]
        worklist = roots
        analyzed_dk = {}

        # setup the loading bar
        self._setup_progress_bar()
        self._analysis_starting_time = time.time()

        index = 0

        # connected graph
        while index < len(worklist):
            parent = worklist[index]
            index += 1

            if parent not in analyzed_dk:
                analyzed_dk[parent] = []

            # take the node's info and find the size of the
            # buffer(s) used to send data to its children
            sa = size_analysis.SizeAnalysis(parent, logger_obj=log)
            max_size = sa.result
            parent_strings = parent.role_data_keys

            # analyze parents
            if self._analyze_parents:
                parent_name = parent.bin.split('/')[-1]
                log.info("Analyzing parents %s" % parent_name)
                for s_addr, s_refs_info in parent.role_info.items():
                    for info in s_refs_info:
                        if info in analyzed_dk[parent]:
                            continue

                        analyzed_dk[parent].append(info)
                        self._register_next_elaboration()
                        log.info("New string: %s" % info[RoleInfo.DATAKEY])
                        self._vuln_analysis(parent, s_addr, info, max_size)
                for vuln_func in exe_funcs:
                    if vuln_func in parent.p.loader.main_object.plt:
                        vuln_func_plt = parent.p.loader.main_object.plt[vuln_func]
                self._report_stats_fun(parent, self._stats)

            if self._analyze_children:
                # analyze children
                for child in self._bdg.graph[parent]:
                    child_name = child.bin.split('/')[-1]
                    log.info("Analyzing children %s" % child_name)

                    if child not in worklist:
                        worklist.append(child)
                    if child not in analyzed_dk:
                        analyzed_dk[child] = []
                    for s_addr, s_refs_info in child.role_info.items():
                        for info in s_refs_info:
                            if info in analyzed_dk[child]:
                                continue
                            for i in info:
                                print (i, ":", info[i])

                            if info[RoleInfo.DATAKEY] in parent_strings or parent.could_be_generated(
                                    info[RoleInfo.DATAKEY]):
                                # update the loading bar
                                self._register_next_elaboration()
                                analyzed_dk[child].append(info)
                                log.info("New string: %s" % info[RoleInfo.DATAKEY])
                                print (help(child))
                                print (s_addr)
                                print (info)
                                print (max_size)
                                self._vuln_analysis(child, s_addr, info, max_size)
                    self._report_stats_fun(child, self._stats)

        if self._analyze_children:
            # orphans
            log.info("Analyzing orphan nodes")
            max_size = size_analysis.MAX_BUF_SIZE
            for n in self._bdg.orphans:
                log.info("Analyzing orphan %s" % n.bin)
                if n not in analyzed_dk:
                    analyzed_dk[n] = []
                #		if "httpd" in n.bin:
                #		    info={"RoleInfo.COMM_BUFF":None,"RoleInfo.ROLE_INS_IDX":None,"RoleInfo.CPF":environment,"RoleInfo.ROLE_INS":0x2BABC,"RoleInfo.ROLE":Role.GETTER,"
                for s_addr, s_refs_info in n.role_info.items():
                    for info in s_refs_info:
                        if info in analyzed_dk[n]:
                            continue
                        if self._config['only_string'].lower() == 'true':
                            if info[RoleInfo.DATAKEY] != self._config['data_keys'][0][1]:
                                continue
                        analyzed_dk[n].append(info)

                        # update the loading bar
                        self._register_next_elaboration()
                        log.info("New string: %s" % info[RoleInfo.DATAKEY])
                        self._vuln_analysis(n, s_addr, info, max_size)
                self._report_stats_fun(n, self._stats)

    def analysis_time(self):
        return self._end_time - self._start_time

    def run(self, report_alert=None, report_stats=None):
        """
        Runs the bug Finder module
        :return:
        """

        def default_report(*_, **__):
            return None

        self._start_time = time.time()
        self._report_alert_fun = default_report if report_alert is None else report_alert
        self._report_stats_fun = default_report if report_stats is None else report_stats

        is_multi_bin = True
        fathers = [f for f, c in self._bdg.graph.items() if len(c) != 0]
        orphans = [n for n in self._bdg.nodes if n.orphan]

        # FIXME: do this in a cleaner way. Perhaps move it into karonte.py?
        if not fathers and not orphans:
            # Single bin case:
            # let's consider common network strings too
            is_multi_bin = False
            self._discover_http_strings(HTTP_KEYWORDS)
            map(lambda x: x.set_orphan(), self._bdg.nodes)

        self._analyze()

        if not self._raised_alert and is_multi_bin:
            # let's consider other possible data-keys too
            self._discover_http_strings(HTTP_KEYWORDS)
            self._analyze()

        self._end_time = time.time()


def main(func_addr=None, taint_addr=None, binary=None, proj=None, cfg=None, loop_sinks_addr_input=None, sink_dst_size=None, gp_addr = None, callerbb=None):
    global sinkTarget
    if gp_addr == None:
        gp_addr = 0x5bbba0
    if not func_addr or not taint_addr or not binary:
        func_addr = int(sys.argv[1], 0)
        taint_addr = int(sys.argv[2], 0)
        binary = sys.argv[3]
        proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
        cfg = proj.analyses.CFG()
    config = {u'bin': [binary], u'pickle_parsers': u'./pickles/parser/test4.pk', u'stats': u'False', u'data_keys': [],
              u'base_addr': u'', u'eg_source_addr': u'', u'fw_path': u'./test', u'angr_explode_bins':
                  [u'openvpn', u'wpa_supplicant', u'vpn', u'dns', u'ip', u'log', u'qemu-arm-static'], u'var_ord': [u''],
              u'glob_var': [], u'arch': u'', u'only_string': u'False'}
    bugfinder = BugFinder(config)
    if callerbb == None:
        callerbb = func_addr
    info = {RoleInfo.ROLE_INS_IDX: None, RoleInfo.CPF: "environment", RoleInfo.ROLE_INS: None,
            RoleInfo.ROLE: Role.GETTER, RoleInfo.CALLER_BB: callerbb, RoleInfo.ROLE_FUN: None,
            RoleInfo.X_REF_FUN: func_addr, RoleInfo.DATAKEY: "", RoleInfo.PAR_N: 0, RoleInfo.GP: gp_addr}
    setBugFindingFlag(True, cfg)
    return bugfinder._vuln_analysis(proj, cfg, "environment", taint_addr, info, loop_sinks_addr_input, sink_dst_size, 4294967295)


if __name__ == "__main__":
    main()
