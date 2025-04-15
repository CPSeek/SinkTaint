from copy import deepcopy
from bug_finder.sinks import getfindflag, setfindflag, init_flag
from bug_finder.taint import main, setSinkTarget, setr4, init_loop_sinks
from taint_analysis.coretaint import setfollowTarget, set_no_calltrace_overlap
import sys
sys.setrecursionlimit(5000)
import angr
import random, string
import pickle
import os
import conv_Ghidra_output
from time import time
import shutil

lastfulltrace = []


def main_main():
    if len(sys.argv) < 3:
        print("python sinktaint_main.py <path_to_firmware> <path_to_config>")
        exit(-1)
    binary = sys.argv[1]
    configfile = sys.argv[2]
    # if '/' in binary:
    #     filepath = '/'.join(binary.split('/')[:-2])
    # binary = '/home/sinktaint/output/R7000/ghidra_extract_result/httpd/httpd'
    # configfile = '/home/sinktaint/output/R7000/ghidra_extract_result/httpd/httpd_ref2sink_bof.result-filte-alter2'
    # # binary = '/home/sinktaint/output/cpylike/AC68U/ghidra_extract_result/httpd/httpd'
    # configfile = '/home/sinktaint/output/cpylike/AC68U/ghidra_extract_result/httpd/httpd_ref2sink_bof.result-filte-alter2'
    # binary = '/home/sinktaint/output/878/ghidra_extract_result/prog.cgi/prog.cgi'
    # configfile = '/home/sinktaint/output/878/ghidra_extract_result/prog.cgi/prog.cgi_ref2sink_bof.result-filte'
    # #binary = '/home/sinktaint/output/wr940nv4/ghidra_extract_result/httpd/httpd'
    #configfile = '/home/sinktaint/output/wr940nv4/ghidra_extract_result/httpd/httpd_ref2sink_bof.result-filte-alter2'
    

    # binary = '/home/sinktaint/output/AC18/ghidra_extract_result/httpd/httpd'
    # configfile = '/home/sinktaint/output/AC18/ghidra_extract_result/httpd/httpd_ref2sink_bof.result-filte-alter2'
    
    filepath = binary
    
    # init_sink_dst_size(sink_dst_size)

    if len(sys.argv) >= 4:
        r4 = int(sys.argv[3], 0)
        setr4(r4)
    appe = binary.split('/')[-1] + "-" + ''.join(random.sample(string.ascii_letters + string.digits, 4))
    if '-alter2' not in configfile:
        conv_Ghidra_output.main(configfile)
        configfile = configfile + '-alter2'
    with open(configfile, 'r') as f:
        cont = f.read().split('\n')
    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    cfg = proj.analyses.CFG()

    loopfile = binary + '-loopaddr'
    f = open(loopfile, 'r')
    loop_sinks_addr = []
    loop_sinks_addr_input = {}
    sink_dst_size = {}
    for line in f.readlines():
        line = line.strip().split(": ")
        if ':' in line[0]:
            continue
        if line[0] == '':
            break
        addr = int(line[0], 16)
        input = line[1].split(' ')
        loop_sinks_addr.append(addr)
        loop_sinks_addr_input[addr] = input

    init_loop_sinks(loop_sinks_addr_input)
    dst_size_file = binary + '_sink_size.txt'
    f = open(dst_size_file, 'r')
    for line in f.readlines():
        line = line.strip().split(":")
        addr = int(line[0], 16)
        dst_size = int(line[1], 10)
        sink_dst_size[addr] = dst_size
    loop_sinks_addr_prev = []
    for addr in loop_sinks_addr:
        curr_block =  cfg.model.get_any_node(addr)
        try:
            prev_block = curr_block.predecessors[0]
            loop_sinks_addr_prev.append(prev_block.addr)
        except:
            continue
    #with open("./httpd.pk",'wb') as f:
    #    pickle.dump((proj,cfg),f)
    # try:
    #     print("read file@" + filepath)
    #     with open(filepath+".pk",'rb') as f:
    #         (proj,cfg)=pickle.load(f)
    #     print("read file@%s is ok..." % filepath)
    # except:
    #     print("Construct CFG")
    #     proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    #     if 'ARM' in proj.arch.name:
    #         cfg = proj.analyses.CFG(force_complete_scan=False)
    #     else:
    #         cfg = proj.analyses.CFG()
    #     print("write file@" + filepath)
    #     with open(filepath +".pk",'wb') as f:
    #         pickle.dump((proj,cfg),f)
    #     print("write file@%s is ok..." % filepath)
    gp_addr = 0x5bbba0
    try:
        if 'MIPS' in proj.arch.name:
            main_function = proj.kb.functions.function(name='main')
            block = proj.factory.block(main_function.addr)
            gp_high = None
            gp_low = None
            for ins in block.disassembly.insns:
                if 'lui' in str(ins) and '$gp' in str(ins):
                    gp_high = int(str(ins).split(', ')[-1],16) * 0x10000
                if '$gp, $gp,' in str(ins) and 'addiu' in str(ins):
                    gp_low = int(str(ins).split(', ')[-1],16)
                    break
            if gp_high != None and gp_low != None:
                gp_addr = gp_high + gp_low
            else:
                gp_addr = 0x5bbba0
    except:
        gp_addr = 0x5bbba0
    cases = 0
    find_cases = 0
    init_flag()
    t = time()
    with open(filepath + '_result-%s.txt' % appe, 'a') as f:
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % configfile)
        f.write("start time: %d\n" % t)
    # ori_cfg = cfg
    # ori_proj = proj

    try:
        for i in range(int(len(cont) / 3)):
            # if len(i.split(' '))>2:
            try:
                # cfg = deepcopy(ori_cfg)
                # proj = deepcopy(ori_proj)
                cases += 1
                # func_addr=[int(j,0) for j in i.split(' ')[1:-1]] # functrace
                if cont[i * 3 + 1] != '':
                    func_addr = [int(j, 0) for j in cont[i * 3 + 1].split(' ')]
                else:
                    func_addr = []
                taint_addr = int(cont[i * 3].split(' ')[0], 0)
                sinkTargets = [int(j, 0) for j in cont[i * 3 + 2].split(' ')]
                # put it to the head of cfg node
                if proj.arch.name != "MIPS32":
                    if not proj.loader.main_object.pic:
                        start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                        callerbb = None
                    else:
                        func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                        taint_addr = taint_addr - 0x10000 + 0x400000
                        sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                        start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                        anyaddr=True).addr
                        callerbb = None
                else:
                    if not proj.loader.main_object.pic or "system.so" in proj.filename:
                        print (hex(int(cont[i * 3].split(' ')[1], 0)))
                        print (cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True))
                        # start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).function_address
                        # callerbb = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                        start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                        callerbb = None
                        with open(binary, 'rb') as f:
                            try:
                                sec = proj.loader.main_object.sections_map['.got']
                                conttmp = f.read()
                                proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                            except:
                                print("[-] No .got")
                    else:
                        func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                        taint_addr = taint_addr - 0x10000 + 0x400000
                        sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                        start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                        anyaddr=True).function_address
                        callerbb = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                    anyaddr=True).addr
                        with open(binary, 'rb') as f:
                            try:
                                sec = proj.loader.main_object.sections_map['.got']
                                conttmp = f.read()
                                proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                            except:
                                print("[-] No .got")

                sinkTargets = [cfg.model.get_any_node(j, anyaddr=True).addr for j in sinkTargets]
                for j in func_addr:
                    #print (hex(j))
                    print (hex(cfg.model.get_any_node(j, anyaddr=True).addr))
                followtar = [cfg.model.get_any_node(j, anyaddr=True).addr for j in func_addr]
                # try:
                #     shutil.rmtree("./tmp/")
                #     os.mkdir("./tmp/")
                # except:
                #     os.mkdir("./tmp/")
                sinkTargets = sinkTargets + loop_sinks_addr_prev
                setfindflag(False)
                setSinkTarget(sinkTargets)
                setfollowTarget(followtar)

                
                
                print ("Analyzing %s from 0x%X, taint 0x%X, sinkTarget%s, functrace %s" % (
                binary, start_addr, taint_addr, str([hex(j) for j in sinkTargets]), str([hex(j) for j in followtar])))
                res = set()
                if not callerbb:
                    res = main(start_addr, taint_addr, binary, proj, cfg, loop_sinks_addr_input, sink_dst_size, gp_addr)
                else:
                    res = main(start_addr, taint_addr, binary, proj, cfg, loop_sinks_addr_input, sink_dst_size, gp_addr, callerbb)
                
                # if getfindflag()[0]:
                #     find_cases += 1
                #     res = set(getfindflag()[1])
                #     res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                #         [hex(i) for i in set(getfindflag()[1])])
                # else:
                #     res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"

                # is_taint, res = getfindflag()
                # res = list(os.walk("./tmp/"))
                # res = res[-1][-1]
                # if res != []:
                #     is_taint = True
                # print("%"*80)
                # print(is_taint,':', res)
                # try:
                #     res.remove('.DS_Store')
                # except:
                #     pass
                #if is_taint:
                if len(res) != 0:
                    find_cases += 1
                    #res = set(getfindflag()[1])
                    #res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                    #    [hex(i) for i in set(res)])
                    res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                        [hex(i) for i in set(res)])
                else:
                    res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"           
                with open(filepath + '_result-%s.txt' % appe, 'a') as f:
                    f.write(res + '\n')
            except:
                # del cfg
                # del proj
                continue
        # del cfg
        # del proj
    except Exception as e:
        print (e)
    end = time()
    with open(filepath + '_result-%s.txt' % appe, 'a') as f:
        f.write("total cases: %d\n" % cases)
        f.write("find cases: %d\n" % find_cases)
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % configfile)
        f.write("end time: %d\n" % end)
        f.write("time: %d\n" % (end - t))
    print("Saved in " + 'result-%s.txt' % appe)
    

def taint_stain_analysis(binary, ghidra_analysis_result, output):

    analysis_type = ""
    if "ref2sink_bof" in ghidra_analysis_result:
        analysis_type = "ref2sink_bof"
    elif "ref2sink_cmdi" in ghidra_analysis_result:
        analysis_type = "ref2sink_cmdi"

    appe = binary.split('/')[-1] + "-" + analysis_type + "-" + ''.join(random.sample(string.ascii_letters + string.digits, 4))
    if '-alter2' not in ghidra_analysis_result:
        conv_Ghidra_output.main(ghidra_analysis_result)
        ghidra_analysis_result = ghidra_analysis_result + '-alter2'
    with open(ghidra_analysis_result, 'r') as f:
        cont = f.read().split('\n')
    proj = angr.Project(binary, auto_load_libs=False, use_sim_procedures=True)
    cfg = proj.analyses.CFG()
    cases = 0
    find_cases = 0
    res = []
    result_file = os.path.join(output, "result-{}.txt".format(appe))
    with open(result_file, 'a') as f:
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % ghidra_analysis_result)

    for i in range(int(len(cont) / 3)):
        # if len(i.split(' '))>2:
        try:
            cases += 1
            # func_addr=[int(j,0) for j in i.split(' ')[1:-1]] # functrace
            if cont[i * 3 + 1] != '':
                func_addr = [int(j, 0) for j in cont[i * 3 + 1].split(' ')]
            else:
                func_addr = []
            taint_addr = int(cont[i * 3].split(' ')[0], 0)
            sinkTargets = [int(j, 0) for j in cont[i * 3 + 2].split(' ')]
            # put it to the head of cfg node
            if proj.arch.name != "MIPS32":
                if not proj.loader.main_object.pic:
                    start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    callerbb = None
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).addr
                    callerbb = None
            else:
                if not proj.loader.main_object.pic or "system.so" in proj.filename:
                    print (hex(int(cont[i * 3].split(' ')[1], 0)))
                    print (cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True))
                    start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).function_address
                    callerbb = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0), anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        try:
                            sec = proj.loader.main_object.sections_map['.got']
                            conttmp = f.read()
                            proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                        except:
                            print("[-] No .got")
                else:
                    func_addr = [j - 0x10000 + 0x400000 for j in func_addr]
                    taint_addr = taint_addr - 0x10000 + 0x400000
                    sinkTargets = [j - 0x10000 + 0x400000 for j in sinkTargets]
                    start_addr = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                  anyaddr=True).function_address
                    callerbb = cfg.model.get_any_node(int(cont[i * 3].split(' ')[1], 0) - 0x10000 + 0x400000,
                                                anyaddr=True).addr
                    with open(binary, 'rb') as f:
                        try:
                            sec = proj.loader.main_object.sections_map['.got']
                            conttmp = f.read()
                            proj.loader.memory.write_bytes(sec.min_addr, conttmp[sec.offset: sec.offset + sec.memsize])
                        except:
                            print("[-] No .got")
            sinkTargets = [cfg.gmodel.et_any_node(j, anyaddr=True).addr for j in sinkTargets]
            for j in func_addr:
                print (j)
                print (cfg.model.get_any_node(j, anyaddr=True).addr)
            followtar = [cfg.model.get_any_node(j, anyaddr=True).addr for j in func_addr]

            setfindflag(0)
            setSinkTarget(sinkTargets)
            setfollowTarget(followtar)

            print ("Analyzing %s from 0x%X, taint 0x%X, sinkTarget%s, functrace %s" % (
                binary, start_addr, taint_addr, str([hex(j) for j in sinkTargets]), str([hex(j) for j in followtar])))
            if not callerbb:
                main(start_addr, taint_addr, binary, proj, cfg)
            else:
                main(start_addr, taint_addr, binary, proj, cfg, callerbb)

            if getfindflag()[0]:
                find_cases += 1
                res = set(getfindflag()[1])
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  found : %s" % " ".join(
                    [hex(i) for i in set(getfindflag()[1])])
            else:
                res = "0x%x 0x%x " % (taint_addr, start_addr) + "  not found"
            with open(result_file, 'a') as f:
                f.write(res + '\n')
        except Exception as e:
            print (e)

    with open(result_file, 'a') as f:
        f.write("total cases: %d\n" % cases)
        f.write("find cases: %d\n" % find_cases)
        f.write("binary: %s\n" % binary)
        f.write("configfile: %s\n" % ghidra_analysis_result)
    print("Saved in " + 'result-%s.txt' % appe)


if __name__ == '__main__':
    main_main()
