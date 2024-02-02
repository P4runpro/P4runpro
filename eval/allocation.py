import sys
sys.path.append("../control_plane")
import json
import os
import six
import random
import time
import copy
from multiprocessing import Process

from myparser import parser
from analyzer import *
from utils import *
from resource_manager import Manager
from smt_solver import solve

t_size = 2048
m_size = 65536


def preparation(granularity ,input_files):
    workloads = []
    for input in input_files:
        fr = open(input, "r")
        s = fr.read()
        s = s.replace("1024", str(int(m_size/granularity)))
        s_stage = Stack()
        s_branch = Stack()
        fbranchs = {}
        f_branch = -1
        is_first_case = False
        stage = 0
        branch_id = 0
        maximun_branch_id = 0
        flow_id = -1
        mem_requirement = {}
        mem_stage_raw = {}
        mem_required = {}

        # generate AST
        result = parser.parse(s)
        result.depth = 0
        s_ast1 = Stack()
        s_ast1.push(result)
        program_name = ""
        pri_nodes = {}
        t1 = time.time()
        # First traverse to get local node in the order of DFS
        while not s_ast1.empty():
            node = s_ast1.pop()
            if node.type == "annotation":
                mem_requirement[node.identifier] = node.integer
                mem_required[node.identifier] = False
                mem_stage_raw[node.identifier] = []
            if node.type == "program":
                stage = 0
                node.stage = 0
                #flow_id = manager.get_flow_id()
                flow_id = 1
                node.flow_id = flow_id
                node.branch_id = 0
                node.pname = node.name
                if node.pname in pri_nodes.keys():
                    print("Error: duplicated program name: " + node.pname)
                    exit()
                pri_nodes[node.pname] = [node]
                fbranchs[node.pname] = {}
            if node.type == "primitive":
                stage = stage + 1
                node.stage = stage
                node.flow_id = flow_id
                node.branch_id = branch_id
                if node.name == "BRANCH":
                    is_first_case = True
                    f_branch = node.branch_id
                    if node.children[-1].type == "case":
                        last_case_node = node.children[-1]
                    else:
                        last_case_node = node.children[-1].children[-1]
                    last_case_node.last_case = True
                    if last_case_node.children[-1].type == "primitive":
                        last_primitive_node = last_case_node.children[-1]
                    else:
                        last_primitive_node = last_case_node.children[-1].children[-1]
                    if last_primitive_node.name == "BRANCH":
                        last_primitive_node.pop_num = node.pop_num + 1
                    else:
                        last_primitive_node.last_pri = True
                if node.last_pri:
                    maximun_branch_id = branch_id
                    for i in range(node.pop_num):
                        branch_id = s_branch.pop()
                        stage = s_stage.pop()
                    pop_num = 1

                if node.name[0:3] == "MEM":
                    mem_stage_raw[node.children[0].data_value].append(node)
                    node.mem_size = mem_requirement[node.children[0].data_value]

                if node.name == "HASH_5_TUPLE_MEM" or node.name == "HASH_MEM":
                    node.mem_size = mem_requirement[node.children[0].data_value]

                pri_nodes[node.pname].append(node)
                #print(node.name)
                #print(node.stage)

            if node.type == "case":
                if is_first_case:
                    s_stage.push(stage)
                    s_branch.push(branch_id)
                    is_first_case = False
                branch_id = maximun_branch_id + 1
                maximun_branch_id = branch_id
                stage = s_stage.top()
                node.branch_id  = branch_id
                fbranchs[node.pname][node.branch_id] = [f_branch, stage]
            for c in reversed(node.children):
                c.depth = node.depth + 1
                c.pname = node.pname
                s_ast1.push(c)

        # aligning
        aligning_tuples = {}
        #print(mem_stage_raw.items())
        for mem_id, ins_ls in mem_stage_raw.items():
            max_stage = -1
            align = False
            for ins in ins_ls:
                if max_stage == -1:
                    max_stage = ins.stage
                else:
                    if ins.stage > max_stage:
                        align = True
                        max_stage = ins.stage
                    elif ins.stage < max_stage:
                        align = True
            if align is True:
                for ins in ins_ls:
                    if ins.stage < max_stage:
                        aligning_tuples[(ins.flow_id, ins.branch_id)] = (ins.stage, max_stage - ins.stage)
        #print(aligning_tuples)
        #print(fbranch)
        for pname, primitive_ls in pri_nodes.items():
            for pri in primitive_ls[1:]:
                last_bid = -1
                bid = pri.branch_id
                brs = -1
                while True:
                    if (pri.flow_id, bid) in aligning_tuples.keys():
                        if bid == pri.branch_id:
                            if pri.stage >= aligning_tuples[(pri.flow_id, bid)][0]:
                                pri.stage = pri.stage + aligning_tuples[(pri.flow_id, bid)][1]
                        elif brs > aligning_tuples[(pri.flow_id, bid)][0]:
                                pri.stage = pri.stage + aligning_tuples[(pri.flow_id, bid)][1]
                                fbranchs[pname][last_bid][1] = fbranchs[pname][last_bid][1] + aligning_tuples[(pri.flow_id, bid)][1]
                    if bid in fbranchs[pname].keys():
                        brs = fbranchs[pname][bid][1]
                        last_bid = bid
                        bid = fbranchs[pname][bid][0]
                        continue
                    else:
                        break
                '''
                if (pri.flow_id, pri.branch_id) in aligning_tuples.keys():
                    if pri.stage >= aligning_tuples[(pri.flow_id, pri.branch_id)][0]:
                        pri.stage = pri.stage + aligning_tuples[(pri.flow_id, pri.branch_id)][1]
                '''
        
        # parse pseudo primitives
        pri_nodes = parse_pseudo_primitive(pri_nodes, fbranchs)
        '''
        for pname, primitive_ls in pri_nodes.items():
            for pri in primitive_ls[1:]:
                print(pri.name)
                print(pri.stage)
                print(pri.branch_id)
        exit()
        '''

        workloads.append((pri_nodes, mem_required, mem_requirement))
    return workloads

class AllocationEvent:
    def __init__(self, config_name, scheme_number, repeat, epochs, scheme, workloads, optim):
        self.output_path = "./data/" + config_name + "/scheme" + str(scheme_number) + "/" + str(repeat)
        if not os.path.exists(self.output_path):
            os.mkdir(self.output_path)
        self.epochs = epochs
        self.scheme = scheme
        self.manager = Manager(m_size, t_size)
        self.workloads = workloads
        self.optim = optim

    def allocate_1_workload(self, wid, epoch):
        pri_nodes = self.workloads[wid][0]
        mem_required = copy.deepcopy(self.workloads[wid][1])
        mem_requirement = self.workloads[wid][2]

        # allocate programs and generate table entries
        for pname, primitive_ls in pri_nodes.items():
            print("Allocating program:" + pname)
            max_slice_number = -1
            for pri in primitive_ls[1:]:
                if pri.stage > max_slice_number:
                    max_slice_number = pri.stage
            tb_not_ava = [[]for i in range(max_slice_number)]
            mem_not_ava = [[] for i in range(max_slice_number)]
            forward = []
            tb_re = [0 for i in range(max_slice_number)]
            mem_re = [0 for i in range(max_slice_number)]

        for pri in primitive_ls[1:]:
            if pri.name == "BRANCH":
                tb_re[pri.stage-1] = tb_re[pri.stage-1] + pri.case_num
            else:
                tb_re[pri.stage-1] = tb_re[pri.stage-1] + 1
            if pri.name[0:3] == "MEM":
                if not mem_required[pri.children[0].data_value]:
                    mem_re[pri.stage-1] = mem_re[pri.stage-1] + mem_requirement[pri.children[0].data_value]
                    mem_required[pri.children[0].data_value] = True
            if pri.name == "FORWARD" or pri.name == "DROP" or pri.name == "RETURN":
                if pri.stage-1 not in forward:
                    forward.append(pri.stage-1)

        tb_ava = self.manager.get_table_available()
        mem_ava = self.manager.get_mem_available()
        for i in range(max_slice_number):
            for j in range(22):
                if tb_re[i] > tb_ava[j]:
                    tb_not_ava[i].append(j)
                if mem_re[i] > mem_ava[j]:
                    mem_not_ava[i].append(j)
        '''
        print(max_slice_number)
        print(tb_not_ava)
        print(mem_not_ava)
        print(forward)
        '''

        suc, max_rpb_num, global_stage_ls = solve(max_slice_number, tb_not_ava, mem_not_ava, forward, optimize=self.optim)
        #suc, max_rpb_num, global_stage_ls = solve(max_slice_number, tb_not_ava, mem_not_ava, forward, optimize=self.optim, a=self.scheme["a"], b=self.scheme["b"])

        if suc:
            table_entry_requirement = [0 for i in range(22)]
            memory_requirement = [0 for i in range(22)]
            
            for i in range(max_slice_number):
                if tb_re[i] > 0:
                    table_entry_requirement[(global_stage_ls[i]-1)%22] = table_entry_requirement[(global_stage_ls[i]-1)%22] + tb_re[i]
                if mem_re[i] > 0:
                    memory_requirement[(global_stage_ls[i]-1)%22] = memory_requirement[(global_stage_ls[i]-1)%22] + mem_re[i]
            # TODO: reallocate
                

            # update resource manager and get the offset

            offsets = self.manager.allocate_program(pname + str(epoch), table_entry_requirement, memory_requirement, primitive_ls[0].flow_id)
            
            '''
            print(offsets)
            for i in range(1,23):
                self.manager.register_pool_available["rpb" + str(i)].show()
            '''

            print("Allocation done, using " + str(max_rpb_num) + " logic rpb")
        else:
            print("allocation fail")
        return suc, global_stage_ls

    def start(self):
        res_dict = {}
        log =  open(self.output_path+"/log.txt", "w")
        workload_map = {"cache": 0, "hh": 1, "lb": 2, "bf": 3, "calc": 4, "cms": 5, "acc": 6, "ecn": 7, "hll": 8, "l2": 9, "l3": 10, "nc": 11, "sf": 12, "sm": 13, "tn": 14}
        for epoch in range(self.epochs):
            if self.scheme["workload"] == "mixed":
                workload = random.randint(0, 2)
            elif self.scheme["workload"] == "capacity":
                workload = random.randint(0, 14)
            else:
                workload = workload_map[self.scheme["workload"]]

            log.writelines("epoch" + str(epoch) + "\n")

            res = {}
            t1 = time.time()
            suc, alloc_logic = self.allocate_1_workload(workload, epoch)
            t2 = time.time()
            if suc:
                alloc_physical = [(i-1)%22 + 1 for i in alloc_logic]
            else:
                alloc_physical = []

            #compute allocation time and memory utilization
            alloc_time = (t2-t1)*1000
            fte = self.manager.get_table_available()
            fmem = self.manager.get_mem_all()
            for i in range(len(fte)):
                if fte[i] < 0:
                    fte[i] = 0
                if fmem[i] < 0:
                    fmem[i] = 0

            log.writelines("allocation time = " + str(alloc_time) + "\n")
            log.writelines("free table entry = " + str(fte) + "\n")
            log.writelines("free memory = " + str(fmem) + "\n")

            tb_utilization = float(t_size*22 - sum(fte)) / float(t_size*22)
            mem_utilization = float(m_size*22 - sum(fmem)) / float(m_size*22)

            tb_utilization_per_stage = [float(t_size-i)/float(t_size) for i in fte]
            mem_utilization_per_stage = [float(m_size-i)/float(m_size) for i in fmem]

            log.writelines("te utilization = " + str(tb_utilization) + "\n")
            log.writelines("mem utilization = " + str(mem_utilization) + "\n")

            res["success"] = suc
            res["alloc_logic"] = str(alloc_logic)
            res["alloc_physical"] = str(alloc_physical)
            res["allocation_time"] = alloc_time
            res["table_entry_utilization"] = tb_utilization
            res["memory_utilizaiton"] = mem_utilization
            res["table_entry_utilization_per_stage"] = str(tb_utilization_per_stage)
            res["memory_utilization_per_stage"] = str(mem_utilization_per_stage)
            res["program"] = workload

            res_dict[epoch] = res

            if not suc:
                #if self.scheme["workload"] == "capacity":
                #    break
                break
             
        with open(self.output_path+"/output.json", "w") as f:
            json.dump(res_dict, f, indent=4, ensure_ascii=False)


def allocation_process(config_name, scheme_number, repeat, epochs, scheme, optim):
    input_files = [
        "../programs/Cache.p4runpro",
        "../programs/HeavyHitter.p4runpro",
        "../programs/LoadBalancer.p4runpro",
        "../programs/BF.p4runpro",
        "../programs/Calculation.p4runpro",
        "../programs/CMS.p4runpro",
        "../programs/DQAcc.p4runpro",
        "../programs/ECN.p4runpro",
        "../programs/HLL.p4runpro",
        "../programs/L2Forwarding.p4runpro",
        "../programs/L3Routing.p4runpro",
        "../programs/NetCache.p4runpro",
        "../programs/StatefulFirewall.p4runpro",
        "../programs/SuMax.p4runpro",
        "../programs/Tunnel.p4runpro"
    ]
    workloads = preparation(scheme["granularity"], input_files)
    event = AllocationEvent(config_name, scheme_number, repeat, epochs, scheme, workloads, optim)
    event.start()


if __name__ == '__main__':
    config_path = sys.argv[1]
    config_name = sys.argv[1].split("/")[-1].replace(".json", "")
    if not os.path.exists("./data/" + config_name):
        os.mkdir("./data/" + config_name)
    config = {}
    with open(config_path, "r") as fr:
        config = json.load(fr)
    epochs = config["epochs"]
    repets = config["repeats"]
    schemes = config["schemes"]
    optim = config["optim"]

    for i in range(len(schemes)):
        scheme = schemes[i]
        if not os.path.exists("./data/" + config_name + "/scheme" + str(i)):
            os.mkdir("./data/" + config_name + "/scheme" + str(i))
        processes = [Process(target=allocation_process, args=(config_name, i, repeat, epochs, scheme, optim)) for repeat in range(repets)]

        for p in processes:
            p.start()
        
        for p in processes:
            p.join()