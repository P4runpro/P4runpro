import sys
sys.path.append("/usr/local/python3/lib/python3.5/site-packages")
import traceback
import time
from myparser import parser
from analyzer import *
from utils import *
from resource_manager import Manager
from ilp_solver import *
from runtime import *

s = '''
@ mem1 1024
program cache(<hdr.udp.dst_port, 7777, 0xffff>) {
	EXTRACT(hdr.l5.key1, sar);
	EXTRACT(hdr.l5.op, har);
	BRANCH:
	case(<sar, 0x0c000000, 0xffffffff>,
		<har, 1, 0xffffffff>
	) {
		FORWARD(168);
		LOADI(mar, 123);
		MEMREAD(mem1);
		MODIFY(hdr.l5.key2, sar);
	}
	case(<sar, 0x0c000000, 0xffffffff>,
		<har, 0, 0xffffffff>
	) {
		FORWARD(168);
		LOADI(mar, 123);
		MEMWRITE(mem1);
	};
	FORWARD(184);
}
'''

ss = '''
@ mem_cms_row1 1024
@ mem_cms_row2 1024
@ mem_bf_row1 1024
@ mem_bf_row2 1024
program heavyhitter(<hdr.ipv4.src, 10.0.0.0, 0xffff0000>) {
    LOADI(sar, 1);
    HASH_5_TUPLE_MEM(mem_cms_row1);
    MEMADD(mem_cms_row1);
    LOADI(har, 1024);
    MIN(har, sar);
    LOADI(sar, 1);
    HASH_5_TUPLE_MEM(mem_cms_row2);
    MEMADD(mem_cms_row2);
    MIN(har, sar);
    BRANCH:
    case(<har, 1024, 0xffffffff>) {
        LOADI(sar, 1);
        HASH_5_TUPLE_MEM(mem_bf_row1);
        MEMOR(mem_bf_row1);
        BRANCH:
        case(<sar, 1, 0xffffffff>) {
            HASH_5_TUPLE_MEM(mem_bf_row2);
            MEMOR(mem_bf_row2);
            BRANCH:
            case(<sar, 0, 0xffffffff>) {
                REPORT;
            };
        }
        case(<sar, 0, 0xffffffff>) {
            LOADI(sar, 1);
            HASH_5_TUPLE_MEM(mem_bf_row2);
            MEMOR(mem_bf_row2);
            REPORT;
        };
    };
}
'''

sss = '''
program loadbanlancer(<hdr.ipv4.src, 10.0.0.0, 0xffff0000>) {
    HASH_5_TUPLE;
    BRANCH:
    case(<har, 0, 0x00000001>) {
        FORWARD(184);
    }
    case(<har, 1, 0x00000001>) {
        FORWARD(168);
    };
}
'''



rt = bfrt_runtime(0, "p4runpro")
#rt.entry_del("SwitchIngress.init.tb_forward", [["ig_intr_md.ingress_port", 0, "exact"]])
rt.entry_add("SwitchIngress.init.tb_forward", [["ig_intr_md.ingress_port", 0, "exact"]], [[['port', 168]], 'SwitchIngress.init.forward'])
#j = 0
#for i in range(1024):
#    if rt.reg_read("SwitchEgress.rpb12.rpb12_register", i) > 1024:
#       j = j + 1
#        print(rt.reg_read("SwitchEgress.rpb12.rpb12_register", i)) 
#print(j)
#exit()
manager = Manager()
input_program_path = "../programs/"
input_programs = [
    "BF",
    "Cache",
    "Calculation",
    "CMS",
    "DQAcc",
    "ECN",
    "HeavyHitter",
    "HLL",
    "L2Forwarding",
    "L3Routing",
    "LoadBalancer",
    "NetCache",
    "StatefulFirewall",
    "SuMax",
    "Tunnel"
]

inputs = {}
for program in input_programs:
    fr = open(input_program_path + program + ".p4runpro", "r")
    inputs[program] = fr.read()
    fr.close()

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
result = parser.parse(ssss)
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
        flow_id = manager.get_flow_id()
        #flow_id = 2
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
            ncs = Stack()
            ncs.push(node)
            while not ncs.empty():
                nc = ncs.pop()
                if nc.type == "case":
                    nc.fbranch_id = node.branch_id
                else:
                    for ncc in nc.children:
                        ncs.push(ncc)
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
        fbranchs[node.pname][node.branch_id] = [node.fbranch_id, stage]
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

# debug
for pname, primitive_ls in pri_nodes.items():
    for pri in primitive_ls[1:]:
        print(pri.name)
        print(pri.stage)
        print(pri.branch_id)
#exit()

        

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

    tb_ava = manager.get_table_available()
    mem_ava = manager.get_mem_available()
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
    print(forward)
    suc, max_rpb_num, global_stage_ls = solve(max_slice_number, tb_not_ava, mem_not_ava, forward)

    if suc:
        table_entry_requirement = [0 for i in range(22)]
        memory_requirement = [0 for i in range(22)]

        for i in range(max_slice_number):
            if tb_re[i] > 0:
                table_entry_requirement[(global_stage_ls[i]-1)%22] = table_entry_requirement[(global_stage_ls[i]-1)%22] + tb_re[i]
            if mem_re[i] > 0:
                memory_requirement[(global_stage_ls[i]-1)%22] = memory_requirement[(global_stage_ls[i]-1)%22] + mem_re[i]

        # update resource manager and get the offset

        offsets = manager.allocate_program(pname, table_entry_requirement, memory_requirement, primitive_ls[0].flow_id)

        offset_dict = {}
        for pri in primitive_ls[1:]:
            if pri.name == "offset":
                if pri.mem_name not in offset_dict.keys():
                    offset = Argument("argument", 1, None, "int", offsets[pri.stage % 22])
                    offset_dict[pri.mem_name] = offsets[pri.stage % 22]
                    offsets[pri.stage % 22] = offsets[pri.stage % 22] + pri.mem_size
                else:
                    offset = Argument("argument", 1, None, "int", offset_dict[pri.mem_name])
                pri.children.append(offset)

        print("Allocation done, using " + str(max_rpb_num) + " logic rpb")
        #print(global_stage_ls)

        # generate table entries
        print("Configuring table entries")
        entries = []
        fid = primitive_ls[0].flow_id
        pname = primitive_ls[0].name
        max_it = int((global_stage_ls[-1] - 1)/22)
        for pri in primitive_ls[1:]:
            pri.stage = global_stage_ls[pri.stage-1]
            entries = entries + get_entry_rpb(pri)
        if max_it >= 1:
            for it in range(max_it+1):
                if it == 0:
                    entries = entries + get_entry_recirculation(pname, flow_id, it, 0)
                elif it == max_it:
                    entries = entries + get_entry_recirculation(pname, flow_id, it, 2)
                else:
                    entries = entries + get_entry_recirculation(pname, flow_id, it, 1)
        entries = entries + get_entry_filter(primitive_ls[0])
    

        # dump table entries
        
        '''eval
        iterations = 50
        dumped = []
        t1 = 0
        t2 = 0
        t_ls = []

        for i in range(iterations):
            try:
                t1 = time.time()
                for e in entries:
                    e.show()
                    rt.entry_add(e.entry["table_name"], e.entry["key_list"], e.entry["data_list"])
                    dumped.append(e)
                t2 = time.time()
                t_ls.append(t2-t1)
            except Exception as err:
                print(traceback.format_exc())
                print(err)
            for e in entries:
                rt.entry_del(e.entry["table_name"], e.entry["key_list"])
        '''
        for e in entries:
            e.show()
        try:
            for e in entries:
                rt.entry_add(e.entry["table_name"], e.entry["key_list"], e.entry["data_list"])
        except Exception as err:
            print(traceback.format_exc())
            print(err)
    else:
        print("allocation fails")
        