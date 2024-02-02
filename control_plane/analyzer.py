# ------------------------------------------------------------
# analyzer.py
# analyze the primitive node, require resource from resource manager and generate entries information
# ------------------------------------------------------------

from myast import *
from utils import *
import re
import copy

re_primitive_with_argument = r'EXTRACT|MODIFY|LOADI|ADD|AND|OR|XOR|MAX|MIN|SGT|SLT|MEM(ADD|SUB|AND|OR|READ|WRITE|MAX)|FORWARD|mask|offset'

re_primitive_without_argument = r'HASH_5_TUPLE|HASH|DROP|RETURN|REPORT|backup|recover(1|2|3)'

re_primitive_branch = r'BRANCH'

re_primitive_pseudo_mem = r'MOVE|ADDI|ANDI|XORI|NOT|SUBI|SUB|SGT|MEM(ADD|SUB|AND|OR|READ|WRITE|MAX)|HASH_5_TUPLE_MEM|HASH_MEM'

primitive_action_mapping_dict = {
    "EXTRACT": "extract_<arg1>_<arg2>",
    "MODIFY": "modify_<arg1>_<arg2>",
    "HASH_5_TUPLE": "hash_5_tuple",
    "HASH": "hash_customization",
    "HASH_5_TUPLE_MEM": "hash_5_tuple_mem",
    "HASH_MEM": "hash_customization_mem",
    "BRANCH": "set_branch_id",
    "LOADI": "loadi_<arg1>",
    "ADD": "add_<arg1>_<arg2>",
    "AND": "and_<arg1>_<arg2>",
    "OR": "or_<arg1>_<arg2>",
    "XOR": "xor_<arg1>_<arg2>",
    "MAX": "max_<arg1>_<arg2>",
    "MIN": "min_<arg1>_<arg2>",
    "MEMADD": "salu_add_sub",
    "MEMSUB": "salu_add_sub",
    "MEMAND": "salu_and_or",
    "MEMOR": "salu_and_or",
    "MEMREAD": "salu_read_write",
    "MEMWRITE": "salu_read_write",
    "MEMMAX": "salu_max",
    "FORWARD": "forward",
    "DROP": "drop",
    "RETURN": "rt",
    "REPORT": "report",
    "mask": "address_translation_mask",
    "offset": "address_translation_offset",
    "backup": "backup",
    "recover": "recover"
}


flow_filter1_items = [
    "hdr.ethernet.dst",
    "hdr.ethernet.src",
    "hdr.ethernet.ether_type"
]

flow_filter2_items = [
    "hdr.ipv4.dst",
    "hdr.ipv4.src",
    "hdr.ipv4.protocol",
    "hdr.tcp.src_port",
    "hdr.tcp.dst_port",
    "hdr.udp.src_port",
    "hdr.udp.dst_port"
]

flow_filter3_items = [
    "hdr.tunnel.dst_id"
]

rpb_size = 22


class Entry:
    """
    P4runpro entry class
    Member variables:
    - program: program name
    - key_list: key list
    - data_list: data list
    """

    def __init__(self, program, table_name, key_list, data_list):
        self.entry = {"program": program, "table_name": table_name, "key_list": key_list, "data_list": data_list}

    def show(self):
        print(self.entry["table_name"])
        print(self.entry["key_list"])
        print(self.entry["data_list"])
        print("")


def parse_pseudo_primitive(pri_nodes, fbranchs):
    """
    Translate pseudo primitive to primitives
    Arguments:
    - pri_nodes: primitive node list dict
    """
    # generate new node with arguments
    for program, primitives in pri_nodes.items():
        fbranch = fbranchs[program]
        #print(fbranch)
        indexes = []
        primitives_slices = []
        stage_dict = {}
        stage_offset = 0
        for i in range(len(primitives)):
            primitive = primitives[i]
            primitive_slice = []
            if primitive.type == "primitive":
                if re.match(re_primitive_pseudo_mem, primitive.name):
                    indexes.append(i)
                    if primitive.name != "NOT" and primitive.name[0:3] != "MEM" and primitive.name[0:4] != "HASH":
                        A = primitive.children[0].children[0]
                        B = primitive.children[0].children[1]
                        if primitive.name == "MOVE":
                            Zero = Argument("argument", 1, None, "int", 0)
                            primitive_slice.append(Primitive("primitive", 1, [A, Zero], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "ADD", True))
                        if primitive.name == "ADDI" or primitive.name == "ANDI" or primitive.name == "ORI" or primitive.name == "XORI":
                            C = Argument("argument", 1, None, "register", get_supportive_reg([A.data_value]))
                            primitive_slice.append(Primitive("primitive", 1, [C, B], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, C], primitive.name.rstrip('I'), True))
                        if primitive.name == "SUBI":
                            B.data_value = 2**32 - B.data_value
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "ADDI", True))
                        if primitive.name == "SUB":
                            C = Argument("argument", 1, None, "register", get_supportive_reg([A.data_value, B.data_value]))
                            Max = Argument("argument", 1, None, "int", 2**32 - 1)
                            One = Argument("argument", 1, None, "int", 1)
                            primitive_slice.append(Primitive("primitive", 1, [C, Max], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [B, C], "XOR", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "ADD", True))
                            primitive_slice.append(Primitive("primitive", 1, [B, C], "XOR", True))
                            primitive_slice.append(Primitive("primitive", 1, [C, One], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, C], "ADD", True))
                        '''
                        if primitive.name == "OR":
                            C = Argument("argument", 1, None, "register", get_supportive_reg([A.data_value, B.data_value]))
                            D = Argument("argument", 1, None, "register", get_supportive_reg([A.data_value, B.data_value, C.data_value]))
                            Max = Argument("argument", 1, None, "int", 2 ** 32 - 1)
                            Zero = Argument("argument", 1, None, "int", 0)
                            primitive_slice.append(Primitive("primitive", 1, [C, Max], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, C], "XOR", True))
                            primitive_slice.append(Primitive("primitive", 1, [B, Zero], "LOADI", True))
                            primitive_slice.append(Primitive("primitive", 1, [D, B], "ADD", True))
                            primitive_slice.append(Primitive("primitive", 1, [D, C], "XOR", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, D], "AND", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, C], "XOR", True))
                        '''
                        if primitive.name == "SGT":
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "MIN", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "XOR", True))
                        if primitive.name == "SLT":
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "MAX", True))
                            primitive_slice.append(Primitive("primitive", 1, [A, B], "XOR", True))
                    elif primitive.name == "NOT":
                        A = primitive.children[0].children[0]
                        Max = Argument("argument", 1, None, "int", 2 ** 32 - 1)
                        C = Argument("argument", 1, None, "register", get_supportive_reg([A.data_value]))
                        primitive_slice.append(Primitive("primitive", 1, [C, Max], "LOADI", True))
                        primitive_slice.append(Primitive("primitive", 1, [A, C], "XOR", True))
                    elif primitive.name == "HASH_5_TUPLE_MEM" or primitive.name == "HASH_MEM":
                        mask = Argument("argument", 1, None, "int", size_to_mask(primitive.mem_size))
                        new_pri = Primitive("primitive", 1, [mask], "mask", True)
                        new_pri.pname = primitive.pname
                        primitive_slice.append(copy.deepcopy(primitive))
                        primitive_slice.append(new_pri)
                    elif primitive.name[0:3] == "MEM":
                        if primitive.name == "MEMADD" or primitive.name == "MEMAND" or primitive.name == "MEMREAD":
                            arg = Argument("argument", 1, None, "int", 0)
                        else:
                            arg = Argument("argument", 1, None, "int", 1)
                        new_pri = Primitive("primitive", 1, [arg], "offset", True)
                        new_pri.mem_size = primitive.mem_size
                        new_pri.mem_name = primitive.children[0].data_value
                        new_pri.pname = primitive.pname
                        primitive_slice.append(new_pri)
                        primitive_slice.append(copy.deepcopy(primitive))
                    '''
                    if (primitive.flow_id, primitive.branch_id) not in stage_dict:
                        stage_dict[(primitive.flow_id, primitive.branch_id)] = 0

                    for j in range(len(primitive_slice)):
                        primitive_slice[j].flow_id = primitive.flow_id
                        primitive_slice[j].branch_id = primitive.branch_id
                        primitive_slice[j].stage = primitive.stage + stage_dict[(primitive.flow_id, primitive.branch_id)] + j
                    stage_dict[(primitive.flow_id, primitive.branch_id)] = stage_dict[(primitive.flow_id, primitive.branch_id)] + len(primitive_slice) - 1
                    '''
                    for j in range(len(primitive_slice)):
                        primitive_slice[j].flow_id = primitive.flow_id
                        primitive_slice[j].branch_id = primitive.branch_id
                        primitive_slice[j].stage = primitive.stage + j
                        
                        bid = primitive.branch_id
                        while True:
                            if bid in stage_dict.keys():
                                primitive_slice[j].stage = primitive_slice[j].stage + stage_dict[bid]
                            if bid in fbranch.keys():
                                bid = fbranch[bid][0]
                                continue
                            else:
                                break
                    if primitive.branch_id not in stage_dict.keys():
                        stage_dict[primitive.branch_id] = len(primitive_slice) - 1
                    else:
                        stage_dict[primitive.branch_id] = stage_dict[primitive.branch_id] + len(primitive_slice) - 1
                    primitives_slices.append(primitive_slice)

        # serialize the pri_node_list
        print(fbranch)
                    
        '''
        for i in primitives_slices:
            print(123)
            for j in i:
                print(j.name)
                print(j.stage)
        '''
        offset = 0
        stage_dict = {}
        for i in range(len(indexes)):
            primitives = primitives[0:indexes[i] + offset] + primitives_slices[i] + primitives[indexes[i] + offset + 1:]
            '''
            if primitives_slices[i][0].branch_id not in stage_dict.keys():
                stage_dict[primitives_slices[i][0].branch_id] = len(primitives_slices[i])-1
            else:
                stage_dict[primitives_slices[i][0].branch_id] = stage_dict[primitives_slices[i][0].branch_id] + len(primitives_slices[i])-1
            '''
            for j in range(indexes[i] + offset + len(primitives_slices[i]), len(primitives)):
                '''
                bid =  primitives[j].branch_id
                if bid not in stage_dict.keys():
                    stage_dict[bid] = 0
                brs = -1
                while True:
                    if primitives[j].flow_id == primitives_slices[i][0].flow_id and bid == primitives_slices[i][0].branch_id:
                        if bid == primitives[j].branch_id:
                            primitives[j].stage = primitives[j].stage + len(primitives_slices[i]) - 1
                        elif brs > primitives_slices[i][0].stage-stage_dict[primitives[j].branch_id]:
                            primitives[j].stage = primitives[j].stage + len(primitives_slices[i]) - 1
                    if bid in fbranch.keys():
                        brs = fbranch[bid][1]
                        bid = fbranch[bid][0]
                        continue
                    else:
                        break
                '''
                '''
                if primitives[j].flow_id == primitives_slices[i][0].flow_id and primitives[j].branch_id == primitives_slices[i][0].branch_id:
                    primitives[j].stage = primitives[j].stage + len(primitives_slices[i]) - 1
                else:
                    break
                '''
                bid = primitives[j].branch_id
                while True:
                    if bid == primitives_slices[i][0].branch_id:
                        primitives[j].stage = primitives[j].stage + len(primitives_slices[i]) - 1
                    if bid in fbranch.keys():
                        bid = fbranch[bid][0]
                        continue
                    else:
                        break
            offset = offset + len(primitives_slices[i]) - 1
        pri_nodes[program] = primitives
    return pri_nodes


def get_entry_filter(ast_node):
    """
    Get table entry for table tb_flow_filter\d
    Arguments:
    - ast_node: AST Node
    """
    table_name = ""
    key_list = []
    data_list = [
        [
            ["flow_id", ast_node.flow_id]
        ],
        "SwitchIngress.init.set_flow_id"
    ]
    rule_list = []

    # find rules
    s = Stack()
    s.push(ast_node)
    while not s.empty():
        node = s.pop()
        if node.type == "rules" or node.type == "program":
            for c in reversed(node.children):
                s.push(c)
        elif node.type == "rule":
            rule_list.append(node.rule)
    #print(rule_list[0][0])
    if rule_list[0][0] in flow_filter1_items:
        table_name = "SwitchIngress.init.tb_flow_filter1"
        key_list = [
            ["hdr.ethernet.dst", 0, 0, "ternary"],
            ["hdr.ethernet.src", 0, 0, "ternary"],
            ["hdr.ethernet.ether_type", 0, 0, "ternary"]
        ]
        for rule in rule_list:
            if rule[0] == "hdr.ethernet.dst":
                key_list[0][1] = rule[1]
                key_list[0][2] = rule[2]
            elif rule[0] == "hdr.ethernet.src":
                key_list[1][1] = rule[1]
                key_list[1][2] = rule[2]
            elif rule[0] == "hdr.ethernet.ether_type":
                key_list[2][1] = rule[1]
                key_list[2][2] = rule[2]            
    elif rule_list[0][0] in flow_filter2_items:
        table_name = "SwitchIngress.init.tb_flow_filter2"
        key_list = [
            ["hdr.ipv4.src", 0, 0, "ternary"],
            ["hdr.ipv4.dst", 0, 0, "ternary"],
            ["hdr.ipv4.protocol", 0, 0, "ternary"],
            ["hdr.l4_port.src_port", 0, 0, "ternary"],
            ["hdr.l4_port.dst_port", 0, 0, "ternary"]
        ]
        for rule in rule_list:
            if rule[0] == "hdr.tcp.src_port":
                key_list[2][1] = 6
                key_list[2][2] = 0xff
                key_list[3][1] = rule[1]
                key_list[3][2] = rule[2]
            elif rule[0] == "hdr.tcp.dst_port":
                key_list[2][1] = 6
                key_list[2][2] = 0xff
                key_list[4][1] = rule[1]
                key_list[4][2] = rule[2]
            elif rule[0] == "hdr.udp.src_port":
                key_list[2][1] = 17
                key_list[2][2] = 0xff
                key_list[3][1] = rule[1]
                key_list[3][2] = rule[2]
            elif rule[0] == "hdr.udp.dst_port":
                key_list[2][1] = 17
                key_list[2][2] = 0xff
                key_list[4][1] = rule[1]
                key_list[4][2] = rule[2]
            elif rule[0] == "hdr.ipv4.src":
                key_list[0][1] = rule[1]
                key_list[0][2] = rule[2]
            elif rule[0] == "hdr.ipv4.dst":
                key_list[1][1] = rule[1]
                key_list[1][2] = rule[2]
            elif rule[0] == "hdr.ipv4.protocol":
                key_list[2][1] = rule[1]
                key_list[2][2] = rule[2]
    elif rule_list[0][0] in flow_filter3_items:
        table_name = "SwitchIngress.init.tb_flow_filter3"
        key_list = [
            ["hdr.tunnel.dst_id", 0, 0, "ternary"]
        ]
        for rule in rule_list:
            if rule[0] == "hdr.tunnel.dst_id":
                key_list[0][1] = rule[1]
                key_list[0][2] = rule[2]
    return [Entry(ast_node.pname, table_name, key_list, data_list)]


def get_entry_rpb(ast_node):
    """
    Get table entry for table tb_operation
    Arguments:
    - ast_node: AST Node
    """
    rpb_number = ((ast_node.stage-1) % rpb_size) + 1
    iterations = int((ast_node.stage - 1) / rpb_size)
    if 1 <= rpb_number <=10:
        prefix = "SwitchIngress.rpb"
    elif 11 <= rpb_number <= 22:
        prefix = "SwitchEgress.rpb"
    table_name = prefix + str(rpb_number) + ".tb_operation"
    key_list = [
        ["hdr.meta.id.flow_id", ast_node.flow_id, "exact"],
        ["hdr.meta.id.branch_id", ast_node.branch_id, "exact"],
        ["hdr.meta.rec.iterations", iterations, "exact"],
        ["hdr.meta.reg.mar", 0, 0, "ternary"],
        ["hdr.meta.reg.sar", 0, 0, "ternary"],
        ["hdr.meta.reg.har", 0, 0, "ternary"],
    ]
    data_list = []
    argument_list = []
    case_list = []

    if ast_node.name == "NOP":
        return []

    # parse primitive with no argument
    if re.match(re_primitive_without_argument, ast_node.name):
        data_list = [
            [],
            prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
        ]
        return [Entry(ast_node.pname, table_name, key_list, data_list)]
    # parse primitive with argument
    elif re.match(re_primitive_with_argument, ast_node.name):
        # get arguments
        s = Stack()
        s.push(ast_node)
        while not s.empty():
            node = s.pop()
            if node.type == "arguments" or node.type == "primitive":
                for c in reversed(node.children):
                    s.push(c)
            elif node.type == "argument":
                argument_list.append(node.data_value)
        if ast_node.name == "EXTRACT" or ast_node.name == "MODIFY":
            data_list = [
                [],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name].replace("<arg1>", argument_list[0].replace(".", "")).replace("<arg2>", argument_list[1])
            ]
        elif ast_node.name == "LOADI":
            data_list = [
                [["i", argument_list[1]]],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name].replace("<arg1>", argument_list[0])
            ]
        elif ast_node.name == "ADD" or ast_node.name == "AND" or ast_node.name == "OR" or ast_node.name =="XOR" or ast_node.name =="MAX" or ast_node.name =="MIN":
            data_list = [
                [],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name].replace("<arg1>", argument_list[0]).replace("<arg2>", argument_list[1])
            ]
        elif ast_node.name == "MEMADD" or ast_node.name == "MEMSUB" or ast_node.name == "MEMAND" or ast_node.name == "MEMOR" or ast_node.name == "MEMREAD" or ast_node.name == "MEMWRITE" or ast_node.name == "MEMMAX":
            data_list = [
                [],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
            ]
        elif ast_node.name == "FORWARD" or ast_node.name == "DROP" or ast_node.name == "REPORT":
            data_list = [
                [["port", argument_list[0]]],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
            ]
        elif ast_node.name == "mask":
            data_list = [
                [["mask", argument_list[0]]],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
            ]
        elif ast_node.name == "offset":
            data_list = [
                [["offset", argument_list[1]], ["flag", argument_list[0]]],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
            ]
        return [Entry(ast_node.pname, table_name, key_list, data_list)]
    elif ast_node.name == "BRANCH":
        res = []
        # get cases
        s = Stack()
        s.push(ast_node)
        while not s.empty():
            node = s.pop()
            if node.type == "cases" or node.type == "primitive":
                for c in reversed(node.children):
                    s.push(c)
            elif node.type == "case":
                case_list.append([node.condition, node.branch_id])
        for c in case_list:
            key_list = [
                ["hdr.meta.id.flow_id", ast_node.flow_id, "exact"],
                ["hdr.meta.id.branch_id", ast_node.branch_id, "exact"],
                ["hdr.meta.rec.iterations", iterations, "exact"],
                ["hdr.meta.reg.mar", 0, 0, "ternary"],
                ["hdr.meta.reg.sar", 0, 0, "ternary"],
                ["hdr.meta.reg.har", 0, 0, "ternary"],
            ]
            for condition in c[0]:
                if condition[0] == "mar":
                    key_list[3][1] = condition[1]
                    key_list[3][2] = condition[2]
                elif condition[0] == "sar":
                    key_list[4][1] = condition[1]
                    key_list[4][2] = condition[2]
                elif condition[0] == "har":
                    key_list[5][1] = condition[1]
                    key_list[5][2] = condition[2]
            data_list = [
                [["branch_id", c[1]]],
                prefix + str(rpb_number) + "." + primitive_action_mapping_dict[ast_node.name]
            ]
            res.append(Entry(ast_node.pname, table_name, key_list, data_list))
        return res
    return []


def get_entry_recirculation(pname, flow_id, iterations, flag):
    """
    Get table entry for table tb_recirculation
    Arguments:
    - flow_id, branch_id, iterations, flag
    """
    table_name = "SwitchIngress.rec.tb_recirculation"
    key_list = [
        ["hdr.meta.id.flow_id", flow_id, "exact"],
        ["hdr.meta.rec.iterations", iterations, "exact"]
    ]
    if flag == 0:
        action_name = "SwitchIngress.rec.first_recirculate"
    elif flag == 1:
        action_name = "SwitchIngress.rec.middle_recirculate"
    elif flag == 2:
        action_name = "SwitchIngress.rec.last_recirculate"
    else:
        return []
    data_list = [
        [],
        action_name
    ]
    return [Entry(pname, table_name, key_list, data_list)]