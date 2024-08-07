# ------------------------------------------------------------
# resource_manager.py
# manage the data palne resources including register and table entries
# ------------------------------------------------------------

from myast import *
from utils import *


class Manager:
    """
    P4runpro resource manager, managing the regiser and table entries per stage
    Member variables:
    - register_size
    - table_size
    - register_usage
    - table_usage
    """

    def __init__(self, register_size=65536, table_size=512):
        self.register_size = register_size
        self.table_size = table_size

        self.flow_id_pool_available = set([i for i in range(1,65536)])

        self.register_pool_available = {}
        for i in range(1, 23):
            self.register_pool_available['rpb' + str(i)] = Chain([0, register_size])
        self.table_pool_available = {'rpb' + str(i): self.table_size for i in range(1, 23)}

        self.allocated_program = {}
        self.allocated_program_entry = {}

    def allocate_program(self, program_name, table_entry_requirement, memory_requirement, flow_id):
        offsets = [-1 for i in range(22)]
        if program_name in self.allocated_program.keys():
            print("Error: duplicated program name")
            exit()
        else:
            self.allocated_program[program_name] = (table_entry_requirement, memory_requirement, flow_id)
            self.allocated_program_entry[program_name] = []
            for i in range(1, 23):
                self.table_pool_available["rpb" + str(i)] = self.table_pool_available["rpb" + str(i)] - table_entry_requirement[i-1]
            for i in range(1, 23):
                offsets[i-1] = self.register_pool_available["rpb" + str(i)].require(memory_requirement[i-1])
        return offsets

    def delete_program(self, program_name):
        if program_name not in self.allocated_program.keys():
            return
        else:
            for i in range(1, 23):
                self.table_pool_available["rpb" + str(i)] = self.table_pool_available["rpb" + str(i)] + self.allocated_program[program_name][0][i-1]
            for i in range(1, 23):
                self.register_pool_available["rpb" + str(i)].add(self.allocated_program[program_name][1][i-1])
            self.flow_id_pool_available.add(self.allocated_program[program_name][2])
            self.allocated_program.pop(program_name)

    def get_flow_id(self):
        if self.flow_id_pool_available:
            return self.flow_id_pool_available.pop()
        else:
            print("Error: flow id is run out")
            exit()

    def get_table_available(self):
        return [self.table_pool_available["rpb" + str(i)] for i in range(1, 23)]

    def get_mem_available(self):
        return [self.register_pool_available["rpb" + str(i)].get_max_range() for i in range(1, 23)]
    
    def get_mem_all(self):
        return [self.register_pool_available["rpb" + str(i)].get_all_range() for i in range(1, 23)]
    
    def entry_allocated(self, e):
        self.allocated_program_entry[e.entry["program"]].append(e)

    def clear_if_exist(self, p):
        if p in self.allocated_program_entry.keys():
            self.allocated_program_entry[p] *= 0
        if p in self.allocated_program.keys():
            self.allocated_program.pop(p)

    def get_allocated_program_entry(self, p):
        if p not in self.allocated_program_entry.keys():
            return None
        else:
            return self.allocated_program_entry[p]

    def show_programs(self):
        print("Existing programs:")
        for pname in self.allocated_program.keys():
            print(pname)

    def check_existence(self, pname):
        #print(pname)
        #print(self.allocated_program.keys())
        if pname in self.allocated_program.keys():
            return True
        return False