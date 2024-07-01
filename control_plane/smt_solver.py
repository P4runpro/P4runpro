# ------------------------------------------------------------
# ilp_solver.py
# Solve the SMT problem
# ------------------------------------------------------------

import sys
from z3 import *


# used for debug


tb_not_ava = [
    [],
    [],
    [],
    [],
    [],
    [],
    [],
    []
]

mem_not_ava = [
    [],
    [],
    [],
    [],
    [],
    [],
    [],
    []
]


forward = [6, 7]


max_rec_time = 5
ub = 5*22


def solve(max_slice_number, tb_not_ava, mem_not_ava, forward, max_rec_time=2, max_rpb_number=22, max_ingressrpb_number=10, optimize=3, a=0.7, b=0.3):
    x = [Int("x" + str(i)) for i in range(max_slice_number)]

    solver = Optimize()

    min_constrain = [x[i] >= 0 for i in range(max_slice_number)]
    solver.add(And(*min_constrain))

    max_constrain = [x[i] <= max_rec_time*max_rpb_number-1 for i in range(max_slice_number)]
    solver.add(And(*max_constrain))

    dep_constrain = [x[i] <= x[i+1]-1 for i in range(max_slice_number-1)]
    solver.add(And(*dep_constrain))

    # table entry constrains
    for i in range(max_slice_number):
        ls = tb_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                solver.add(x[i] != j + max_rpb_number*k)

    # memory constrains
    for i in range(max_slice_number):
        ls = mem_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                solver.add(x[i] != j + max_rpb_number*k)

    # forward
    forward_constrains = []
    for j in forward:
        forward_or_constrains = [And(x[j]>= max_rpb_number*i, x[j] <= max_ingressrpb_number-1 + max_rpb_number*i) for i in range(max_rec_time)]
        forward_constrains.append(Or(*forward_or_constrains))
        solver.add(And(*forward_constrains))

    if optimize == 1:
        objective = x[max_slice_number-1]

    if optimize == 2:
        if max_slice_number == 1:
            objective = x[max_slice_number-1]
        objective = (x[max_slice_number-1] + 1)/(x[0] + 1)

    if optimize == 3:
        if max_slice_number == 1:
            objective = x[max_slice_number-1]
        objective = a*x[max_slice_number-1]-b*x[0]
    
    if optimize == 4:
        objective = x[max_slice_number-1]

    solver.minimize(objective)

    max_stgae_number = 0

    if solver.check() == sat:
        m = solver.model()
        max_stgae_number = m[x[max_slice_number-1]].as_long()
        if optimize != 4:
            return True, m[x[max_slice_number-1]].as_long() + 1, [m[i].as_long()+1 for i in x] 
    else:
        return False, None, None
    
    l2solver = Optimize()

    min_constrain = [x[i] >= 0 for i in range(max_slice_number-1)]
    l2solver.add(And(*min_constrain))

    max_constrain = [x[i] <= max_stgae_number-1 for i in range(max_slice_number-1)]
    l2solver.add(And(*max_constrain))

    dep_constrain = [x[i] <= x[i+1]-1 for i in range(max_slice_number-2)]
    l2solver.add(And(*dep_constrain))

    # table entry constrains
    for i in range(max_slice_number-1):
        ls = tb_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                l2solver.add(x[i] != j + max_rpb_number*k)

    # memory constrains
    for i in range(max_slice_number-1):
        ls = mem_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                l2solver.add(x[i] != j + max_rpb_number*k)

    # forward
    forward_constrains = []
    for j in forward:
        forward_or_constrains = [And(x[j]>= max_rpb_number*i, x[j] <= max_ingressrpb_number-1 + max_rpb_number*i) for i in range(max_rec_time)]
        forward_constrains.append(Or(*forward_or_constrains))
        l2solver.add(And(*forward_constrains))

    objective = x[0]

    l2solver.maximize(objective)

    if l2solver.check() == sat:
        m2= l2solver.model()
        return True, max_stgae_number + 1, [m2[x[i]].as_long()+1 for i in range(len(x)-1)] + [max_stgae_number + 1]
    else:
        return False, None, None



if __name__ == "__main__":
    solve(8, tb_not_ava, mem_not_ava, forward)