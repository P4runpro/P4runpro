# ------------------------------------------------------------
# ilp_solver.py
# Solve the ILP problem
# ------------------------------------------------------------

import gurobipy as grb

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

translation = [
    [4, 5]
]

max_rec_time = 5
ub = 5*22


def solve(max_slice_number, tb_not_ava, mem_not_ava, forward, max_rec_time=5, max_rpb_number=22, max_ingressrpb_number=10):
    model = grb.Model("P4runpro")
    x = model.addVars(max_slice_number, lb=0, ub=max_rpb_number*max_rec_time-1, vtype=grb.GRB.INTEGER, name="x")
    #m = model.addVar(lb=0, ub=max_rpb_number*max_rec_time-1, vtype=grb.GRB.INTEGER, name="m")
    y = model.addVars(max_rec_time, vtype=grb.GRB.BINARY, name="y")
    model.update()
    model.setObjective(x[max_slice_number-1], grb.GRB.MINIMIZE)

    # max linearization
    #for i in range(max_slice_number):
    #    model.addConstr(x[i] <= m)

    # aligning is accomplished by analyzer

    # dependency
    i = 0
    while i < max_slice_number-1:
        model.addConstr(x[i] <= x[i+1] - 1)
        i = i + 1

    # table entry constrains
    for i in range(max_slice_number):
        ls = tb_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                model.addConstr(x[i] != j + max_rpb_number*k)

    # memory constrains
    for i in range(max_slice_number):
        ls = mem_not_ava[i]
        for j in ls:
            for k in range(max_rec_time):
                model.addConstr(x[i] != j + max_rpb_number*k)

    # forward
    for j in forward:
        model.addConstr(sum(max_rpb_number*i*y[i] for i in range(max_rec_time)) <= x[j])
        model.addConstr(x[j] <= sum(max_ingressrpb_number-1 + max_rpb_number*i*y[i] for i in range(max_rec_time)))
    model.addConstr(sum(y[i] for i in range(max_rec_time)) == 1)

    # translation
    #for t in translation:
    #    model.addConstr(x[t[1]] - x[t[0]] >= 2)

    model.Params.LogToConsole = False
    model.Params.TimeLimit = 100

    model.optimize()

    suc = False
    if model.status == grb.GRB.OPTIMAL:
        suc = True

    if suc:
        vals = []
        for var in model.getVars():
            if var.VarName[0] == "x":
                vals.append(int(var.X)+1)
        return suc, int(model.objVal+1), vals
    else:
        return suc ,None, None


if __name__ == "__main__":
    logical_stage, vals = solve(8, tb_not_ava, mem_not_ava, forward, translation)
    print(logical_stage)
    print(vals)



