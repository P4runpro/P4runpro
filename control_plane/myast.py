__metaclass__ = type
# ------------------------------------------------------------
# myast.py
# ast node of P4runpro primitive parser
# ------------------------------------------------------------
Node_type_list = [
    "start",
    "annotations",
    "annotation",
    "programs",
    "program",
    "rules",
    "rule",
    "primitives",
    "primitive",
    "arguments",
    "argument",
    "cases",
    "case",
    "condition"
    "empty",
]


class Node:
    """
    General ast node class
    Member variables:
    - type: ast node type
    - value: ast node value, different meaning for different type
    - children: ast node children list
    - variables below are attributes set when traverse the ast instead of building the ast
    - depth: ast node depth
    - stage: primitive stage number
    - pname: program name
    - branch_id: branch id
    - flow_id:  flow id
    """
    def __init__(self, type, value, children=None):
        self.type = type
        self.value = value
        if children is None:
            self.children = []
        else:
            self.children = children
        self.depth = -1
        self.stage = -1
        self.pname = ""
        self.branch_id = -1
        self.flow_id = -1


class Annotation(Node):
    """
    Annotation node class
    Member variables:
    - identifier: annotation node identifier
    - int: annotation node int
    """
    def __init__(self, type, value, children, identifier, integer):
        super(Annotation, self).__init__(type, value, children)
        self.identifier = identifier
        self.integer = integer


class Program(Node):
    """
    Program node class
    Member variables:
    - name: program name
    """
    def __init__(self, type, value, children, name):
        super(Program, self).__init__(type, value, children)
        self.name = name


class Primitive(Node):
    """
    Primitive node class
    Member variables:
    - name: primitive name
    - has_arg: True if this primitive has arguments
    """
    def __init__(self, type, value, children, name, has_arg=False, case_num=0):
        super(Primitive, self).__init__(type, value, children)
        self.name = name
        self.has_arg = has_arg
        self.case_num = case_num
        self.mem_size = 0
        self.mem_name = 0
        self.last_pri = False
        self.pop_num = 1


class Argument(Node):
    """
    Argument node class
    Member variables:
    - data_type: argument data type
    - data_value: argument data value
    """
    def __init__(self, type, value, children, data_type, data_value):
        super(Argument, self).__init__(type, value, children)
        self.data_type = data_type
        self.data_value = data_value


class Case(Node):
    """
    Case node class
    Member variables:
    - condition: condition list of 2 condition tuple
    - last_case
    """
    def __init__(self, type, value, children, condition):
        super(Case, self).__init__(type, value, children)
        self.condition = condition
        self.first_case = False
        self.last_case = False
        self.fbranch_id = -1

class Condition(Node):
    """
    Condition node class
    Member variables:
    - condition: condition list of 2 condition tuple
    - last_case
    """
    def __init__(self, type, value, children, condition):
        super(Condition, self).__init__(type, value, children)
        self.condition = condition


class Rule(Node):
    """
    Rule node class
    Member variables:
    - rule: filtering rule tuple
    """
    def __init__(self, type, value, children, rule):
        super(Rule, self).__init__(type, value, children)
        self.rule = rule
