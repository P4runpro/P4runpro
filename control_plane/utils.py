# ------------------------------------------------------------
# lex.py
# utils
# ------------------------------------------------------------


def ip_to_int(ip):
    """
    covert ip address to int value
    Args:
    - ip: ipv4 address string
    """
    ls = ip.split('.')
    return int(ls[0])*2**24 + int(ls[1])*2**16 + int(ls[2])*2**8 + int(ls[3])*2**0


def sys_convert(numstr):
    """
    covert a binary and hexadecimal number string to int value
    Args:
    - numstr: number string
    """
    if numstr[0:2] == "0x":
        return int(numstr[2:], 16)
    elif numstr[0:2] == "0b":
        return int(numstr[2:], 2)
    else:
        return int(numstr)


def size_to_mask(size):
    for i in range(17):
        if int(size/(2**i)) == 1:
            res = 0
            for j in range(i):
                res = res + 2**j
            return res
    return 0


class Stack(object):
    def __init__(self):
        """
        class to implement stack
        """
        self.stack = []

    def push(self, data):
        self.stack.append(data)

    def pop(self):
        if self.stack:
            return self.stack.pop()
        else:
            raise IndexError("Can't pop a element in an empty stack")

    def top(self):
        if self.stack:
            return self.stack[-1]
        else:
            raise IndexError("can't get the top element in an empty stack")

    def empty(self):
        return not bool(self.stack)

    def size(self):
        return len(self.stack)


class ChainNode(object):
    def __init__(self, prec=None, succ=None, value=None):
        """
        class to implement chain node
        """
        self.prec = prec
        self.succ = succ
        self.value = value
        self.is_header = False
        self.is_tail = False


class Chain(object):
    def __init__(self,value):
        """
        class to implement sorted chain
        """
        node = ChainNode(None, None, value)
        self.header = ChainNode(None, node)
        self.header.is_header = True
        self.tail = ChainNode(node, None)
        self.tail.is_tail = True
        node.succ = self.tail
        node.prec = self.header

    def require(self, r):
        if r <= 0:
            return -1
        p1 = self.header.succ
        while not p1.is_tail:
            if p1.value[1]-p1.value[0] > r:
                p1.value[0] = p1.value[0] + r
                return p1.value[0] - r
            elif p1.value[1]-p1.value[0] == r:
                p1.prec.succ = p1.succ
                p1.succ.prec = p1.prec
                return p1.value[0]
            p1 = p1.succ
        return -1
    
    def show(self):
        p1 = self.header.succ
        if p1.is_tail:
            print(None)
            return
        while not p1.is_tail:
            print(str(p1.value))
            p1 = p1.succ
        return

    def free(self, size, offset):
        p1 = self.header.succ
        if p1.is_tail:
            new_node = ChainNode(self.header, self.tail, [offset, offset + size])
            self.header.succ = new_node
            self.tail.prec = new_node
            return True
        while not p1.is_tail:
            if p1.value[0] > offset + size:
                new_node = ChainNode(p1.prec, p1, [offset, offset + size])
                p1.prec = new_node
                return True
            if p1.value[0] == offset + size:
                p1.value[0] = offset
                return True
            p1 = p1.succ

    def add(self, r):
        if len(r) == 0:
            return True
        p1 = self.header.succ
        if p1.is_tail:
            new_node = ChainNode(self.header, self.tail, r)
            self.header.succ = new_node
            self.tail.prec = new_node
            return True
        while not p1.is_tail:
            p2 = p1.succ
            if p1.prec.is_header:
                if r[1] < p1.value[0]:
                    new_node = ChainNode(p1.prec, p1, r)
                    p1.prec = new_node
                    return True
                elif r[1] == p1.value[0]:
                    p1.value[0] = r[0]
                    return True
            elif p2.is_tail:
                if r[0] > p1.value[1]:
                    new_node = ChainNode(p1, p2, r)
                    p1.succ = new_node
                    return True
                elif r[0] == p1.value[1]:
                    p1.value[1] = r[1]
                    return True
            else:
                if p1.value[1] < r[0] and r[1] < p2.value[0]:
                    new_node = ChainNode(p1, p2, r)
                    p1.succ = new_node
                    p2.prec = new_node
                    return True
                elif p1.value[1] == r[0] and r[1] == p2.value[0]:
                    p1.succ = p2.succ
                    p1.value[1] = p2.value[1]
                    return True
                elif p1.value[1] == r[0] and r[1] < p2.value[0]:
                    p1.value[1] = r[1]
                    return True
                elif p1.value[1] < r[0] and r[1] == p2.value[0]:
                    p2.value[0] = r[0]
                    return True
            p1 = p2
        return False

    def get_max_range(self):
        res = 0
        p1 = self.header.succ
        while not p1.is_tail:
            if p1.value[1] - p1.value[0] > res:
                res = p1.value[1] - p1.value[0]
            p1 = p1.succ
        return res
    
    def get_all_range(self):
        res = 0
        p1 = self.header.succ
        while not p1.is_tail:
            res = res + p1.value[1] - p1.value[0]
            p1 = p1.succ
        return res


def get_supportive_reg(reg_name_ls):
    all = ["har", "sar", "mar"]
    for reg in reg_name_ls:
        if reg in all:
            all.remove(reg)
    if all:
        return all[0]
    return None

def type_check(type_list, check_list):
    if len(type_list) != len(check_list):
        return False
    for i in range(len(type_list)):
        if type_list[i] != check_list[i]:
            return False
    return True

if __name__ == "__main__":
    print(size_to_mask(1024))
