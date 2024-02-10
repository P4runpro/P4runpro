# ------------------------------------------------------------
# myscanner.py
# tokenizer for P4runpro primitive parser
# ------------------------------------------------------------
import ply.lex as lex
from utils import *

# List of token names.   This is always required
tokens = (
   'ANNOTATION',
   'PROGRAM',
   'IDENTIFIER',
   'FIELD',
   'ADDRESS',
   'REGISTER',
   'INT',
   'PRIMITIVE',
   'PRIMITIVE_NO_ARG',
   'PRIMITIVE_BRANCH',
   'CASE',
   'LESSTHAN',
   'MORETHAN',
   'SEMICOLON',
   'COLON',
   'COMMA',
   'LBRACE',
   'RBRACE',
   'LPAREN',
   'RPAREN',
)

# Regular expression rules for simple tokens
t_ANNOTATION = r'@'
t_LESSTHAN = r'\<'
t_MORETHAN = r'\>'
t_SEMICOLON = r'\;'
t_COLON = r'\:'
t_COMMA = r','
t_LBRACE = r'\{'
t_RBRACE = r'\}'
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_ignore = ' \t'


def t_ADDRESS(t):
    r'((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)'
    t.value = ("address", ip_to_int(t.value))
    return t


def t_INT(t):
    r'0[Bb][01]+|0[Xx][0-9a-fA-F]+|\d+'
    t.value = ("int", sys_convert(t.value))
    return t

def t_PROGRAM(t):
    r'program'
    return t

def t_CASE(t):
    r'case'
    return t

def t_PRIMITIVE(t):
    r'(ADD|SUB|AND|OR|XOR)I|EXTRACT|MODIFY|LOADI|ADD|AND|OR|XOR|MAX|MIN|MEM(ADD|SUB|AND|OR|READ|WRITE|MAX)|FORWARD|MOVE|SUB|NOT|SLT|SGT|HASH_5_TUPLE_MEM|HASH_MEM'
    return t

def t_PRIMITIVE_NO_ARG(t):
    r'HASH_5_TUPLE|HASH|DROP|RETURN|REPORT|NOP'
    return t

def t_PRIMITIVE_BRANCH(t):
    r'BRANCH'
    return t

def t_REGISTER(t):
    r'har|mar|sar'
    t.value = ("register", t.value)
    return t

def t_FIELD(t):
    r'([A-Za-z][_0-9A-Za-z]*\.)+([A-Za-z][_0-9A-Za-z]*)'
    t.value = ("field", t.value)
    return t

def t_IDENTIFIER(t):
    r'[A-Za-z][_0-9A-Za-z]*'
    t.value = ("identifier", t.value)
    return t

def t_ignore_COMMET(t):
    r'\#.*'
    pass


def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)


def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)


lexer = lex.lex(optimzie=1)

if __name__ == "__main__":
    lexer.input("0xfffff")
    while True:
        tok = lexer.token()
        if not tok:
            break
        print(tok)