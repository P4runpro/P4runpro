# ------------------------------------------------------------
# myparser.py
# Analyze the syntax and semantics of P4runpro primitive
# ------------------------------------------------------------
import ply.yacc as yacc
from myscanner import tokens
from utils import *
from myast import *


def p_start(p):
    'start : annotations programs'
    p[0] = Node("start", 1, [p[1], p[2]])

def p_annotations(p):
    '''annotations : annotation
                   | annotations annotation'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 3:
        p[0] = Node("annotations", p[1].value + p[2].value, [p[1], p[2]])

def p_annotation(p):
    '''annotation : empty
                  | ANNOTATION IDENTIFIER INT'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 4:
        p[0] = Annotation("annotation", 1, None, p[2][1], p[3][1])
    # TODO: type check

def p_prgrams(p):
    '''programs : program
                | programs program'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 3:
        p[0] = Node("programs", p[1].value + p[2].value, [p[1], p[2]])

def p_program(p):
    '''program : PROGRAM IDENTIFIER LPAREN rules RPAREN LBRACE primitives RBRACE'''
    p[0] = Program("program", 1, [p[4], p[7]], p[2][1])

def p_rules(p):
    '''rules : rule
             | rules COMMA rule'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 4:
        p[0] = Node("rules", p[1].value + p[3].value, [p[1], p[3]])

def p_rule(p):
    '''rule : empty
            | LESSTHAN FIELD COMMA ADDRESS COMMA INT MORETHAN
            | LESSTHAN FIELD COMMA INT COMMA INT MORETHAN'''
    if len(p) == 2:
        p[0] = p[1]
    elif p[4][0] == "address":
        p[0] = Rule("rule", 1, None, (p[2][1], p[4][1], p[6][1]))
    elif p[4][0] == "int":
        p[0] = Rule("rule", 1, None, (p[2][1], p[4][1], p[6][1]))
    # TODO check rule

def p_primitives(p):
    '''primitives : primitive
                  | primitives primitive'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 3:
        p[0] = Node("primitives", p[1].value + p[2].value, [p[1], p[2]])

def p_primitive(p):
    '''primitive : PRIMITIVE LPAREN arguments RPAREN SEMICOLON
                 | PRIMITIVE_NO_ARG SEMICOLON
                 | PRIMITIVE_BRANCH COLON cases SEMICOLON'''
    if len(p) == 3:
        p[0] = Primitive("primitive", 1, None, p[1], False)
    elif len(p) == 6:
        p[0] = Primitive("primitive", 1, [p[3]], p[1], True)
    elif len(p) == 5:
        p[0] = Primitive("primitive", p[3].value[0] + 1, [p[3]], p[1], False, p[3].value[1])
    #TODO check arguments

def p_arguments(p):
    '''arguments : argument
                 | arguments COMMA argument'''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 4:
        p[0] = Node("arguments", p[1].value + p[3].value, [p[1], p[3]])

def p_argument(p):
    '''argument : IDENTIFIER
                | FIELD
                | ADDRESS
                | REGISTER
                | INT'''
    p[0] = Argument("argument", 1, None, p[1][0], p[1][1])

def p_cases(p):
    '''cases : case
             | cases case'''
    if len(p) == 2:
        p[0] = p[1]
        p[0].first_case = True
    elif len(p) == 3:
        p[0] = Node("cases", (p[1].value[0] + p[2].value[0], p[1].value[1] + p[2].value[1]), [p[1], p[2]])

def p_case(p):
    '''case : CASE LPAREN condition RPAREN LBRACE primitives RBRACE
            | CASE LPAREN condition COMMA condition RPAREN LBRACE primitives RBRACE
            | CASE LPAREN condition COMMA condition COMMA condition RPAREN LBRACE primitives RBRACE'''
    if len(p) == 8:
        p[0] = Case("case", (p[6].value, 1), [p[6]], [p[3].condition])
    elif len(p) == 10:
        p[0] = Case("case", (p[8].value, 1), [p[8]], [p[3].condition, p[5].condition])
    elif len(p) == 12:
        p[0] = Case("case", (p[10].value, 1), [p[10]], [p[3].condition, p[5].condition, p[7].condition])

def p_condition(p):
    'condition : LESSTHAN REGISTER COMMA INT COMMA INT MORETHAN'
    p[0] = Condition("condition", 1, [], (p[2][1], p[4][1], p[6][1]))

def p_empty(p):
    'empty :'
    p[0] = Node("empty", 0, None)

def p_error(p):
    if p is None:
        print("Syntax error at the end of the program")
    else:
        print("Line: " + str(p.lineno) + ", position: " + str(p.lexpos) + ", syntax error at token " + str(p.value))


parser = yacc.yacc()
