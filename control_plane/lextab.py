# lextab.py. This file automatically created by PLY (version 3.11). Don't edit!
_tabversion   = '3.10'
_lextokens    = set(('ADDRESS', 'ANNOTATION', 'CASE', 'COLON', 'COMMA', 'FIELD', 'IDENTIFIER', 'INT', 'LBRACE', 'LESSTHAN', 'LPAREN', 'MORETHAN', 'PRIMITIVE', 'PRIMITIVE_BRANCH', 'PRIMITIVE_NO_ARG', 'PROGRAM', 'RBRACE', 'REGISTER', 'RPAREN', 'SEMICOLON'))
_lexreflags   = 64
_lexliterals  = ''
_lexstateinfo = {'INITIAL': 'inclusive'}
_lexstatere   = {'INITIAL': [('(?P<t_ADDRESS>((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d))|(?P<t_INT>0[Bb][01]+|0[Xx][0-9a-fA-F]+|\\d+)|(?P<t_PROGRAM>program)|(?P<t_CASE>case)|(?P<t_PRIMITIVE>(ADD|SUB|AND|OR|XOR)I|EXTRACT|MODIFY|LOADI|ADD|AND|OR|XOR|MAX|MIN|MEM(ADD|SUB|AND|OR|READ|WRITE|MAX)|FORWARD|MOVE|SUB|NOT|SLT|SGT|HASH_5_TUPLE_MEM|HASH_MEM)|(?P<t_PRIMITIVE_NO_ARG>HASH_5_TUPLE|HASH|DROP|RETURN|REPORT|NOP)|(?P<t_PRIMITIVE_BRANCH>BRANCH)|(?P<t_REGISTER>har|mar|sar)|(?P<t_FIELD>([A-Za-z][_0-9A-Za-z]*\\.)+([A-Za-z][_0-9A-Za-z]*))|(?P<t_IDENTIFIER>[A-Za-z][_0-9A-Za-z]*)|(?P<t_ignore_COMMET>\\#.*)|(?P<t_newline>\\n+)|(?P<t_LBRACE>\\{)|(?P<t_RBRACE>\\})|(?P<t_SEMICOLON>\\;)|(?P<t_COLON>\\:)|(?P<t_RPAREN>\\))|(?P<t_LESSTHAN>\\<)|(?P<t_LPAREN>\\()|(?P<t_MORETHAN>\\>)|(?P<t_ANNOTATION>@)|(?P<t_COMMA>,)', [None, ('t_ADDRESS', 'ADDRESS'), None, None, None, ('t_INT', 'INT'), ('t_PROGRAM', 'PROGRAM'), ('t_CASE', 'CASE'), ('t_PRIMITIVE', 'PRIMITIVE'), None, None, ('t_PRIMITIVE_NO_ARG', 'PRIMITIVE_NO_ARG'), ('t_PRIMITIVE_BRANCH', 'PRIMITIVE_BRANCH'), ('t_REGISTER', 'REGISTER'), ('t_FIELD', 'FIELD'), None, None, ('t_IDENTIFIER', 'IDENTIFIER'), ('t_ignore_COMMET', 'ignore_COMMET'), ('t_newline', 'newline'), (None, 'LBRACE'), (None, 'RBRACE'), (None, 'SEMICOLON'), (None, 'COLON'), (None, 'RPAREN'), (None, 'LESSTHAN'), (None, 'LPAREN'), (None, 'MORETHAN'), (None, 'ANNOTATION'), (None, 'COMMA')])]}
_lexstateignore = {'INITIAL': ' \t'}
_lexstateerrorf = {'INITIAL': 't_error'}
_lexstateeoff = {}
