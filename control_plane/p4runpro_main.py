# -*- coding:UTF-8 -*-
import sys
import traceback
import time
import cmd
from myparser import parser
from analyzer import *
from utils import *
from resource_manager import Manager
from mycompiler import *
#from ilp_solver import *
from smt_solver import *
from runtime import *

class ArgParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super(ArgParser, self).__init__(*args, **kwargs)

        self.error_message = ''

    def error(self, message):
        self.error_message = message

    def parse_args(self, *args, **kwargs):
        # catch SystemExit exception to prevent closing the application
        result = None
        try:
            result = super(ArgParser, self).parse_args(*args, **kwargs)
        except SystemExit:
            pass
        return result

class P4runproController(cmd.Cmd):
    intro = """
    P4runpro controller start!!
    """
    prompt = 'P4runpro> '

    def __init__(self, config_file = 'config.json'):
        cmd.Cmd.__init__(self)
        try:
            self.rt = bfrt_runtime(0, "p4runpro")
            self.manager = Manager()
        except Exception as e:
            print(traceback.format_exc())
            exit(1)

    def emptyline(self):
        pass
    
    def do_exit(self, line):
        print("")
        exit(0)

    def do_deploy(self, arg):
        """ parse a p4runpro program
        Args:
            "-f", "--file" : p4runpro program path
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-f", "--file", dest="file", type=str, required=True, help="e.g., ./cache.p4runpro")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return
            f = open(input, args.file)
            program = f.read()
            f.close()
            compile(self.rt, self.manager, program)
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
        
    def do_revoke(self, arg):
        """ parse a primitive file
        Args:
            "-p", "--program" : p4runpro program name
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-p", "--program", dest="program", type=str, required=True, help="e.g., cache")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return
            revoke(self.manager, self.rt, args.program)
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None

    def do_add_froward(self, arg):
        """ parse a primitive file
        Args:
            "-ip", "--ingress_port" : ingress port number
            "-ep", "--egress_port"    : egress port number
        Returns:
            None
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-ip", "--ingress_port", dest="ingress_port", type=int, required=True, default="", help="a int number")
        parser.add_argument("-ep", "--egress_port", dest="egress_port", type=int, required=True, help="a int number")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return

            self.rt.entry_add("SwitchIngress.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]], [[["port", int(args.egress_port)]], "SwitchIngress.forward"])

            return None

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None

    def do_del_froward(self, arg):
        """ parse a primitive file
        Args:
            "-ip", "--ingress_port" : ingress port number
        Returns:
            None
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-ip", "--ingress_port", dest="ingress_port", type=int, required=True, default="", help="a int number")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return

            self.rt.entry_del("SwitchIngress.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]])

            return None

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
    
    def do_clear_all(self, arg):
        #TODO: 1 step to reset all
        pass


if __name__ == "__main__":
    P4runproController().cmdloop()