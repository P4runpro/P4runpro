# -*- coding:UTF-8 -*-
import sys
import traceback
import time
import cmd
import argparse
import os
import random


from myparser import parser
from analyzer import *
from utils import *
from resource_manager import Manager
from mycompiler import *
from ilp_solver import *
#from smt_solver import *
from runtime import *

#for evaluation
programs = [
    "BF.p4runpro",
    "CMS.p4runpro",
    "HeavyHitter.p4runpro",
    "L3Routing.p4runpro", 
    "StatefulFirewall.p4runpro",
    "Cache.p4runpro",        
    "DQAcc.p4runpro",  
    "HLL.p4runpro",           
    "LoadBalancer.p4runpro",  
    "SuMax.p4runpro",
    "Calculation.p4runpro",  
    "ECN.p4runpro",    
    "L2Forwarding.p4runpro",
    "NetCache.p4runpro",      
    "Tunnel.p4runpro"
]

program_names = [
    ["bf"],
    ["cms"],
    ["heavyhitter"],
    ["l3routing_rule1", "l3routing_rule2"], 
    ["statefulfirewall"],
    ["cache"],
    ["databasequeryacceleration"],
    ["hll"],
    ["loadbanlancer"],
    ["sumax"],
    ["calculation"],
    ["ecn"],
    ["l2forwarding_rule1", "l2forwarding_rule2"],
    ["netcache"],
    ["tunnel_rule1", "tunnel_rule2"]
]

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
----------P4runpro controller starts!!----------
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

    def do_show(self, line):
        """ show allocated p4runpro program
        Args:
        Exceptions:
            parser error
        """
        try:
            self.manager.show_programs()
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
        

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
            f = open(args.file, 'r')
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
            revoke(self.rt, self.manager, args.program)
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

            self.rt.entry_add("SwitchIngress.init.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]], [[["port", int(args.egress_port)]], "SwitchIngress.init.forward"])

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

            self.rt.entry_del("SwitchIngress.init.tb_forward", [["ig_intr_md.ingress_port", int(args.ingress_port), "exact"]])

            return None

        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None
    
    def do_case_study_random_deploy(self, arg):
        """ perform the process of random deployment and revoking
        Args:
            "-p", "--path": p4runpro programs's folder path
            "-c", "--count": iteration count
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-p", "--path", dest="path", type=str, required=True, help="e.g., ./programs")
        parser.add_argument("-c", "--count", dest="count", type=int, required=True, help="e.g., 30")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return
            c = 0
            while c < args.count:
                pid = random.randint(0, 14)
                if self.manager.check_existence(program_names[pid][0]):
                    for pname in program_names[pid]:
                        revoke(self.rt, self.manager, pname)
                else:
                    f = open(os.path.join(args.path, programs[pid]), 'r')
                    program = f.read()
                    f.close()
                    compile(self.rt, self.manager, program)
                print("\n")
                time.sleep(0.5)
                c = c + 1
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None

    def do_evaluate_update_delay(self, arg):
        """ evaluate_the_update_delay
        Args:
            "-p", "--path": p4runpro programs's folder path
        Exceptions:
            parser error
        """

        parser = ArgParser()
        parser.add_argument("-p", "--path", dest="path", type=str, required=True, help="e.g., ./programs")

        try:
            args = parser.parse_args(arg.split())
            if parser.error_message or args is None:
                print(parser.error_message)
                return
            for i in range(15):
                f = open(os.path.join(args.path, programs[i]), 'r')
                program = f.read()
                f.close()
                pnames = program_names[i]
                t = compile(self.rt, self.manager, program, eval=True)
                print("update delay of program \"" + programs[i] + "\": " + str(t) + "ms")
        except Exception as e:
            print(traceback.format_exc())
            print(e)
            return None



    def do_clear_all(self, arg):
        #TODO: 1 step to reset all
        pass


if __name__ == "__main__":
    P4runproController().cmdloop()