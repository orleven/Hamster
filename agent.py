#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from argparse import ArgumentParser
from lib.core.core import start_agent

def arg_set(parser):
    parser.add_argument('-sh', "--server-host", action='store', help='Server address', type=str)
    parser.add_argument('-sp', "--server-port", action='store', help='Server port',  type=int)
    parser.add_argument('-ph', "--support-host", action='store', help='Support address', type=str)
    parser.add_argument('-pp', "--support-port", action='store', help='Support port', type=int)
    parser.add_argument("-d", "--debug", action='store_true', help="Run debug", default=False)
    parser.add_argument("-h", "--help", action='store_true', help="Show help", default=False)
    return parser

if __name__ == '__main__':
    parser = ArgumentParser(add_help=False)
    parser = arg_set(parser)
    args = parser.parse_args()
    if args.help:
        parser.print_help()
    else:
        start_agent(args)