#!/usr/bin/env python2

import os
import sys
import binaryninja
import argparse
import json

def main():
    parser = argparse.ArgumentParser(
        description='extract cfg from ethersplay')
    parser.add_argument('--input', '-i', type=str, help='input evm file')
    parser.add_argument('--output', '-o', type=argparse.FileType('wb'), help='output cfg file (.json)')
    parser.add_argument('--verbosity', '-v', type=str, default="None",
                        help='log output verbosity (None,  Critical, Error, Warning, Info, Debug)')
    args = parser.parse_args()

    if args.input is None or args.output is None:
        parser.print_usage()
        sys.exit(1)

    bv = binaryninja.BinaryViewType["EVM"].open(args.input)
    bv.update_analysis_and_wait()


    edges = set()
    for function in bv.functions:
        for block in function:
            for edge in block.outgoing_edges:
                pair = (block.start, edge.target.start)
                edges.add(pair)

    args.output.write(json.dumps(list(edges)))
    print("[+] Wrote {} edges to {}".format(len(edges), args.output.name))

if __name__ == '__main__':
    main()