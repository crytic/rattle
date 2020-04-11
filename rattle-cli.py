#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile

import rattle

# This might not be true, but I have a habit of running the wrong python version and this is to save me frustration
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)

logger = logging.getLogger(__name__)


def main() -> None:  # run me with python3, fool
    parser = argparse.ArgumentParser(
        description='rattle ethereum evm binary analysis')
    parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
    parser.add_argument('--optimize', '-O', action='store_true', help='optimize resulting SSA form')
    parser.add_argument('--no-split-functions', '-nsf', action='store_false', help='split functions')
    parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout,
                        help='log output file (default stdout)')
    parser.add_argument('--verbosity', '-v', type=str, default="None",
                        help='log output verbosity (None,  Critical, Error, Warning, Info, Debug)')
    parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('rb'), default=None, help='optional cfg file')
    args = parser.parse_args()

    if args.input is None:
        parser.print_usage()
        sys.exit(1)

    edges = []
    if args.supplemental_cfg_file:
        edges = json.loads(args.supplemental_cfg_file.read())

    try:
        loglevel = getattr(logging, args.verbosity.upper())
    except AttributeError:
        loglevel = None

    logging.basicConfig(stream=args.log, level=loglevel)
    logger.info(f"Rattle running on input: {args.input.name}")

    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
                         split_functions=args.no_split_functions)

    print(ssa)

    print("Identified Functions:")
    for function in ssa.functions:
        print(f'\t{function.desc()} argument offsets:{function.arguments()}')

    print("")

    print("Storage Locations: " + repr(ssa.storage))
    print("Memory Locations: " + repr(ssa.memory))

    for location in [x for x in ssa.memory if x > 0x20]:
        print(f"Analyzing Memory Location: {location}\n")
        for insn in ssa.memory_at(location):
            print(f'\t{insn.offset:#x}: {insn}')
        print('\n\n')

    for function in ssa.functions:
        print(f"Function {function.desc()} storage:")
        for location in function.storage:
            print(f"\tAnalyzing Storage Location: {location}")
            for insn in ssa.storage_at(location):
                print(f'\t\t{insn.offset:#x}: {insn}')
            print('\n')

    '''
    print("Tracing SLOAD(0) (ignoring ANDs)")
    for insn in ssa.storage_at(0):
        print(insn)
        if insn.insn.name == 'SLOAD':
            g = rattle.DefUseGraph(insn.return_value)
            print(g.dot(lambda x: x.insn.name in ('AND', )))
        print('\n')
    '''

    can_send, functions_that_can_send = ssa.can_send_ether()
    if can_send:
        print("[+] Contract can send ether from following functions:")
        for function in functions_that_can_send:
            print(f"\t- {function.desc()}")

            _, insns = function.can_send_ether()
            for insn in insns:

                print(f"\t\t{insn}")

                if insn.insn.name == 'SELFDESTRUCT':
                    address = insn.arguments[0]
                    print(f'\t\t\t{address.writer}')

                elif insn.insn.name == 'CALL':
                    address = insn.arguments[1]
                    value = insn.arguments[2]
                    print(f'\t\t\tTo:\t{address.writer}')

                    try:
                        if value.writer:
                            print(f'\t\t\tValue:\t{value.writer}')
                        else:
                            value_in_eth = int(value) * 1.0 / 10 ** 18
                            print(f'\t\t\tValue:\t{value} {value_in_eth}ETH')
                    except Exception as e:
                        print(e)

                print("")
    else:
        print("[+] Contract can not send ether.")

    print("[+] Contract calls:")
    for call in ssa.calls():
        print(f"\t{call}")
        if call.insn.name == 'DELEGATECALL':
            gas, to, in_offset, in_size, out_offset, out_size = call.arguments
            value = None
        else:
            gas, to, value, in_offset, in_size, out_offset, out_size = call.arguments

        print(f"\t\tGas: {gas}", end='')
        if gas.writer:
            print(f'\t\t\t{gas.writer}')
        else:
            print("\n", end='')

        print(f"\t\tTo: {to} ", end='')
        if to.writer:
            print(f'\t\t\t{to.writer}')
        else:
            print("\n", end='')

        if value:
            print(f"\t\tValue: {value}", end='')
            if value.writer:
                print(f'\t\t\t{value.writer}')
            else:
                print("\n", end='')

        print(f"\t\tIn Data Offset: {in_offset}", end='')
        if in_offset.writer:
            print(f'\t\t{in_offset.writer}')
        else:
            print("\n", end='')

        print(f"\t\tIn Data Size: {in_size}", end='')
        if in_size.writer:
            print(f'\t\t{in_size.writer}')
        else:
            print("\n", end='')

        print(f"\t\tOut Data Offset: {out_offset}", end='')
        if out_offset.writer:
            print(f'\t\t{out_offset.writer}')
        else:
            print("\n", end='')

        print(f"\t\tOut Data Size: {out_size}", end='')
        if out_size.writer:
            print(f'\t\t{out_size.writer}')
        else:
            print("\n", end='')

        print("")

    for function in ssa.functions:
        g = rattle.ControlFlowGraph(function)
        t = tempfile.NamedTemporaryFile(suffix='.dot', mode='w')
        t.write(g.dot())
        t.flush()

        try:
            os.makedirs('output')
        except:
            pass

        out_file = f'output/{function.desc()}.png'

        subprocess.call(['dot', '-Tpng', f'-o{out_file}', t.name])
        print(f'[+] Wrote {function.desc()} to {out_file}')

        try:
            # This is mac specific
            subprocess.call(['open', out_file])
        except OSError as e:
            pass

    # Maybe a way to query the current value of a storage location out of some api (can infra do that?)
    # print(loc0.value.top())
    # print(loc0.value.attx(012323213))


if __name__ == '__main__':
    main()
