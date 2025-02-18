#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Sequence
import rattle

# Ensure Python 3.6 or higher
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)
logger = logging.getLogger(__name__)

def main(argv: Sequence[str] = tuple(sys.argv)) -> None:
    parser = argparse.ArgumentParser(description='rattle ethereum evm binary analysis')
    parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
    parser.add_argument('--optimize', '-O', action='store_true', help='optimize resulting SSA form')
    parser.add_argument('--no-split-functions', '-nsf', action='store_false', help='split functions')
    parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout, help='log output file (default stdout)')
    parser.add_argument('--verbosity', '-v', type=str, default="None", help='log output verbosity (None, Critical, Error, Warning, Info, Debug)')
    parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('rb'), default=None, help='optional cfg file')
    parser.add_argument('--stdout_to', type=argparse.FileType('wt'), default=None, help='redirect stdout to file')
    parser.add_argument('--output_json', type=str, default="output.json", help='output JSON file')
    args = parser.parse_args(argv[1:])
    
    if args.input is None:
        parser.print_usage()
        sys.exit(1)

    orig_stdout = sys.stdout
    if args.stdout_to:
        sys.stdout = args.stdout_to

    edges = []
    if args.supplemental_cfg_file:
        edges = json.loads(args.supplemental_cfg_file.read())

    try:
        loglevel = getattr(logging, args.verbosity.upper())
    except AttributeError:
        loglevel = None

    logging.basicConfig(stream=args.log, level=loglevel)
    logger.info(f"Rattle running on input: {args.input.name}")

    # Perform analysis
    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize, split_functions=args.no_split_functions)

    # Prepare JSON output
    output_data = {
        "functions": [],
        "storage_locations": [],
        "memory_locations": [],
        "can_send_ether": False,
        "calls": []
    }

    # Collect function information
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        func_data = {
            "name": function.desc(),
            "offset": function.offset,
            "arguments": function.arguments(),
            "storage": []
        }
        for location in function.storage:
            storage_data = {
                "location": location,
                "instructions": []
            }
            for insn in sorted(ssa.storage_at(location), key=lambda i: i.offset):
                storage_data["instructions"].append({
                    "offset": insn.offset,
                    "instruction": str(insn)
                })
            func_data["storage"].append(storage_data)
        output_data["functions"].append(func_data)

    # Collect storage locations
    output_data["storage_locations"] = list(ssa.storage)

    # Collect memory locations
    output_data["memory_locations"] = list(ssa.memory)

    # Check if the contract can send ether
    can_send, functions_that_can_send = ssa.can_send_ether()
    output_data["can_send_ether"] = can_send
    if can_send:
        output_data["functions_that_can_send"] = []
        for function in functions_that_can_send:
            func_data = {
                "name": function.desc(),
                "calls": []
            }
            _, insns = function.can_send_ether()
            for insn in insns:
                call_data = {
                    "instruction": str(insn),
                    "details": {}
                }
                if insn.insn.name == 'SELFDESTRUCT':
                    address = insn.arguments[0]
                    call_data["details"]["address_writer"] = str(address.writer)
                elif insn.insn.name == 'CALL':
                    address = insn.arguments[1]
                    value = insn.arguments[2]
                    call_data["details"]["to_writer"] = str(address.writer)
                    try:
                        if value.writer:
                            call_data["details"]["value_writer"] = str(value.writer)
                        else:
                            value_in_eth = int(value) * 1.0 / 10 ** 18
                            call_data["details"]["value"] = f"{value} ({value_in_eth} ETH)"
                    except Exception as e:
                        call_data["details"]["error"] = str(e)
                func_data["calls"].append(call_data)
            output_data["functions_that_can_send"].append(func_data)

    # Collect contract calls
    for call in ssa.calls():
        call_data = {
            "instruction": str(call),
            "details": {}
        }
        if call.insn.name == 'DELEGATECALL':
            gas, to, in_offset, in_size, out_offset, out_size = call.arguments
            value = None
        else:
            gas, to, value, in_offset, in_size, out_offset, out_size = call.arguments
        call_data["details"]["gas"] = str(gas)
        call_data["details"]["to"] = str(to)
        call_data["details"]["in_offset"] = str(in_offset)
        call_data["details"]["in_size"] = str(in_size)
        call_data["details"]["out_offset"] = str(out_offset)
        call_data["details"]["out_size"] = str(out_size)
        if value:
            call_data["details"]["value"] = str(value)
        output_data["calls"].append(call_data)

    # Write JSON output to file
    with open(args.output_json, 'w') as json_file:
        json.dump(output_data, json_file, indent=4)
    print(f"[+] Wrote analysis results to {args.output_json}")

    # Generate PNG outputs (optional)
    for function in sorted(ssa.functions, key=lambda f: f.offset):
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
            # This is macOS-specific
            subprocess.call(['open', out_file])
        except OSError as e:
            pass

    # Cleanup
    if args.stdout_to:
        sys.stdout = orig_stdout
        args.stdout_to.close()
    if args.input:
        args.input.close()

if __name__ == "__main__":
    main()