#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from rattle.evmasm import EVMAsm
from .ssa import *
import logging
import struct
import copy

from typing import List, Dict, Tuple, Optional, Set, cast, Iterable

logger = logging.getLogger(__name__)

class InternalRecover(object):
    filedata: List[bytes]
    functions: List[SSAFunction]
    edges: List[Tuple[int, int]]
    insns: Dict[int, EVMAsm.Instruction]

    def __init__(self, filedata: List[bytes], edges: List[Tuple[int,int]], optimize=False) -> None:
        logger.debug(f'{len(filedata)} bytes of input data')
        self.filedata = list(map(lambda x: struct.pack("B", x), filedata))

        # Remove swarm hash if its there
        filestring = ''.join([chr(int.from_bytes(x, byteorder='little')) for x in self.filedata])
        while True:
            if '\xa1ebzzr0' in filestring:
                # replace the swarm hash with stops
                offset = filestring.find('\xa1ebzzr0')
                self.filedata = self.filedata[:offset]
                self.filedata.extend([b'\x00', ] * 43)
                self.filedata.extend(self.filedata[offset + 43:])
                filestring = ''.join([chr(int.from_bytes(x, byteorder='little')) for x in self.filedata])
            else:
                break

        dispatch = SSAFunction(0)
        self.functions = [dispatch, ]
        self.edges = edges

        self.recover(dispatch)

        if optimize:
            self.optimize()

        self.split_functions(dispatch)

        self.guarenteed_optimizations()

        # Remove stop-only blocks from dispatch
        blocks_to_remove = []
        for block in dispatch:
            if len(block.insns) != 1:
                continue

            insn = block.insns[0]
            if insn.insn.name != 'STOP':
                continue

            if len(block.in_edges) != 0:
                continue

            if block.fallthrough_edge:
                continue

            if len(block.jump_edges) != 0:
                continue

            blocks_to_remove.append(block)

        dispatch.remove_blocks(blocks_to_remove)


    def recover(self, function: SSAFunction) -> None:
        self.identify_blocks(function)

        # If we have supplied edges, set them
        for start, end in self.edges:
            try:
                source = function.blockmap[start]
                source.add_jump_target(end)
            except:
                pass

        while True:
            try:
                self.recover_loop(function)
                break
            except NewEdgeException as e:
                continue


    def recover_loop(self, function: SSAFunction) -> None:
        function.clear()
        self.repopulate_blocks(function)

        for block in function:
            for insn in list(block.insns): # make a new list because we modify it during iterating

                if insn.insn.is_push:
                    # Push is special, we keep it around so we know where constants are declared
                    # but we optimize it out later in most cases
                    insn.append_argument(ConcreteStackValue(insn.insn.operand))
                    insn.return_value = function.new_placeholder_value()
                    block.stack_push(insn.return_value)
                    continue

                if insn.insn.is_dup:
                    distance: int = insn.insn.pops
                    item: StackValue = block.stack[-distance]
                    block.stack_push(item)
                    insn.remove_from_parent()
                    continue

                if insn.insn.is_swap:
                    distance = insn.insn.pops
                    block.stack[-distance], block.stack[-1] = block.stack[-1], block.stack[-distance]
                    insn.remove_from_parent()
                    continue

                if insn.insn.is_pop:
                    block.stack_pop()
                    insn.remove_from_parent()
                    continue

                if insn.insn.name == 'JUMPDEST':
                    insn.remove_from_parent()
                    continue

                for _ in range(insn.insn.pops):
                    insn.append_argument(block.stack_pop())

                if insn.insn.pushes > 0:
                    insn.return_value = function.new_placeholder_value()
                    block.stack_push(insn.return_value)

        if self.resolve_xrefs(function):
            raise NewEdgeException()

        self.resolve_phis(function)

        if self.resolve_xrefs(function):
            raise NewEdgeException()

    def identify_blocks(self, function: SSAFunction) -> None:
        # Initial function that identifies and populate blocks

        insns = list(EVMAsm.disassemble_all(self.filedata, 0))
        self.insns = {x.offset : x for x in insns}

        blocks_set: Set[int] = set()
        blocks_set.add(0)  # First insn starts a block

        max_pc : int = max([x.offset + x.size for x in insns])

        for offset, insn in self.insns.items():
            if insn.name == "JUMPDEST":
                blocks_set.add(offset)
            elif insn.is_terminator and \
                    (insn.offset + insn.size) < max_pc:
                # insn after a terminator is always a new block
                blocks_set.add(offset + 1)

        blocks_list = list(sorted(blocks_set))

        for i, start in enumerate(blocks_list):
            block = SSABasicBlock(start, function)
            if i + 1 < len(blocks_list):
                end = blocks_list[i + 1]
            else:
                end = len(self.insns)

            for idx in [x.offset for x in insns if x.offset >= start and x.offset < end]:
                block.insns.append(SSAInstruction(self.insns[idx], block))

            block.end = end

        for block in function:
            if len(block.insns) == 0:
                continue

            terminator: SSAInstruction = block.insns[-1]

            if terminator.insn.name == "JUMPI" or not terminator.insn.is_terminator:
                block.set_fallthrough_target(terminator.offset + terminator.insn.size)

    def repopulate_blocks(self, function: SSAFunction) -> None:
        for block in function:
            start = block.offset
            end = block.end

            for insn in [insn for offset, insn in self.insns.items() \
                         if offset >= start and offset < end]:
                block.insns.append(SSAInstruction(insn, block))

    def resolve_xrefs(self, function: SSAFunction) -> bool:
        dirty = False

        for block in function:
            if len(block.insns) == 0:
                continue

            terminator : SSAInstruction = block.insns[-1]

            if terminator.insn.name in ("JUMP", "JUMPI"):
                target : StackValue = terminator.arguments[0]

                if isinstance(target, ConcreteStackValue):
                    dirty |= block.add_jump_target(target.concrete_value)
                elif not isinstance(target, PlaceholderStackValue) and \
                        target.writer is not None:

                    def handle_writers(writer, depth) -> bool:
                        if depth == 0:
                            return False

                        dirty = False
                        if writer.insn.is_push:
                            value = cast(ConcreteStackValue, writer.arguments[0])
                            dirty |= block.add_jump_target(value.concrete_value)
                        elif isinstance(writer.insn, PHIInstruction):
                            for arg in writer.arguments:
                                if arg.writer is None:
                                    continue

                                dirty |= handle_writers(arg.writer, depth-1)

                        return dirty

                    dirty |= handle_writers(target.writer, 5)

        return dirty

    def resolve_phis(self, function: SSAFunction) -> bool:
        # resolve phis
        dirty = False

        for block in function:
            for insn in block:
                insn.resolve_arguments()

        for _ in range(3):
            for block in function:
                block.canonicalize()

        return dirty

    def _resolve_unresolved_stack(self, slot : StackValue) -> Tuple[StackValue, bool]:
        return slot, False


    def split_functions(self, function : SSAFunction) -> List[SSAFunction]:
        functions = self.split_dispatched_methods(function)

        return functions

    def extract_method(self, function: SSAFunction, method_start : int) -> Optional[SSAFunction]:
        start_block = function.blockmap[method_start]

        method_blocks = function.trace_blocks(start_block)

        # Make sure the fallthrough blocks are self contained and not inlined from somewhere else
        block_starts: Set[int] = set()
        method_in_edges: Set[int] = set()
        for block in method_blocks:
            block_starts.add(block.offset)
            method_in_edges |= set([x.offset for x in block.in_edges])

        all_in_edges = method_in_edges.difference(block_starts)
        if all_in_edges != set([x.offset for x in start_block.in_edges]):
            logger.warning(
                f"Identified a method we couldn't extract. In edges were not complete: got {[x.offset for x in list(start_block.in_edges)]} needed {list(all_in_edges)}")
            return None

        function.remove_blocks(list(method_blocks))

        new_method = SSAFunction(offset=method_start)
        for block in sorted(method_blocks, key=lambda x: x.offset):
            new_method.add_block(block)

        # Unlink blocks and inject calls
        edge : SSABasicBlock
        for edge in start_block.in_edges:
            pc = edge.offset
            last_insn = None
            if len(edge.insns) > 0:
                last_insn = edge.insns[-1]
                pc = last_insn.offset

            if edge.fallthrough_edge == start_block:
                edge.fallthrough_edge = None

                icall = InternalCall(new_method, 0, pc, edge)
                edge.insns.append(icall)

            if start_block in edge.jump_edges:
                edge.jump_edges.remove(start_block)

                if last_insn is None:
                    continue

                if last_insn.insn.name != 'JUMPI':
                    continue

                last_insn.remove_from_parent()

                icondcall = ConditionalInternalCall(new_method, 1, pc, edge)
                icondcall.append_argument(last_insn.arguments[1])
                edge.insns.append(icondcall)

        start_block.in_edges = set()

        return new_method

    def split_dispatched_methods(self, function : SSAFunction) -> None:
        # Trace reads from calldataload(0)
        for block in function:
            for insn in block:
                if insn.insn.name != "CALLDATALOAD":
                    continue

                if len(insn.arguments) != 1:
                    continue

                arg = insn.arguments[0]
                if not isinstance(arg, ConcreteStackValue):
                    continue

                arg_value = arg.concrete_value
                if arg_value != 0:
                    continue

                logger.debug(f"Found calldataload(0) at {insn.offset:#x} {insn}")
                # Find all the users of calldataload(0) while striping out div/and/etc. Users should be all EQ insns
                users = insn.return_value.filtered_readers(lambda x: not (x.insn.is_arithmetic or x.insn.is_boolean_logic))

                for user in users:
                    if user.insn.name != 'EQ':
                        logger.warning(f"Found CALLDATALOAD(0) user that isn't an EQ {user}")
                        continue

                    hash_arg = user.arguments[0]
                    if not isinstance(hash_arg, ConcreteStackValue):
                        continue

                    hash = hash_arg.concrete_value
                    if user.return_value is None:
                        continue

                    eq_readers = list(user.return_value.readers())
                    for jump in eq_readers:
                        if jump.insn.name != "JUMPI":
                            continue

                        # hash -> jumpi target

                        assert(isinstance(jump.arguments[0], ConcreteStackValue))
                        jump_target = jump.arguments[0].concrete_value

                        logger.debug(f"Method identified with hash {hash:#x} starting at block {jump_target:#x}")

                        method = self.extract_method(function, jump_target)
                        if method is None:
                            continue

                        method.name = ''
                        method.hash = hash

                        self.functions.append(method)


        # Trace reads from calldatasize() and compares against zero
        for block in function:
            for insn in block:
                if insn.insn.name != "CALLDATASIZE":
                    continue

                if insn.return_value is None:
                    continue

                for comp in insn.return_value.readers():
                    if not comp.insn.is_comparison:
                        continue

                    if len(comp.arguments) != 2:
                        continue

                    # LT(CALLDATASIZE(), 4) and ISZERO(CALLDATASIZE()) have been used
                    if not isinstance(comp.arguments[1], ConcreteStackValue):
                        continue

                    if not (comp.insn.name == 'LT' and comp.arguments[1].concrete_value == 4) and \
                            not comp.insn.name == 'ISZERO':
                        continue

                    if comp.return_value is None:
                        continue

                    jumps = comp.return_value.readers()
                    for jump in list(jumps):
                        if not isinstance(jump.arguments[0], ConcreteStackValue):
                            continue

                        jump_target: int = jump.arguments[0].concrete_value
                        logger.debug(f"_fallthrough function at {jump_target:#x}")

                        fallthrough = self.extract_method(function, jump_target)
                        if fallthrough is None:
                            continue

                        fallthrough.name = '_fallthrough'
                        self.functions.append(fallthrough)



    def split_inline_functions(self, function : SSAFunction) -> List[SSAFunction]:
        # Find inline function calls
        for block in function:
            for insn in block:
                '''
                Find blocks that JUMP or JUMPI to a target defined from a different block
                '''
                if not insn.insn.is_branch:
                    continue

                writer = cast(SSAInstruction, insn.arguments[0].writer)

                if not isinstance(writer.insn, PHIInstruction):
                    continue

                starts = [x.writer.parent_block for x in writer]

                if not any([x != insn.parent_block for x in starts]):
                    continue

                blocks = set()

                def find_exits(start: SSABasicBlock, end: SSABasicBlock) -> None:
                    blocks.add(end)

                    if start.fallthrough_edge == end:
                        return

                    if end in start.jump_edges:
                        return

                    if start in blocks:
                        return

                    blocks.add(start)

                    if start.fallthrough_edge:
                        find_exits(start.fallthrough_edge, end)

                    for jump in start.jump_edges:
                        find_exits(jump, end)

                for start in starts:
                    find_exits(start, insn.parent_block)

                print(f"Inline function identified between {writer.offset:#x} {writer} and {insn.offset:#x} {insn}")
                print(list([f"{x.offset:#x}" for x in blocks]))
                print("\n\n")


    def optimize(self) -> None:
        logger.debug(f"Running optimizer!")
        self.constant_folder()

        # Peephole, single instruction optimizer
        dirty = True
        max_count = 25
        while dirty and max_count > 0:
            dirty = False
            max_count -= 1

            for function in self.functions:
                for block in function:
                    for insn in block:
                        update = self.peephole_optimizer(insn)
                        dirty |= update

    def constant_folder(self) -> None:
        worklist : List[ConcreteStackValue] = copy.copy(concrete_values)

        two_concrete_arguments = {
            'EXP' : lambda x, y : x ** y,
            'ADD' : lambda x, y : x + y,
            'SUB' : lambda x, y : x - y,
            'DIV' : lambda x, y : x / y,
            'MUL' : lambda x, y : x * y,
            'AND' : lambda x, y : x & y,
            'XOR' : lambda x, y : x ^ y,
            'OR'  : lambda x, y : x | y,
        }

        while len(worklist) > 0:
            item : ConcreteStackValue = worklist.pop()

            for reader in list(item.readers()):

                def do_replace(v: StackValue) -> None:
                    logger.debug(f"Replacing {reader} with {v}")
                    reader.replace_uses_with(v)
                    if isinstance(v, ConcreteStackValue):
                        worklist.append(v)

                if len(reader.arguments) == 2:
                    # 2 Arguments
                    if all([isinstance(x, ConcreteStackValue) for x in reader.arguments]):
                        # 2 Arguments, all concrete
                        x: int = cast(ConcreteStackValue, reader.arguments[0]).concrete_value
                        y: int = cast(ConcreteStackValue, reader.arguments[1]).concrete_value

                        op = two_concrete_arguments.get(reader.insn.name, None)
                        if op is not None:
                            do_replace(ConcreteStackValue(op(x, y)))
                    else:

                        def one_concrete_argument(symbolic_idx : int, concrete_idx : int) -> None:
                            symbolic_arg: StackValue = reader.arguments[symbolic_idx]
                            y: int = cast(ConcreteStackValue, reader.arguments[concrete_idx]).concrete_value

                            if reader.insn.name in ('DIV', 'MUL', 'EXP') and y == 1:
                                do_replace(symbolic_arg)

                            if reader.insn.name in ('ADD', 'SUB', 'XOR', 'OR') and y == 0:
                                do_replace(symbolic_arg)

                            if reader.insn.name in ('EXP', 'MUL') and y == 0:
                                do_replace(ConcreteStackValue(1))

                        if isinstance(reader.arguments[0], ConcreteStackValue):
                            # Only first argument is concrete
                            one_concrete_argument(1, 0)
                        elif isinstance(reader.arguments[1], ConcreteStackValue):
                            # Only second argument is concrete
                            one_concrete_argument(0, 1)


                if reader.insn.name == 'NOT' and isinstance(reader.arguments[0], ConcreteStackValue):
                    x: int = cast(ConcreteStackValue, reader.arguments[0]).concrete_value
                    do_replace(ConcreteStackValue(~x & (0x10000000000000000000000000000000000000000000000000000000000000000 - 1)))

                if reader.insn.is_push:
                    reader.replace_uses_with(item)
                    worklist.append(item)


    def peephole_optimizer(self, ssainsn : SSAInstruction) -> bool:
        # Peephole optimizer!

        '''
        Specifically handle odd solidity things, like all the ISZERO repeats
        '''
        if ssainsn.insn.is_comparison:
            '''
              %10 = LT(%9, #16345785d8a0000)
              %11 = ISZERO(%10)
              %12 = ISZERO(%11)
              JUMPI(#c7, %12)

              to

              %10 = LT(%9, #16345785d8a0000)
              JUMPI(#c7, %10)
            '''
            readers = list(ssainsn.return_value.readers())
            for reader in readers:
                if reader.insn.name == 'ISZERO' and reader.return_value is not None:
                    sub_readers = list(reader.return_value.readers())
                    for sub_reader in sub_readers:
                        if sub_reader.insn.name == 'ISZERO' and sub_reader.return_value is not None:
                            logger.debug(f"Removing redundant ISZERO(ISZERO(CMP)) instructions {ssainsn} {reader} {sub_reader}")
                            sub_reader.replace_uses_with(ssainsn.return_value)
                            return True

        if ssainsn.insn.name in ('CALLER', 'SLOAD', 'CALLDATALOAD', 'MLOAD'):
            readers = list(ssainsn.return_value.readers())
            for reader in readers:
                if reader.insn.name != 'AND':
                    continue

                other_arg = reader.arguments[1] if reader.arguments[0] == ssainsn.return_value else reader.arguments[0]

                if isinstance(other_arg, ConcreteStackValue):
                    if other_arg.concrete_value == 0xffffffffffffffffffffffffffffffffffffffff:
                        # Address mask, let's just remove it
                        ssainsn.add_comment("ADDRESS")
                        reader.replace_uses_with(ssainsn.return_value)
                        return True




        '''
        Remove all operations with unused results (assuming no side-effects)
        '''
        if ssainsn.return_value is None:
            return False

        if len(ssainsn.return_value.readers()) > 0:
            return False

        # Don't remove CALL variants if their result isn't used
        if ssainsn.insn.is_system:
            return False

        logger.debug(f"Removing unused insn {ssainsn}")
        ssainsn.clear_arguments()
        ssainsn.remove_from_parent()

        return True

    def guarenteed_optimizations(self) -> None:
        # PUSHES are lowered
        worklist: List[ConcreteStackValue] = copy.copy(concrete_values)
        while len(worklist) > 0:
            item : ConcreteStackValue = worklist.pop()

            for reader in list(item.readers()):
                if reader.insn.is_push:
                    reader.replace_uses_with(item)
                    worklist.append(item)


        # Remove single jump blocks
        for function in self.functions:
            for block in list(function):
                if len(block) == 1:
                    insn = block.insns[0]
                    if insn.insn.name != 'JUMP':
                        continue

                    if len(block.jump_edges) != 1:
                        continue

                    jump_edge = list(block.jump_edges)[0]

                    for edge in list(block.in_edges):
                        edge : SSABasicBlock

                        if edge.fallthrough_edge == block:
                            edge.fallthrough_edge = jump_edge

                            try:
                                jump_edge.in_edges.remove(block)
                            except:
                                pass
                            jump_edge.in_edges.add(edge)

                        if block in edge.jump_edges:
                            edge.jump_edges.remove(block)
                            edge.jump_edges.add(jump_edge)

                            try:
                                jump_edge.in_edges.remove(block)
                            except:
                                pass
                            jump_edge.in_edges.add(edge)

                    block.fallthrough_edge = None
                    block.jump_edges.clear()
                    block.in_edges.clear()
                    function.blocks.remove(block)



        # Remove empty blocks
        for function in self.functions:
            for block in list(function):
                if len(block) == 0:
                    if len(block.jump_edges) != 0:
                        continue

                    for edge in list(block.in_edges):
                        edge : SSABasicBlock

                        if edge.fallthrough_edge == block:
                            edge.fallthrough_edge = block.fallthrough_edge

                            if edge.fallthrough_edge:
                                try:
                                    edge.fallthrough_edge.in_edges.remove(block)
                                except:
                                    pass
                                edge.fallthrough_edge.in_edges.add(edge)

                        if block in edge.jump_edges:
                            edge.jump_edges.remove(block)
                            if block.fallthrough_edge:
                                edge.jump_edges.add(block.fallthrough_edge)

                            try:
                                edge.in_edges.remove(block)
                            except:
                                pass
                            edge.in_edges.add(edge)



                    block.fallthrough_edge = None
                    block.jump_edges.clear()
                    block.in_edges.clear()
                    function.blocks.remove(block)



class Recover(object):
    internal : InternalRecover

    def __init__(self, filedata: List[bytes], edges: List[Tuple[int,int]], optimize=False) -> None:
        self.internal = InternalRecover(filedata, edges, optimize)

    @property
    def functions(self) -> List[SSAFunction]:
        return self.internal.functions

    def __str__(self) -> str:
        rv = ''
        for function in self.internal.functions:
            rv += str(function) + "\n\n"
        return rv

    @property
    @functools.lru_cache(maxsize=16)
    def storage(self) -> List[int]:
        locations = set()

        for function in self.internal.functions:
            locations.update(set(function.storage))

        return list(locations)

    def storage_at(self, offset : int) -> Iterable[SSAInstruction]:
        for function in self.internal.functions:
            for insn in function.storage_at(offset):
                yield insn

    @property
    @functools.lru_cache(maxsize=16)
    def memory(self) -> List[int]:
        locations = set()

        for function in self.internal.functions:
            locations.update(set(function.memory))

        return list(locations)

    def memory_at(self, offset: int) -> List[SSAInstruction]:
        for function in self.internal.functions:
            for insn in function.memory_at(offset):
                yield insn

    @functools.lru_cache(maxsize=16)
    def can_send_ether(self) -> Tuple[bool, List[SSAFunction]]:
        can_send = []
        rv = False
        for function in self.internal.functions:
            frv, _ = function.can_send_ether()
            if frv:
                rv = True
                can_send.append(function)

        return rv, can_send

    def calls(self) -> Iterable[SSAInstruction]:
        for function in self.internal.functions:
            function_calls = function.calls()
            for call in function_calls:
                yield call

