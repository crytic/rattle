#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import functools
import logging
from typing import List, Dict, Tuple, Optional, Set, cast, Iterator, Callable, Iterable

from rattle.evmasm import EVMAsm
from .hashes import hashes

logger = logging.getLogger(__name__)

concrete_values: List['ConcreteStackValue'] = []


class NewEdgeException(Exception):
    pass


class PHIRemovalException(Exception):
    pass


class PHIInstruction(EVMAsm.EVMInstruction):
    original: 'PlaceholderStackValue'

    def __init__(self, args: int, original: 'PlaceholderStackValue', offset: int = 0) -> None:
        super().__init__(0x100, "PHI", 0, args, 1, 0, "SSA PHI Node", 0, offset)
        self.original = original


class MethodDispatch(EVMAsm.EVMInstruction):
    target: 'SSAFunction'

    def __init__(self, target: 'SSAFunction', args: int, offset: int = 0) -> None:
        self.target = target
        super().__init__(0x101, "CONDICALL", 0, args, 1, 0, "Conditional Internal Call", 0, offset)


class InternalCallOp(EVMAsm.EVMInstruction):
    def __init__(self, args: int, offset: int = 0) -> None:
        super().__init__(0x102, "ICALL", 0, args, 1, 0, "Conditional Internal Call", 0, offset)


class StackValue(object):
    _writer: Optional['SSAInstruction'] = None
    _readers: Set['SSAInstruction']

    def __init__(self, value: int) -> None:
        self.value = value
        self._writer = None
        self._readers = set()

    @property
    def writer(self) -> Optional['SSAInstruction']:
        return self._writer

    @writer.setter
    def writer(self, insn: 'SSAInstruction') -> None:
        self._writer = insn

    def __repr__(self) -> str:
        return f"%{self.value}"

    def readers(self) -> Set['SSAInstruction']:
        return self._readers

    def add_reader(self, insn: 'SSAInstruction') -> None:
        self._readers.add(insn)

    def remove_reader(self, insn: 'SSAInstruction') -> None:
        try:
            self._readers.remove(insn)
        except:
            pass

    def resolve(self) -> Tuple['StackValue', bool]:
        return (self, False)

    def filtered_readers(self, filt: Callable[['SSAInstruction'], bool]) -> Set['SSAInstruction']:
        rv: Set['SSAInstruction'] = set()
        for reader in self.readers():
            if not filt(reader) and reader.return_value:
                rv |= reader.return_value.filtered_readers(filt)
            else:
                rv.add(reader)

        return rv

    def __int__(self):
        raise Exception("Could not convert non-concrete value to integer")


class ConcreteStackValue(StackValue):
    def __init__(self, value: int) -> None:
        self.concrete_value = int(value)
        super().__init__(-1)

        concrete_values.append(self)

    def __del__(self) -> None:
        concrete_values.remove(self)

    def __repr__(self) -> str:
        return f"#{self.concrete_value:x}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ConcreteStackValue) \
               and self.concrete_value == other.concrete_value

    def __lt__(self, other: 'ConcreteStackValue') -> bool:
        return self.concrete_value < other.concrete_value

    def __hash__(self) -> int:
        return hash(self.concrete_value)

    def __int__(self):
        return self.concrete_value


class PlaceholderStackValue(StackValue):
    sp: int
    block: 'SSABasicBlock'
    resolving: bool = False

    def __init__(self, sp: int, block: 'SSABasicBlock') -> None:
        self.sp = sp
        self.block = block
        super().__init__(-1)

    def __repr__(self) -> str:
        return f'<Unresolved sp:{self.sp} block:{self.block.offset:#x}>'

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PlaceholderStackValue) \
               and self.sp == other.sp \
               and self.block.offset == self.block.offset

    def __hash__(self) -> int:
        return hash((self.sp, self.block))

    def resolve(self) -> Tuple[StackValue, bool]:
        # Resolve!
        # print(f"Resolving placeholder {self}")

        if self.resolving:
            self.resolving = False
            return self, False

        self.resolving = True

        if len(self.block.in_edges) == 0:
            self.resolving = False
            return self, False

        if self.block.offset == 0:
            # TODO: Handle the case where people branch back to zero
            self.resolving = False
            return self, False

        if len(self.block.in_edges) == 1:
            parent: SSABasicBlock = list(self.block.in_edges)[0]
            parent_stack: List[StackValue] = parent.stack

            try:
                new_slot: StackValue = parent_stack[self.sp]
            except IndexError:
                self.resolving = False
                return self, False

            if isinstance(new_slot, PlaceholderStackValue):
                rv = new_slot.resolve()
                self.resolving = False
                return rv

            self.resolving = False
            return new_slot, True

        if len(self.block.in_edges) > 1:
            # Create a phi

            # Find first instruction in block that isn't a phi and insert there
            first_non_phi_index = 0
            for i, x in enumerate(self.block.insns):
                if not isinstance(x.insn, PHIInstruction):
                    first_non_phi_index = i
                    break

            # Avoid creating new PHI nodes if a new one works
            if self.block.function.phis.get(self, False):
                self.resolving = False
                return self.block.function.phis[self].return_value, True

            args = set()
            for edge in sorted(self.block.in_edges, key=lambda bb: bb.offset):
                edge_stack: List[StackValue] = edge.stack
                try:
                    new_slot = edge_stack[self.sp]
                    new_slot, _ = new_slot.resolve()  # Resolve it as far as you can
                except IndexError:
                    ''' 
                    Parent block doesn't have enough stack slots so i guess it should go higher up the call stack,
                    but I don't do that here.
                    '''
                    new_slot = PlaceholderStackValue(self.sp + len(edge_stack), list(self.block.in_edges)[0])

                if not isinstance(new_slot, PlaceholderStackValue):
                    args.add(new_slot)

            num_args = len(args)
            if num_args == 1:
                self.resolving = False
                return list(args)[0], True

            phi_insn: SSAInstruction = SSAInstruction(PHIInstruction(num_args, self, self.block.offset), self.block)
            self.block.function.phis[self] = phi_insn

            for arg in args:
                phi_insn.append_argument(arg)

            # If any arguments are not resolved, strip them maybe?
            if any([isinstance(x, PlaceholderStackValue) for x in phi_insn.arguments]):
                self.resolving = False
                return self, False

            self.block.insns.insert(first_non_phi_index, phi_insn)
            phi_insn.return_value = self.block.function.new_placeholder_value()
            self.resolving = False
            return phi_insn.return_value, True

        self.resolving = False
        return self, False


class SSAInstruction(object):
    insn: EVMAsm.EVMInstruction
    offset: int
    arguments: List[StackValue]
    parent_block: 'SSABasicBlock'
    _return_value: Optional[StackValue]
    comment = None

    def __init__(self, evminsn: EVMAsm.EVMInstruction, parent_block: 'SSABasicBlock') -> None:
        self.insn = evminsn
        self.arguments = []
        self._return_value = None
        self.offset = evminsn.pc
        self.parent_block = parent_block

    def __repr__(self) -> str:
        def key_for_PHI_arguments(sv: StackValue):
            return sv.concrete_value if isinstance(sv, ConcreteStackValue) else sv.value
        # <def

        rv: str = ''
        if self.return_value:
            rv += f"{self.return_value} = "

        # PHI arguments have no stable order and this causes trouble for the regression tests (SSA listing compare).
        # Checking here for PHI and sorting the arguments solves it. Not nice, but good for now.
        arguments = sorted(self.arguments, key=key_for_PHI_arguments) if self.insn.name == 'PHI' else self.arguments

        rv += f"{self.insn.name}("
        rv += ', '.join([f"{x}" for x in arguments])
        rv += ")"

        if self.comment:
            rv += f'    // {self.comment}'

        return rv

    def __iter__(self) -> Iterator[StackValue]:
        for arg in self.arguments:
            yield arg

    def append_argument(self, v: StackValue) -> None:
        assert (self.insn.pops > len(self.arguments) or
                self.insn.is_push or
                isinstance(self.insn, PHIInstruction))
        self.arguments.append(v)
        v.add_reader(self)

    def clear_arguments(self) -> None:
        for arg in self.arguments:
            arg.remove_reader(self)

        self.arguments.clear()

    def replace_argument(self, old: StackValue, new: StackValue) -> None:
        for i, arg in enumerate(self.arguments):
            if arg == old:
                self.arguments[i] = new
                new.add_reader(self)

        assert (self.insn.pops == len(self.arguments) or
                self.insn.is_push or
                isinstance(self.insn, PHIInstruction))

    def remove_argument(self, old: StackValue) -> None:
        # print(f"Removing argument {old} from {self}")
        if self.insn.is_branch:
            return

        if not isinstance(self.insn, PHIInstruction):
            return
            # raise Exception(f"Can't remove argument from non-PHI: {old} from {self}")

        new_args = [x for x in self.arguments if x != old]
        old.remove_reader(self)

        new_phi = PHIInstruction(len(new_args), self.insn.original, self.insn.pc)
        self.clear_arguments()

        self.insn = new_phi
        for arg in new_args:
            self.append_argument(arg)

    @property
    def return_value(self) -> Optional[StackValue]:
        return self._return_value

    @return_value.setter
    def return_value(self, v: StackValue) -> None:
        self._return_value = v

        if v is not None:
            v.writer = self

    def remove_from_parent(self) -> None:
        try:
            self.parent_block.insns.remove(self)
        except:
            pass

    def resolve_arguments(self) -> bool:
        dirty = False
        for i, arg in enumerate(list(self.arguments)):
            a, update = arg.resolve()
            if update:
                dirty = True
                # print(f"Replacing argument: {arg} with {a}")
                self.replace_argument(arg, a)

        return dirty

    def canonicalize(self) -> None:
        if not isinstance(self.insn, PHIInstruction):
            return

        if len(self.return_value.readers()) == 0:
            self.clear_arguments()
            self.remove_from_parent()
        elif len(self.arguments) == 0:
            for reader in list(self.return_value.readers()):
                if isinstance(reader.insn, PHIInstruction):
                    reader.remove_argument(self.return_value)
                    reader.canonicalize()
                else:
                    raise PHIRemovalException("Removing argument from non-PHI")

            if len(self.return_value.readers()) == 0:
                self.remove_from_parent()

        else:
            # Maybe we can remove args from phi function that has a CALLDATALOAD(0) user/reader as arg
            # Remove duplicates
            self.arguments = list(set(self.arguments))

            # Try to remove phi function if all its arguments are the same
            self.remove_phi_function()

        return

    def remove_phi_function(self):
        """Returns True if its remove phi function, otherwise returns False"""
        if all(self.arguments[0] == rest for rest in self.arguments):
            arg = self.arguments[0]
            self.remove_from_parent()
            self.clear_arguments()

            for reader in list(self.return_value.readers()):
                reader.replace_argument(self.return_value, arg)
                reader.canonicalize()

            return True

        return False

    def replace_uses_with(self, sv: StackValue) -> None:

        if self.return_value is None:
            return

        for reader in (self.return_value.readers()).copy():
            # Remove duplicates concrete values in phis functions. Ex: phi(#0, %332, #0) became phi(#0, %332)
            if reader.insn.name == 'PHI' and isinstance(sv, ConcreteStackValue):
                if sv not in reader.arguments:
                    reader.replace_argument(self.return_value, sv)
                else:
                    reader.remove_argument(self.return_value)
            else:
                reader.replace_argument(self.return_value, sv)

        self.clear_arguments()

        # Remove from parent, but this could be called several times
        try:
            self.remove_from_parent()
        except:
            pass

    def add_comment(self, comment: str) -> None:
        self.comment = comment


class SSABasicBlock(object):
    function: 'SSAFunction'
    offset: int
    insns: List[SSAInstruction]
    end: int

    in_edges: Set['SSABasicBlock']
    fallthrough_edge: Optional['SSABasicBlock']
    jump_edges: Set['SSABasicBlock']

    stack: List[StackValue]

    def __init__(self, offset: int, function: 'SSAFunction') -> None:
        self.offset = offset
        self.end = offset
        self.function = function
        self.function.add_block(self)

        self.in_edges = set()
        self.fallthrough_edge = None
        self.jump_edges = set()

        self.insns = []
        self.stack = [PlaceholderStackValue(-x, self) for x in range(32, 0, -1)]

    def __repr__(self) -> str:
        insns = []
        for i in self.insns:
            insns.append(f"\t<{i.offset:#x}: {i}>")
        insn_str = '\n'.join(insns)
        if len(self.insns) > 0:
            insn_str = '\n' + insn_str + '\n'

        if self.fallthrough_edge:
            out_block: SSABasicBlock = cast(SSABasicBlock, self.fallthrough_edge)
            out0: str = f"{out_block.offset:#x}"
        else:
            out0 = "None"

        if len(self.jump_edges) > 0:
            jump_targets = [f"{x.offset:#x}" for x in self.jump_edges]
            out1: str = "[" + ','.join(sorted(jump_targets)) + "]"
        else:
            out1 = "None"

        in_edges = ','.join([f"{x.offset:#x}" for x in sorted(self.in_edges, key=lambda b: b.offset)])

        return f"<SSABasicBlock offset:{self.offset:#x} " \
               f"num_insns:{len(self.insns)} " \
               f"in: [{in_edges}] " \
               f"insns:[{insn_str}] " \
               f"fallthrough:{out0} " \
               f"jumps:{out1}>"

    def __iter__(self) -> Iterator[SSAInstruction]:
        for insn in self.insns:
            yield insn

    def __len__(self) -> int:
        return len(self.insns)

    def stack_pop(self) -> StackValue:
        return self.stack.pop()

    def stack_push(self, item: StackValue) -> None:
        self.stack.append(item)

    def add_jump_target(self, offset: int) -> bool:
        # We do not support jumps to the beginning of the contract
        if offset == 0:
            return False
        target_block: SSABasicBlock = self.function.blockmap.get(offset, None)
        if target_block is None:
            # Likely a jump to an invalid instruction
            # target_block = self.invalid_jumpdest(offset)
            return False

        if self.fallthrough_edge == target_block:
            return False

        before_len = len(self.jump_edges)
        self.jump_edges.add(target_block)
        target_block.in_edges.add(self)

        return before_len != len(self.jump_edges)

    def invalid_jumpdest(self, offset: int) -> 'SSABasicBlock':
        new_block = SSABasicBlock(offset, self.function)
        insn = EVMAsm.disassemble_one('\xfe', offset)
        invalid_insn = SSAInstruction(insn, new_block)
        new_block.insns.append(invalid_insn)

        print("INVALID JUMPDEST: {}".format(new_block))

        return new_block

    def set_fallthrough_target(self, other: int) -> None:
        target_block: SSABasicBlock = self.function.blockmap[other]

        self.fallthrough_edge = target_block
        target_block.in_edges.add(self)

    def clear(self) -> None:
        self.insns = []
        self.stack = [PlaceholderStackValue(-x, self) for x in range(32, 0, -1)]

    def canonicalize(self) -> None:

        while True:
            pre_count = len(self.insns)
            for insn in self.insns:
                try:
                    insn.canonicalize()
                except PHIRemovalException:
                    pass

            if pre_count == len(self.insns):
                break


class SSAFunction(object):
    blocks: List[SSABasicBlock]
    blockmap: Dict[int, SSABasicBlock]
    name: str
    _hash: int
    offset: int
    phis: Dict[StackValue, SSAInstruction]

    num_values: int = 0

    def __init__(self, offset: int, name: str = "_dispatch", hash: int = 0) -> None:
        self.name = name
        self.hash = hash
        self.offset = offset

        self.blocks = []
        self.blockmap = {}
        self.phis = {}

    def __repr__(self) -> str:
        blocks = '\n'.join([f'{x}' for x in self.blocks])
        return f"<SSAFunction name:{self.name} " \
               f"hash:{self.hash:#x} " \
               f"offset:{self.offset:#x} " \
               f"num_blocks:{len(self.blocks)} " \
               f"blocks:{blocks}>"

    def __iter__(self) -> Iterator[SSABasicBlock]:
        for block in self.blocks:
            yield block

    def __len__(self) -> int:
        return len(self.blocks)

    @property
    def hash(self) -> int:
        return self._hash

    @hash.setter
    def hash(self, v: int) -> None:
        self._hash = v
        if v != 0:
            self.name = hashes.get(v, '')

    def desc(self) -> str:
        name = self.name
        if self.name == '':
            name = f'_unknown_{self.hash:#x}()'

        return name

    def add_block(self, block: SSABasicBlock) -> None:
        if self.blockmap.get(block.offset):
            return

        # print(f"New block: {block.offset:#x}")

        self.blocks.append(block)
        self.blockmap[block.offset] = block

    def new_placeholder_value(self) -> StackValue:
        value = StackValue(self.num_values)
        self.num_values += 1
        return value

    def clear(self) -> None:
        for block in self.blocks:
            block.clear()

        self.phis = {}
        self.num_values = 0

    def optimize(self) -> None:
        for block in self:
            for insn in block:
                if insn.insn.is_push:
                    arg = insn.arguments[0]
                    for reader in list(insn.return_value.readers()):
                        logger.debug(f"Replacing {reader} arg with {arg}")
                        reader.replace_argument(insn.return_value, arg)

    def trace_blocks(self, start: SSABasicBlock, extracted: Optional[Set[SSABasicBlock]] = None) -> List[SSABasicBlock]:
        if extracted is None:
            extracted = set()

        extracted.add(start)
        if start.fallthrough_edge and start.fallthrough_edge not in extracted:
            extracted.add(start.fallthrough_edge)
            extracted |= self.trace_blocks(start.fallthrough_edge, extracted)

        for BB in start.jump_edges:
            if BB not in extracted:
                extracted.add(BB)
                extracted |= self.trace_blocks(BB, extracted)

        return extracted

    def remove_blocks(self, blocks: List[SSABasicBlock]) -> None:
        for block in blocks:
            try:
                self.blocks.remove(block)
            except:
                pass

    @property
    @functools.lru_cache(maxsize=16)
    def storage(self) -> List[int]:
        locations = set()
        for block in self:
            for insn in block:
                if not insn.insn.name in ('SSTORE', 'SLOAD'):
                    continue

                arg0 = insn.arguments[0]
                if not isinstance(arg0, ConcreteStackValue):
                    continue

                locations.add(arg0.concrete_value)

        return list(locations)

    def storage_at(self, offset: int) -> Iterable[SSAInstruction]:
        for block in self:
            for insn in block:
                if insn.insn.name not in ('SSTORE', 'SLOAD'):
                    continue

                arg0 = insn.arguments[0]
                if not isinstance(arg0, ConcreteStackValue):
                    continue

                if arg0.concrete_value == offset:
                    yield insn

    @property
    @functools.lru_cache(maxsize=16)
    def memory(self) -> List[int]:
        locations = set()
        for block in self:
            for insn in block:
                if insn.insn.name == 'SHA3':
                    (start, end) = insn.arguments[:2]
                    if not isinstance(start, ConcreteStackValue) or \
                            not isinstance(end, ConcreteStackValue):
                        continue

                    locations.update(set(range(start.concrete_value, end.concrete_value)))

                if not insn.insn.name in ('MSTORE', 'MLOAD'):
                    continue

                arg0 = insn.arguments[0]
                if not isinstance(arg0, ConcreteStackValue):
                    continue

                locations.add(arg0.concrete_value)

        return list(locations)

    def memory_at(self, offset: int) -> Iterable[SSAInstruction]:
        for block in self:
            for insn in block:
                if insn.insn.name == 'SHA3':
                    # handle sha3
                    (start, end) = insn.arguments[:2]
                    if not isinstance(start, ConcreteStackValue) or \
                            not isinstance(end, ConcreteStackValue):
                        continue

                    if start.concrete_value <= offset < end.concrete_value:
                        yield insn

                elif insn.insn.name not in ('MSTORE', 'MLOAD'):
                    continue

                arg0 = insn.arguments[0]
                if not isinstance(arg0, ConcreteStackValue):
                    continue

                if arg0.concrete_value == offset:
                    yield insn

    @functools.lru_cache(maxsize=16)
    def can_send_ether(self) -> Tuple[bool, List[SSAInstruction]]:
        rv = False
        insns_that_send = []
        for block in self:
            for insn in block:
                if insn.insn.name == 'SELFDESTRUCT':
                    insns_that_send.append(insn)
                    rv = True
                elif insn.insn.name in ('CALL', 'CALLCODE'):
                    gas, to, value, in_offset, in_size, out_offset, out_size = insn.arguments

                    if not isinstance(value, ConcreteStackValue):
                        insns_that_send.append(insn)
                        rv = True
                        continue

                    if value.concrete_value == 0:
                        continue

                    insns_that_send.append(insn)
                    rv = True

        return rv, insns_that_send

    @functools.lru_cache(maxsize=16)
    def calls(self) -> List[SSAInstruction]:
        rv = []
        for block in self:
            for insn in block:
                if insn.insn.name in ('CALL', 'CALLCODE', 'DELEGATECALL'):
                    rv.append(insn)

        return rv

    @functools.lru_cache(maxsize=16)
    def arguments(self) -> List[Tuple[int, int]]:
        starts = set()
        for block in self:
            for insn in block:
                if insn.insn.name != 'CALLDATALOAD':
                    continue

                if len(insn.arguments) != 1:
                    continue

                arg0 = insn.arguments[0]
                if not isinstance(arg0, ConcreteStackValue):
                    continue

                starts.add(arg0.concrete_value)

        if len(starts) == 0:
            return []

        args = set()
        end = max(list(starts)) + 32
        for start in reversed(list(starts)):
            args.add((start, end))
            end = start

        return sorted(list(args), key=lambda x: x[0])


class InternalCall(SSAInstruction):
    target: SSAFunction

    def __init__(self, target: SSAFunction, args: int, offset: int, parent_block: 'SSABasicBlock') -> None:
        super().__init__(InternalCallOp(args, offset), parent_block)
        self.target = target

    def __repr__(self) -> str:
        rv: str = ''
        if self.return_value:
            rv += f"{self.return_value} = "

        rv += f"ICALL({self.target.desc()}"
        if len(self.arguments) > 0:
            rv += ', '

        rv += ', '.join([f"{x}" for x in self.arguments])
        rv += ")"

        return rv


class ConditionalInternalCall(SSAInstruction):
    target: SSAFunction

    def __init__(self, target: SSAFunction, args: int, offset: int, parent_block: 'SSABasicBlock') -> None:
        super().__init__(MethodDispatch(args, offset), parent_block)
        self.target = target

    def __repr__(self) -> str:
        rv: str = ''
        if self.return_value:
            rv += f"{self.return_value} = "

        rv += f"ICONDCALL({self.target.desc()}"
        if len(self.arguments) > 0:
            rv += ', '

        rv += ', '.join([f"{x}" for x in self.arguments])
        rv += ")"

        return rv
