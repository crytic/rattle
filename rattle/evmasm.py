from typing import Optional, Iterable

import pyevmasm


class EVMAsm(object):
    '''
        EVM Instruction factory

        Example use::

            >>> from manticore.platforms.evm import EVMAsm
            >>> EVMAsm.disassemble_one('\\x60\\x10')
            Instruction(0x60, 'PUSH', 1, 0, 1, 0, 'Place 1 byte item on stack.', 16, 0)
            >>> EVMAsm.assemble_one('PUSH1 0x10')
            Instruction(0x60, 'PUSH', 1, 0, 1, 0, 'Place 1 byte item on stack.', 16, 0)
            >>> tuple(EVMAsm.disassemble_all('\\x30\\x31'))
            (Instruction(0x30, 'ADDRESS', 0, 0, 1, 2, 'Get address of currently executing account.', None, 0),
             Instruction(0x31, 'BALANCE', 0, 1, 1, 20, 'Get balance of the given account.', None, 1))
            >>> tuple(EVMAsm.assemble_all('ADDRESS\\nBALANCE'))
            (Instruction(0x30, 'ADDRESS', 0, 0, 1, 2, 'Get address of currently executing account.', None, 0),
             Instruction(0x31, 'BALANCE', 0, 1, 1, 20, 'Get balance of the given account.', None, 1))
            >>> EVMAsm.assemble_hex(
            ...                         """PUSH1 0x60
            ...                            BLOCKHASH
            ...                            MSTORE
            ...                            PUSH1 0x2
            ...                            PUSH2 0x100
            ...                         """
            ...                      )
            '0x606040526002610100'
            >>> EVMAsm.disassemble_hex('0x606040526002610100')
            'PUSH1 0x60\\nBLOCKHASH\\nMSTORE\\nPUSH1 0x2\\nPUSH2 0x100'
    '''

    class EVMInstruction(pyevmasm.Instruction):
        def __init__(self, opcode: int, name: str, operand_size: int, pops: int, pushes: int, fee: int,
                     description: str, operand: Optional[int] = None, pc: Optional[int] = 0) -> None:
            '''
            This represents an EVM instruction.
            EVMAsm will create this for you.

            :param opcode: the opcode value
            :param name: instruction name
            :param operand_size: immediate operand size in bytes
            :param pops: number of items popped from the stack
            :param pushes: number of items pushed into the stack
            :param fee: gas fee for the instruction
            :param description: textual description of the instruction
            :param operand: optional immediate operand
            :param pc: optional program counter of this instruction in the program

            Example use::

                instruction = EVMAsm.assemble_one('PUSH1 0x10')
                print 'Instruction: %s'% instruction
                print '\tdescription:', instruction.description
                print '\tgroup:', instruction.group
                print '\tpc:', instruction.pc
                print '\tsize:', instruction.size
                print '\thas_operand:', instruction.has_operand
                print '\toperand_size:', instruction.operand_size
                print '\toperand:', instruction.operand
                print '\tsemantics:', instruction.semantics
                print '\tpops:', instruction.pops
                print '\tpushes:', instruction.pushes
                print '\tbytes:', '0x'+instruction.bytes.encode('hex')
                print '\twrites to stack:', instruction.writes_to_stack
                print '\treads from stack:', instruction.reads_from_stack
                print '\twrites to memory:', instruction.writes_to_memory
                print '\treads from memory:', instruction.reads_from_memory
                print '\twrites to storage:', instruction.writes_to_storage
                print '\treads from storage:', instruction.reads_from_storage
                print '\tis terminator', instruction.is_terminator


            '''
            super().__init__(opcode, name, operand_size, pops, pushes, fee, description, operand, pc)
            if operand_size != 0 and operand is not None:
                mask = (1 << operand_size * 8) - 1
                if ~mask & operand:
                    raise ValueError("operand should be %d bits long" % (operand_size * 8))

        def __repr__(self) -> str:
            output = 'EVMInstruction(0x{:x}, {}, {:d}, {:d}, {:d}, {:d}, {}, {}, {})'.format(
                self._opcode, self._name, self._operand_size,
                self._pops, self._pushes, self._fee, self._description, self._operand, self._pc)
            return output

        def __hash__(self) -> int:
            return hash((self._opcode, self._pops, self._pushes, self._pc))

        @property
        def is_push(self) -> bool:
            return self.semantics == 'PUSH'

        @property
        def is_pop(self) -> bool:
            return self.semantics == 'POP'

        @property
        def is_dup(self) -> bool:
            return self.semantics == 'DUP'

        @property
        def is_swap(self) -> bool:
            return self.semantics == 'SWAP'

        @property
        def is_comparison(self) -> bool:
            return self.semantics in ('LT', 'GT', 'SLT', 'SGT', 'EQ', 'ISZERO')

        @property
        def is_boolean_logic(self) -> bool:
            return self.semantics in ('AND', 'OR', 'XOR', 'NOT')

    @staticmethod
    def convert_instruction_to_evminstruction(instruction):
        return EVMAsm.EVMInstruction(instruction._opcode, instruction._name, instruction._operand_size,
                                     instruction._pops, instruction._pushes, instruction._fee,
                                     instruction._description, instruction._operand, instruction._pc)

    @staticmethod
    def assemble_one(assembler: str, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> EVMInstruction:
        ''' Assemble one EVM instruction from its textual representation.

            :param assembler: assembler code for one instruction
            :param pc: program counter of the instruction in the bytecode (optional)
            :return: An Instruction object

            Example use::

                >>> print evm.EVMAsm.assemble_one('LT')


        '''
        instruction = pyevmasm.assemble_one(assembler, pc, fork)
        return EVMAsm.convert_instruction_to_evminstruction(instruction)

    @staticmethod
    def convert_multiple_instructions_to_evminstructions(instructions):
        for i in instructions:
            yield EVMAsm.convert_instruction_to_evminstruction(i)

    @staticmethod
    def assemble_all(assembler: str, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> Iterable[EVMInstruction]:
        ''' Assemble a sequence of textual representation of EVM instructions

            :param assembler: assembler code for any number of instructions
            :param pc: program counter of the first instruction in the bytecode(optional)
            :return: An generator of Instruction objects

            Example use::

                >>> evm.EVMAsm.assemble_one("""PUSH1 0x60\n \
                            PUSH1 0x40\n \
                            MSTORE\n \
                            PUSH1 0x2\n \
                            PUSH2 0x108\n \
                            PUSH1 0x0\n \
                            POP\n \
                            SSTORE\n \
                            PUSH1 0x40\n \
                            MLOAD\n \
                            """)

        '''
        instructions = pyevmasm.assemble_all(assembler, pc, fork)
        return EVMAsm.convert_multiple_instructions_to_evminstructions(instructions)

    @staticmethod
    def disassemble_one(bytecode: Iterable, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> EVMInstruction:
        ''' Decode a single instruction from a bytecode

            :param bytecode: the bytecode stream
            :param pc: program counter of the instruction in the bytecode(optional)
            :type bytecode: iterator/sequence/str
            :return: an Instruction object

            Example use::

                >>> print EVMAsm.assemble_one('PUSH1 0x10')

        '''
        instruction = pyevmasm.disassemble_one(bytecode, pc, fork)
        return EVMAsm.convert_instruction_to_evminstruction(instruction)

    @staticmethod
    def disassemble_all(bytecode: Iterable, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> Iterable[EVMInstruction]:
        ''' Decode all instructions in bytecode

            :param bytecode: an evm bytecode (binary)
            :param pc: program counter of the first instruction in the bytecode(optional)
            :type bytecode: iterator/sequence/str
            :return: An generator of Instruction objects

            Example use::

                >>> for inst in EVMAsm.decode_all(bytecode):
                ...    print inst

                ...
                PUSH1 0x60
                PUSH1 0x40
                MSTORE
                PUSH1 0x2
                PUSH2 0x108
                PUSH1 0x0
                POP
                SSTORE
                PUSH1 0x40
                MLOAD


        '''
        instructions = pyevmasm.disassemble_all(bytecode, pc, fork)
        return EVMAsm.convert_multiple_instructions_to_evminstructions(instructions)

    @staticmethod
    def disassemble(bytecode: Iterable, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> str:
        ''' Disassemble an EVM bytecode

            :param bytecode: binary representation of an evm bytecode (hexadecimal)
            :param pc: program counter of the first instruction in the bytecode(optional)
            :type bytecode: str
            :return: the text representation of the assembler code

            Example use::

                >>> EVMAsm.disassemble("\x60\x60\x60\x40\x52\x60\x02\x61\x01\x00")
                ...
                PUSH1 0x60
                BLOCKHASH
                MSTORE
                PUSH1 0x2
                PUSH2 0x100

        '''
        return pyevmasm.disassemble(bytecode, pc, fork)

    @staticmethod
    def assemble(asmcode, pc=0, fork=pyevmasm.DEFAULT_FORK):
        return pyevmasm.assemble(asmcode, pc, fork)

    @staticmethod
    def disassemble_hex(bytecode: str, pc: int = 0, fork=pyevmasm.DEFAULT_FORK) -> str:
        ''' Disassemble an EVM bytecode

            :param bytecode: canonical representation of an evm bytecode (hexadecimal)
            :param int pc: program counter of the first instruction in the bytecode(optional)
            :type bytecode: str
            :return: the text representation of the assembler code

            Example use::

                >>> EVMAsm.disassemble_hex("0x6060604052600261010")
                ...
                PUSH1 0x60
                BLOCKHASH
                MSTORE
                PUSH1 0x2
                PUSH2 0x100

        '''
        return pyevmasm.disassemble_hex(bytecode, pc, fork)

    @staticmethod
    def assemble_hex(asmcode, pc=0, fork=pyevmasm.DEFAULT_FORK):
        return pyevmasm.assemble_hex(asmcode, pc, fork)
