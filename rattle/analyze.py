#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .recover import *

logger = logging.getLogger(__name__)


class UseDefGraph(object):
    value: StackValue

    def __init__(self, value: StackValue) -> None:
        self.value = value

    def dot(self) -> str:
        rv = ''
        rv += 'digraph G {\n'

        es = self.edges(self.value)

        for reader in self.value.readers():
            reader_s = str(reader).replace('%', '\\%')
            value_s = str(self.value).replace('%', '\\%')
            es.append(f"\"{value_s}\" -> \"{reader_s}\"")

        rv += '\n'.join(list(set(es)))
        rv += '\n}'

    def edges(self, value) -> List[str]:
        rv = []
        writer = value.writer
        if writer is None:
            return []

        value_s = str(value).replace('%', '\\%')
        writer_s = str(writer).replace('%', '\\%')
        rv.append(f"\"{writer_s}\" -> \"{value_s}\"")

        for arg in writer:
            arg_s = str(arg).replace('%', '\\%')
            writer_s = str(writer).replace('%', '\\%')
            rv.append(f"\"{arg_s}\" -> \"{writer_s}\"")
            rv.extend(self.edges(arg))

        for reader in writer.return_value.readers():
            reader_s = str(reader).replace('%', '\\%')
            value_s = str(value).replace('%', '\\%')
            rv.append(f"\"{value_s}\" -> \"{reader_s}\"")

        return rv


class DefUseGraph(object):
    value: StackValue

    def __init__(self, value: StackValue) -> None:
        self.value = value

    def dot(self, filt=None) -> str:
        if filt is None:
            filt = lambda x: True

        rv = ''
        rv += 'digraph G {\n'

        es = self.edges(self.value, filt)

        for reader in self.value.readers():
            reader_s = str(reader).replace('%', '\\%')
            value_s = str(self.value).replace('%', '\\%')
            es.append(f"\"{value_s}\" -> \"{reader_s}\"")

        rv += '\n'.join(list(set(es)))
        rv += '\n}'

        return rv

    def edges(self, value, filt) -> List[str]:
        rv = []
        writer = value.writer
        if writer is None:
            return []

        value_s = str(value).replace('%', '\\%')
        writer_s = str(writer).replace('%', '\\%')
        rv.append(f"\"{writer_s}\" -> \"{value_s}\"")

        for reader in writer.return_value.readers():
            reader_s = str(reader).replace('%', '\\%')
            value_s = str(value).replace('%', '\\%')
            rv.append(f"\"{value_s}\" -> \"{reader_s}\"")

            if filt(reader):
                rv.extend(self.edges(reader.return_value, filt))

        return rv


class ControlFlowGraph(object):
    def __init__(self, function: SSAFunction) -> None:
        self.function = function

    def dot(self) -> str:
        rv = ''
        rv += 'digraph G {\n'
        rv += 'graph [fontname = "consolas"];\n'
        rv += 'node [fontname = "consolas"];\n'
        rv += 'edge [fontname = "consolas"];\n'

        name = self.function.desc()
        hash = f'Hash: {self.function.hash:#x}'
        offset = f'Start: {self.function.offset:#x}'
        arguments = f'Arguments: {self.function.arguments()}'
        storage = f'Storage: {self.function.storage}'
        # memory = f'Memory: {self.function.memory}'

        function_desc = [name, hash, offset, arguments, storage]

        rv += f'ff [label="{{' + '\\l'.join(function_desc) + '\\l}}", shape="record" ];'

        edges = []

        for block in self.function:
            block_id = f'block_{block.offset}'
            block_body = '\\l'.join([f'{insn.offset:#x}: {insn}' for insn in block])
            block_body = block_body.replace('<', '\\<').replace('>', '\\>')
            block_dot = f'{block_id} [label="{block_body}\\l", shape="record"];'

            fallthrough_label = ''
            jump_label = ''
            if len(block.jump_edges) > 0 and block.fallthrough_edge:
                fallthrough_label = ' [label=" f", color="red"]'
                jump_label = ' [label=" t", color="darkgreen"]'

            if block.fallthrough_edge:
                target_block_id = f'block_{block.fallthrough_edge.offset}'
                edges.append(f'{block_id} -> {target_block_id}{fallthrough_label};')

            for edge in block.jump_edges:
                target_block_id = f'block_{edge.offset}'
                edges.append(f'{block_id} -> {target_block_id}{jump_label};')

            rv += block_dot + '\n'

        for edge in edges:
            rv += edge + '\n'

        rv += '}\n'

        return rv
