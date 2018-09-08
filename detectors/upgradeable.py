
from .detector import AbstractDetector
from rattle import SSAFunction

class Upgradeable(AbstractDetector):

    def __init__(self, ssa):
        super(Upgradeable, self).__init__()
        self.ssa = ssa
        self.results_ = []

    def check(self):

        fallthrough : SSAFunction

        # Find fallback function
        for function in self.ssa.functions:
            if function.name == '_fallthrough':
                fallthrough = function
                break
        else:
            return None

        print("Fallthrough found!")
        print(fallthrough)

        storage_addresses = []


        # Fallback must have a delegate call
        for block in fallthrough.blocks:
            for insn in block.insns:
                if insn.insn.name == 'DELEGATECALL':
                    to = insn.arguments[1]
                    if to.writer.insn.name == 'SLOAD':
                        soffset = to.writer.arguments[0]
                        print("Delegate call with storage address at offset: {}".format(soffset))
                        storage_addresses.append(soffset)


        # No delegate calls with indirect addresses
        if len(storage_addresses) == 0:
            return False


        # Next, find SSTORES to storage addresses
        for function in self.ssa.functions:
            for block in function.blocks:
                for insn in block.insns:
                    if insn.insn.name != 'SSTORE':
                        continue

                    store_offset = insn.arguments[0]

                    for load_offset in storage_addresses:
                        if store_offset == load_offset:
                            print("STORAGE[{}] can be updated here: {}: {:#x} {}".format(store_offset, function.name, insn.offset, insn))
                            self.results_.append((store_offset, function, insn))

        return True