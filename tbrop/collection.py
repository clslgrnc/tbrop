# Replacement for dumbGadget.py

from capstone import *

from tbrop.arch import SUPPORTED_ARCH
from tbrop.gadget import *

X86_MAX_INST_LEN = 16


class GadgetsCollection:
    def __init__(self, target_arch, data, offset=0, gentryPoints=None):
        self.data = data

        arch_class = SUPPORTED_ARCH.get(target_arch)
        if arch_class is None:
            raise Exception("ArchitectureNotSupported")

        self.arch = arch_class()

        if self.arch.addrSize == 8:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.mdfast = Cs(CS_ARCH_X86, CS_MODE_64)
        if self.arch.addrSize == 4:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.mdfast = Cs(CS_ARCH_X86, CS_MODE_64)

        self.md.detail = True
        self.mdfast.detail = False

        self.gentryPoints = gentryPoints

        self.disasm_cache = {}
        self.offset = offset

        if self.gentryPoints == None:
            self.InitEntryPoints()

        self.gadgets = []
        self.by_address = {}
        self.by_bytes = {}

        self.instCache = {}

    def isFinal(self, inst):
        groups = inst.groups

        #        if CS_GRP_INVALID in groups:
        #            return False
        if CS_GRP_RET in groups:
            if inst.mnemonic.startswith("retf"):
                return False
            return True
        elif CS_GRP_JUMP in groups or CS_GRP_CALL in groups:
            if len(inst.operands) != 1:
                print("weird capstone bug at ", hex(inst.address))
                #                print(self.data[inst.address-self.offset:inst.address-self.offset+16].hex())
                print(inst.bytes.hex().rjust(16), "\t", inst.mnemonic, inst.op_str)
                #                print(str(groups))
                print(str(inst.groups))
                #                print(str(CS_GRP_JUMP), str(CS_GRP_CALL))
                return False
            _type = inst.operands[0].type
            if _type == CS_OP_REG or _type == CS_OP_MEM:
                # ignore jmp qword ptr [rip + ...]
                if (
                    _type == CS_OP_MEM
                    and inst.operands[0].mem.base == capstone.x86_const.X86_REG_RIP
                ):
                    return False
                return True
        else:  # not a JMP/CALL/RET
            return False

    def InitEntryPoints(self, subrange=None):
        if subrange == None:
            len_data = len(self.data)
            subrange = range(len_data)
        self.gentryPoints = []
        for index in subrange:
            # skip 0x0FFF
            if index < len(self.data) - 1:
                if self.data[index : index + 2] == b"\x0f\xff":
                    continue

            i = list(self.md.disasm(self.data[index:], self.offset + index, 1))
            if i and self.isFinal(i[0]):
                self.gentryPoints.append(index)

    def getPredecessors(self, address, max_ins_size=X86_MAX_INST_LEN):
        Preds = []
        for cur_ins_size in range(1, max_ins_size + 1):
            if (
                self.data[address - cur_ins_size : address - cur_ins_size + 2]
                == b"\x0f\xff"
            ):
                continue
            # 0 or 1 instruction
            instOpt = self.md.disasm(
                self.data[address - cur_ins_size :],
                self.offset + address - cur_ins_size,
                1,
            )
            for inst in instOpt:
                # should be CS_GRP_PRIVILEGE, but bug in capstone next, X86_GRP_BRANCH_RELATIVE
                if inst.size == cur_ins_size and not (
                    set(inst.groups).intersection(
                        range(1 + capstone.x86_const.X86_GRP_BRANCH_RELATIVE)
                    )
                ):
                    Preds.append(inst)
        return Preds

    def getPredecessorsOpt(self, address, max_ins_size=X86_MAX_INST_LEN):
        Preds = []
        for cur_ins_size in range(1, max_ins_size + 1):
            if not address - cur_ins_size in self.instCache.keys():
                self.instCache[address - cur_ins_size] = None
                if (
                    self.data[address - cur_ins_size : address - cur_ins_size + 2]
                    == b"\x0f\xff"
                ):
                    continue
                # 0 or 1 instruction
                instOpt = self.md.disasm(
                    self.data[address - cur_ins_size :],
                    self.offset + address - cur_ins_size,
                    1,
                )
                for inst in instOpt:
                    # should be CS_GRP_PRIVILEGE, but bug in capstone next, X86_GRP_BRANCH_RELATIVE
                    if not (
                        set(inst.groups).intersection(
                            range(1 + capstone.x86_const.X86_GRP_BRANCH_RELATIVE)
                        )
                    ):
                        self.instCache[address - cur_ins_size] = inst
            if self.instCache[address - cur_ins_size] != None:
                inst = self.instCache[address - cur_ins_size]
                if inst.size == cur_ins_size:
                    Preds.append(inst)
        return Preds

    def getPredecessorsOpt2(self, address, max_ins_size=X86_MAX_INST_LEN):
        Preds = []
        for cur_ins_size in range(1, max_ins_size + 1):
            if not address - cur_ins_size in self.instCache.keys():
                self.instCache[address - cur_ins_size] = 0
                if (
                    self.data[address - cur_ins_size : address - cur_ins_size + 2]
                    == b"\x0f\xff"
                ):
                    continue
                # 0 or 1 instruction
                instOpt = self.mdfast.disasm(
                    self.data[address - cur_ins_size :],
                    self.offset + address - cur_ins_size,
                    1,
                )
                for inst in instOpt:
                    self.instCache[address - cur_ins_size] = inst.size
            if self.instCache[address - cur_ins_size] == cur_ins_size:
                instOpt = self.md.disasm(
                    self.data[address - cur_ins_size :],
                    self.offset + address - cur_ins_size,
                    1,
                )
                for inst in instOpt:
                    # should be CS_GRP_PRIVILEGE, but bug in capstone next, X86_GRP_BRANCH_RELATIVE
                    if set(inst.groups).intersection(
                        range(1 + capstone.x86_const.X86_GRP_BRANCH_RELATIVE)
                    ):
                        self.instCache[address - cur_ins_size] = 0
                    else:
                        Preds.append(inst)
        return Preds

    def add_gadget(self, gadget):
        gadget_bytes = gadget.bytes()
        duplicate = self.by_bytes.get(gadget_bytes)

        if duplicate is not None:
            duplicate.addresses_of_duplicates |= gadget.addresses_of_duplicates
        else:
            self.by_bytes[gadget_bytes] = gadget
            self.gadgets.append(gadget)

    def defaultCallback(self, gadget, context):
        #        print(str(gadget.max_cost))
        if gadget.cost() > gadget.max_cost:
            return False
        else:
            gdgtcpy = gadget.copy()
            self.add_gadget(gdgtcpy)
            return True

    # @profile
    def collect(self, callback=defaultCallback, context=None, max_cost=64):
        worklist = {}

        # Init worklist
        for address in self.gentryPoints:
            gadget = Gadget(
                self.arch,
                [next(self.md.disasm(self.data[address:], address + self.offset, 1))],
                max_cost=max_cost,
            )
            gadget_bytes = gadget.bytes()
            duplicate = worklist.get(gadget_bytes)

            if duplicate is not None:
                duplicate.addresses_of_duplicates |= gadget.addresses_of_duplicates
            else:
                worklist[gadget_bytes] = gadget

        while worklist != {}:
            gadget_bytes, gadget = worklist.popitem()

            if not callback(self, gadget, context):
                # We do not want to extend this gadget
                continue

            if not gadget.canBeExtended():
                # We can not to extend this gadget
                continue

            predecessors = []
            for first_addr in gadget.addresses_of_duplicates:
                #                pred = self.getPredecessors(firstInst.address-self.offset)
                predecessors.extend(self.getPredecessorsOpt2(first_addr - self.offset))

            for inst in predecessors:
                new_gadget_bytes = bytes(inst.bytes) + gadget_bytes
                new_gadget = worklist.get(new_gadget_bytes)

                if new_gadget is not None:
                    new_gadget.addresses_of_duplicates.add(inst.address)
                else:
                    new_gadget = gadget.copy()
                    new_gadget.extend(inst)

                    worklist[new_gadget_bytes] = new_gadget

        return
