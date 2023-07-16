# Replacement for dumbGadget.py

from capstone import *

from tbrop.arch import SUPPORTED_ARCH
from tbrop.gadget import *
from tbrop.graph import build_graph_from_bytes, clean_up_graph

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

        self.init_graph()

        if self.gentryPoints == None:
            self.InitEntryPoints()

        self.gadgets = []
        self.by_address = {}
        self.by_bytes = {}

        self.instCache = {}

    def init_graph(self):
        self.graph = build_graph_from_bytes(self.data)
        clean_up_graph(self.graph)

    def InitEntryPoints(self):
        self.gentryPoints = []
        for node in self.graph:
            if next(self.graph.successors(node), None) is None:
                # no successors
                self.gentryPoints.append(node)

    def getPredecessors(self, address, max_ins_size=X86_MAX_INST_LEN):
        predecessors = []
        for predecessor_address in self.graph.predecessors(address):
            for pred in self.md.disasm(
                self.data[predecessor_address:],
                predecessor_address,
                1,
            ):
                predecessors.append(pred)
        return predecessors

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
                [next(self.md.disasm(self.data[address:], address, 1))],
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
                predecessors.extend(self.getPredecessors(first_addr))

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
