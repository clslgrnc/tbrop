# Use full graph to capture branching gadgets
# as in ROPGadget --multibr
# and "Return-Oriented Programming on RISC-V" Jaloyan et al.

from typing import Any, Iterator, Optional, cast

import capstone as cs
import networkx as nx

INSTR_MAX_SIZE = 16


def node_from_instruction(instruction: cs.CsInsn) -> dict[str, Any]:
    """
    Builds a node from an instruction
    """
    branch_to = None
    if cs.x86.X86_GRP_BRANCH_RELATIVE in instruction.groups:
        assert len(instruction.operands) > 0
        destination = instruction.operands[0]
        assert destination.type == cs.CS_OP_IMM
        branch_to = destination.imm  # capstone resolves addresses

    return {
        # "instruction": instruction,
        "mnemonic": instruction.mnemonic,
        "groups": instruction.groups,
        "branch_to": branch_to,
    }


def skip_instruction(
    instruction: cs.CsInsn,
    skippable_groups: Optional[set[int]] = None,
    skippable_mnemonics: Optional[set[str]] = None,
) -> bool:
    """
    Returns true iff instruction should not be taken into account
    """
    if skippable_groups is None:
        skippable_groups = {
            cs.CS_GRP_INVALID,
            cs.CS_GRP_INT,
            cs.CS_GRP_IRET,
            cs.CS_GRP_PRIVILEGE,  # remove line for kernel ROP
        }
    if skippable_mnemonics is None:
        skippable_mnemonics = {"retf"}

    instruction_groups = set(instruction.groups)

    return (
        not instruction_groups.isdisjoint(skippable_groups)
        or instruction.mnemonic in skippable_mnemonics
    )


def successors(instruction: cs.CsInsn) -> list[int]:
    instruction_groups = set(instruction.groups)
    next_address = instruction.address + instruction.size

    # No know successors for RET like instructions
    if instruction_groups & {
        cs.CS_GRP_RET,
        cs.CS_GRP_IRET,
    }:
        return []

    # We do not consider the return path of interrupts (TODO?)
    if cs.CS_GRP_INT in instruction_groups and instruction.mnemonic not in {
        "into",
    }:
        # into is a conditional interrupt
        return []

    # Regular non-branching instructions
    if instruction_groups.isdisjoint(
        {
            cs.CS_GRP_JUMP,
            cs.CS_GRP_CALL,
        }
    ):
        return [next_address]

    # we now either have a jump or a call
    offsets: list[int] = []

    # TODO: the remaining of the function is too x86 specific

    # for conditional jumps, we can jump to `next_address`
    # for calls, we ignore the return path (TODO?)
    if cs.CS_GRP_JUMP in instruction_groups and instruction.mnemonic != "jmp":
        offsets.append(next_address)

    if cs.x86.X86_GRP_BRANCH_RELATIVE not in instruction_groups:
        # call/jmp to register or memory
        return offsets

    # all that remain are call/jmp to imm
    assert len(instruction.operands) > 0
    destination = instruction.operands[0]
    assert destination.type == cs.CS_OP_IMM

    offsets.append(destination.imm)  # capstone resolves addresses

    return offsets


def build_graph_from_bytes(
    code: bytes,
    arch: int = cs.CS_ARCH_X86,
    mode: int = cs.CS_MODE_64,
) -> nx.DiGraph:
    graph = nx.DiGraph()

    code_analyzer = cs.Cs(arch, mode)
    code_analyzer.detail = True

    for i in range(len(code)):
        instr: Optional[cs.CsInsn] = next(
            code_analyzer.disasm(code[i : i + INSTR_MAX_SIZE], i), None
        )
        if instr is None or skip_instruction(instr):
            continue

        graph.add_node(i, **node_from_instruction(instr))

        for dst in successors(instr):
            graph.add_edge(i, dst)

    return graph


def hidden_successors(groups: set[int]) -> bool:
    if (
        groups
        & {
            cs.CS_GRP_JUMP,
            cs.CS_GRP_CALL,
        }
        and cs.x86.X86_GRP_BRANCH_RELATIVE not in groups
    ):
        # instruction has an unknown successor
        return True
    if groups & {
        cs.CS_GRP_INT,
        cs.CS_GRP_RET,
        cs.CS_GRP_IRET,
    }:
        # instruction has an unknown successor
        return True

    return False


def remove_node_and_get_predecessors(graph: nx.DiGraph, node: int) -> set[int]:
    # remove node and return predecessors without successors
    output: set[int] = set()
    predecessors = cast(Iterator[int], graph.predecessors(node))

    # only remove predecessors without alternatives
    # do not remove jcc with one valid branch or
    # calls that may not return (anyway, we do not consider return paths for now)
    graph.remove_node(node)
    for pred in predecessors:
        pred_groups = set(graph.nodes[pred]["groups"])
        if hidden_successors(pred_groups):
            # pred has another unknown successor
            continue
        if {
            cs.CS_GRP_CALL,
            cs.x86.X86_GRP_BRANCH_RELATIVE,
        } <= pred_groups and node == graph.nodes[pred]["branch_to"]:
            output.add(pred)
            continue
        if next(graph.successors(pred), None) is None:
            # no successors
            output.add(pred)
            continue

    return output


def clean_up_graph(graph: nx.DiGraph) -> None:
    worklist = set()
    for node, attributes in graph.nodes.items():
        if len(attributes) == 0:
            worklist.add(node)

    while worklist:
        node = worklist.pop()
        if node not in graph:
            continue
        worklist |= remove_node_and_get_predecessors(graph, node)
