# -*- coding: utf-8 -*-

import unittest

import capstone

import tbrop.arch as arch
import tbrop.gadget as gadget


class TestGadget(unittest.TestCase):

    def test_archx64(self):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        archx64 = arch.Arch_x86_64()
        for test_case in TestGadget.test_cases:
            if "x64" not in test_case:
                continue

            with self.subTest(data=test_case["bytes"]):
                instList = list(md.disasm(test_case["bytes"],0))

                asm = ""
                for inst in instList:
                    asm += inst.bytes.hex().rjust(16) + "   " + inst.mnemonic + " " + inst.op_str + "\n"

                self.assertEqual(test_case["x64"]["asm"], asm)

                gdgt = gadget.Gadget(archx64, instList)

                self.assertEqual(test_case["x64"]["cost"], gdgt.cost())
                self.assertEqual(test_case["x64"]["dependencies"], gdgt.gadgetMatrix.printDep())

    @classmethod
    def setUpClass(cls):
        TestGadget.test_cases = []

        TestGadget.test_cases.append({
            "bytes": b"\x58\xc3",
            "x64": {
                "asm": "              58   pop rax\n"
                       "              c3   ret \n",
                "cost": 21,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rax <--- stack_0\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_1\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x89\x74\x24\x48\xff\xe0",
            "x64": {
                "asm": "      4889742448   mov qword ptr [rsp + 0x48], rsi\n"
                       "            ffe0   jmp rax\n",
                "cost": 21,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "deref <--- deref, rsp\n"
                                "stack_9 <--- rsi\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x81\xc4\xE0\xFF\xFF\xFF\xc2\x18\x00",
            "x64": {
                "asm": "  4881c4e0ffffff   add rsp, -0x20\n"
                       "          c21800   ret 0x18\n",
                "cost": 21,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_{-1}\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x81\xc4\x40\x01\x00\x00\xff\xe0",
            "x64": {
                "asm": "  4881c440010000   add rsp, 0x140\n"
                       "            ffe0   jmp rax\n",
                "cost": 22,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x92\xC2\xE8\xb8",
            "x64": {
                "asm": "              92   xchg eax, edx\n"
                       "          c2e8b8   ret 0xb8e8\n",
                "cost": 24,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rax <--- rax, edx\n"
                                "rdx <--- rdx, eax\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x4d\x85\xff\x0F\x84\xC7\x01\x00\x00\xFF\xE0",
            "x64": {
                "asm": "          4d85ff   test r15, r15\n"
                       "    0f84c7010000   je 0x1d0\n"
                       "            ffe0   jmp rax\n",
                "cost": 24,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- r15\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x5e\x5b\xC3",
            "x64": {
                "asm": "              5e   pop rsi\n"
                       "              5b   pop rbx\n"
                       "              c3   ret \n",
                "cost": 29,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rbx <--- stack_1\n"
                                "rsi <--- stack_0\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_2\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x44\x87\x3d\x4c\xdd\x3c\x00\x4c\x87\xc2\xff\xe0",
            "x64": {
                "asm": "  44873d4cdd3c00   xchg dword ptr [rip + 0x3cdd4c], r15d\n"
                       "          4c87c2   xchg rdx, r8\n"
                       "            ffe0   jmp rax\n",
                "cost": 35,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rdx <--- r8\n"
                                "r8 <--- rdx\n"
                                "r15 <--- r15, rip, mem_r\n"
                                "deref <--- deref, rip\n"
                                "mem_w <--- mem_w, r15d\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x8b\x5c\x24\x30\x48\x83\xc4\x20\x5f\xc3",
            "x64": {
                "asm": "        8b5c2430   mov ebx, dword ptr [rsp + 0x30]\n"
                       "        4883c420   add rsp, 0x20\n"
                       "              5f   pop rdi\n"
                       "              c3   ret \n",
                "cost": 37,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "rbx <--- rbx, stack_6\n"
                                "rdi <--- stack_4\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_5\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x40\x48\x8B\x74\x24\x48\x48\x83\xC4\x30\x5F\xC3",
            "x64": {
                "asm": "    40488b742448   mov rsi, qword ptr [rsp + 0x48]\n"
                       "        4883c430   add rsp, 0x30\n"
                       "              5f   pop rdi\n"
                       "              c3   ret \n",
                "cost": 37,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "rdi <--- stack_6\n"
                                "rsi <--- stack_9\n"
                                "deref <--- deref, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_7\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x89\x74\x24\x48\x48\x83\xC4\x30\x5F\xC3",
            "x64": {
                "asm": "      4889742448   mov qword ptr [rsp + 0x48], rsi\n"
                       "        4883c430   add rsp, 0x30\n"
                       "              5f   pop rdi\n"
                       "              c3   ret \n",
                "cost": 38,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "rdi <--- stack_6\n"
                                "deref <--- deref, rsp\n"
                                "stack_1 <--- rsi\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_7\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x89\x74\x24\x48\x48\x83\xC4\x48\x5f\xff\xe0",
            "x64": {
                "asm": "      4889742448   mov qword ptr [rsp + 0x48], rsi\n"
                       "        4883c448   add rsp, 0x48\n"
                       "              5f   pop rdi\n"
                       "            ffe0   jmp rax\n",
                "cost": 38,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rsp\n"
                                "rdi <--- rsi\n"
                                "deref <--- deref, rsp\n"
                                "stack_{-1} <--- rsi\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x41\x56\x45\x33\xc0\x48\xff\x25\xa2\x46\x27\x00",
            "x64": {
                "asm": "            4156   push r14\n"
                       "          4533c0   xor r8d, r8d\n"
                       "  48ff25a2462700   jmp qword ptr [rip + 0x2746a2]\n",
                "cost": 39,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "deref <--- deref, rip, rsp\n"
                                "stack_0 <--- r14\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rip, mem_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x8B\xCB\x4C\x8B\x05\x23\x02\x1F\x00\x41\xFF\xD0",
            "x64": {
                "asm": "          488bcb   mov rcx, rbx\n"
                       "  4c8b0523021f00   mov r8, qword ptr [rip + 0x1f0223]\n"
                       "          41ffd0   call r8\n",
                "cost": 40,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rcx <--- rbx\n"
                                "r8 <--- rip, mem_r\n"
                                "deref <--- deref, rip, rsp\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rip, mem_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x8D\x97\x78\x01\x00\x00\x48\x8B\xE8\x41\xFF\x91\xA0\x00\x00\x00",
            "x64": {
                "asm": "    8d9778010000   lea edx, [rdi + 0x178]\n"
                       "          488be8   mov rbp, rax\n"
                       "  41ff91a0000000   call qword ptr [r9 + 0xa0]\n",
                "cost": 40,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rbp <--- rax\n"
                                "rdx <--- rdx, rdi\n"
                                "deref <--- deref, rsp, r9\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "r9, mem_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x01\xe8\xa4\xc3",
            "x64": {
                "asm": "            01e8   add eax, ebp\n"
                       "              a4   movsb byte ptr [rdi], byte ptr [rsi]\n"
                       "              c3   ret \n",
                "cost": 55,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- eax, ebp\n"
                                "rax <--- rax, ebp\n"
                                "rdi <--- rdi, eax, ebp, rsi, mem_r\n"
                                "rsi <--- rsi, eax, ebp, rdi, mem_r\n"
                                "deref <--- deref, rdi, rsi, rsp\n"
                                "mem_w <--- eax, ebp, rdi, rsi, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_0\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x00\x00\x00\x48\x8b\xd3\x48\x8b\xff\x57\x30",
            "x64": {
                "asm": "            0000   add byte ptr [rax], al\n"
                       "          00488b   add byte ptr [rax - 0x75], cl\n"
                       "          d3488b   ror dword ptr [rax - 0x75], cl\n"
                       "          ff5730   call qword ptr [rdi + 0x30]\n",
                "cost": 58,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- cl, rax, mem_r\n"
                                "deref <--- deref, rax, rdi, rsp\n"
                                "mem_w <--- cl, rax, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "mem_r, rdi\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x48\x8b\xe0\x48\x89\x74\x24\x48\x48\x83\xC4\x30\x5F\xC3",
            "x64": {
                "asm": "          488be0   mov rsp, rax\n"
                       "      4889742448   mov qword ptr [rsp + 0x48], rsi\n"
                       "        4883c430   add rsp, 0x30\n"
                       "              5f   pop rdi\n"
                       "              c3   ret \n",
                "cost": 62,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rax\n"
                                "rdi <--- rax, mem_r\n"
                                "rsp <--- rax\n"
                                "deref <--- deref, rax\n"
                                "stackOver_r <--- rax, mem_r\n"
                                "stackOver_w <--- rax, mem_r\n"
                                "stack_{-12} <--- rax, mem_r\n"
                                "stack_{-11} <--- rax, mem_r\n"
                                "stack_{-10} <--- rax, mem_r\n"
                                "stack_{-9} <--- rax, mem_r\n"
                                "stack_{-8} <--- rax, mem_r\n"
                                "stack_{-7} <--- rax, mem_r\n"
                                "stack_{-6} <--- rax, mem_r\n"
                                "stack_{-5} <--- rax, mem_r\n"
                                "stack_{-4} <--- rax, mem_r\n"
                                "stack_{-3} <--- rax, mem_r\n"
                                "stack_{-2} <--- rax, mem_r\n"
                                "stack_{-1} <--- rax, mem_r\n"
                                "stack_0 <--- rax, mem_r\n"
                                "stack_1 <--- rsi\n"
                                "stack_2 <--- rax, mem_r\n"
                                "stack_3 <--- rax, mem_r\n"
                                "stack_4 <--- rax, mem_r\n"
                                "stack_5 <--- rax, mem_r\n"
                                "stack_6 <--- rax, mem_r\n"
                                "stack_7 <--- rax, mem_r\n"
                                "stack_8 <--- rax, mem_r\n"
                                "stack_9 <--- rax, mem_r\n"
                                "stack_10 <--- rax, mem_r\n"
                                "stack_11 <--- rax, mem_r\n"
                                "stack_12 <--- rax, mem_r\n"
                                "stack_13 <--- rax, mem_r\n"
                                "stack_14 <--- rax, mem_r\n"
                                "stack_15 <--- rax, mem_r\n"
                                "stack_16 <--- rax, mem_r\n"
                                "stack_17 <--- rax, mem_r\n"
                                "stack_18 <--- rax, mem_r\n"
                                "stack_19 <--- rax, mem_r\n"
                                "stack_20 <--- rax, mem_r\n"
                                "stack_21 <--- rax, mem_r\n"
                                "stack_22 <--- rax, mem_r\n"
                                "stack_23 <--- rax, mem_r\n"
                                "stack_24 <--- rax, mem_r\n"
                                "stack_25 <--- rax, mem_r\n"
                                "stack_26 <--- rax, mem_r\n"
                                "stack_27 <--- rax, mem_r\n"
                                "stack_28 <--- rax, mem_r\n"
                                "stack_29 <--- rax, mem_r\n"
                                "stack_30 <--- rax, mem_r\n"
                                "stack_31 <--- rax, mem_r\n"
                                "stack_32 <--- rax, mem_r\n"
                                "stack_33 <--- rax, mem_r\n"
                                "stack_34 <--- rax, mem_r\n"
                                "stack_35 <--- rax, mem_r\n"
                                "stack_36 <--- rax, mem_r\n"
                                "stack_37 <--- rax, mem_r\n"
                                "stack_38 <--- rax, mem_r\n"
                                "stack_r <--- rax, mem_r\n"
                                "stack_w <--- rax, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "mem_r, rax\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x20\xB9\x02\x00\x00\x00\x48\x0B\xC2\x48\x8D\x97\x78\x01\x00\x00\x48\x8B\xE8\x41\xFF\x91\xA0\x00\x00\x00",
            "x64": {
                "asm": "    20b902000000   and byte ptr [rcx + 2], bh\n"
                       "          480bc2   or rax, rdx\n"
                       "  488d9778010000   lea rdx, [rdi + 0x178]\n"
                       "          488be8   mov rbp, rax\n"
                       "  41ff91a0000000   call qword ptr [r9 + 0xa0]\n",
                "cost": 69,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rax, rdx\n"
                                "rax <--- rax, rdx\n"
                                "rbp <--- rax, rdx\n"
                                "rdx <--- rdi\n"
                                "deref <--- deref, rcx, rsp, r9\n"
                                "mem_w <--- bh, rcx, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "r9, mem_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x00\x00\x00\xE9\x9B\xE4\xFF\xFF\x49\x8B\xC2\xE9\xB6",
            "x64": {
                "asm": "            0000   add byte ptr [rax], al\n"
                       "            00e9   add cl, ch\n"
                       "              9b   wait \n"
                       "            e4ff   in al, 0xff\n"
                       "          ff498b   dec dword ptr [rcx - 0x75]\n"
                       "          c2e9b6   ret 0xb6e9\n",
                "cost": 76,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rcx, mem_r\n"
                                "deref <--- deref, rax, rcx, rsp\n"
                                "mem_w <--- rcx, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x03\x48\x89\x58\x08\x0F\xB6\x45\x01\x41\x3B\xC2\x0F\x85",
            "x64": {
                "asm": "          034889   add ecx, dword ptr [rax - 0x77]\n"
                       "              58   pop rax\n"
                       "            080f   or byte ptr [rdi], cl\n"
                       "            b645   mov dh, 0x45\n"
                       "          01413b   add dword ptr [rcx + 0x3b], eax\n"
                       "          c20f85   ret 0x850f\n",
                "cost": 98,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rax, rcx, mem_r, stack_0\n"
                                "rax <--- stack_0\n"
                                "rcx <--- rcx, rax, mem_r\n"
                                "deref <--- deref, rax, rcx, rdi, rsp, mem_r\n"
                                "mem_w <--- rax, rcx, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "stack_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x91\x9E\xFF\x4C\x8D\x5C\x24\x60\x49\x8B\x5B\x38\x49\x8B\x6B\x40\x49\x8B\x73\x48\x49\x8B\xE3\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5F\xC3",
            "x64": {
                "asm": "              91   xchg eax, ecx\n"
                       "              9e   sahf \n"
                       "        ff4c8d5c   dec dword ptr [rbp + rcx*4 + 0x5c]\n"
                       "            2460   and al, 0x60\n"
                       "        498b5b38   mov rbx, qword ptr [r11 + 0x38]\n"
                       "        498b6b40   mov rbp, qword ptr [r11 + 0x40]\n"
                       "        498b7348   mov rsi, qword ptr [r11 + 0x48]\n"
                       "          498be3   mov rsp, r11\n"
                       "            415f   pop r15\n"
                       "            415e   pop r14\n"
                       "            415d   pop r13\n"
                       "            415c   pop r12\n"
                       "              5f   pop rdi\n"
                       "              c3   ret \n",
                "cost": 167,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- ecx\n"
                                "rax <--- rax, ecx\n"
                                "rbp <--- r11, mem_r\n"
                                "rbx <--- r11, mem_r\n"
                                "rcx <--- rcx, eax\n"
                                "rdi <--- r11, mem_r\n"
                                "rsi <--- r11, mem_r\n"
                                "rsp <--- r11\n"
                                "r12 <--- r11, mem_r\n"
                                "r13 <--- r11, mem_r\n"
                                "r14 <--- r11, mem_r\n"
                                "r15 <--- r11, mem_r\n"
                                "deref <--- deref, eax, rbp, rcx, r11\n"
                                "mem_w <--- eax, rbp, rcx, mem_r\n"
                                "stackOver_r <--- r11, mem_r\n"
                                "stackOver_w <--- r11, mem_r\n"
                                "stack_{-12} <--- r11, mem_r\n"
                                "stack_{-11} <--- r11, mem_r\n"
                                "stack_{-10} <--- r11, mem_r\n"
                                "stack_{-9} <--- r11, mem_r\n"
                                "stack_{-8} <--- r11, mem_r\n"
                                "stack_{-7} <--- r11, mem_r\n"
                                "stack_{-6} <--- r11, mem_r\n"
                                "stack_{-5} <--- r11, mem_r\n"
                                "stack_{-4} <--- r11, mem_r\n"
                                "stack_{-3} <--- r11, mem_r\n"
                                "stack_{-2} <--- r11, mem_r\n"
                                "stack_{-1} <--- r11, mem_r\n"
                                "stack_0 <--- r11, mem_r\n"
                                "stack_1 <--- r11, mem_r\n"
                                "stack_2 <--- r11, mem_r\n"
                                "stack_3 <--- r11, mem_r\n"
                                "stack_4 <--- r11, mem_r\n"
                                "stack_5 <--- r11, mem_r\n"
                                "stack_6 <--- r11, mem_r\n"
                                "stack_7 <--- r11, mem_r\n"
                                "stack_8 <--- r11, mem_r\n"
                                "stack_9 <--- r11, mem_r\n"
                                "stack_10 <--- r11, mem_r\n"
                                "stack_11 <--- r11, mem_r\n"
                                "stack_12 <--- r11, mem_r\n"
                                "stack_13 <--- r11, mem_r\n"
                                "stack_14 <--- r11, mem_r\n"
                                "stack_15 <--- r11, mem_r\n"
                                "stack_16 <--- r11, mem_r\n"
                                "stack_17 <--- r11, mem_r\n"
                                "stack_18 <--- r11, mem_r\n"
                                "stack_19 <--- r11, mem_r\n"
                                "stack_20 <--- r11, mem_r\n"
                                "stack_21 <--- r11, mem_r\n"
                                "stack_22 <--- r11, mem_r\n"
                                "stack_23 <--- r11, mem_r\n"
                                "stack_24 <--- r11, mem_r\n"
                                "stack_25 <--- r11, mem_r\n"
                                "stack_26 <--- r11, mem_r\n"
                                "stack_27 <--- r11, mem_r\n"
                                "stack_28 <--- r11, mem_r\n"
                                "stack_29 <--- r11, mem_r\n"
                                "stack_30 <--- r11, mem_r\n"
                                "stack_31 <--- r11, mem_r\n"
                                "stack_32 <--- r11, mem_r\n"
                                "stack_33 <--- r11, mem_r\n"
                                "stack_34 <--- r11, mem_r\n"
                                "stack_35 <--- r11, mem_r\n"
                                "stack_36 <--- r11, mem_r\n"
                                "stack_37 <--- r11, mem_r\n"
                                "stack_38 <--- r11, mem_r\n"
                                "stack_r <--- r11, mem_r\n"
                                "stack_w <--- r11, mem_r\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "r11, mem_r\n",
            },
        })
        TestGadget.test_cases.append({
            "bytes": b"\x41\x56\x45\x33\xc0\x48\x8b\xf9\x48\x8b\xd7\x57\x48\x8B\x91\x88\x00\x00\x00\x48\x8D\x05\x4F\x41\xF8\xFF\x48\x85\xD2\x48\x0F\x44\xD0\x48\x89\x91\x88\x00\x00\x00\x4C\x8B\xD2\x48\x81\xEA\x80\x01\x00\x00\x48\x89\x52\x18\x4C\x89\x52\x20\x41\x0F\x20\xC0\x4C\x89\x82\xC0\x01\x00\x00\x41\x0F\x20\xD0\x4C\x89\x82\xC8\x01\x00\x00\x41\x0F\x20\xD8\x4C\x89\x82\xD0\x01\x00\x00\x41\x0F\x20\xE0\x4C\x89\x82\xD8\x01\x00\x00\xc3",
            "x64": {
                "asm": "            4156   push r14\n"
                       "          4533c0   xor r8d, r8d\n"
                       "          488bf9   mov rdi, rcx\n"
                       "          488bd7   mov rdx, rdi\n"
                       "              57   push rdi\n"
                       "  488b9188000000   mov rdx, qword ptr [rcx + 0x88]\n"
                       "  488d054f41f8ff   lea rax, [rip - 0x7beb1]\n"
                       "          4885d2   test rdx, rdx\n"
                       "        480f44d0   cmove rdx, rax\n"
                       "  48899188000000   mov qword ptr [rcx + 0x88], rdx\n"
                       "          4c8bd2   mov r10, rdx\n"
                       "  4881ea80010000   sub rdx, 0x180\n"
                       "        48895218   mov qword ptr [rdx + 0x18], rdx\n"
                       "        4c895220   mov qword ptr [rdx + 0x20], r10\n"
                       "        410f20c0   mov r8, cr0\n"
                       "  4c8982c0010000   mov qword ptr [rdx + 0x1c0], r8\n"
                       "        410f20d0   mov r8, cr2\n"
                       "  4c8982c8010000   mov qword ptr [rdx + 0x1c8], r8\n"
                       "        410f20d8   mov r8, cr3\n"
                       "  4c8982d0010000   mov qword ptr [rdx + 0x1d0], r8\n"
                       "        410f20e0   mov r8, cr4\n"
                       "  4c8982d8010000   mov qword ptr [rdx + 0x1d8], r8\n"
                       "              c3   ret \n",
                "cost": 222,
                "dependencies": "\n"
                                "++++ DepMatrix ++++\n"
                                "rflags <--- rcx, rip, mem_r\n"
                                "rax <--- rip\n"
                                "rdi <--- rcx\n"
                                "rdx <--- rcx, rip, mem_r\n"
                                "r8 <--- cr4\n"
                                "r10 <--- rcx, rip, mem_r\n"
                                "deref <--- deref, rcx, rip, rsp, mem_r\n"
                                "mem_w <--- rcx, rip, cr4, mem_r\n"
                                "stack_{-1} <--- rcx\n"
                                "stack_0 <--- r14\n"
                                "\n"
                                "++++ chainCond ++++\n"
                                "rcx\n",
            },
        })

if __name__ == '__main__':
    unittest.main()
