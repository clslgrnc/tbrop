[![Build Status](https://travis-ci.com/clslgrnc/tbrop.svg?branch=master)](https://travis-ci.com/clslgrnc/tbrop)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=alert_status)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=coverage)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=code_smells)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)  
[![DeepSource](https://static.deepsource.io/deepsource-badge-light.svg)](https://deepsource.io/gh/clslgrnc/tbrop/?ref=repository-badge)

# TBrop
> Taint-Based Return Oriented Programming
---

This is an implementation of the taint-based gadget management approach presented at [SSTIC](https://www.sstic.org/2018/presentation/T-Brop/) ([paper](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/T-Brop/SSTIC2018-Article-T-Brop-le-guernic_khourbiga.pdf), [slides](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/T-Brop/SSTIC2018-Slides-T-Brop-le-guernic_khourbiga.pdf), [talk](https://static.sstic.org/videos2018/SSTIC_2018-06-13_P03.mp4), in french) and [REcon](https://recon.cx/2018/montreal/schedule/events/129.html) in 2018.

This is still a PoC, and the code is still ugly as can be attested by the various badges at the top of this README.

## Background
There are roughly two kinds of tools for return oriented programming (ROP):
_syntactic_ tools that return the disassembly of gadgets and sometimes perform
template based automatic chaining, and _symbolic_ tools that compute a symbolic
representation of the output state for each gadget and allow more powerful
manipulations.
The former are very fast but only allow regex queries, the latter allow symbolic
queries but are much slower.

Taint-based ROP is an alternative approach, faster than symbolic tools and allowing more expressive queries than syntactic tools.
TBrop uses a coarse semantic of instructions. Instead of a precise symbolic I/O
relationship, it only relies on a dependency matrix reflecting how a taint would
be propagated by a given gadget.

As an example, from the following gadget:

```nasm
xchg rax, rbx
xor  rcx, rcx
add  rcx, rax
jmp  rcx
```

TBrop compute the following (sparse boolean) matrix:

|     | ... | rax | rbx | rcx | ...
|:---:|:---:|:---:|:---:|:---:|:---:
| ... |     |     |     |     |
| rax |     |  .  | <┘  |  .  |
| rbx |     | <┘  |  .  |  .  |
| rcx |     |  .  | <┘  |  .  |
| ... |     |     |     |     |

which reads as `rax` is influenced by `rbx`, `rbx` is influenced by `rax`, and `rcx` is influenced by `rbx`. The matrix also contains indices corresponding to `rip` (chain condition), some of the stack cells, and dereferencing among others.

## Getting Started

To build with docker:
```
sudo docker build -t tbrop .
```

Otherwise, just `pip install` the dependencies:
- [capstone](https://pypi.org/project/capstone/) to disassemble opcodes;
- [lief](https://pypi.org/project/lief/) to load various executable formats;
- [numpy](https://pypi.org/project/numpy/) and [scipy](https://pypi.org/project/scipy/) for sparse boolean matrices;
- [ipython](https://pypi.org/project/ipython/) if you want to use the TBrop script, as opposed to just using TBrop as a lib.
## Usage

To analyse ```/FULL/LOCAL/PATH/FILE```:
```
sudo docker run --rm -it -v /FULL/LOCAL/PATH/FILE:/app/FILE:ro tbrop /app/FILE
```

It should (eventually) bring you to an ipython shell where you can do stuff like:
```python
for g in gdgtCollection.gadgets:
  if g.gadgetMatrix.matrix[X86_REG_RSP,X86_REG_RAX] \
  and g.gadgetMatrix.chainCond[0,X86_REG_RCX]:
    print(hex(g.getAddress()),g)
```

All the gadgets are in the `gadgets` attribute of the `gdgtCollection` object (some refactoring is needed...). Each gadget as a `gadgetMatrix` attribute that can be queried in the following way:
- `g.gadgetMatrix.matrix[X86_REG_RSP,X86_REG_RAX]` is `True` if and only if there is a dependency from `X86_REG_RAX` before the execution of the gadget to `X86_REG_RSP` after its execution
- `g.gadgetMatrix.chainCond[0,X86_REG_RCX]` is `True` if and only if there is a dependency from `X86_REG_RCX` before the execution of the gadget to `rip` after its execution. In other word: if you control `rcx` before the execution of the gadget, you might be able to control its destination and chain it with other gadgets or code.

Thus, the previous snippet of code will print all gadgets that overwrite `rsp` to a value influenced by `rax` and jump to an address influenced by `rcx`.

Since we import [x86_const](https://github.com/aquynh/capstone/blob/4.0.1/bindings/python/capstone/x86_const.py), all the `X86_REG_*` can be directly used as indices to `gadgetMatrix.matrix` and `gadgetMatrix.chainCond`. Other indices can be used:
- `deref`: as an example `g.gadgetMatrix.matrix[deref,X86_REG_RAX]` selects gadgets for which a value influenced by `rax` is dereferenced;
- `memR`: as an example `g.gadgetMatrix.matrix[X86_REG_RBX, memR]` selects gadgets that modify the value of `rbx` with something taken from memory (together with `g.gadgetMatrix.matrix[deref,X86_REG_RAX]` and `g.gadgetMatrix.matrix[X86_REG_RBX,X86_REG_RAX]`, it would select gadgets that modify the value of `rbx` with something pointed to by `rax`);
- `stackTop + <integer>`: as an example `g.gadgetMatrix.matrix[X86_REG_RCX, stackTop+2]` selects gadgets that modify the value of `rcx` with something influenced by the second cell of the stack (i.e. `[rsp+0X10]`). Just make sure that `stackTop+x` is between `sF` and `sL` as the size of the pseudo-stack is limited. Negative values of `x` refer to cells out of the stack.

## When to use TBrop
When you feel desperate. Seriously, start with [rp++](https://github.com/0vercl0k/rp) or [ROPGenerator](https://github.com/Boyan-MILANOV/ropgenerator).

If you cannot grep your way out of a huge gadgets listing, or cannot express your constraints, or load your target binary, with a semantic tool, then you might want to give TBrop a try.

As an example, if you control `rip` and the buffer pointed to by `rsp+8`, TBrop might help you find a stack pivot (along with a few silly suggestions):
```nasm
mov rcx, qword ptr [rsp + 8];  # rcx now points to the buffer you control
mov byte ptr [rsp], dl;
mov rax, qword ptr [rcx];      # thus you control rax
mov rdi, rcx;
call qword ptr [rax + 0x48];   # and can jump wherever you want, while rcx points to your buffer

mov rsp, rcx;
ret
```

Another use case is if you find yourself working with an exotic architecture and do not want to encode the whole precise semantic of instructions, you can try to retrieve the taint propagation rules of instructions (with [TaintInduce](https://github.com/melynx/taintinduce) or another approach) and implement the corresponding architecture for TBrop (good luck with that).

--- 
Originally developped by [@iNod3](https://github.com/iNod3) and [@clslgrnc]() at [@DGA-MI-SSI](https://github.com/DGA-MI-SSI/T-Brop).