# Ghidra: The Deobfuscator Dragon

## Abstract

This blog post delves into the process of deobfuscating control flow graphs (CFGs) using the Ghidra tool. After previously exploring an obfuscation technique through an LLVM pass, the focus shifts to untangling the complexity introduced by obfuscation. The objective is to recover the CFG using Ghidra, while excluding the recovery of the application binary interface (ABI). Various methodologies are explored, including leveraging Ghidra's pcode, modify flow feature, and callfixup functionality. Despite attempts to achieve architecture-agnostic solutions, the complexity of the problem lead the result to an architecture-dependent approach. Ultimately, the blog post presents a solution and the recovered control flow structures, highlighting the intricate nature of Ghidra's capabilities.

## Thanks

I'd like to express my gratitude to all the individuals who provided assistance during [this conversation](https://github.com/NationalSecurityAgency/ghidra/discussions/5693).

## Contents
- [Ghidra: The Deobfuscator Dragon](#ghidra-the-deobfuscator-dragon)
  - [Abstract](#abstract)
  - [Thanks](#thanks)
  - [Contents](#contents)
  - [Abbreviations](#abbreviations)
  - [Introduction](#introduction)
  - [How to deobfuscate the CFG](#how-to-deobfuscate-the-cfg)
    - [Parse the dispatcher](#parse-the-dispatcher)
    - [Statically get offsets](#statically-get-offsets)
    - [Patch](#patch)
      - [Leverage the decompiler instance and the pcode](#leverage-the-decompiler-instance-and-the-pcode)
      - [The modify flow feature](#the-modify-flow-feature)
      - [Callfixup functionality](#callfixup-functionality)
      - [The solution](#the-solution)
    - [Results](#results)
  - [Conclusion](#conclusion)

## Abbreviations

- ABI : Application Binary Interface
- AST : Abstract Syntax Tree
- CFG : Control Flow Graph

## Introduction

In the prior [blog post](./ARTICLE.md), we developed a proof of concept illustrating an obfuscation technique through the utilization of an LLVM pass. Presently, our focus shifts to the deobfuscation phase, wherein we shall employ the Ghidra tool. While it might be straightforward to generate confusion, the process of untangling it is notably more intricate. Our attention will be directed solely towards the recovery of the control flow graph (CFG), without delving into the recovery of the application binary interface (ABI).

## How to deobfuscate the CFG

If I recall correctly, we recently divided the nodes within the control flow graph (CFG) into numerous functions, excluding those at the function entry points. Our next course of action involves employing the subsequent algorithm to restore the CFG of one function:

```python
def recoverCFG(entrypoint, parsed_dispatcher):
    traversed   = []
    to_traverse = [entrypoint]
    while len(to_analyze) != 0:
        entry = to_traverse.pop()
        if entry in traversed:
            continue
        traversed.append(entry)
        patch(entry, parsed_dispatcher)
        for offset in get_offsets_from(entry):
            to_traverse.append(parsed_dispatcher[offset])
```

As evident, our approach hinges on three key elements:
- The `parsed_dispatcher` array, which holds the function targets corresponding to each parsed offset.
- The `get_offsets_from` function, tasked with statically identifying all potential jump targets.
- The `patch` function, responsible for generating code fragments to redirect the CFG and mend the given entry.

Subsequently, we will delve into the precise operational mechanisms of these functions.

### Parse the dispatcher

If I recall correctly, the `dispatcher` essentially takes the form of a switch function, resembling the following structure:

```c
void dispatcher(int base, int offset) {
    switch(base + offset) {
        case 0: {
            block0();
            break;
        }
        /* [...] */
        case N: {
            blockN();
            break;
        }
    }
}
```

By employing the `getJumpTables` method from the [HighFunction](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html) class within Ghidra, applied to the `dispatcher` function, we can gather the jump targets as inferred by the decompilation analysis.

### Statically get offsets

The `dispatcher` is invoked at the conclusion of the function-wrapped basic block when the respective basic block node contains child nodes. The supplied `base` argument to the `dispatcher` function is a constant, and there exist multiple approaches to acquire it:

- Retrieving the constant from the register or stack location designated by the ABI to store the initial argument of the `dispatcher`.
- Analyzing the Abstract Syntax Tree (AST) of the pseudo-C decompiled code to find the `dispatcher` call first argument.

Regarding the `offset` argument, two scenarios emerge: it could either be 0, indicating that the basic block has only one child, or the value might be restricted by a binary AND operation. In the former case, similar techniques as those used for the `base` argument could be applied. In the latter case, retrieving the constant employed for the binary AND operation can be accomplished by:

- Extracting the constant from the binary AND operation within the assembly code.
- Scrutinizing the Abstract Syntax Tree (AST) of the pseudo-C decompiled code to locate the second argument of the `dispatcher` call, and subsequently parsing it to isolate the constant.

To sum up, in both scenarios, we can utilize the C Abstract Syntax Tree (AST) to extract the necessary information. Given my lack of prior experience with it, and considering its architecture-agnostic nature, I will opt to utilize the AST for our purposes.

By utilizing the `getCCodeMarkup` method provided by the [DecompileResults](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileResults.html) class in Ghidra, which is applied to the target function under analysis, we can access and examine the C Abstract Syntax Tree (AST).

As an example, if the call looks like that :

```c
dispatcher(16, (rax == 2 ^ 0xff) & 1);
```

We have the ability to extract the constant base, which is 16, and the binary AND constant, which is 1. With this pairing of values, we ascertain that the potential targets within the dispatcher switch case can be either 16 or 17, given that the offset lies between 0 and 1.

### Patch 

In my attempt to refine the CFG, I delved into a range of concepts. Nevertheless, the majority of these concepts either exhibited excessive complexity or were unviable given the current version of Ghidra. I considered several different approaches:

- Exploiting the pcode, which constitutes the intermediary representation employed by Ghidra during the decompilation process.
- Engaging the modify flow feature.
- Utilizing the callfixup functionality.

The overarching objective behind these ideas was to achieve architecture-agnostic modifications. Regrettably, I encountered setbacks in all of these avenues. I will proceed to elucidate the reasons for these challenges.

#### Leverage the decompiler instance and the pcode

The first idea was basically to modify the pcode of the program. The following snippet show the x64 CALL instruction and its corresponding pcode :

```
CALL dispatcher
    RSP  =  INT_SUB  RSP , 8:8
    STORE  ram (RSP ), 0x101285 :8
    CALL  *[ram ]0x101190 :8
```

As evident, the CALL instruction comprises three pcode operations. The initial two operations involve pushing the address of the subsequent instruction, while the third involves the actual call to the `dispatcher`, situated at memory address 0x101190. Given the nature of the call pcode operation, my initial notion involved substituting it with a sequence of comparisons and conditional jumps. As an illustration, supposing this call could potentially target addresses ADDR1 and ADDR2, the adjusted pcode would be structured in the following manner:

```
if(RSI == 0) goto ADDR1;
goto ADDR2;
```

However, the primary challenge emerges in the process of injecting these instructions. This task appears feasible only if we were to establish our own language and craft a customized [PcodeInjectLibrary](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/PcodeInjectLibrary.html). For a practical demonstration of this approach, you might find value in reading [this blogpost](https://swarm.ptsecurity.com/guide-to-p-code-injection/). Nevertheless, the prospect of implementing an entire language purely to deobfuscate a specific program appears excessively intricate. Alternatively, one could contemplate employing less straightforward methods, such as delving into unconventional practices like hooking the decompiler with personalized callbacks – a route that is both complicated and potentially precarious. We need to find other ideas...

#### The modify flow feature

Indeed, Ghidra provides a functionality that enables the modification of a call instruction's behavior. For instance, it allows transforming a call instruction to function as if it were a branch instruction. A potential approach could involve altering all calls to the `dispatcher` and in the `dispatcher` into branches. Subsequently, by relying on the decompilation optimizations, the decompiled code could potentially be clarified and streamlined. Regrettably, the outcomes yielded by this approach did not meet the desired level of satisfaction. For example, the following C source code was decompiled like that :

- C function before compilation

```c
int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage : %s LICENSE_KEY\n", argv[0]);
        return 1;
    }
    check(argv[1]);
    puts("Great");
    return 0;
}
```

- deobfuscated C function

```c
undefined8 __unnamed_1(void)

{
  undefined8 uVar1;
  byte bVar2;
  ulong uVar3;
  long *plVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  ulong uVar7;
  long lVar8;
  ulong auStack_60 [6];
  long alStack_30 [6];
  
  _local = 0;
  _local.7 = _arg;
  _local.8 = _arg.9;
  bVar2 = (_arg != 2 ^ 0xffU) & 1;
  uVar3 = (ulong)bVar2;
  uVar7 = (ulong)bVar2;
  lVar8 = 9;
  plVar4 = alStack_30 + 4;
  alStack_30[4] = 0x101452;
  while( true ) {
    *(ulong *)((long)plVar4 + -8) = uVar3;
    *(ulong *)((long)plVar4 + -8) = lVar8 + uVar7;
    if (0xc < lVar8 + uVar7) break;
    lVar8 = (long)&switchD_001011b7::switchdataD_00102004 +
            (long)(int)(&switchD_001011b7::switchdataD_00102004)[*(long *)((long)plVar4 + -8)];
    switch(lVar8) {
    case 0x1011fa:
      *(undefined8 *)((long)plVar4 + -0x10) = 0x1011ff;
      *(long *)((long)plVar4 + -0x18) = lVar8;
      uVar1 = *_local.8;
      *(undefined8 *)((long)plVar4 + -0x20) = 0x101479;
      printf("Usage : %s LICENSE_KEY\n",uVar1);
      _local = 1;
      lVar8 = 0xb;
      uVar3 = 0;
      uVar7 = 0;
      puVar5 = (undefined8 *)((long)plVar4 + -0x20);
      plVar4 = (long *)((long)plVar4 + -0x20);
      *puVar5 = 0x101491;
      break;
    case 0x101201:
      *(undefined8 *)((long)plVar4 + -0x10) = 0x101206;
      *(long *)((long)plVar4 + -0x18) = lVar8;
      check_arg = _local.8[1];
      *(undefined8 *)((long)plVar4 + -0x20) = 0x1014b8;
      check.13();
      *(undefined8 *)((long)plVar4 + -0x20) = 0x1014c4;
      puts("Great");
      _local = 0;
      lVar8 = 0xc;
      uVar3 = 0;
      uVar7 = 0;
      puVar6 = (undefined8 *)((long)plVar4 + -0x20);
      plVar4 = (long *)((long)plVar4 + -0x20);
      *puVar6 = 0x1014dc;
    }
  }
  return *(undefined8 *)((long)plVar4 + -8);
}
```

#### Callfixup functionality

Ghidra offers a highly effective method for altering the behavior of a function through the use of callfixups. Essentially, this involves a set of static pcode operations that replace the function's original body. This concept aligns with the earlier notion but differs in that the pcode is not generated dynamically but rather statically. Given this insight, we can contemplate the following algorithm as a means to patch the binary:

```python
def patch(func, parsed_dispatcher)
    callfixup      = generate_fixup(func, parsed_dispatcher)
    callfixup_func = createFunction()
    callfixup_func.applyFixup(callfixup)
    getCallToDispatcher(func).addReferenceTo(callfixup_func)    
```

As evident, this algorithm's role is to generate the code snippet responsible for constituting CFG edges. Subsequently, an empty function is generated, which serves as the container for the CFG edges' body. Finally, the call to the dispatcher is replaced with a call to the previously created function. I did two versions of the `generate_fixup` function:

The initial version involved branching to the basic block-wrapped functions.
```python
def generate_fixup(func, parsed_dispatcher):
    fixup = ""
    for i, offset in enumerate(get_offsets_from(entry)):
        fixup += f"if(RSI == {i}) goto {parsed_dispatcher[offset].getEntrypoint()}\n"
    return fixup
```
Unfortunately, this fixup was not correctly jumping to the basic blocks. For example, for this fixup :

```xml
<callfixup name="__unnamed_1">
  <pcode>
    <body><![CDATA[
      if(RSI == 0) goto <next_0>;
      RIP = 0x00101460;
      goto [RIP];
      <next_0>
      if(RSI == 1) goto <next_1>;
      RIP = 0x001014a0;
      goto [RIP];
      <next_1>
    ]]></body>
  </pcode>
</callfixup>
```

The first basic block recovered for the previously showed `main` is the following :

```c
ulong __unnamed_1(void)

{
  byte bVar1;
  
  _local = 0;
  _local.7 = _arg;
  _local.8 = _arg.9;
  bVar1 = (_arg != 2 ^ 0xffU) & 1;
  if (bVar1 != 0) {    /////////////////////////////////
    if (bVar1 != 1) {  // The problem is located here // 
      return 0x101452; //                             //
    }                  /////////////////////////////////
  }
                    /* WARNING: This code block may not be properly labeled as switch case */
  printf("Usage : %s LICENSE_KEY\n",*_arg.9);
  _local = 1;
  dispatcher(0xb,0);
  return (ulong)bVar1;
}
```

As you can see, we recover only one branch of the CFG (the one when argc != 2). I guess this is a problem because I am jumping on functions, which imply a return operation. So the second version involved invoking the basic block-wrapped functions directly. This approach capitalized on Ghidra's inline feature, which essentially entails embedding the pcode of a function directly into the caller's codebase.
```python
def generate_fixup(func, parsed_dispatcher):
    fixup = ""
    for i, offset in enumerate(get_offsets_from(entry)):
        fixup += f"if(RSI == {i}) goto {parsed_dispatcher[offset].getEntrypoint()}\n"
    return fixup
```

Regrettably, this time the manner in which the decompiler inlines the functions does not align with my requirements. This becomes evident through the following example fixup:

```xml
<callfixup name="__unnamed_1">
  <pcode>
    <body><![CDATA[
      if(RSI != 0) goto <next_0>;
      call 0x00101460;
      <next_0>
      if(RSI != 1) goto <next_1>;
      call 0x001014a0;
      <next_1>
    ]]></body>
  </pcode>
</callfixup>
```

The decompiled C is the following :

```c
undefined8 __unnamed_1(void)

{
  undefined8 *puVar1;
  ulong uVar2;
  undefined8 uStack_10;
  undefined auStack_8 [8];
  
  _local = 0;
  _local.7 = _arg;
  _local.8 = _arg.9;
  uVar2 = (ulong)((_arg != 2 ^ 0xffU) & 1);
                    /* WARNING: Return address prevents inlining here */
                    /* WARNING: Could not inline here */
  uStack_10 = 0x101452;
  puVar1 = &uStack_10;
  if (uVar2 == 0) {
    __unnamed_3(9);
    puVar1 = (undefined8 *)auStack_8;
  }
  if (uVar2 == 1) {
    __unnamed_4();
    puVar1 = (undefined8 *)((long)puVar1 + 8);
  }
  return *puVar1;
}
```

This time, the issue boils down to a concise statement: "Return address prevents inlining here." The decompiler's prerequisites for inlining a function involve the following conditions, as indicated by [this comment](https://github.com/NationalSecurityAgency/ghidra/blob/ba5fcdf4ede478ba1d394cc1efa7802099023510/Ghidra/Features/Decompiler/src/decompile/cpp/flow.cc#L1085):

- The function can only be inlined once.
- There must exist a p-code operation to return to.
- A distinct return address is necessary for the replacement of RETURN with BRANCH.

From your analysis, it seems that due to the absence of actual instructions associated with the p-code body I'm generating for a function, I lack a *distinct return address* as mandated by the third requirement. Consequently, this solution proves to be unsatisfactory.

#### The solution

In the end, I made the decision to embrace an architecture-dependent solution. If you possess a functional Proof of Concept (PoC) that accomplishes my goal in an architecture-agnostic manner, or if you've identified any flaws in my methodology, I invite you to reach out. I'm genuinely enthusiastic about the prospect of finding a solution, and I'm open to collaboration and assistance. Feel free to contact me with any insights or ideas you might have.

For the solution, we will adopt a similar methodology to that of the callfixup approach, but with the implementation of the fixup function in x64 assembly. Additionally, we will make use of Ghidra's fallthrough feature to split the basic block right after the CMP operation, if one exists.


### Results

For the following program :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char c, char high, char low) {
    if(((c & 0xf) ^ low) | ((c >> 4) ^ high)) {
        exit(1);
    }
    return;
}

int check(char *licence_key) {
    char key[14] = {0x7, 0x4, 0x6, 0x8, 0x6, 0x5, 0x5, 0xf, 0x6, 0xb, 0x6, 0x5, 0x7, 0x9};

    if(strlen(licence_key) != 7) {
        exit(1);
    }

    for(int i=0; i<sizeof(key)/2; i++) {
        trigger(licence_key[i], key[2*i], key[2*i+1]);
    }

    return 0;
}

int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage : %s LICENSE_KEY\n", argv[0]);
        return 1;
    }
    check(argv[1]);
    puts("Great");
    return 0;
}
```

- The obfuscated `main` is the following :

```c
undefined8 __unnamed_1(void)

{
  undefined8 in_RAX;
  
  _local = 0;
  _local.7 = _arg;
  _local.8 = _arg.9;
  dispatcher(9,(_arg != 2 ^ 0xffU) & 1);
  return in_RAX;
}
```

- The recovered `main` is the following :

```c
void __unnamed_1(void)

{
  bool bVar1;
  
  _local = 0;
  _local.7 = _arg;
  _local.8 = _arg.9;
  bVar1 = _arg != 2;
  if (bVar1) {
    printf("Usage : %s LICENSE_KEY\n",*_arg.9);
  }
  else {
    check_arg = _arg.9[1];
    check.13();
    puts("Great");
  }
  _local = (uint)bVar1;
  _ret = _local;
  return;
}
```

- The obfuscated `check` is the following :

```c
undefined8 check.13(void)

{
  undefined8 in_RAX;
  long lVar1;
  
  check_local = check_arg;
  check_local.5._0_8_ = 0xf05050608060407;
  check_local.5._8_4_ = 0x5060b06;
  check_local.5._12_2_ = 0x907;
  lVar1 = strlen(check_arg);
  dispatcher(2,(lVar1 != 7 ^ 0xffU) & 1);
  return in_RAX;
}
```

- The recovered `check` is the following :

```c
void check.13(void)

{
  long lVar1;
  long *plVar2;
  undefined *puVar3;
  undefined8 *puVar4;
  undefined8 uVar5;
  long lStack_10;
  undefined auStack_8 [8];
  
  plVar2 = (long *)auStack_8;
  check_local = check_arg;
  check_local.5._0_8_ = 0xf05050608060407;
  check_local.5._8_4_ = 0x5060b06;
  check_local.5._12_2_ = 0x907;
  lStack_10 = 0x1012f3;
  lVar1 = strlen(check_arg);
  if (lVar1 == 7) {
    uVar5 = 7;
  }
  else {
    plVar2 = &lStack_10;
    lStack_10 = lVar1;
    uVar5 = exit(1);
  }
  puVar3 = (undefined *)((long)plVar2 + -8);
  *(undefined8 *)((long)plVar2 + -8) = uVar5;
  check_local.6 = 0;
  uVar5 = 4;
  while( true ) {
    *(undefined8 *)(puVar3 + -8) = 0;
    if (6 < (ulong)(long)check_local.6) break;
    *(long *)(puVar3 + -0x10) = (long)check_local.6;
    trigger_arg = *(undefined *)(check_local + check_local.6);
    trigger_arg.3 = check_local.5[check_local.6 << 1];
    trigger_arg.4 = check_local.5[check_local.6 * 2 + 1];
    *(undefined8 *)(puVar3 + -0x18) = 0x1013c8;
    trigger.10(uVar5);
    puVar4 = (undefined8 *)(puVar3 + -0x18);
    puVar3 = puVar3 + -0x18;
    *puVar4 = 0;
    check_local.6 = check_local.6 + 1;
    uVar5 = 8;
  }
  check_ret = 0;
  return;
}
```

- The obfuscated `trigger` is the following :

```c
undefined8 trigger.10(void)

{
  undefined8 in_RAX;
  
  trigger_local = trigger_arg;
  trigger_local.1 = trigger_arg.3;
  trigger_local.2 = trigger_arg.4;
  dispatcher(0,((byte)(trigger_arg & 0xf ^ trigger_arg.4 | (char)trigger_arg >> 4 ^ trigger_arg. 3)
                 != 0 ^ 0xffU) & 1);
  return in_RAX;
}
```

- The recovered `trigger` is the following :

```c
void trigger.10(void)

{
  trigger_local = trigger_arg;
  trigger_local.1 = trigger_arg.3;
  trigger_local.2 = trigger_arg.4;
  if ((byte)(trigger_arg & 0xf ^ trigger_arg.4 | (char)trigger_arg >> 4 ^ trigger_arg.3) != 0) {
    exit(1);
  }
  return;
}
```

As you can see, we are recovering the important control flow structures :
- The if/else in the `main`
- The if/else and the loop in the `check`
- The if/else in the `trigger`

## Conclusion

You can find the code for this deobfuscation step available [here](./../ghidra_scripts/simple_deobfuscate.py) and the agnostic version [here](./../ghidra_scripts/simple_deobfuscate_agno.py). Ghidra is quite intricate, and I'm really keen on delving into its inner workings to gain a comprehensive understanding. At the moment, I'm far from being a Ghidra expert. I trust you've found this short exploration of my initial foray into deobfuscation rather enjoyable!