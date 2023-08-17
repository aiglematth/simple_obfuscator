# LLVM obfuscation pass or how to have beatiful codebase but messy binaries

## Abstract

In the world of cybersecurity, a peculiar paradox exists: malware developers craft elegant, understandable code that devolves into utter chaos after compilation and obfuscation. This blog recounts a conversation between a student (me 😁) and their reverse engineering professor, exploring how malicious coders achieve this transformation. The instructor suggested that compiler plugins play a pivotal role in the process. I was previously unfamiliar with compilation intricacies, but after my internship I learned about LLVM passes and decided to create a PoC of LLVM obfuscation pass.

## Thanks

Before delving into the intricate realm of LLVM, I wish to express my gratitude to my reverse engineering teacher : without the time he spent with me I would never have the idea to do this PoC.

## Contents
- [LLVM obfuscation pass or how to have beatiful codebase but messy binaries](#llvm-obfuscation-pass-or-how-to-have-beatiful-codebase-but-messy-binaries)
  - [Abstract](#abstract)
  - [Thanks](#thanks)
  - [Contents](#contents)
  - [Abbreviations](#abbreviations)
  - [Definitions](#definitions)
  - [Introduction](#introduction)
  - [What obfuscation techniques I choosed](#what-obfuscation-techniques-i-choosed)
    - [Elevate local variables](#elevate-local-variables)
    - [Upgrade function arguments](#upgrade-function-arguments)
    - [Raise function return](#raise-function-return)
    - [Explode the CFG](#explode-the-cfg)
    - [Redirect function calls](#redirect-function-calls)
    - [Last step : create a new `main`](#last-step--create-a-new-main)
    - [Little note](#little-note)
    - [Conclusion](#conclusion)

## Abbreviations

- ABI : Application Binary Interface
- CFG : Control Flow Graph

## Definitions

- <a name="Lifter"></a>Lifter : Software able to convert a binary to an intermediate representation.

## Introduction

While chatting with my reverse engineering instructor, he mentioned coming across a malware codebase that was exceptionally well-crafted. Curious, I inquired about the point in the process when the source code transitions into convoluted, obfuscated code. He suggested that this transformation likely occurs during compilation, possibly due to the involvement of compiler plugins. Inspired by our conversation, I'm now eager to conduct a proof of concept to gain a deeper understanding of this phenomenon.

## What obfuscation techniques I choosed

Already speaking with my instructor, he explained me that an obfuscation techniaue really time consuming for the analyst is when you break the simplicity of the control flow graph (CFG). So we will try to break it by putting all the edges in one main dispatcher. to do, we will follow the following steps :

- Elevate local variables to the status of global variables.
- Upgrade function arguments to the level of global variables.
- Raise function return values to the rank of global variables.
- Explode the function basic blocks (CFG nodes) in functions
- Redirect function calls to a fresh entry point.
- Drop all the input functions and just leave the obfuscated code.

Next, we will use this example : 
  
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int dumb(char *progname) {
    switch(strlen(progname)) {
        case 5: {
            puts("Little");
            break;
        }

        case 10: {
            puts("Medium");
            break;
        }

        default: {
            puts("Unknow");
            break;
        }

    }

    return 0;
}

int main(int argc, char **argv) {
    return dumb(argv[0]);
}
```

The CFG of the `dumb` function in the previous snippet could looks like that :

![](./images/dumb_cfg.svg "`dumb` function cfg")


### Elevate local variables

In this section, the objective is to transform local variables into global ones. This step is necessary because as we break down the basic blocks into separate functions, and these blocks share local variables, we need to discover a means of enabling variable sharing across functions. After this part, the `dumb` function looks like that :

```c
static int DUMB_GLOB_1;

int dumb(char *progname) {
    DUMB_GLOB_1 = strlen(progname);
    switch(DUMB_GLOB_1) {
        case 5: {
            puts("Little");
            break;
        }

        case 10: {
            puts("Medium");
            break;
        }

        default: {
            puts("Unknow");
            break;
        }

    }

    return 0;
}
```

### Upgrade function arguments

In this section, our aim is to convert function parameters into global variables. While not a mandatory step, disrupting the functions' ABI will force analysts to invest time in recovering them. Following this phase, the `dumb` function takes on the following appearance:

```c
static int DUMB_GLOB_1;
static char *DUMB_PARAM_1;

int dumb(void) {
    DUMB_GLOB_1 = strlen(DUMB_PARAM_1);
    switch(DUMB_GLOB_1) {
        case 5: {
            puts("Little");
            break;
        }

        case 10: {
            puts("Medium");
            break;
        }

        default: {
            puts("Unknow");
            break;
        }

    }

    return 0;
}
```

### Raise function return

In this section, our aim is to convert function returns into global variables. While not a mandatory step too, it is another time disrupting the functions' ABI to force analysts to invest time in recovering them. Following this phase, the `dumb` function takes on the following appearance:

```c
static int DUMB_GLOB_1;
static char *DUMB_PARAM_1;
static int DUMB_RET;

void dumb(void) {
    DUMB_GLOB_1 = strlen(DUMB_PARAM_1);
    switch(DUMB_GLOB_1) {
        case 5: {
            puts("Little");
            break;
        }

        case 10: {
            puts("Medium");
            break;
        }

        default: {
            puts("Unknow");
            break;
        }

    }

    DUMB_RET = 0;
}
```

### Explode the CFG

In this phase, we will enclose each basic block within a separate function. The CFG details will be incorporated into the `dispatcher` function. As a result, the `dumb` function will be structured as follows :

```c
static int DUMB_GLOB_1;
static char *DUMB_PARAM_1;
static int DUMB_RET;

void dumb_1(void) {
    DUMB_GLOB_1 = strlen(DUMB_PARAM_1);
    dispatcher(0, DUMB_GLOB_1&15)

void dumb_2(void) {
    puts("Little");
    dispatcher(0x10, 0);
}

void dumb_3(void) {
    puts("Medium");
    dispatcher(0x10, 0);
}

void dumb_4(void) {
    puts("Unknow");
    dispatcher(0x10, 0);
}

void dumb_5(void) {
    DUMB_RET = 0;
}

void dispatcher(int base, int offset) {
    switch(base + offset) {
        case 0x00: dumb_4(); break;
        case 0x01: dumb_4(); break;
        case 0x02: dumb_4(); break;
        case 0x03: dumb_4(); break;
        case 0x04: dumb_4(); break;
        case 0x05: dumb_2(); break;
        case 0x06: dumb_4(); break;
        case 0x07: dumb_4(); break;
        case 0x08: dumb_4(); break;
        case 0x09: dumb_4(); break;
        case 0x0a: dumb_3(); break;
        case 0x0b: dumb_4(); break;
        case 0x0c: dumb_4(); break;
        case 0x0d: dumb_4(); break;
        case 0x0e: dumb_4(); break;
        case 0x0f: dumb_4(); break;
        case 0x10: dumb_5(); break;
    }
}
```

### Redirect function calls

The current objective involves modifying function calls within basic blocks. For instance, in the `main` function, where we call the `dumb` function, the alteration will be executed as follows :

```c
static int DUMB_GLOB_1;
static char *DUMB_PARAM_1;
static int DUMB_RET;

static int MAIN_GLOB_1;
static int MAIN_PARAM_1;
static char **MAIN_PARAM_2;
static int MAIN_RET;


void main_1(void) {
    DUMB_PARAM_1 = MAIN_PARAM_2[0];
    dumb_1();
    MAIN_GLOB_1 = DUMB_RET;
    MAIN_RET = MAIN_GLOB_1;
}
```

### Last step : create a new `main`

Finally, we must create a new `main`, just calling the input one :

```c
int main(int argc, char **argv) {
    MAIN_PARAM_1 = argc;
    MAIN_PARAM_2 = argv;
    main_1();
    return MAIN_RET;
}
```

### Little note

It could have been feasible to also reroute function calls to the `dispatcher`, but the intention here is to employ two branching techniques that would induce a bit more frustration for the analyst 😁.

### Conclusion

You can find the code for this obfuscation step available [here](https://github.com/aiglematth/simple_obfuscator). I trust you found this brief expedition into my basic obfuscation pass enjoyable! The code is structured in a manner that makes it easy to incorporate additional obfuscation techniques – so don't hesitate to explore further !