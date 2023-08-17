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
  - [Introduction](#introduction)
  - [What obfuscation techniques I choosed](#what-obfuscation-techniques-i-choosed)
    - [Elevate local variables](#elevate-local-variables)
    - [Upgrade function arguments](#upgrade-function-arguments)
    - [Raise function return](#raise-function-return)
    - [Explode the CFG](#explode-the-cfg)
    - [Redirect function calls](#redirect-function-calls)
    - [Last step : create a new `main`](#last-step--create-a-new-main)
    - [Little note](#little-note)
    - [Gorry comparison](#gorry-comparison)
  - [Conclusion](#conclusion)

## Abbreviations

- ABI : Application Binary Interface
- CFG : Control Flow Graph

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

### Gorry comparison

Here, we could read the LLVM Intermediate Representation of the not obfuscated code first ; readable ; and the obfuscated one after.

```llvm
; ModuleID = '/mnt/c/Users/Matthieu/Documents/GitHub/simple_obfuscator/tests/article_test/src/main.c'
source_filename = "/mnt/c/Users/Matthieu/Documents/GitHub/simple_obfuscator/tests/article_test/src/main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [7 x i8] c"Little\00", align 1
@.str.1 = private unnamed_addr constant [7 x i8] c"Medium\00", align 1
@.str.2 = private unnamed_addr constant [7 x i8] c"Unknow\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @dumb(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %3 = load ptr, ptr %2, align 8
  %4 = call i64 @strlen(ptr noundef %3) #3
  switch i64 %4, label %9 [
    i64 5, label %5
    i64 10, label %7
  ]

5:                                                ; preds = %1
  %6 = call i32 @puts(ptr noundef @.str)
  br label %11

7:                                                ; preds = %1
  %8 = call i32 @puts(ptr noundef @.str.1)
  br label %11

9:                                                ; preds = %1
  %10 = call i32 @puts(ptr noundef @.str.2)
  br label %11

11:                                               ; preds = %9, %7, %5
  ret i32 0
}

; Function Attrs: nounwind willreturn memory(read)
declare i64 @strlen(ptr noundef) #1

declare i32 @puts(ptr noundef) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 noundef %0, ptr noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store i32 0, ptr %3, align 4
  store i32 %0, ptr %4, align 4
  store ptr %1, ptr %5, align 8
  %6 = load ptr, ptr %5, align 8
  %7 = getelementptr inbounds ptr, ptr %6, i64 0
  %8 = load ptr, ptr %7, align 8
  %9 = call i32 @dumb(ptr noundef %8)
  ret i32 %9
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind willreturn memory(read) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind willreturn memory(read) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 16.0.4 (https://github.com/llvm/llvm-project ae42196bc493ffe877a7e3dff8be32035dea4d07)"}
```

```llvm
; ModuleID = '/mnt/c/Users/Matthieu/Documents/GitHub/simple_obfuscator/tests/article_test/build/main.ll'
source_filename = "/mnt/c/Users/Matthieu/Documents/GitHub/simple_obfuscator/tests/article_test/src/main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [7 x i8] c"Little\00", align 1
@.str.1 = private unnamed_addr constant [7 x i8] c"Medium\00", align 1
@.str.2 = private unnamed_addr constant [7 x i8] c"Unknow\00", align 1
@dumb_local = internal global ptr null
@dumb_arg = internal global ptr null
@dumb_ret = internal global i32 0
@_local = internal global i32 0
@_local.1 = internal global i32 0
@_local.2 = internal global ptr null
@_arg = internal global i32 0
@_arg.3 = internal global ptr null
@_ret = internal global i32 0

; Function Attrs: nounwind willreturn memory(read)
declare i64 @strlen(ptr noundef) #0

declare i32 @puts(ptr noundef) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 noundef %0, ptr noundef %1) #2 {
  store i32 %0, ptr @_arg, align 4
  store ptr %1, ptr @_arg.3, align 8
  call void @1()
  %3 = load i32, ptr @_ret, align 4
  ret i32 %3
}

define internal void @0(i64 %0, i64 %1) {
  %3 = add i64 %0, %1
  switch i64 %3, label %4 [
    i64 0, label %5
    i64 1, label %6
    i64 2, label %7
    i64 3, label %8
    i64 4, label %9
    i64 5, label %10
    i64 6, label %11
    i64 7, label %12
    i64 8, label %13
    i64 9, label %14
    i64 10, label %15
    i64 11, label %16
    i64 12, label %17
    i64 13, label %18
    i64 14, label %19
    i64 15, label %20
    i64 16, label %21
    i64 17, label %22
  ]

4:                                                ; preds = %2
  ret void

5:                                                ; preds = %2
  call void @dumb.7()
  ret void

6:                                                ; preds = %2
  call void @dumb.7()
  ret void

7:                                                ; preds = %2
  call void @dumb.7()
  ret void

8:                                                ; preds = %2
  call void @dumb.7()
  ret void

9:                                                ; preds = %2
  call void @dumb.7()
  ret void

10:                                               ; preds = %2
  call void @dumb.5()
  ret void

11:                                               ; preds = %2
  call void @dumb.7()
  ret void

12:                                               ; preds = %2
  call void @dumb.7()
  ret void

13:                                               ; preds = %2
  call void @dumb.7()
  ret void

14:                                               ; preds = %2
  call void @dumb.7()
  ret void

15:                                               ; preds = %2
  call void @dumb.6()
  ret void

16:                                               ; preds = %2
  call void @dumb.7()
  ret void

17:                                               ; preds = %2
  call void @dumb.7()
  ret void

18:                                               ; preds = %2
  call void @dumb.7()
  ret void

19:                                               ; preds = %2
  call void @dumb.7()
  ret void

20:                                               ; preds = %2
  call void @dumb.8()
  ret void

21:                                               ; preds = %2
  call void @dumb.8()
  ret void

22:                                               ; preds = %2
  call void @dumb.8()
  ret void
}

define internal void @dumb.4() {
  %1 = load ptr, ptr @dumb_arg, align 8
  store ptr %1, ptr @dumb_local, align 8
  %2 = load ptr, ptr @dumb_local, align 8
  %3 = call i64 @strlen(ptr noundef %2) #3
  %4 = and i64 %3, 15
  call void @0(i64 0, i64 %4)
  ret void
}

define internal void @dumb.5() {
  %1 = call i32 @puts(ptr noundef @.str)
  call void @0(i64 15, i64 0)
  ret void
}

define internal void @dumb.6() {
  %1 = call i32 @puts(ptr noundef @.str.1)
  call void @0(i64 16, i64 0)
  ret void
}

define internal void @dumb.7() {
  %1 = call i32 @puts(ptr noundef @.str.2)
  call void @0(i64 17, i64 0)
  ret void
}

define internal void @dumb.8() {
  store i32 0, ptr @dumb_ret, align 4
  ret void
}

define internal void @1() {
  store i32 0, ptr @_local, align 4
  %1 = load i32, ptr @_arg, align 4
  store i32 %1, ptr @_local.1, align 4
  %2 = load ptr, ptr @_arg.3, align 8
  store ptr %2, ptr @_local.2, align 8
  %3 = load ptr, ptr @_local.2, align 8
  %4 = getelementptr inbounds ptr, ptr %3, i64 0
  %5 = load ptr, ptr %4, align 8
  store ptr %5, ptr @dumb_arg, align 8
  call void @dumb.4()
  %6 = load i32, ptr @dumb_ret, align 4
  store i32 %6, ptr @_ret, align 4
  ret void
}

attributes #0 = { nounwind willreturn memory(read) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind willreturn memory(read) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 16.0.4 (https://github.com/llvm/llvm-project ae42196bc493ffe877a7e3dff8be32035dea4d07)"}
```

## Conclusion

You can find the code for this obfuscation step available [here](https://github.com/aiglematth/simple_obfuscator). I trust you found this brief expedition into my basic obfuscation pass enjoyable! The code is structured in a manner that makes it easy to incorporate additional obfuscation techniques – so don't hesitate to explore further !