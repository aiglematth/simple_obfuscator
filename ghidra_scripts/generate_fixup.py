DECOMP = ghidra.app.decompiler.DecompInterface()
DECOMP.openProgram(currentProgram)

DECOMP_MAP = {}

def getHighFunction(func):
    if DECOMP_MAP.get(func) == None:
        DECOMP_MAP[func] = DECOMP.decompileFunction(func, 30, None)
    return DECOMP_MAP[func].getHighFunction()

dispatcher = getHighFunction(getFunctionContaining(currentAddress))
jumps = []
for jmp_addr in dispatcher.getJumpTables()[0].getCases()[:-1]:
    for pcode_op in dispatcher.getPcodeOps(jmp_addr):
        if pcode_op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL:
            break
    jumps.append(getFunctionContaining(pcode_op.getInput(0).getAddress()))

code = ["tmp = RDI + RSI;"]
for index, func in enumerate(jumps):
    code += ["if(!(tmp == " + str(index) + ")) goto <n" + str(index) + ">;"]
    code += ["RIP = 0x" + func.getEntryPoint().toString() + ";"]
    code += ["goto <end>;"]
    code += ["<n" + str(index) + ">"]
code += ["<end>"]
code += ["goto [RIP];"]

for line in code:
    print("      " + line)