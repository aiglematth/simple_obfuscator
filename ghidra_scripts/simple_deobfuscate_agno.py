SPEC_EXT = ghidra.program.database.SpecExtension(currentProgram)

DECOMP = ghidra.app.decompiler.DecompInterface()
DECOMP.openProgram(currentProgram)

DECOMP_MAP = {}

def getC(func):
    if DECOMP_MAP.get(func) == None:
        DECOMP_MAP[func] = DECOMP.decompileFunction(func, 30, None)
    return DECOMP_MAP[func].getDecompiledFunction().getC()

def getHighFunction(func):
    if DECOMP_MAP.get(func) == None:
        DECOMP_MAP[func] = DECOMP.decompileFunction(func, 30, None)
    return DECOMP_MAP[func].getHighFunction()

def getClangAST(func):
    if DECOMP_MAP.get(func) == None:
        DECOMP_MAP[func] = DECOMP.decompileFunction(func, 30, None)
    return DECOMP_MAP[func].getCCodeMarkup()

def getPcode(func):
    high = getHighFunction(func)
    for opcodeast in high.getPcodeOps():
        yield opcodeast

def getAddressSpace(name):
    space = currentProgram.getAddressFactory().getAddressSpace(name)
    if space == None:
        ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd(
            name, 
            None, 
            currentProgram.getName(),
            currentProgram.getAddressFactory()
                            # .getAddressSpace("ram")
                            .getAddressSpace("OTHER")
                            .getAddress(0),
            0x1,
            True,
            True,
            True,
            False,
            True
        ).applyTo(currentProgram)
    return currentProgram.getAddressFactory().getAddressSpace(name)

class Dispatcher():
      
    def __init__(self, func):
        self.func  = func
        self.entry = func.getEntryPoint()
        self.high_func = getHighFunction(func)
        self.jumps = []
        for jmp_addr in self.high_func.getJumpTables()[0].getCases()[:-1]:
            for pcode_op in self.high_func.getPcodeOps(jmp_addr):
                if pcode_op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL:
                    self.jumps.append(getFunctionContaining(pcode_op.getInput(0).getAddress()))
                    self.jumps[-1].setInline(True)
                    break;

    def get(self, offset):
        return self.jumps[offset]

    def analyze(self, func):
        node = self._get_dispatcher_call(func)
        
        if node == None: 
            return

        node_iter = iter(node)
        while True:
            n = next(node_iter)
            if n.toString() == "(":
                break

        params = [[], []]
        index  = 0
        for subnode in node_iter:
            if subnode.toString() == ",": 
                index += 1
                continue

            if subnode.toString() == "": 
                continue

            params[index].append(subnode)

        return params
    
    def get_base(self, nodes):
        for node in nodes:
            try:
                return int(node.toString(), 16)
            except:
                pass

    def get_offset(self, nodes):
        i = 0
        for index, node in enumerate(nodes):
            if node.toString() == "&":
                i = index
        return range(0, 2**self.get_base(nodes[i:]))

    def _is_dispatcher_call(self, node):
        if node.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL:
            if node.getInput(0).getAddress() == self.entry:
                return True
        return False

    def _get_dispatcher_call(self, func):
        to_traverse = [getClangAST(func)]
        while len(to_traverse) != 0:
            to_analyze = to_traverse.pop()

            for node in to_analyze:
                if isinstance(node, ghidra.app.decompiler.ClangTokenGroup):
                    to_traverse.append(node)
                
                if isinstance(node, ghidra.app.decompiler.ClangStatement):
                    if self._is_dispatcher_call(node.getPcodeOp()):
                        return node

class RecoveredFunction():
     
    def __init__(self, entrypoint, dispatcher):
        self._dispatcher = dispatcher
        self._entrypoint = entrypoint

        traversed = []
        to_traverse = [entrypoint]
        while len(to_traverse) != 0:
            to_analyze = to_traverse.pop()
            if to_analyze in traversed:
                continue
            traversed.append(to_analyze)
            self.patch(to_analyze)
            to_traverse += self.find_dispatcher_call(to_analyze)

    def find_dispatcher_call(self, func):
        childs = []
        params = self._dispatcher.analyze(func)
        
        if params == None:
            return childs

        base   = self._dispatcher.get_base(params[0])
        offset = self._dispatcher.get_offset(params[1])

        if base != None and offset != None:

            for i in [base + o for o in offset]:
                child = self._dispatcher.get(i)
                childs.append(child)
        
        return childs

    def patch(self, func):
        params = self._dispatcher.analyze(func)
        
        if params == None:
            return

        base   = self._dispatcher.get_base(params[0])
        offset = self._dispatcher.get_offset(params[1])

        if base != None and offset != None:
            callfixup_name = func.getName()
            code = [
                "<callfixup name=\"" + callfixup_name + "\">", 
                "  <pcode>", 
                "    <body><![CDATA["
            ]
            for index, dispatcher_index in enumerate([base + o for o in offset]):
                to_call    = self._dispatcher.get(dispatcher_index).getEntryPoint()
                next_label = "<next_" + str(index) + ">"
                code += [
                    "if(RSI != " + str(index) + ") goto " + next_label + ";",
                    # "RIP = 0x" + to_call.toString() + ";",
                    # "goto [RIP];",
                    "call 0x" + to_call.toString() + ";",
                    # "RIP = *RSP;",
                    # "RSP = RSP + 8;"
                    # "return [RIP];",
                    next_label
                ]
            code += [
                "    ]]></body>", 
                "  </pcode>", 
                "</callfixup>"
            ]
            print("\n".join(code))
            SPEC_EXT.addReplaceCompilerSpecExtension("\n".join(code), getMonitor())

            patched_func_name = "PATCH_" + func.getName()
            patch_space = getAddressSpace(patched_func_name)
            created_func = getFunctionContaining(patch_space.getAddress(0))
            if created_func == None:
                create_func = ghidra.app.cmd.function.CreateFunctionCmd(
                    patched_func_name,
                    patch_space.getAddress(0),
                    None,
                    ghidra.program.model.symbol.SourceType.ANALYSIS,
                    False,
                    True
                )
                create_func.applyTo(currentProgram, getMonitor())
                created_func = create_func.getFunction()
            created_func.setCallFixup(callfixup_name)
            call_instr = getInstructionContaining(
                self._dispatcher._get_dispatcher_call(func).getPcodeOp().getSeqnum().getTarget()
            )
            # print(call_instr.getAddress())
            ref = currentProgram.getReferenceManager().addMemoryReference(
                call_instr.getAddress(),
                created_func.getEntryPoint(),
                ghidra.program.model.symbol.FlowType.UNCONDITIONAL_CALL,
                ghidra.program.model.symbol.SourceType.ANALYSIS,
                ghidra.program.model.symbol.Reference.MNEMONIC
            )
            currentProgram.getReferenceManager().setPrimary(ref, True)

dispatcher = Dispatcher(getFunctionContaining(toAddr(0x101190)))

r = RecoveredFunction(getFunctionContaining(currentAddress), dispatcher)
