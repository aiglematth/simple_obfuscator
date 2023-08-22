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

class Ram():

    def __init__(self, size=0x10000):
        self.current_address = toAddr(0)
        try:
            ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd(
                "PATCH_OBFUSCATION_SNIPPETS", 
                None, 
                currentProgram.getName(),
                currentProgram.getAddressFactory()
                                .getAddressSpace("ram")
                                # .getAddressSpace("OTHER")
                                .getAddress(self.current_address.getOffset()),
                size,
                True,
                True,
                True,
                False,
                0x0,
                False
            ).applyTo(currentProgram)
        except:
            instr = getInstructionAt(self.current_address)
            while instr != None:
                self.current_address = self.current_address.add(len(instr.getBytes()))
                instr = getInstructionAt(self.current_address)



    def getAvailableRam(self):
        return self.current_address

    def consumeRam(self, size):
        self.current_address = self.current_address.add(size)

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
     
    def __init__(self, entrypoint, dispatcher, ram):
        self._dispatcher = dispatcher
        self._entrypoint = entrypoint
        self._ram        = ram

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
            call_instr = getInstructionContaining(
                self._dispatcher._get_dispatcher_call(func).getPcodeOp().getSeqnum().getTarget()
            ).getPrevious()

            assembler = ghidra.app.plugin.assembler.Assemblers.getAssembler(currentProgram)

            code = []
            if len(offset) == 1:
                to_call = self._dispatcher.get(base).getEntryPoint()
                code += ["JMP 0x" + to_call.toString()]
            elif len(offset) == 2:
                while call_instr.getMnemonicString() != "CMP":
                    call_instr = call_instr.getPrevious()

                jmptype = call_instr.getNext().getMnemonicString().replace("SET", "J")
                code += [
                    jmptype + " 0x" + self._dispatcher.get(base).getEntryPoint().toString(),
                    "JMP 0x" + self._dispatcher.get(base+1).getEntryPoint().toString()
                ]
            else:
                offset = [base + o for o in offset]
                for index, dispatcher_index in enumerate(offset[:-1]):
                    to_call    = self._dispatcher.get(dispatcher_index).getEntryPoint()
                    code += [
                        "CMP RSI, " + str(index),
                        "JZ 0x" + to_call.toString(),
                    ]
                to_call = self._dispatcher.get(offset[-1]).getEntryPoint()
                code += ["JMP 0x" + to_call.toString()]

            patch_address = self._ram.getAvailableRam()
            instrs = list(assembler.assemble(patch_address, *code))
            self._ram.consumeRam(sum([len(instr.getBytes()) for instr in instrs]))
            
            call_instr.setFallThrough(patch_address)
            # assembler.assemble(call_instr.getAddress(), "JMP 0x" + patch_address.toString())

            

ram = Ram()
dispatcher = Dispatcher(getFunctionContaining(toAddr(0x101190)))

r = RecoveredFunction(getFunctionContaining(currentAddress), dispatcher, ram)