// Export an analyzed program into streaming JSON Lines.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import com.google.gson.Gson;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.BufferedWriter;
import java.util.*;

public class PistonExport extends GhidraScript {
    private final Map<String,Map<String,Object>> tables = new LinkedHashMap<>();
    private long pointerAt(ghidra.program.model.address.Address address) throws Exception {
        return currentProgram.getDefaultPointerSize()==8 ? getLong(address) : Integer.toUnsignedLong(getInt(address));
    }
    private String adjustorTarget(Function function) {
        if(!currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86")) return "";
        var instructions=currentProgram.getListing().getInstructions(function.getBody(),true);
        boolean adjusted=false;String target="";int count=0;
        while(instructions.hasNext()) {
            var instruction=instructions.next();if(++count>5)return "";
            String mnemonic=instruction.getMnemonicString().toUpperCase(Locale.ROOT);
            if(mnemonic.equals("ENDBR64") || mnemonic.equals("NOP"))continue;
            if((mnemonic.equals("ADD") || mnemonic.equals("SUB")) && !adjusted && target.isEmpty()) {
                var register=instruction.getRegister(0);var scalar=instruction.getScalar(1);
                if(register==null || scalar==null || !(register.getName().equalsIgnoreCase("RDI") || register.getName().equalsIgnoreCase("RCX")))return "";
                adjusted=true;continue;
            }
            if(mnemonic.equals("JMP") && adjusted && target.isEmpty() && instruction.getFlows().length==1) {
                var address=instruction.getFlows()[0];
                if(currentProgram.getFunctionManager().getFunctionAt(address)==null)return "";
                target=address.toString();continue;
            }
            return "";
        }
        return target;
    }
    private Map<String,Object> rttiEvidence(ghidra.program.model.address.Address address) {
        Map<String,Object> result=new LinkedHashMap<>();
        try {
            int width=currentProgram.getDefaultPointerSize();
            var symbol=currentProgram.getSymbolTable().getPrimarySymbol(address);
            String name=symbol==null?"":symbol.getName(true);
            result.put("symbol",name);result.put("address",address.toString());
            // Restrict ABI decoding to identified Itanium typeinfo. Stripped tables remain candidates.
            if(!name.contains("typeinfo") && !name.contains("_ZTI")) return result;
            var nameAddress=toAddr(pointerAt(address.add(width)));
            StringBuilder encoded=new StringBuilder();
            for(int i=0;i<512;i++) {int c=Byte.toUnsignedInt(getByte(nameAddress.add(i)));if(c==0)break;if(c<32 || c>126)break;encoded.append((char)c);}
            result.put("encoded_type_name",encoded.toString());
            var abiVptr=toAddr(pointerAt(address));
            var abiSymbol=currentProgram.getSymbolTable().getPrimarySymbol(abiVptr);
            if(abiSymbol==null || !abiSymbol.getName(true).contains("class_type_info")) abiSymbol=currentProgram.getSymbolTable().getPrimarySymbol(abiVptr.subtract(2L*width));
            if(abiSymbol==null || !abiSymbol.getName(true).contains("class_type_info")) for(var reference:currentProgram.getReferenceManager().getReferencesFrom(address)) {
                var candidate=currentProgram.getSymbolTable().getPrimarySymbol(reference.getToAddress());
                if(candidate!=null && candidate.getName(true).contains("class_type_info")) {abiSymbol=candidate;break;}
            }
            String abi=abiSymbol==null?"":abiSymbol.getName(true);
            result.put("abi_type_symbol",abi);
            List<Map<String,Object>> bases=new ArrayList<>();
            if(abi.contains("__si_class_type_info")) {
                bases.add(Map.of("typeinfo",toAddr(pointerAt(address.add(2L*width))).toString(),"kind","single_nonvirtual_base"));
            } else if(abi.contains("__vmi_class_type_info")) {
                int count=getInt(address.add(2L*width+4));
                if(count<0 || count>64) return result;
                for(int index=0;index<count;index++) {
                    var entry=address.add(2L*width+8+index*2L*width);
                    long flags=pointerAt(entry.add(width));if(width==4) flags=(int)flags;
                    boolean virtual=(flags&1)!=0;
                    bases.add(Map.of("typeinfo",toAddr(pointerAt(entry)).toString(),"virtual",virtual,"public",(flags&2)!=0,"offset",flags>>8,"offset_kind",virtual?"vtable_offset_location":"subobject_offset"));
                }
            }
            result.put("bases",bases);
        } catch(Exception error) {result.put("partial",true);}
        return result;
    }
    private void discoverTables() throws Exception {
        int width=currentProgram.getDefaultPointerSize();
        // Pointer runs are candidates, not proof of a C++ vtable. Bound work per block.
        for(var block:currentProgram.getMemory().getBlocks()) {
            if(!block.isInitialized() || block.isExecute() || !block.isRead()) continue;
            long length=Math.min(block.getSize(),32L*1024*1024);
            for(long offset=0;offset+width<=length && tables.size()<4096;offset+=width) {
                monitor.checkCancelled();
                var start=block.getStart().add(offset);var cursor=start;
                List<Map<String,Object>> slots=new ArrayList<>();
                for(int slot=0;slot<128 && block.contains(cursor.add(width-1));slot++,cursor=cursor.add(width)) {
                    var target=toAddr(pointerAt(cursor));
                    Function method=currentProgram.getFunctionManager().getFunctionAt(target);
                    if(method==null || method.isExternal()) break;
                    slots.add(Map.of("offset",slot*width,"target",target.toString(),"symbol",method.getName(true)));
                }
                if(slots.size()<2) continue;
                Map<String,Object> table=new LinkedHashMap<>();
                table.put("address",start.toString());table.put("slots",slots);table.put("classification","pointer_table_candidate");
                var symbol=currentProgram.getSymbolTable().getPrimarySymbol(start);
                table.put("symbol",symbol==null?"":symbol.getName(true));
                if(offset>=2L*width) {
                    long top=pointerAt(start.subtract(2L*width));
                    if(width==4) top=(int)top;
                    var rtti=toAddr(pointerAt(start.subtract(width)));
                    var rttiBlock=currentProgram.getMemory().getBlock(rtti);
                    if(top<=0 && top>=-1048576 && rttiBlock!=null && !rttiBlock.isExecute()) {
                        table.put("itanium_offset_to_top_candidate",top);table.put("rtti_address",rtti.toString());
                        var rs=currentProgram.getSymbolTable().getPrimarySymbol(rtti);
                        table.put("rtti_symbol",rs==null?"":rs.getName(true));
                        table.put("rtti",rttiEvidence(rtti));
                    }
                }
                tables.put(start.toString(),table);offset+=(slots.size()-1L)*width;
            }
        }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected export path");
        Map<String,Object> metadata = new LinkedHashMap<>();
        metadata.put("image_base", currentProgram.getImageBase().getOffset());
        metadata.put("pointer_width", currentProgram.getDefaultPointerSize());
        metadata.put("ghidra_version", ghidra.framework.Application.getApplicationVersion());
        metadata.put("exporter_version", "pistondecompiler-export-v2");
        metadata.put("language", currentProgram.getLanguageID().toString());
        metadata.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        metadata.put("decompiler_timeout_seconds", 60);
        Files.writeString(Path.of(args[0].replaceFirst("\\.[^.]+$", "") + ".metadata.json"), new Gson().toJson(metadata), StandardCharsets.UTF_8);
        discoverTables();
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Cannot open decompiler");
        Gson gson = new Gson();
        try (BufferedWriter out = Files.newBufferedWriter(Path.of(args[0]), StandardCharsets.UTF_8)) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            int completed = 0;
            int total = currentProgram.getFunctionManager().getFunctionCount();
            long lastProgress = 0;
            Path progress = Path.of(args[0] + ".progress.json");
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                if (System.currentTimeMillis() - lastProgress >= 1000) {
                    Path temporary = Path.of(progress + ".tmp");
                    Files.writeString(temporary, gson.toJson(Map.of("completed", completed, "total", total, "function", function.getName())), StandardCharsets.UTF_8);
                    Files.move(temporary, progress, StandardCopyOption.REPLACE_EXISTING);
                    lastProgress = System.currentTimeMillis();
                }
                Map<String,Object> row = new LinkedHashMap<>();
                row.put("address", function.getEntryPoint().toString());
                row.put("name", function.getName());
                Map<String,Object> typeContext=new LinkedHashMap<>();
                typeContext.put("prototype",function.getPrototypeString(true,true));
                typeContext.put("namespace",function.getParentNamespace().getName(true));
                typeContext.put("calling_convention",function.getCallingConventionName());
                typeContext.put("pointer_width",currentProgram.getDefaultPointerSize());
                List<String> typeDescriptions=new ArrayList<>();
                List<String> recoveredLayouts=new ArrayList<>();
                for(Parameter parameter:function.getParameters()) {
                    var type=parameter.getDataType();
                    for(int depth=0;depth<8 && type instanceof ghidra.program.model.data.Pointer;depth++) type=((ghidra.program.model.data.Pointer)type).getDataType();
                    if(type!=null) {
                        typeDescriptions.add(type.toString());
                        String layout=currentProgram.getOptions("Piston C++ layouts").getString(type.getName(),"");
                        if(!layout.isEmpty()) recoveredLayouts.add(layout);
                    }
                }
                typeContext.put("parameter_definitions",typeDescriptions);
                typeContext.put("class_layouts",recoveredLayouts);
                typeContext.put("return_type",function.getReturnType().toString());

                row.put("comment", Objects.toString(function.getComment(), ""));
                row.put("size", function.getBody().getNumAddresses());
                row.put("thunk", function.isThunk());
                row.put("external", function.isExternal());
                Function thunkTarget = function.getThunkedFunction(true);
                row.put("external_thunk", thunkTarget != null && thunkTarget.isExternal());
                var memoryBlock = currentProgram.getMemory().getBlock(function.getEntryPoint());
                row.put("executable", memoryBlock != null && memoryBlock.isExecute());
                var result = decompiler.decompileFunction(function, 60, monitor);
                row.put("pseudocode", result.decompileCompleted() ? result.getDecompiledFunction().getC() : "");
                Map<String,Object> cpp=new LinkedHashMap<>();
                cpp.put("qualified_symbol",function.getName(true));
                cpp.put("symbol_aliases",Arrays.stream(currentProgram.getSymbolTable().getSymbols(function.getEntryPoint())).map(symbol->Map.of("name",symbol.getName(true),"source",symbol.getSource().toString())).toList());
                cpp.put("thunk_target",function.getThunkedFunction(true)==null?adjustorTarget(function):function.getThunkedFunction(true).getEntryPoint().toString());
                List<Map<String,Object>> locals=new ArrayList<>();
                if(result.getHighFunction()!=null) {
                    var symbols=result.getHighFunction().getLocalSymbolMap().getSymbols();
                    while(symbols.hasNext()) {
                        var symbol=symbols.next();
                        if(symbol.isParameter()) continue;
                        locals.add(Map.of("name",symbol.getName(),"storage",symbol.getStorage().toString(),"first_use",symbol.getPCAddress()==null?"":symbol.getPCAddress().toString(),"type",symbol.getDataType().toString()));
                    }
                }
                cpp.put("locals",locals);
                Set<String> referencedTables=new TreeSet<>();
                List<Map<String,Object>> indirect=new ArrayList<>();
                List<Map<String,Object>> stores=new ArrayList<>();
                Set<String> callees = new TreeSet<>();
                Set<String> imports = new TreeSet<>();
                Set<String> strings = new TreeSet<>();
                for (Function callee : function.getCalledFunctions(monitor)) {
                    callees.add(callee.getEntryPoint().toString());
                    if (callee.isExternal() || callee.isThunk()) imports.add(callee.getName());
                }
                StringBuilder disassembly = new StringBuilder();
                StringBuilder pcode = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructions.next();
                    if (disassembly.length() < 100000) disassembly.append(instruction.getAddress()).append(": ").append(instruction).append('\n');
                    if (pcode.length() < 100000) for (var op : instruction.getPcode()) pcode.append(op).append('\n');
                    if(instruction.getFlowType().isCall() && instruction.getFlowType().isComputed())
                        indirect.add(Map.of("site",instruction.getAddress().toString(),"instruction",instruction.toString()));
                    for(var op:instruction.getPcode()) if(op.getOpcode()==ghidra.program.model.pcode.PcodeOp.STORE && stores.size()<128)
                        stores.add(Map.of("site",instruction.getAddress().toString(),"pcode",op.toString()));
                    for (Reference ref : instruction.getReferencesFrom()) {
                        String direct=ref.getToAddress().toString();
                        String header=ref.getToAddress().add(2L*currentProgram.getDefaultPointerSize()).toString();
                        if(tables.containsKey(direct)) referencedTables.add(direct);
                        if(tables.containsKey(header)) referencedTables.add(header);
                        Data data = currentProgram.getListing().getDataAt(ref.getToAddress());
                        if (data != null && data.hasStringValue() && strings.size() < 256) strings.add(String.valueOf(data.getValue()));
                    }
                }
                for(var entry:tables.entrySet()) {
                    @SuppressWarnings("unchecked") var slots=(List<Map<String,Object>>)entry.getValue().get("slots");
                    if(slots.stream().anyMatch(slot->slot.get("target").equals(function.getEntryPoint().toString()))) referencedTables.add(entry.getKey());
                }
                cpp.put("vtables",referencedTables.stream().limit(64).map(tables::get).toList());
                cpp.put("indirect_calls",indirect);cpp.put("stores",stores);
                cpp.put("constructor_destructor_candidate",!referencedTables.isEmpty() && !stores.isEmpty());
                cpp.put("wrapper_candidate",function.isThunk() || (callees.size()==1 && function.getBody().getNumAddresses()<64));
                cpp.put("rtti_and_symbols_are_hints",true);
                typeContext.put("cpp",cpp);
                row.put("type_context",new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(typeContext));
                row.put("callees", callees);
                row.put("imports", imports);
                row.put("strings", strings);
                row.put("disassembly", disassembly.toString());
                row.put("pcode", pcode.toString());
                out.write(gson.toJson(row));
                out.newLine();
                completed++;
            }
            monitor.checkCancelled();
        } finally { decompiler.dispose(); }
    }
}
