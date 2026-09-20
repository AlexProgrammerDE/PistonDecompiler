// Preview and apply structured type plans in one program transaction.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;

public class PistonTypes extends GhidraScript {
    private final Gson gson = new GsonBuilder().serializeNulls().create();
    private final CategoryPath category = new CategoryPath("/PistonRecovered");
    private final Map<String,DataType> types = new HashMap<>();
    private DataTypeManager manager;
    private JsonObject trialReport;

    private DataType resolve(JsonObject ref) throws Exception {
        switch (ref.get("kind").getAsString()) {
            case "function": {
                FunctionDefinitionDataType function=new FunctionDefinitionDataType("prototype_"+Integer.toUnsignedString(ref.toString().hashCode()),manager);
                function.setReturnType(resolve(ref.getAsJsonObject("return_type")));
                List<ParameterDefinition> parameters=new ArrayList<>();int index=0;
                for(JsonElement parameter:ref.getAsJsonArray("parameters")) parameters.add(new ParameterDefinitionImpl("arg"+(index++),resolve(parameter.getAsJsonObject()),null));
                function.setArguments(parameters.toArray(new ParameterDefinition[0]));return function;
            }
            case "named": {
                DataType t=types.get(ref.get("name").getAsString());
                if(t==null) throw new IllegalArgumentException("Unresolved named type");
                return t;
            }
            case "pointer": return new PointerDataType(resolve(ref.getAsJsonObject("to")),manager);
            case "array": {
                DataType element=resolve(ref.getAsJsonObject("element"));
                return new ArrayDataType(element,ref.get("count").getAsInt(),element.getLength(),manager);
            }
            case "primitive": switch(ref.get("name").getAsString()) {
                case "void": return VoidDataType.dataType;
                case "bool": return BooleanDataType.dataType;
                case "i8": return SignedByteDataType.dataType;
                case "u8": return ByteDataType.dataType;
                case "i16": return ShortDataType.dataType;
                case "u16": return UnsignedShortDataType.dataType;
                case "i32": return IntegerDataType.dataType;
                case "u32": return UnsignedIntegerDataType.dataType;
                case "i64": return LongLongDataType.dataType;
                case "u64": return UnsignedLongLongDataType.dataType;
                case "f32": return FloatDataType.dataType;
                case "f64": return DoubleDataType.dataType;
            }
        }
        throw new IllegalArgumentException("Unsupported type reference");
    }
    private JsonObject cpp(JsonObject plan) {
        return plan.has("cpp") ? plan.getAsJsonObject("cpp") : new JsonObject();
    }
    private JsonArray items(JsonObject object,String key) {
        return object.has(key)?object.getAsJsonArray(key):new JsonArray();
    }
    private ghidra.program.model.pcode.HighSymbol localSymbol(JsonObject local) throws Exception {
        var function=currentProgram.getFunctionManager().getFunctionAt(toAddr(local.get("function").getAsString()));
        if(function==null) throw new IllegalArgumentException("Local function missing");
        var decompiler=new ghidra.app.decompiler.DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            var result=decompiler.decompileFunction(function,60,monitor);
            if(result.getHighFunction()==null) throw new IllegalStateException("Cannot resolve local variables");
            var symbols=result.getHighFunction().getLocalSymbolMap().getSymbols();
            ghidra.program.model.pcode.HighSymbol found=null;
            while(symbols.hasNext()) {
                var symbol=symbols.next();
                String pc=symbol.getPCAddress()==null?"":symbol.getPCAddress().toString();
                if(!symbol.isParameter() && symbol.getStorage().toString().equals(local.get("storage").getAsString()) && pc.equals(local.get("first_use").getAsString())) {
                    if(found!=null) throw new IllegalStateException("Ambiguous local identity");
                    found=symbol;
                }
            }
            if(found==null) throw new IllegalStateException("Local variable identity changed");
            return found;
        } finally {decompiler.dispose();}
    }
    private JsonObject cppState(JsonObject plan) throws Exception {
        JsonObject result=new JsonObject();JsonArray classes=new JsonArray(),tables=new JsonArray(),locals=new JsonArray();
        for(var item:items(cpp(plan),"classes")) {
            String name=item.getAsJsonObject().get("name").getAsString();
            classes.add(currentProgram.getOptions("Piston C++ layouts").getString(name,""));
        }
        for(var item:items(cpp(plan),"vtables")) {
            var table=item.getAsJsonObject();var address=toAddr(table.get("address").getAsString());
            JsonObject value=new JsonObject();var data=getDataAt(address);
            value.addProperty("type",data==null?"":data.getDataType().getPathName());
            value.addProperty("bytes",java.util.HexFormat.of().formatHex(getBytes(address,table.getAsJsonArray("targets").size()*currentProgram.getDefaultPointerSize())));
            JsonArray units=new JsonArray();
            var end=address.add(table.getAsJsonArray("targets").size()*currentProgram.getDefaultPointerSize()-1);
            var containing=currentProgram.getListing().getDataContaining(address);
            if(containing!=null && !containing.getAddress().equals(address)) throw new IllegalStateException("Vtable starts inside existing data");
            var defined=currentProgram.getListing().getDefinedData(new ghidra.program.model.address.AddressSet(address,end),true);
            while(defined.hasNext()) {
                var unit=defined.next();if(unit.getMaxAddress().compareTo(end)>0) throw new IllegalStateException("Vtable ends inside existing data");
                JsonObject entry=new JsonObject();entry.addProperty("address",unit.getAddress().toString());entry.addProperty("type",unit.getDataType().getPathName());entry.addProperty("length",unit.getLength());units.add(entry);
            }
            value.add("defined_data",units);tables.add(value);
        }
        for(var item:items(cpp(plan),"locals")) {
            var symbol=localSymbol(item.getAsJsonObject());JsonObject value=new JsonObject();
            value.addProperty("name",symbol.getName());value.addProperty("type",symbol.getDataType().getPathName());locals.add(value);
        }
        result.add("classes",classes);result.add("vtables",tables);result.add("locals",locals);return result;
    }
    private void applyCpp(JsonObject plan) throws Exception {
        for(var item:items(cpp(plan),"classes")) {
            var layout=item.getAsJsonObject();String name=layout.get("name").getAsString();
            if(!(types.get(name) instanceof Structure)) throw new IllegalArgumentException("Missing class structure");
            if(currentProgram.getSymbolTable().getNamespace(name,currentProgram.getGlobalNamespace())==null)
                currentProgram.getSymbolTable().createClass(currentProgram.getGlobalNamespace(),name,SourceType.USER_DEFINED);
            currentProgram.getOptions("Piston C++ layouts").setString(name,layout.toString());
            types.get(name).setDescription(Objects.toString(types.get(name).getDescription(),"")+"; C++ layout hypothesis: "+layout);
        }
        int width=currentProgram.getDefaultPointerSize();
        for(var item:items(cpp(plan),"vtables")) {
            var table=item.getAsJsonObject();var start=toAddr(table.get("address").getAsString());
            var targets=table.getAsJsonArray("targets");var type=types.get(table.get("table_type").getAsString());
            if(type==null || type.getLength()!=targets.size()*width) throw new IllegalArgumentException("Vtable width mismatch");
            for(int index=0;index<targets.size();index++) {
                var slot=start.add((long)index*width);long raw=width==8?getLong(slot):Integer.toUnsignedLong(getInt(slot));
                if(!toAddr(raw).equals(toAddr(targets.get(index).getAsString()))) throw new IllegalStateException("Vtable pointer differs from evidence");
                if(currentProgram.getFunctionManager().getFunctionAt(toAddr(raw))==null) throw new IllegalStateException("Vtable target is not a known function");
            }
            var end=start.add(type.getLength()-1);
            if(currentProgram.getListing().getInstructions(new ghidra.program.model.address.AddressSet(start,end),true).hasNext()) throw new IllegalStateException("Vtable overlaps instructions");
            currentProgram.getListing().clearCodeUnits(start,end,false);
            createData(start,type);
        }
        for(var item:items(cpp(plan),"locals")) {
            var local=item.getAsJsonObject();var symbol=localSymbol(local);
            if(!symbol.getName().equals(local.get("expected_name").getAsString()) && !symbol.getName().equals(local.get("name").getAsString())) throw new IllegalStateException("Local name changed since evidence capture");
            ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(symbol,local.get("name").getAsString(),resolve(local.getAsJsonObject("data_type")),SourceType.USER_DEFINED);
        }
    }

    private JsonObject savedState(String encoded) {
        var state=JsonParser.parseString(encoded).getAsJsonObject();
        // Historical operation snapshots predate layout extent metadata.
        // Missing metadata means unknown, never an exact-size assertion.
        if(state.has("definitions")) for(var entry:state.getAsJsonObject("definitions").entrySet()) {
            if(entry.getValue().isJsonObject() && !entry.getValue().getAsJsonObject().has("extent"))
                entry.getValue().getAsJsonObject().addProperty("extent","");
        }
        return state;
    }
    private JsonObject state(JsonObject plan) throws Exception {
        JsonObject state=new JsonObject();
        state.addProperty("pointer_width",currentProgram.getDefaultPointerSize());
        JsonObject definitions=new JsonObject();
        for(JsonElement e:plan.getAsJsonArray("definitions")) {
            String name=e.getAsJsonObject().get("name").getAsString();
            DataType type=manager.getDataType(category,name);
            if(type==null) {definitions.add(name,JsonNull.INSTANCE);continue;}
            JsonObject value=new JsonObject();value.addProperty("description",type.toString());value.addProperty("extent",currentProgram.getOptions("Piston layout extents").getString(name,""));value.addProperty("size",type.getLength());
            if(type instanceof Structure) {
                JsonArray fields=new JsonArray();
                for(DataTypeComponent field:((Structure)type).getDefinedComponents()) {
                    JsonObject f=new JsonObject(); f.addProperty("offset",field.getOffset());f.addProperty("name",field.getFieldName());f.addProperty("type",field.getDataType().getPathName());f.addProperty("length",field.getLength());fields.add(f);
                }
                value.add("fields",fields);
            }
            definitions.add(name,value);
        }
        state.add("definitions",definitions);
        JsonObject signatures=new JsonObject();
        for(JsonElement e:plan.getAsJsonArray("signatures")) {
            String address=e.getAsJsonObject().get("address").getAsString();
            Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
            if(f==null) throw new IllegalArgumentException("Function missing: "+address);
            JsonObject value=new JsonObject();value.addProperty("prototype",f.getPrototypeString(true,true));value.addProperty("namespace",f.getParentNamespace().getName(true));value.addProperty("convention",f.getCallingConventionName());value.addProperty("variadic",f.hasVarArgs());
            signatures.add(address,value);
        }
        state.add("signatures",signatures);if(plan.has("cpp")) state.add("cpp",cppState(plan));return state;
    }
    public void verifyApplied() throws Exception {
        String[] args=getScriptArgs();
        JsonObject plan=JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        String stored=currentProgram.getOptions("PistonDecompiler").getString(args[1],"");
        String appliedState=currentProgram.getOptions("PistonDecompiler").getString(args[1]+".state","");
        if(stored.isEmpty()) throw new IllegalStateException("Saved type operation marker is missing");
        if(!plan.equals(JsonParser.parseString(stored))) throw new IllegalStateException("Saved type plan differs from the applied operation");
        if(appliedState.isEmpty()) throw new IllegalStateException("Saved type state marker is missing");
        if(!state(plan).equals(savedState(appliedState)))
            throw new IllegalStateException("Saved type state differs: expected " + appliedState + "; actual " + gson.toJson(state(plan)));
    }
    private boolean exact(JsonObject definition) {
        return definition.has("extent") && definition.getAsJsonObject("extent").get("kind").getAsString().equals("exact");
    }
    private record Quality(int artifacts, String warning) {}
    private Map<String,Quality> measure(JsonObject plan) throws Exception {
        Map<String,Quality> values=new TreeMap<>();
        Set<String> affected=new TreeSet<>();
        for(var item:plan.getAsJsonArray("signatures")) {
            var function=currentProgram.getFunctionManager().getFunctionAt(toAddr(item.getAsJsonObject().get("address").getAsString()));
            if(function!=null) {
                affected.add(function.getEntryPoint().toString());
                for(var caller:function.getCallingFunctions(monitor)) affected.add(caller.getEntryPoint().toString());
            }
        }
        for(var item:items(cpp(plan),"locals")) affected.add(item.getAsJsonObject().get("function").getAsString());
        // A shared type can affect global accesses and transitive callers too.
        // Check the whole program for layout plans instead of sampling users.
        var functions=currentProgram.getFunctionManager().getFunctions(true);
        var decompiler=new ghidra.app.decompiler.DecompInterface();
        try {
            decompiler.openProgram(currentProgram);
            while(functions.hasNext()) {
                monitor.checkCancelled();var function=functions.next();
                if(function.isExternal() || function.isThunk()) continue;
                String address=function.getEntryPoint().toString();
                if(plan.getAsJsonArray("definitions").isEmpty() && !affected.contains(address)) continue;
                var result=decompiler.decompileFunction(function,30,monitor);
                if(!result.decompileCompleted() || result.getDecompiledFunction()==null) {
                    values.put(address,new Quality(-1,"unavailable"));continue;
                }
                String text=result.getDecompiledFunction().getC().replaceAll("(?s)/\\*.*?\\*/","");
                int artifacts=(int)java.util.regex.Pattern.compile("\\b(?:CONCAT|SUB)\\d+\\s*\\(").matcher(text).results().count();
                values.put(address,new Quality(artifacts,Objects.toString(result.getErrorMessage(),"")));
            }
        } finally { decompiler.dispose(); }
        return values;
    }
    private void verifyTrial(Map<String,Quality> before, Map<String,Quality> after) {
        for(var entry:before.entrySet()) {
            var a=entry.getValue();var b=after.get(entry.getKey());
            if(a.artifacts()<0) continue;
            if(b==null || b.artifacts()<0 || b.artifacts()>a.artifacts() || !b.warning().equals(a.warning()))
                throw new IllegalStateException("Type trial regresses decompilation at "+entry.getKey());
        }
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=5) throw new IllegalArgumentException("Expected mode, operation, plan, expected, report");
        Program live=currentProgram;
        Program shadow=null;
        try {
            if(args[0].equals("preview")) {
                shadow=(Program)live.getDomainFile().getReadOnlyDomainObject(this,-1,monitor);
                if(shadow==live) throw new IllegalStateException("Type trials require an isolated program");
                currentProgram=shadow;
            }
            executePlan(args);
        } catch(Exception error) {
            if(!args[0].equals("preview")) throw error;
            monitor.checkCancelled();
            JsonObject rejected=trialReport==null?new JsonObject():trialReport;rejected.addProperty("status","rejected");
            rejected.addProperty("error",error.getMessage());
            Files.writeString(Path.of(args[4]),gson.toJson(rejected));
        } finally { currentProgram=live;if(shadow!=null) shadow.release(this); }
    }
    private void executePlan(String[] args) throws Exception {

        manager=currentProgram.getDataTypeManager();
        JsonObject plan=JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        JsonObject report=new JsonObject();trialReport=report;
        boolean preview=args[0].equals("preview");
        JsonObject before=state(plan);
        Map<String,Quality> baseline=preview?measure(plan):Map.of();
        if(preview) report.add("before_metrics",gson.toJsonTree(baseline));
        if(preview) report.add("expected",before);
        if(preview || args[0].equals("apply")) {
            String encoded=gson.toJson(plan);
            String prior=preview ? "" : currentProgram.getOptions("PistonDecompiler").getString(args[1],"");
            if(!prior.isEmpty() && !prior.equals(encoded)) throw new IllegalStateException("Operation identity conflict");
            if(!prior.isEmpty()) {
                String appliedState=currentProgram.getOptions("PistonDecompiler").getString(args[1]+".state","");
                if(appliedState.isEmpty() || !state(plan).equals(savedState(appliedState))) throw new IllegalStateException("Applied values changed outside this operation");
            }
            if(prior.isEmpty()) {
                JsonObject expected=preview ? before : savedState(Files.readString(Path.of(args[3])));
                if(!state(plan).equals(expected)) throw new IllegalStateException("Ghidra types or signatures changed since preview");
                int transaction=currentProgram.startTransaction("Piston type recovery");boolean success=false;
                try {
                    // Forward declarations support recursive pointers.
                    for(JsonElement e:plan.getAsJsonArray("definitions")) {
                        JsonObject d=e.getAsJsonObject();String name=d.get("name").getAsString();int size=d.get("size").getAsInt();
                        DataType old=manager.getDataType(category,name);
                        if(d.get("kind").getAsString().equals("structure")) {
                            if(old!=null && !(old instanceof Structure)) throw new IllegalStateException("Type kind conflict");
                            types.put(name,old!=null?old:manager.addDataType(new StructureDataType(category,name,size,manager),DataTypeConflictHandler.DEFAULT_HANDLER));
                        } else {
                            EnumDataType en=new EnumDataType(category,name,size,manager);
                            for(var value:d.getAsJsonObject("values").entrySet()) en.add(value.getKey(),value.getValue().getAsLong());
                            types.put(name,manager.addDataType(en,DataTypeConflictHandler.REPLACE_HANDLER));
                        }
                    }
                    for(JsonElement e:plan.getAsJsonArray("definitions")) {
                        JsonObject d=e.getAsJsonObject();if(!d.get("kind").getAsString().equals("structure"))continue;
                        Structure structure=(Structure)types.get(d.get("name").getAsString());
                        int requested=d.get("size").getAsInt();
                        if(exact(d) && structure.getLength()>requested) throw new IllegalStateException("Complete size would discard existing layout evidence");
                        String oldExtent=currentProgram.getOptions("Piston layout extents").getString(structure.getName(),"");
                        if(!oldExtent.isEmpty() && JsonParser.parseString(oldExtent).getAsJsonObject().get("kind").getAsString().equals("exact") && requested>structure.getLength())
                            throw new IllegalStateException("New layout exceeds previously established complete size");
                        if(requested>structure.getLength()) structure.growStructure(requested-structure.getLength());
                        JsonObject extent=d.has("extent")?d.getAsJsonObject("extent"):JsonParser.parseString("{\"kind\":\"minimum\"}").getAsJsonObject();
                        if(!exact(d) && !oldExtent.isEmpty()) extent=JsonParser.parseString(oldExtent).getAsJsonObject();
                        currentProgram.getOptions("Piston layout extents").setString(structure.getName(),extent.toString());
                        structure.setDescription("Recovered layout extent: "+extent+"; gaps are unknown bytes, not proven padding.");
                    }
                    for(JsonElement e:plan.getAsJsonArray("definitions")) {
                        JsonObject d=e.getAsJsonObject();if(!d.get("kind").getAsString().equals("structure"))continue;
                        Structure structure=(Structure)types.get(d.get("name").getAsString());
                        for(JsonElement f:d.getAsJsonArray("fields")) {
                            JsonObject field=f.getAsJsonObject();DataType type=resolve(field.getAsJsonObject("data_type"));
                            int offset=field.get("offset").getAsInt();
                            for(var existing:structure.getDefinedComponents()) {
                                if(existing.getOffset()<offset+type.getLength() && existing.getEndOffset()>=offset &&
                                    (existing.getOffset()!=offset || existing.getLength()!=type.getLength()))
                                    throw new IllegalStateException("Proposed field overlaps existing layout evidence");
                                if(Objects.equals(existing.getFieldName(),field.get("name").getAsString()) && existing.getOffset()!=offset)
                                    throw new IllegalStateException("Field identity has conflicting offsets");
                            }
                            structure.replaceAtOffset(offset,type,type.getLength(),field.get("name").getAsString(),null);
                        }
                    }
                    for(JsonElement e:plan.getAsJsonArray("signatures")) {
                        JsonObject s=e.getAsJsonObject();Function f=currentProgram.getFunctionManager().getFunctionAt(toAddr(s.get("address").getAsString()));
                        Namespace namespace=currentProgram.getGlobalNamespace();
                        for(JsonElement n:s.getAsJsonArray("namespace")) {
                            String name=n.getAsString();Namespace next=currentProgram.getSymbolTable().getNamespace(name,namespace);
                            if(next==null) next=currentProgram.getSymbolTable().createClass(namespace,name,SourceType.USER_DEFINED);
                            namespace=next;
                        }
                        f.setParentNamespace(namespace);f.setName(s.get("name").getAsString(),SourceType.USER_DEFINED);
                        String convention=s.get("calling_convention").getAsString();
                        if(convention.isEmpty()) convention=f.getCallingConventionName();
                        if(convention.equals("unknown") || convention.equals("default"))
                            convention=currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
                        if(!convention.equals("unknown") && !convention.equals("default") && currentProgram.getCompilerSpec().getCallingConvention(convention)==null) throw new IllegalArgumentException("Unknown calling convention: "+convention);
                        List<Variable> parameters=new ArrayList<>();
                        for(JsonElement p:s.getAsJsonArray("parameters")) {
                            JsonObject parameter=p.getAsJsonObject();parameters.add(new ParameterImpl(parameter.get("name").getAsString(),resolve(parameter.getAsJsonObject("data_type")),currentProgram));
                        }
                        f.updateFunction(convention,new ReturnParameterImpl(resolve(s.getAsJsonObject("return_type")),currentProgram),Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,parameters.toArray(new Variable[0]));
                        f.setVarArgs(s.get("variadic").getAsBoolean());
                        if(!f.getName().equals(s.get("name").getAsString()) || f.getParameterCount()!=parameters.size()) throw new IllegalStateException("Ghidra changed the requested signature");
                        for(int index=0;index<parameters.size();index++) {
                            Parameter actual=f.getParameter(index);Variable desired=parameters.get(index);
                            if(!actual.getName().equals(desired.getName()) || !actual.getDataType().isEquivalent(desired.getDataType())) throw new IllegalStateException("Ghidra parameter verification failed");
                        }
                        if(!f.getReturnType().isEquivalent(resolve(s.getAsJsonObject("return_type")))) throw new IllegalStateException("Ghidra return type verification failed");
                    }
                    for(JsonElement e:plan.getAsJsonArray("definitions")) {
                        JsonObject d=e.getAsJsonObject();DataType type=types.get(d.get("name").getAsString());
                        if((exact(d) && type.getLength()!=d.get("size").getAsInt()) || type.getLength()<d.get("size").getAsInt()) throw new IllegalStateException("Resolved layout size differs from proposal");
                    }
                    applyCpp(plan);
                    if(preview) {
                        var after=measure(plan);
                        report.add("after_metrics",gson.toJsonTree(after));
                        verifyTrial(baseline,after);
                        report.addProperty("unchanged",before.equals(state(plan)));
                    }
                    currentProgram.getOptions("PistonDecompiler").setString(args[1],encoded);
                    currentProgram.getOptions("PistonDecompiler").setString(args[1]+".state",gson.toJson(state(plan)));
                    success=true;
                } finally {currentProgram.endTransaction(transaction,success && !preview);}
            }
            report.addProperty("status",preview ? "validated" : "applied");report.add("actual",state(plan));
        } else throw new IllegalArgumentException("Unknown operation mode");
        Files.writeString(Path.of(args[4]),gson.toJson(report));
    }
}
