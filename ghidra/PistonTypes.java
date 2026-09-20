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
    private JsonObject state(JsonObject plan) throws Exception {
        JsonObject state=new JsonObject();
        state.addProperty("pointer_width",currentProgram.getDefaultPointerSize());
        JsonObject definitions=new JsonObject();
        for(JsonElement e:plan.getAsJsonArray("definitions")) {
            String name=e.getAsJsonObject().get("name").getAsString();
            DataType type=manager.getDataType(category,name);
            if(type==null) {definitions.add(name,JsonNull.INSTANCE);continue;}
            JsonObject value=new JsonObject();value.addProperty("description",type.toString());value.addProperty("size",type.getLength());
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
        state.add("signatures",signatures);return state;
    }
    public void verifyApplied() throws Exception {
        String[] args=getScriptArgs();
        JsonObject plan=JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        String stored=currentProgram.getOptions("PistonDecompiler").getString(args[1],"");
        String appliedState=currentProgram.getOptions("PistonDecompiler").getString(args[1]+".state","");
        if(stored.isEmpty()) throw new IllegalStateException("Saved type operation marker is missing");
        if(!plan.equals(JsonParser.parseString(stored))) throw new IllegalStateException("Saved type plan differs from the applied operation");
        if(appliedState.isEmpty()) throw new IllegalStateException("Saved type state marker is missing");
        if(!state(plan).equals(JsonParser.parseString(appliedState)))
            throw new IllegalStateException("Saved type state differs: expected " + appliedState + "; actual " + gson.toJson(state(plan)));
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=5) throw new IllegalArgumentException("Expected mode, operation, plan, expected, report");
        manager=currentProgram.getDataTypeManager();
        JsonObject plan=JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
        JsonObject report=new JsonObject();
        if(args[0].equals("preview")) {report.add("expected",state(plan));}
        else if(args[0].equals("apply")) {
            String encoded=gson.toJson(plan);
            String prior=currentProgram.getOptions("PistonDecompiler").getString(args[1],"");
            if(!prior.isEmpty() && !prior.equals(encoded)) throw new IllegalStateException("Operation identity conflict");
            if(!prior.isEmpty()) {
                String appliedState=currentProgram.getOptions("PistonDecompiler").getString(args[1]+".state","");
                if(appliedState.isEmpty() || !state(plan).equals(JsonParser.parseString(appliedState))) throw new IllegalStateException("Applied values changed outside this operation");
            }
            if(prior.isEmpty()) {
                JsonObject expected=JsonParser.parseString(Files.readString(Path.of(args[3]))).getAsJsonObject();
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
                        structure.deleteAll();structure.setPackingEnabled(false);structure.growStructure(d.get("size").getAsInt());
                    }
                    for(JsonElement e:plan.getAsJsonArray("definitions")) {
                        JsonObject d=e.getAsJsonObject();if(!d.get("kind").getAsString().equals("structure"))continue;
                        Structure structure=(Structure)types.get(d.get("name").getAsString());
                        for(JsonElement f:d.getAsJsonArray("fields")) {
                            JsonObject field=f.getAsJsonObject();DataType type=resolve(field.getAsJsonObject("data_type"));
                            structure.replaceAtOffset(field.get("offset").getAsInt(),type,type.getLength(),field.get("name").getAsString(),null);
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
                        if(type.getLength()!=d.get("size").getAsInt()) throw new IllegalStateException("Resolved layout size differs from proposal");
                    }
                    currentProgram.getOptions("PistonDecompiler").setString(args[1],encoded);
                    currentProgram.getOptions("PistonDecompiler").setString(args[1]+".state",gson.toJson(state(plan)));
                    success=true;
                } finally {currentProgram.endTransaction(transaction,success);}
            }
            report.addProperty("status","applied");report.add("actual",state(plan));
        } else throw new IllegalArgumentException("Unknown operation mode");
        Files.writeString(Path.of(args[4]),gson.toJson(report));
    }
}
