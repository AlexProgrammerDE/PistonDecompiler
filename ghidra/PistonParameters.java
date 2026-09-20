// Try parameter interpretations against native decompilation before saving winners.
// @category PistonDecompiler
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import com.google.gson.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

public class PistonParameters extends GhidraScript {
    private Program workingProgram;
    private final Gson gson = new Gson();
    private static final Pattern GENERATED = Pattern.compile("(?:param_|arg_?)\\d+");
    private static final Pattern ARTIFACT = Pattern.compile("\\b(?:CONCAT|SUB)\\d+\\s*\\(");
    private static final Pattern CAST = Pattern.compile("\\((?:u?int|u?long|u?short|char|byte|sbyte|undefined|void|bool|float|double)[\\w\\s*]*\\)");
    private record Edit(int index, String name, DataType type, String source) {}
    private record ParameterState(String name, DataType type, String storage) {}
    private record Quality(int artifacts, int casts, int undefined, int fields, String warning) {}

    private Function function(Address address) { return workingProgram.getFunctionManager().getFunctionAt(address); }
    private DecompileResults decompile(Function function) throws Exception {
        monitor.checkCancelled();
        var decompiler = new DecompInterface();
        try {
            decompiler.openProgram(workingProgram);
            var result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null || result.getDecompiledFunction() == null)
                throw new IllegalStateException("Cannot decompile " + function.getEntryPoint() + ": " + result.getErrorMessage());
            return result;
        } finally { decompiler.dispose(); }
    }
    private List<ParameterState> parameters(DecompileResults result) {
        var prototype = result.getHighFunction().getFunctionPrototype();
        List<ParameterState> values = new ArrayList<>();
        for (int i=0;i<prototype.getNumParams();i++) {
            var symbol=prototype.getParam(i);
            values.add(new ParameterState(symbol.getName(),symbol.getDataType(),symbol.getStorage().toString()));
        }
        return values;
    }
    private static int count(Pattern pattern, String text) { return (int)pattern.matcher(text).results().count(); }
    private Quality quality(DecompileResults result) {
        String text=result.getDecompiledFunction().getC().replaceAll("(?s)/\\*.*?\\*/", "");
        return new Quality(count(ARTIFACT,text),count(CAST,text),count(Pattern.compile("\\bundefined\\d*\\b"),text),count(Pattern.compile("->"),text),result.getErrorMessage());
    }
    private Map<Address,Quality> measure(List<Address> affected) throws Exception {
        Map<Address,Quality> result=new LinkedHashMap<>();
        for(var address:affected) {
            try { result.put(address,quality(decompile(function(address)))); }
            catch(IllegalStateException error) {
                monitor.checkCancelled();
                result.put(address,new Quality(0,0,0,0,"unavailable:"+error.getMessage()));
            }
        }
        return result;
    }
    private boolean noRegression(Map<Address,Quality> before, Map<Address,Quality> after, boolean naming) {
        for(var address:before.keySet()) {
            var a=before.get(address);var b=after.get(address);
            if(a.warning.startsWith("unavailable:")) {
                if(!naming) return false;
                if(b.warning.equals(a.warning)) continue;
            }
            if(b.artifacts>a.artifacts || (!naming && b.casts>a.casts) || b.undefined>a.undefined || b.fields<a.fields || !Objects.equals(a.warning,b.warning)) return false;
        }
        return true;
    }
    private boolean improvement(Map<Address,Quality> before, Map<Address,Quality> after) {
        for(var address:before.keySet()) if(!before.get(address).equals(after.get(address))) return true;
        return false;
    }
    private JsonObject metrics(Map<Address,Quality> values) {
        var object=new JsonObject();
        values.forEach((a,q)->object.add(a.toString(),gson.toJsonTree(q)));
        return object;
    }
    private JsonObject coverage(List<ParameterState> parameters) {
        var result=new JsonObject();
        result.addProperty("total",parameters.size());
        result.addProperty("named",parameters.stream().filter(p->!GENERATED.matcher(p.name).matches()).count());
        result.addProperty("typed",parameters.stream().filter(p->!unknown(p.type)).count());
        return result;
    }
    private boolean unknown(DataType type) {
        if(type instanceof TypeDef definition) return unknown(definition.getBaseDataType());
        return Undefined.isUndefined(type) || (type instanceof Pointer pointer && (pointer.getDataType()==null || pointer.getDataType() instanceof VoidDataType || unknown(pointer.getDataType())));
    }
    private DataType resolve(JsonObject ref) {
        if(ref==null) return null;
        var manager=workingProgram.getDataTypeManager();
        return switch(ref.get("kind").getAsString()) {
            case "primitive" -> switch(ref.get("name").getAsString()) {
                case "bool" -> BooleanDataType.dataType;
                case "i8" -> SignedByteDataType.dataType;
                case "u8" -> ByteDataType.dataType;
                case "i16" -> ShortDataType.dataType;
                case "u16" -> UnsignedShortDataType.dataType;
                case "i32" -> IntegerDataType.dataType;
                case "u32" -> UnsignedIntegerDataType.dataType;
                case "i64" -> LongLongDataType.dataType;
                case "u64" -> UnsignedLongLongDataType.dataType;
                case "f32" -> FloatDataType.dataType;
                case "f64" -> DoubleDataType.dataType;
                default -> null;
            };
            case "named" -> manager.getDataType(new CategoryPath("/PistonRecovered"),ref.get("name").getAsString());
            case "pointer" -> {
                var inner=ref.getAsJsonObject("to");
                DataType target=inner.has("name") && inner.get("name").getAsString().equals("void") ? VoidDataType.dataType : resolve(inner);
                yield target==null ? null : new PointerDataType(target,manager);
            }
            default -> null;
        };
    }
    // Only an unchanged value may transfer a callee's parameter constraint.
    // Arithmetic, loads and PHI joins deliberately do not unify unrelated objects.
    private int origin(Varnode node, HighFunction high, Set<Varnode> seen) {
        if(node==null || !seen.add(node) || seen.size()>32) return -1;
        var variable=node.getHigh();
        var prototype=high.getFunctionPrototype();
        for(int i=0;i<prototype.getNumParams();i++)
            if(variable!=null && variable.getSymbol()==prototype.getParam(i)) return i;
        var def=node.getDef();
        if(def!=null && (def.getOpcode()==PcodeOp.COPY || def.getOpcode()==PcodeOp.CAST) && def.getInput(0).getSize()==node.getSize())
            return origin(def.getInput(0),high,seen);
        return -1;
    }
    private List<Edit> propagated(DecompileResults result) {
        Map<Integer,List<DataType>> constraints=new TreeMap<>();
        Map<Integer,Set<String>> names=new TreeMap<>();
        var high=result.getHighFunction();var ops=high.getPcodeOps();
        while(ops.hasNext()) {
            var op=ops.next();if(op.getOpcode()!=PcodeOp.CALL) continue;
            Function callee=function(op.getInput(0).getAddress());
            if(callee!=null && callee.isThunk()) callee=callee.getThunkedFunction(true);
            if(callee==null || callee==high.getFunction()) continue;
            for(int arg=1;arg<op.getNumInputs() && arg<=callee.getParameterCount();arg++) {
                int index=origin(op.getInput(arg),high,new HashSet<>());
                var parameter=callee.getParameter(arg-1);var type=parameter.getDataType();
                String name=parameter.getName();
                if(index>=0 && name.length()>1 && !GENERATED.matcher(name).matches()) names.computeIfAbsent(index,k->new TreeSet<>()).add(name);
                if(index>=0 && !unknown(type) && !(type instanceof VoidDataType)) constraints.computeIfAbsent(index,k->new ArrayList<>()).add(type);
            }
        }
        List<Edit> resultEdits=new ArrayList<>();
        constraints.forEach((index,types)-> {
            var type=types.get(0);
            if(types.stream().allMatch(type::isEquivalent)) resultEdits.add(new Edit(index,null,type,"call_constraint"));
        });
        names.forEach((index,values)-> { if(values.size()==1) resultEdits.add(new Edit(index,values.iterator().next(),null,"call_name")); });
        return resultEdits;
    }
    private void apply(Address address, List<ParameterState> baseline, List<Edit> edits) throws Exception {
        var f=function(address);List<Variable> values=new ArrayList<>();
        for(int i=0;i<baseline.size();i++) {
            var original=baseline.get(i);String name=original.name;DataType type=original.type;
            for(var edit:edits) if(edit.index==i) { if(edit.name!=null) name=edit.name; if(edit.type!=null) type=edit.type; }
            values.add(new ParameterImpl(name,type,workingProgram));
        }
        // Replacing parameters preserves the return type, function identity and convention.
        f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.ANALYSIS,values.toArray(new Variable[0]));
    }
    private String effectiveConvention(String convention) {
        if(convention==null || convention.equals("unknown") || convention.equals("default"))
            return workingProgram.getCompilerSpec().getDefaultCallingConvention().getName();
        return convention;
    }
    private String state(Function f) {
        StringBuilder state=new StringBuilder(f.getPrototypeString(true,false)).append('|').append(effectiveConvention(f.getCallingConventionName())).append('|').append(f.hasVarArgs());
        for(var p:f.getParameters()) state.append('|').append(p.getName()).append(':').append(p.getDataType().getPathName()).append(':').append(p.getVariableStorage());
        return state.toString();
    }
    private String canonicalSavedState(String saved) {
        String[] parts=saved.split("\\|",-1);
        if(parts.length<3) return saved;
        // Older markers included the convention twice and recorded "unknown"
        // even when parameter storage already used the compiler's default ABI.
        parts[0]=parts[0].replace(" "+parts[1]+" "," ");
        parts[1]=effectiveConvention(parts[1]);
        return String.join("|",parts);
    }
    public void verifyApplied() throws Exception {
        workingProgram=currentProgram;
        var args=getScriptArgs();var options=workingProgram.getOptions("PistonDecompiler");
        var report=JsonParser.parseString(options.getString(args[0],"{}")).getAsJsonObject();
        if(!report.has("state") || !canonicalSavedState(report.get("state").getAsString()).equals(state(function(toAddr(report.get("address").getAsString())))))
            throw new IllegalStateException("Saved parameter state differs from the operation: expected "+report.get("state")+"; actual "+state(function(toAddr(report.get("address").getAsString()))));
    }
    @Override public void run() throws Exception {
        workingProgram=currentProgram;
        String[] args=getScriptArgs();
        if(args.length!=3) throw new IllegalArgumentException("Expected operation, input, report");
        String input=Files.readString(Path.of(args[1]));var request=JsonParser.parseString(input).getAsJsonObject();
        var options=workingProgram.getOptions("PistonDecompiler");String previous=options.getString(args[0],"");
        if(!previous.isEmpty()) {
            var report=JsonParser.parseString(previous).getAsJsonObject();
            if(!report.get("input").getAsString().equals(input)) throw new IllegalStateException("Parameter operation identity conflict");
            verifyApplied();Files.writeString(Path.of(args[2]),previous);return;
        }
        Program savedProgram=workingProgram;
        // A separately opened saved program has no enclosing script transaction.
        // Trials must never share the live program's transaction manager.
        var shadow=(Program)savedProgram.getDomainFile().getReadOnlyDomainObject(this, -1, monitor);
        if(shadow==savedProgram) { shadow.release(this);throw new IllegalStateException("Parameter trials require an isolated program"); }
        workingProgram=shadow;
        try {
        Address address=toAddr(request.get("address").getAsString());var target=function(address);
        if(target==null || target.isExternal()) throw new IllegalArgumentException("Expected an internal function");
        var report=new JsonObject();var trials=new JsonArray();report.add("trials",trials);report.addProperty("address",address.toString());report.addProperty("input",input);
        List<Edit> winners=new ArrayList<>();
        // Implicit ABI parameters require a separate storage-aware model.
        if(!target.isThunk() && !target.hasCustomVariableStorage() && target.getAutoParameterCount()==0) {
            DecompileResults original;
            try { original=decompile(target); }
            catch(IllegalStateException error) {
                monitor.checkCancelled();workingProgram=savedProgram;
                report.addProperty("reason",error.getMessage());report.addProperty("changed",false);report.addProperty("status","completed");report.addProperty("state",state(function(address)));
                int transaction=workingProgram.startTransaction("Record unavailable parameter evidence");
                try { options.setString(args[0],gson.toJson(report)); } finally { workingProgram.endTransaction(transaction,true); }
                Files.writeString(Path.of(args[2]),gson.toJson(report));return;
            }
            var baseline=parameters(original);String nativeBefore=state(target);
            report.add("coverage_before",coverage(baseline));
            List<Address> affected=new ArrayList<>();affected.add(address);
            target.getCallingFunctions(monitor).stream().filter(f->!f.isExternal() && !f.isThunk() && !f.getEntryPoint().equals(address)).map(Function::getEntryPoint).sorted().limit(65).forEach(affected::add);
            if(affected.size()<=65 && baseline.size()<=64) {
                var before=measure(affected);report.add("before",metrics(before));
                var inherited=propagated(original);
                List<Edit> candidates=new ArrayList<>();
                inherited.stream().filter(e->e.type!=null).forEach(candidates::add);
                report.addProperty("propagated_candidates",inherited.size());
                for(var element:request.getAsJsonArray("candidates")) {
                    var c=element.getAsJsonObject();int index=c.get("index").getAsInt();String name=c.get("name").getAsString();
                    if(index<0 || index>=baseline.size()) continue;
                    // Name and type are independent experiments.
                    if(name.matches("[A-Za-z_][A-Za-z_0-9]{0,159}") && !GENERATED.matcher(name).matches() && GENERATED.matcher(baseline.get(index).name).matches())
                        candidates.add(new Edit(index,name,null,"ai_name"));
                    if(c.has("data_type") && !c.get("data_type").isJsonNull()) {
                        var type=resolve(c.getAsJsonObject("data_type"));
                        if(type!=null) candidates.add(new Edit(index,null,type,"ai_type"));
                    }
                }
                inherited.stream().filter(e->e.name!=null).forEach(candidates::add);
                Set<String> seen=new HashSet<>();
                for(var edit:candidates) {
                    monitor.checkCancelled();
                    if(edit.index<0 || edit.index>=baseline.size()) continue;
                    var old=baseline.get(edit.index);
                    if(edit.name!=null && !GENERATED.matcher(old.name).matches()) continue;
                    if(edit.type!=null && (edit.type.getLength()!=old.type.getLength() || edit.type.isEquivalent(old.type))) continue;
                    String key=edit.index+":"+edit.name+":"+(edit.type==null?"":edit.type.getPathName());
                    if(!seen.add(key)) continue;
                    if(edit.name!=null && winners.stream().anyMatch(w -> w.index==edit.index && w.name!=null)) continue;
                    var trial=new JsonObject();trial.addProperty("index",edit.index);trial.addProperty("source",edit.source);trial.addProperty("name",edit.name);trial.addProperty("type",edit.type==null?null:edit.type.getPathName());
                    List<Edit> proposed=new ArrayList<>(winners);
                    if(edit.type!=null) proposed.removeIf(w -> w.index==edit.index && w.type!=null);
                    proposed.add(edit);
                    int transaction=workingProgram.startTransaction("Trial parameter interpretation");
                    boolean accepted=false;Map<Address,Quality> after=null;
                    try {
                        apply(address,baseline,proposed);
                        var fresh=parameters(decompile(function(address)));
                        boolean stable=fresh.size()==baseline.size();
                        for(int i=0;stable && i<fresh.size();i++) stable=fresh.get(i).storage.equals(baseline.get(i).storage);
                        after=measure(affected);
                        boolean useful=edit.name!=null || improvement(before,after) || (unknown(old.type) && !unknown(edit.type) && winners.stream().noneMatch(w -> w.index==edit.index && w.type!=null));
                        accepted=stable && useful && noRegression(before,after,edit.name!=null);
                        trial.add("metrics",metrics(after));trial.addProperty("reason",accepted?"Improved parameter interpretation within structural checks":"No improvement or native decompilation regressed");
                    } catch(Exception error) {
                        monitor.checkCancelled();trial.addProperty("reason",error.getMessage());
                    } finally { workingProgram.endTransaction(transaction,false); }
                    // Detect accidental nested transactions or incomplete rollback immediately.
                    if(!nativeBefore.equals(state(function(address)))) throw new IllegalStateException("Parameter trial did not roll back");
                    trial.addProperty("accepted",accepted);trials.add(trial);
                    if(accepted) { winners=proposed;before=after; }
                }
            } else report.addProperty("reason","Parameter or caller scope exceeds the bounded experiment size");
            workingProgram=savedProgram;
            if(!nativeBefore.equals(state(function(address)))) throw new IllegalStateException("Native parameters changed during experiments");
            int transaction=workingProgram.startTransaction("Save parameter experiment winners");boolean success=false;
            try {
                if(!winners.isEmpty()) apply(address,baseline,winners);
                report.add("coverage_after",coverage(parameters(decompile(function(address)))));
                report.addProperty("changed",!winners.isEmpty());report.addProperty("status","completed");report.addProperty("state",state(function(address)));
                options.setString(args[0],gson.toJson(report));success=true;
            } finally { workingProgram.endTransaction(transaction,success); }
        } else {
            workingProgram=savedProgram;
            report.addProperty("reason","Thunk, custom storage, or implicit ABI parameters retained");report.addProperty("changed",false);report.addProperty("status","completed");report.addProperty("state",state(target));
            int transaction=workingProgram.startTransaction("Record parameter experiment");try { options.setString(args[0],gson.toJson(report)); } finally { workingProgram.endTransaction(transaction,true); }
        }
        verifyApplied();Files.writeString(Path.of(args[2]),gson.toJson(report));
        } finally { workingProgram=savedProgram;shadow.release(this); }
    }
}
