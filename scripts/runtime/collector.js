// Frida agent. Host supplies a validated capture plan before the target resumes.
let sequence = 0;
const started = Date.now();
let stopping = false;
let invocation = 0;
let allocationSequence = 0;
let dropped = 0;
let count = 0;
const allocations = new Map();
const listeners = [];
let skippedFunctions = 0;
let hookedFunctions = 0;
let settings;
let module;
let traceThread = () => {};
const tracedThreads = new Set();
const pendingDispatch = new Map();
const dispatchSamples = new Map();
function emit(functionRva, observation) {
  if (stopping || count >= settings.max_events) { dropped++; return false; }
  count++;
  send({sequence: ++sequence, timestamp_us: (Date.now() - started) * 1000, thread: Process.getCurrentThreadId(), function_rva: functionRva, ...observation});
  return true;
}
function addressNumber(pointer) {
  const n = Number(pointer.toString());
  if (!Number.isSafeInteger(n)) throw new Error('Address exceeds exact JavaScript integer range');
  return n;
}
function region(pointer, bytes, functionRva) {
  // Interior pointers retain a known allocation identity. Unknown readable regions
  // receive a fresh identity per observation, never an invented malloc lifetime.
  for (const allocation of allocations.values()) {
    if (pointer.compare(allocation.base) >= 0 && pointer.compare(allocation.base.add(allocation.size)) < 0)
      return {...allocation, offset:addressNumber(pointer.sub(allocation.base))};
  }
  const range = Process.findRangeByAddress(pointer);
  if (!range || !range.protection.includes('r')) return null;
  const size = Math.min(bytes, addressNumber(range.base.add(range.size).sub(pointer)), 4096);
  const id = `region-${++allocationSequence}`;
  if (!emit(functionRva, {kind:'region', allocation:id, address:addressNumber(pointer), size})) return null;
  return {id, base:pointer, size, offset:0};
}
function snapshot(functionRva, pointer, bytes, invocation, phase, argumentIndex) {
  try {
    const allocation = region(pointer, bytes, functionRva);
    if (!allocation) return;
    const buffer = new Uint8Array(pointer.readByteArray(Math.min(bytes, allocation.size-allocation.offset, 4096)));
    emit(functionRva, {kind:'snapshot', allocation:allocation.id, offset:allocation.offset,
      invocation, phase, argument_index:argumentIndex,
      bytes:Array.from(buffer, b => b.toString(16).padStart(2,'0')).join('')});
  } catch (_) { dropped++; }
}
function memorySample(functionRva, instructionRva, pointer, width, write) {
  try {
    const allocation = region(pointer, width, functionRva);
    if (!allocation || allocation.offset + width > allocation.size) return;
    const buffer = new Uint8Array(pointer.readByteArray(width));
    emit(functionRva, {kind:'memory', allocation:allocation.id, offset:allocation.offset, width, write,
      instruction_rva:instructionRva, value:Array.from(buffer, b => b.toString(16).padStart(2,'0')).join('')});
  } catch (_) { dropped++; }
}
function moduleRva(address) {
  const offset=addressNumber(address.sub(module.base));
  return offset>=0 && offset<module.size ? offset : null;
}
function effectiveAddress(mem, next, context) {
  if(mem.segment) return null;
  let address=mem.base==='rip'?next:mem.base?context[mem.base]:ptr(0);
  if(!address) return null;
  if(mem.index) {if(!context[mem.index]) return null;address=address.add(addressNumber(context[mem.index])*mem.scale);}
  return address.add(mem.disp);
}
function dispatchSample(owner, site, operand, next, context) {
  const thread=Process.getCurrentThreadId();pendingDispatch.delete(thread);
  if((dispatchSamples.get(site)||0)>=settings.samples_per_function) return;
  try {
    const receiver=Process.platform==='windows'?context.rcx:context.rdi;
    if(!receiver || receiver.isNull()) return;
    const target=operand.type==='reg'?context[operand.value]:effectiveAddress(operand.value,next,context)?.readPointer();
    if(!target || moduleRva(target)===null) return;
    const table=receiver.readPointer();const tableRva=moduleRva(table);
    if(tableRva===null) return;
    const range=Process.findRangeByAddress(table);
    if(!range || !range.protection.includes('r') || range.protection.includes('x')) return;
    const matches=[];
    const operandAddress=operand.type==='mem'?effectiveAddress(operand.value,next,context):null;
    for(let slot=0;slot<128;slot++) {
      const entry=table.add(slot*Process.pointerSize);
      if(entry.add(Process.pointerSize).compare(range.base.add(range.size))>0) break;
      const pointer=entry.readPointer();
      const code=Process.findRangeByAddress(pointer);
      if(!code || !code.protection.includes('x')) break;
      if(pointer.equals(target)) matches.push(slot);
    }
    const exact=operandAddress?matches.filter(slot=>table.add(slot*Process.pointerSize).equals(operandAddress)):[];
    const candidates=exact.length?exact:matches;
    if(candidates.length!==1) return;
    const slot=candidates[0];
      const object=region(receiver,Process.pointerSize,owner);
      if(!object || object.offset+Process.pointerSize>object.size) return;
      const id=++invocation;
      if(emit(owner,{kind:'virtual_dispatch',invocation:id,allocation:object.id,object_offset:object.offset,receiver:addressNumber(receiver),vtable_rva:tableRva,slot_offset:slot*Process.pointerSize,site_rva:site,target_rva:moduleRva(target)})) {
        dispatchSamples.set(site,(dispatchSamples.get(site)||0)+1);
        pendingDispatch.set(thread,{owner,invocation:id,object,receiver,target:moduleRva(target),implementation:settings.thunk_targets?.[moduleRva(target)]});
      }
      return;
  } catch (_) { dropped++; }
}
rpc.exports = {
  identity() { const m=Process.mainModule; return {path:m.path,base:m.base.toString(),pointer_width:Process.pointerSize,architecture:Process.arch}; },
  marker(label) { if (typeof label !== "string" || !label.length || label.length > 256) throw new Error("Invalid marker"); emit(null,{kind:"marker",label}); },
  start(plan) {
    settings = plan;
    module = Process.mainModule;
    if (plan.trace_memory && Process.arch !== "x64") throw new Error("Instruction memory capture currently requires x86-64");
    // Only the main module and configured allocator entry points are supported.
    function allocated(result, size) {
      if (result.isNull() || size <= 0) return;
      const key = result.toString();
      // An allocator hook can call another hooked allocator internally.
      if (allocations.has(key)) return;
      const id = `allocation-${++allocationSequence}`;
      if (emit(null, {kind:'allocation', allocation:id, address:addressNumber(result), size}))
        allocations.set(key, {id, base:ptr(result.toString()), size});
    }
    function released(pointer) {
      const key = pointer.toString(); const allocation = allocations.get(key);
      if (allocation) {emit(null,{kind:'free',allocation:allocation.id});allocations.delete(key);}
    }
    const malloc = Module.findGlobalExportByName('malloc');
    const free = Module.findGlobalExportByName('free');
    const hooked = new Set();
    function allocator(allocate, release, sizeArgument) {
      if (!hooked.has(allocate.toString())) {
        hooked.add(allocate.toString());
        listeners.push(Interceptor.attach(allocate, {
          onEnter(args) {this.size = addressNumber(args[sizeArgument]);},
          onLeave(result) {allocated(result,this.size);}
        }));
      }
      if (!hooked.has(release.toString())) {
        hooked.add(release.toString());
        listeners.push(Interceptor.attach(release,{onEnter(args){released(args[0]);}}));
      }
    }
    if (malloc && free && plan.allocations) {
      allocator(malloc,free,0);
      const calloc = Module.findGlobalExportByName('calloc');
      if (calloc) listeners.push(Interceptor.attach(calloc, {
        onEnter(args) {this.size = addressNumber(args[0]) * addressNumber(args[1]);},
        onLeave(result) {if(Number.isSafeInteger(this.size)) allocated(result,this.size);}
      }));
      const realloc = Module.findGlobalExportByName('realloc');
      if (realloc) listeners.push(Interceptor.attach(realloc, {
        onEnter(args) {this.old=args[0];this.size=addressNumber(args[1]);},
        onLeave(result) {
          if (!result.isNull()) {released(this.old);allocated(result,this.size);}
          // realloc(p,0) varies by platform. Retire our knowledge without asserting a free.
          else if(this.size===0) allocations.delete(this.old.toString());
        }
      }));
    }
    for (const hook of (plan.allocator_hooks || [])) {
      for (const rva of [hook.allocate_rva,hook.free_rva]) {
        if(!Number.isSafeInteger(rva) || rva<0 || rva>=module.size) throw new Error('Allocator is outside main module');
      }
      if(!Number.isInteger(hook.size_argument) || hook.size_argument<0 || hook.size_argument>=8) throw new Error('Invalid allocator argument');
      allocator(module.base.add(hook.allocate_rva),module.base.add(hook.free_rva),hook.size_argument);
    }
    if (plan.trace_calls || plan.trace_blocks || plan.trace_memory) {
      Stalker.queueDrainInterval = 50;
      const sites = new Map();
      for (const fn of plan.functions) for (const site of (fn.instruction_rvas || [])) sites.set(site, fn.rva);
      const entries = new Set(plan.function_entries || plan.functions.map(fn => fn.rva));
      traceThread = (threadId) => {
        if(tracedThreads.has(threadId)) return;
        tracedThreads.add(threadId);
        Stalker.follow(threadId, {transform: (plan.trace_memory || (plan.trace_objects && Process.arch === "x64")) ? (iterator) => {
          let instruction;
          while ((instruction = iterator.next()) !== null) {
            const site = Number(instruction.address.sub(module.base).toString());
            const owner = sites.get(site);
            if(plan.trace_objects && Process.arch==='x64' && owner!==undefined && instruction.mnemonic==='call') {
              const operand=instruction.operands[0];const next=instruction.next;
              if(operand && (operand.type==='reg' || operand.type==='mem')) {
                const saved={...operand,value:operand.type==='mem'?{...operand.value}:operand.value};
                iterator.putCallout(context=>dispatchSample(owner,site,saved,next,context));
              }
            }
            // Only plain MOV loads/stores: no REP, atomics, segment addressing,
            // vector instructions or read-modify-write claims without an adapter.
            const operand = plan.trace_memory && instruction.mnemonic === 'mov' && instruction.operands.find(o => o.type === 'mem');
            if (owner === undefined || !operand || operand.size > 8 || operand.size < 1 || operand.value.segment) { iterator.keep(); continue; }
            const mem = {...operand.value};
            const width = operand.size;
            const write = operand.access.includes('w');
            const read = operand.access.includes('r');
            const next = instruction.next;
            const pending = new Map();
            iterator.putCallout(context => {
              let address = mem.base === 'rip' ? next : mem.base ? context[mem.base] : ptr(0);
              if (!address) return;
              if (mem.index) { if (!context[mem.index]) return; const index = addressNumber(context[mem.index]); address = address.add(index * mem.scale); }
              address = address.add(mem.disp);
              if (read) memorySample(owner, site, address, width, false);
              if (write) pending.set(Process.getCurrentThreadId(), address);
            });
            iterator.keep();
            if (write) iterator.putCallout(() => {
              const tid = Process.getCurrentThreadId();
              const address = pending.get(tid); pending.delete(tid);
              if (address) memorySample(owner, site, address, width, true);
            });
          }
        } : undefined, events:{call:Boolean(plan.trace_calls),block:Boolean(plan.trace_blocks)}, onReceive(buffer) {
          for (const event of Stalker.parse(buffer, {annotate:true,stringify:false})) {
            if(event[0] === 'block') {
              const block=Number(event[1].sub(module.base).toString());
              const caller=sites.get(block);
              if(caller!==undefined) emit(caller,{kind:'block',block_rva:block,hits:1,thread:threadId});
              continue;
            }
            if(event[0] !== 'call') continue;
            const site = Number(event[1].sub(module.base).toString());
            const target = Number(event[2].sub(module.base).toString());
            const caller = sites.get(site);
            if(caller !== undefined && entries.has(target)) emit(caller,{kind:'call',site_rva:site,target_rva:target,thread:threadId});
          }
        }});
      };
    }
    for (const fn of plan.functions) {
      const target = module.base.add(fn.rva);
      if (fn.rva < 0 || fn.rva >= module.size) {skippedFunctions++;continue;}
      const range = Process.findRangeByAddress(target);
      if (!range || !range.protection.includes('x')) {skippedFunctions++;continue;}
      let samples = 0;
      let hits = 0;
      try { listeners.push(Interceptor.attach(target, {
        onEnter(args) {
          traceThread(this.threadId);
          const dispatch=pendingDispatch.get(this.threadId);
          const enteringThunk=dispatch && dispatch.implementation!==undefined && dispatch.implementation!==dispatch.target && dispatch.target===fn.rva;
          if(!enteringThunk) pendingDispatch.delete(this.threadId);
          if(dispatch && (dispatch.implementation===undefined?dispatch.target:dispatch.implementation)===fn.rva) {
            const after=args[0];const offset=addressNumber(after)-addressNumber(dispatch.object.base);
            if(offset>=0 && offset<dispatch.object.size)
              emit(dispatch.owner,{kind:'this_adjustment',invocation:dispatch.invocation,allocation:dispatch.object.id,receiver_before:addressNumber(dispatch.receiver),receiver_after:addressNumber(after),adjustment:addressNumber(after)-addressNumber(dispatch.receiver),target_rva:dispatch.target});
          }
          hits++;
          // Record coverage once per function; samples are bounded separately.
          if (hits === 1) emit(fn.rva,{kind:'coverage',hits:1});
          this.sample = samples++ < plan.samples_per_function;
          if (!this.sample) return;
          this.invocation = ++invocation;
          this.pointers=[];
          for(let i=0;i<fn.arguments;i++) {
            emit(fn.rva,{kind:'argument',invocation:this.invocation,index:i,value:args[i].toString()});
            this.pointers.push(args[i]);
            if (fn.snapshot_bytes) snapshot(fn.rva,args[i],fn.snapshot_bytes,this.invocation,"entry",i);
          }
        },
        onLeave(value) {
          if(!this.sample) return;
          emit(fn.rva,{kind:'return',invocation:this.invocation,value:value.toString()});
          if(fn.snapshot_bytes) for(const [index,pointer] of this.pointers.entries()) snapshot(fn.rva,pointer,fn.snapshot_bytes,this.invocation,"return",index);
        }
      })); hookedFunctions++; } catch (_) {skippedFunctions++;}
    }
    if (hookedFunctions === 0) throw new Error("None of the selected functions could be instrumented");
    return {skipped_functions:skippedFunctions,path:module.path,pointer_width:Process.pointerSize,architecture:Process.arch,allocator_hooks:Boolean(malloc && free && plan.allocations)};
  },
  async stop() {
    traceThread = () => {};
    for(const thread of tracedThreads) Stalker.unfollow(thread);
    Stalker.flush();
    await new Promise(resolve => setTimeout(resolve, 100));
    for(const listener of listeners) listener.detach();
    stopping = true;
    return {dropped_events:dropped};
  }
};
