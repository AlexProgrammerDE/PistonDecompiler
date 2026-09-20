// Frida agent. Host supplies a validated capture plan before the target resumes.
let sequence = 0;
let invocation = 0;
let allocationSequence = 0;
let dropped = 0;
let count = 0;
const allocations = new Map();
const listeners = [];
let settings;
let module;
let traceThread = () => {};
const tracedThreads = new Set();
function emit(functionRva, observation) {
  if (count >= settings.max_events) { dropped++; return false; }
  count++;
  send({sequence: ++sequence, thread: Process.getCurrentThreadId(), function_rva: functionRva, ...observation});
  return true;
}
function addressNumber(pointer) {
  const n = Number(pointer.toString());
  if (!Number.isSafeInteger(n)) throw new Error('Address exceeds exact JavaScript integer range');
  return n;
}
function snapshot(functionRva, pointer, bytes) {
  const allocation = allocations.get(pointer.toString());
  if (!allocation) return;
  try {
    const buffer = new Uint8Array(pointer.readByteArray(Math.min(bytes, allocation.size, 4096)));
    emit(functionRva, {kind:'snapshot', allocation:allocation.id, offset:0,
      bytes:Array.from(buffer, b => b.toString(16).padStart(2,'0')).join('')});
  } catch (_) { dropped++; }
}
rpc.exports = {
  start(plan) {
    settings = plan;
    module = Process.mainModule;
    // Only the main module is supported by this adapter.
    const malloc = Module.findGlobalExportByName('malloc');
    const free = Module.findGlobalExportByName('free');
    if (malloc && free && plan.allocations) {
      listeners.push(Interceptor.attach(malloc, {
        onEnter(args) { this.size = addressNumber(args[0]); },
        onLeave(result) {
          if (result.isNull() || this.size <= 0) return;
          const id = `allocation-${++allocationSequence}`;
          if (emit(null, {kind:'allocation', allocation:id, address:addressNumber(result), size:this.size})) allocations.set(result.toString(), {id, size:this.size});
        }
      }));
      listeners.push(Interceptor.attach(free, {
        onEnter(args) {
          const key=args[0].toString(); const allocation=allocations.get(key);
          if (allocation) { emit(null,{kind:'free',allocation:allocation.id}); allocations.delete(key); }
        }
      }));
    }
    if (plan.trace_calls || plan.trace_blocks) {
      Stalker.queueDrainInterval = 50;
      const sites = new Map();
      for (const fn of plan.functions) for (const site of (fn.instruction_rvas || [])) sites.set(site, fn.rva);
      const entries = new Set(plan.functions.map(fn => fn.rva));
      traceThread = (threadId) => {
        if(tracedThreads.has(threadId)) return;
        tracedThreads.add(threadId);
        Stalker.follow(threadId, {events:{call:Boolean(plan.trace_calls),block:Boolean(plan.trace_blocks)}, onReceive(buffer) {
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
      if (fn.rva < 0 || fn.rva >= module.size) throw new Error('Function is outside main module');
      let samples = 0;
      let hits = 0;
      listeners.push(Interceptor.attach(target, {
        onEnter(args) {
          traceThread(this.threadId);
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
            if (fn.snapshot_bytes) snapshot(fn.rva,args[i],fn.snapshot_bytes);
          }
        },
        onLeave(value) {
          if(!this.sample) return;
          emit(fn.rva,{kind:'return',invocation:this.invocation,value:value.toString()});
          if(fn.snapshot_bytes) for(const pointer of this.pointers) snapshot(fn.rva,pointer,fn.snapshot_bytes);
        }
      }));
    }
    return {path:module.path,pointer_width:Process.pointerSize,architecture:Process.arch,allocator_hooks:Boolean(malloc && free && plan.allocations)};
  },
  async stop() {
    traceThread = () => {};
    for(const thread of tracedThreads) Stalker.unfollow(thread);
    Stalker.flush();
    await new Promise(resolve => setTimeout(resolve, 100));
    for(const listener of listeners) listener.detach();
    return {dropped_events:dropped};
  }
};
