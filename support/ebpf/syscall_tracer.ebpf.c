#include "bpfdefs.h"
#include "types.h"
#include "tracemgmt.h"

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

bpf_map_def SEC("maps") syscall_durations = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u64),   // pid_tgid
  .value_size = sizeof(u64), // time in ns
  .max_entries = 256,
};

static inline
int collect_syscall_trace(void *ctx, TraceOrigin origin, u32 pid, u32 tid,
  u64 trace_timestamp, u64 duration, s32 syscall_id) {
  if (pid == 0) {
    return 0;
  }

  // The trace is reused on each call to this function so we have to reset the
  // variables used to maintain state.
  DEBUG_PRINT("Resetting CPU record");
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace = &record->trace;
  trace->origin = origin;
  trace->pid = pid;
  trace->tid = tid;
  trace->ktime = trace_timestamp;
  trace->offtime = duration;
  trace->syscall_id = syscall_id;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }
  
  // Get the kernel mode stack trace first
  trace->kernel_stack_id = -1;
  DEBUG_PRINT("kernel stack id = %d", trace->kernel_stack_id);

  // Recursive unwind frames
  int unwinder = PROG_UNWIND_STOP;
  bool has_usermode_regs = false;
  ErrorCode error = get_usermode_regs2(ctx, &record->state, &has_usermode_regs);
  if (error || !has_usermode_regs) {
    goto exit;
  }

  if (!pid_information_exists(ctx, pid)) {
    if (report_pid(ctx, pid, RATELIMIT_ACTION_DEFAULT)) {
      increment_metric(metricID_NumProcNew);
    }
    return 0;
  }
  error = get_next_unwinder_after_native_frame(record, &unwinder);

exit:
  record->state.unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("bpf_tail call failed for %d in native_tracer_entry", unwinder);
  return -1;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint_sys_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u32 key = 0;
  SystemConfig* syscfg = bpf_map_lookup_elem(&system_config, &key);
  if (!syscfg) {
    // Unreachable: array maps are always fully initialized.
    return ERR_UNREACHABLE;
  }

  if ((syscfg->syscall_sampling_pid !=-1 && syscfg->syscall_sampling_pid != pid) || bpf_get_prandom_u32() > syscfg->syscall_sampling_threshold) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  if (bpf_map_update_elem(&syscall_durations, &pid_tgid, &ts, BPF_ANY)<0){
    DEBUG_PRINT("Failed to record sched_switch event entry");
	  return 0;
  }

  return 0;
}

bpf_map_def SEC("maps") tracepoint_progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(u32),
  .value_size = sizeof(u32),
  .max_entries = NUM_TRACER_PROGS,
};

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint_sys_exit(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 *ts = bpf_map_lookup_elem(&syscall_durations, &pid_tgid);
  if (!ts) {
    return 0;
  }

  u64 end_ts = bpf_ktime_get_ns();
  u64 duration = end_ts - *ts;
  bpf_map_delete_elem(&syscall_durations, &pid_tgid);

  return collect_syscall_trace(ctx, TRACE_SYSCALL, pid, tid, end_ts, duration, (s32)ctx->id);
}

SEC("tracepoint/dummy")
int dummy2(struct pt_regs *ctx) {
    bpf_tail_call(ctx, &tracepoint_progs,0);
    return 0;
}
