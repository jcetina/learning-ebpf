#!/usr/bin/python3  
from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}

int openat(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   char command[16];

   bpf_get_current_comm(&command, sizeof(command));
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   bpf_trace_printk("openat");
   return 0;
}
"""

# bpf_trace_printk("%s", sizeof(command), command);

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
openat = b.get_syscall_fnname("openat")
write = b.get_syscall_fnname("write")
b.attach_kprobe(event=syscall, fn_name="hello")
b.attach_kprobe(event=openat, fn_name="openat")
b.attach_kprobe(event=write, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    b.trace_print()
    sleep(2)
    s = ""
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
