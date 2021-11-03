// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux/vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "audit-seccomp.h"

#include <gadgettracermanager/bpf-maps.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/audit_seccomp")
int kprobe__audit_seccomp(struct pt_regs *ctx)
{
	unsigned long syscall = PT_REGS_PARM1(ctx);
	int code = PT_REGS_PARM3(ctx);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns_id == 0) {
		return 0;
	}

#ifdef WITH_FILTER
	__u32 *found = bpf_map_lookup_elem(&filter, &mntns_id);
	if (!found)
		return 0;
#endif

	struct event event = {};
	event.pid = bpf_get_current_pid_tgid();
	event.mntns_id = mntns_id;
	event.syscall = syscall;
	event.code = code;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	struct container *container_entry;
	container_entry = bpf_map_lookup_elem(&containers, &mntns_id);
	if (container_entry) {
		int i;
		for (i = 0; i< sizeof(event.pod); i++)
			event.pod[i] = container_entry->pod[i];
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

char _license[] SEC("license") = "GPL";
