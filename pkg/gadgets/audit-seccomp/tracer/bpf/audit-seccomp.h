#ifndef GADGET_AUDIT_SECCOMP_H
#define GADGET_AUDIT_SECCOMP_H

#include "../../../../vmlinux/vmlinux-cgo.h"
// #ifndef __VMLINUX_H__
// typedef long long unsigned int __u64;
// #endif

#define TASK_COMM_LEN 16

// From pkg/gadgettracermanager/common.h
#define NAME_MAX_LENGTH 256

struct event {
	__u64 pid;
	__u64 mntns_id;
	__u64 syscall;
	__u64 code;
	char comm[TASK_COMM_LEN];
	char pod[NAME_MAX_LENGTH];
};

#endif
