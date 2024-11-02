import sys
from bcc import BPF
from socket import inet_ntoa, ntohl
import struct
from time import sleep
import datetime
import ctypes
import datetime
import socket, struct

bpf_program = """
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/security.h>
#include <linux/limits.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/string.h>
#include <linux/ktime.h>

struct entry_t {
	u8 syscall_type;
	u32 uid;
	u32 pid;
	char path[32];
	u64 ip;
	bool allowed;
};


BPF_HASH(hooks, u64, struct entry_t);
BPF_HASH(inode, u32);

// task 1: deny file creation in a particular directory
LSM_PROBE(inode_create, struct inode *dir, struct dentry *dentry, umode_t mode) {
	struct entry_t e;
	u32 u_id;
	u64 ts;
	ts = bpf_ktime_get_ns();
	u_id = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	e.syscall_type = 1;
	e.uid = u_id;
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_kernel_str(e.path, sizeof(e.path), dentry->d_name.name);

	u32 key = 0;
	u64 *restricted_ino = inode.lookup(&key);
	
	if (restricted_ino != 0) {		
		if (dir->i_ino == *restricted_ino) {
			e.allowed = 0;
			hooks.update(&ts, &e);
			return -EPERM;
		} else {
			e.allowed = 1;
			hooks.update(&ts, &e);
			return 0;
		}
	} else {
		e.allowed = 1;
		hooks.update(&ts, &e);
		return 0;
	}
}


// task 2: deny execution of /bin/nc
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
	struct entry_t e;
	u32 u_id;
	u64 ts;
	ts = bpf_ktime_get_ns();
	u_id = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	e.syscall_type = 2;
	e.uid = u_id;
	e.pid = bpf_get_current_pid_tgid() >> 32;

	char filepath[32];
	bpf_probe_read_kernel_str(e.path, sizeof(e.path), bprm->filename);
	bpf_probe_read_kernel_str(filepath, sizeof(filepath), bprm->filename);

	
	const char target[] = "/bin/nc";
	// Check if the path matches /bin/nc
	if (strncmp(filepath, target, sizeof(target)) == 0) {
 	      	if (u_id != 0) {	// Allow root to execute
					e.allowed = 0;
					hooks.update(&ts, &e);
					return -EPERM;
        	}
	}

	e.allowed = 1;
	hooks.update(&ts, &e);
	return 0;
}

// task 3: deny outbound connections to 192.168.125.125
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *addr, int addrlen) {
	struct entry_t e;
	u32 u_id;
	u64 ts;
	ts = bpf_ktime_get_ns();
	u_id = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	e.syscall_type = 3;
	e.uid = u_id;
	e.pid = bpf_get_current_pid_tgid() >> 32;
	
	struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
	e.ip = addr_in->sin_addr.s_addr;
	if (addr_in->sin_family == AF_INET) {
		if (addr_in->sin_addr.s_addr == htonl(0xc0a87d7d)) {
			e.allowed = 0;
			hooks.update(&ts, &e);
			return -EPERM;
		}
	}

	e.allowed = 1;
	hooks.update(&ts, &e);
	return 0;
}
"""

# Define the key and value as ctypes Structures
class Key(ctypes.Structure):
    _fields_ = [("key", ctypes.c_uint32)]

class Value(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint64)]


if __name__ == "__main__":

	if len(sys.argv) != 2:
		print("Usage: python3 eguard.py <restricted_dir_inode>")
		exit(1)


	restricted_inode = int(sys.argv[1])

	# Load and attach the BPF program
	bpf = BPF(text=bpf_program)
	hooks_map = bpf["hooks"]
	inode_map = bpf["inode"]

	k = Key()
	v = Value()
	k.key = 0
	v.value = restricted_inode
	
	inode_map[k] = v

	print("Running eguard... Press Ctrl+C to stop.")

	try:
		print("%20s\t%20s\t%10s\t%10s\t%32s\t%10s" %("Timestamp", "System Call", "UID", "PID", "Path/IP", "Action"), end="\n\n")

		# Read the data map continuously
		while True:
			sleep(2)
			hooks_map = bpf["hooks"]
			for k, v in hooks_map.items():
				timestamp = datetime.datetime.now().replace(microsecond=0).isoformat()
				syscall = ""
				if v.syscall_type == 1:
					syscall = "open"
					path = v.path.decode('utf-8')

				elif v.syscall_type == 2:
					syscall = "execve"
					path = v.path.decode('utf-8')

				elif v.syscall_type == 3:
					syscall = "connect"
					path = socket.inet_ntoa(struct.pack('<L', v.ip))

				action = "allowed" if v.allowed else "denied"
				print(f"{timestamp:>20}\t{syscall:>20}\t{v.uid:>10}\t{v.pid:>10}\t{path:>32}\t{action:>10}")

				hooks_map.pop(k)

	except KeyboardInterrupt:
		print("Detaching BPF program and exiting...")

	finally:
		# Detach program and clean up on exit
		bpf.cleanup()
