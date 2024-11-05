## Overview

Linux Security Modules (LSM) provide a mechanism to enforce security policies by intercepting and controlling key system operations such as file access, process execution, and network communication. LSM uses hooks — integration points within the kernel—that enable security modules like SELinux, AppArmor, and Smack to monitor and restrict activities. These hooks allow policies to be enforced dynamically, ensuring that only authorized actions are permitted. This framework is essential in environments where fine-grained control over user and process activities is needed to maintain system integrity and security. By intercepting system calls through LSM, administrators can apply restrictions tailored to specific scenarios, preventing unauthorized actions or malicious behavior.

Extended Berkeley Packet Filter (eBPF) is a technology that allows developers to run custom code within the Linux kernel. Initially designed for network packet filtering, eBPF has evolved into a powerful tool for monitoring and managing performance, networking, and security policies. By attaching eBPF programs to LSM hooks, you can create dynamic security policies that are lightweight and efficient, without requiring kernel recompilation.
This assignment focuses on how eBPF programs, combined with LSM hooks, can be used to enforce security policies in real-time. This approach allows for rapid responses to system events, providing a flexible way to enforce restrictions based on specific security requirements.

In this assignment, you are encouraged to use the BPF Compiler Collection (BCC) to help with the development of eBPF programs. BCC is a toolkit that simplifies the process of writing, compiling, and running eBPF code. It provides a collection of Python bindings, pre-built tools, and examples that make working with eBPF more accessible. Using BCC, you can write eBPF programs in a high-level language like Python and easily attach them to various LSM hooks.

BCC will allow you to experiment with eBPF policies quickly and observe how they behave under different conditions. You can use BCC to compile your eBPF programs, load them into the kernel, and monitor the outputs directly. Make sure to explore the documentation and available tools to understand how BCC can assist in implementing dynamic security policies.

The goal of this assignment is to provide hands-on experience in using Linux Security Modules (LSM) and eBPF to enforce security policies at the kernel level. You will implement the following security policies to create a tool eGuard
1. Task1 : Deny File Creation in a directory Create a security policy to prevent the current user from creating regular files in a specific directory. This task simulates a situation where sensitive directories need to be protected to prevent unauthorized file creation. For instance, a directory containing configuration files or logs should not allow users to create new files, as this could introduce malicious code or unauthorized data. Using LSM hooks with eBPF, you will monitor file creation attempts. If a regular file is created in the designated directory, your program must deny the operation and log the event.
2. Task2: Block Execution of /bin/nc In this task, you will develop a policy to block the execution of the /bin/nc command (Netcat) by the current user. While Netcat is useful for legitimate purposes such as testing connections, it is also known to be misused by attackers to open backdoors or transfer data covertly. This makes it a potential security risk in certain environments. You will write an eBPF program that attaches to the LSM hook responsible for process execution. The program should monitor attempts to run /bin/nc and deny execution when it is initiated by the current user.
3. Task3: Block Network Connections to a Specific IP This task involves blocking network connections to the IP address 192.168.125.125. Organizations often block access to known malicious IP addresses to prevent data leaks and unauthorized communication with suspicious servers. In this scenario, the policy will prevent the current user from establishing outbound connections to the specified IP address.
Using LSM hooks attached to networking functions, your program will intercept outbound connection at- tempts. If the connection target matches the restricted IP address, the connection should be denied and the event logged.
In this assignment, you will use BPF maps to store information about events intercepted by your eBPF programs. A BPF map is a key-value store within the kernel, allowing eBPF programs to share data between different components or send data to user-level applications. Using BPF maps is essential for this assignment because they provide an efficient way to store and manage data in real-time between the eBPF program running in the kernel and user-space applications. BPF maps allow your program to log events without costly context switches, ensuring minimal performance overhead. They also support concurrent access, making them ideal for tracking multiple events, such as system calls or network activities, simultaneously. Additionally, BPF maps offer persistence across different invocations of eBPF hooks, allowing your program to accumulate logs over time. By leveraging BPF maps, you can store event details like timestamps, process IDs, system calls, and actions, which can then be retrieved and printed by user-space programs for analysis and reporting.

<br>

Each intercepted event should print your output in the format:

- Timestamp: The time the event was triggered.
- System Call: The system call that triggered the event (e.g., open, execve, connect). • UID: The user ID of the process initiating the event.
- PID: The process ID of the triggering process.
- Path: The absolute path related to the event (e.g., file or executable path).
- Action: This field indicates whether the action was allowed or denied.

<br>

### How to run the tool


```
sudo python3 eguard.py <restricted_dir>
```

- `<restricted_dir>`: The path of the directory where file creation is to be denied

<br>

### How to stop the tool

Press Ctrl+C to stop the tool


<br>

#### Sample output
![alt text](image-4.png)

#### Observations
- Attempts to create files inside `/home/sekar/test` are denied
- Attempts to connect to `192.168.125.125` are denied
- Attempts to run `/bin/nc` are denied

#### Note:

For task 2, the absolute path of the filename is printed only if the file path has the prefix `/home/sekar/`. Otherwise, the relative filepath is printed