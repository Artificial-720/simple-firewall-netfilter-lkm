# simple-firewall-netfilter-lkm

Using Linux Kernel Modules (LKM) and Netfilter to implement a packet filtering module. This module will filter packets based on hard coded rules. Effectively creating a simple firewall.

Environment is a NAT network with two machines on it:
- Machine A (has firewall installed on it)
- Machine B

## Firewall Rules implemented
1. Outbound telnet traffic from Machine A to Machine B.
2. Inbound telnet traffic to Machine A from Machine B.
3. Outbound SSH (Secure Shell) traffic from Machine A to Machine B.
4. Inbound SSH traffic to Machine A from Machine B.
5. Access from Machine A to a specific external website.

## Simple Install
Uses a bash script to run the commands
```bash
$ make
$ sudo ./reload.sh
```

## Manual Install
Build
```bash
$ make
```
Install module into the Kernel
```bash
$ sudo insmod myfirewall.ko
```
Check that module was loaded
```bash
$ lsmod | grep myfire
```

To check log for the kernal files
```bash
$ sudo dmesg | tail -10
```

To **uninstall** Module
```bash
$ sudo rmmod myfirewall
```