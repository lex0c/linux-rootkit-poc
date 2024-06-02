# Linux Rootkit POC

This rootkit runs in userland and manipulates system calls and critical functions to hide its presence and provide backdoors for unauthorized access.

**Why**? For fun...

**Disclaimer**

The author is in no way responsible for any illegal use of this software. It is provided as an educational proof of concept (poc) only. He is also not responsible for any damages or mishaps that may occur while using this software. Use it at your own risk.

This poc is based on: [azazel](https://github.com/chokepoint/azazel)

## Features

- Hides processes, files, directories and network connections
- Open remote terminal (plaintext) with password
- Add PAM backdoor for local root access
- Block some binaries to avoid analysis
- Hides from the rkhunter and unhide
- Avoids local sniffing
- Exit on debug

## Access remote backdoor

```sh
nc <IP> <PORT>
```
*enter the password!*

## Access local backdoor

```sh
sudo -u <USER> -s

export HIDE_THIS_SHELL=foobar // to be owner
```

## Update hash db 

```sh
make -f Makefile.rootkit update-hashdb
```

## Checks

- `sudo ss -antup`

- `sudo nmap -sV -p- -v <IP> --reason`

- `sudo tcpdump <PROTOCOL> port <PORT> -A`

- `sudo lsof -u <USER>`
- `sudo lsof -i :<PORT>`
- `sudo lsof -i <PROTOCOL>`
- `sudo lsof -p <PID>`

- `sudo unhide proc`
- `sudo unhide sys`

- `sudo rkhunter --update && sudo rkhunter --check`

- `sudo ps aux | grep shellserver`

- `sudo strace -p <PID>`

- `sudo cat /proc/net/tcp`
- `sudo cat /proc/net/tc6`

- `sudo w`

- `sudo last`

## Block remote backdoor

- `sudo iptables -A INPUT -p tcp --dport <PORT> -j DROP`

## Unblock remote backdoor

- `sudo iptables -L -v -n --line-numbers`
- `sudo iptables -D INPUT <NUM>`

