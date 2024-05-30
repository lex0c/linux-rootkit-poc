# Linux Rootkit POC

The poc works in two stages:

- **1**: Adds a shared lib to the ld preload. This lib contains hooks to hide the backdoor.
- **2**: Install the backdoor on the systemd. The backdoor listens to connections on a specific password-protected port.

**Why**? For fun...

**Disclaimer**

The author is in no way responsible for any illegal use of this software. It is provided as an educational proof of concept (poc) only. He is also not responsible for any damages or mishaps that may occur while using this software. Use it at your own risk.

This poc is based on: [azazel](https://github.com/chokepoint/azazel)

## Features

- Hide files and dirs
- Hide process and connections
- Open n remote pty (plaintext) with password
- Avoids unhide
- Avoids local sniffing
- Exit on debug

## Access backdoor

```sh
nc <BACKDOOR-IP> <BACKDOOR-PORT>
```
*enter the password!*

## Checks

- `sudo ss -antup`

- `sudo nmap -sV -p- -v <IP> --reason`

- `sudo tcpdump <PROTOCOL> port <BACKDOOR-PORT> -A`

- `sudo lsof -u <USER>`
- `sudo lsof -i :<BACKDOOR-PORT>`
- `sudo lsof -i <PROTOCOL>`
- `sudo lsof -p <BACKDOOR-PID>`

- `sudo unhide proc`
- `sudo unhide sys`

- `sudo ps aux | grep shellserver`

- `sudo cat /proc/net/tcp`
- `sudo cat /proc/net/tc6`

- `sudo w`

- `sudo last`

## Block backdoor

- `sudo iptables -A INPUT -p tcp --dport <BACKDOOR-PORT> -j DROP`

## Unblock backdoor

- `sudo iptables -L -v -n --line-numbers`
- `sudo iptables -D INPUT <NUM>`

