# Recon

## Hosts

`sudo nmap -sn 10.10.48.42/24`
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-21 12:50 EST
Nmap scan report for 10.10.48.1
Host is up (0.043s latency).
Nmap scan report for 10.10.48.100
Host is up (0.045s latency).
Nmap scan report for 10.10.48.186
Host is up (0.044s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 22.10 seconds

## Ports
Nmap scan report for **10.10.48.42**
Host is up (0.046s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
3389/tcp open  ms-wbt-server
9999/tcp open  abyss

Nmap scan report for **10.10.48.100**
Host is up (0.043s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http

Nmap scan report for **10.10.48.186**
Host is up (0.043s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
111/tcp open  rpcbind 2-4 (RPC #100000)

## Buffer overflow

Checking out the service on port 9999:

!(Service port 9999)[./img/service_port_9999.png]

Fuzzing it: Crash after sending **4700** bytes


