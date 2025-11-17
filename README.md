# Penetration-testing-lab-with-Kali-Linux-on-Metasploitable-2
## Purpose
The aim of this lab is to experience ethical hacking in a virtual environment composed of two virtual machines: an attacker machine running Kali Linux (an Advanced Penetration Testing Linux distribution used for Penetration Testing) and a victim host running Metasploitable 2 (an intentionally vulnerable Ubuntu Linux virtual machine designed for testing common vulnerabilities).
In this lab, I will:
* Lean the penetration testing methodology.
* Conduct port scanning and services enumeration on the target host.
* Brute force the login page of a web application.
* Exploit a command injection vulnerability on a vulnerable web server and gain an unprivileged access through a reverse shell execution.
* Escalate privilege and become root user on the vulnerable machine.
* Install a backdoor on the compromised host to maintain access.
* Hide traces on the victim system by installing and configuring a rootkit.

## Lab configuration
Two virtual hosts running Linux operating system are required to achieve this lab. The first is the attacker machine and is running **Kali Linux** (an Advanced Penetration Testing Linux distribution used for Penetration Testing). The second is the victim machine running **Metasploitable 2** (an intentionally vulnerable Ubuntu Linux virtual machine designed for testing common vulnerabilities). The two network adapters of these machines are attached to a NAT Network, so that they can communicate to each other and talk to outside (main host, local network, and internet).
