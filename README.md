# NetAttack
The net_attack.py script automates the discovery of weak usernames and passwords commonly used in various network services and supports post-exploitation for services where weak credentials are found. It accepts the following parameters: -t or --target for the target IP address, -p or --ports for the ports to scan, -u or --username for the username, and -l or --password-list for the path to a file containing a list of passwords. The script uses the following Python modules: argparse, time, os, sys, paramiko, scapy, socket, and requests.

This project includes two main components:
1. net_attack.py: Automates scanning, service detection, credential bruteforcing, and post-exploitation.
2. shell.py: A persistent reverse shell script for post-access automation.

The tool allows attackers to:
1. Check connectivity using ICMP.
2. Scan TCP ports and identify common services.
3. Confirm presence of SSH and HTTP services.
4. Bust directories on accessible web servers.
5. Bruteforce login credentials for SSH and Web logins.
6. Gain shell access via SSH.
7. Deploy persistent reverse shell (shell.py) and maintain remote access.

Usage:

      python3 net_attack.py -t <target_ip> -p <ports> -u <username> -l <password_list>

Example:
      
      python3 net_attack.py -t 192.168.56.100 -p 22,80 -u root -l rockyou.txt

During SSH login success, you will be prompted to:
1. Press y to launch a live SSH shell
2. Press P to deploy the persistent reverse shell (shell.py)
3. Press N to continue without shell access

