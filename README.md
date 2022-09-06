```
██████╗ ███████╗███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔════╝██╔════╝██║  ██║██╔════╝██║     ██║     
██║  ██║█████╗  ███████╗███████║█████╗  ██║     ██║     
██║  ██║██╔══╝  ╚════██║██╔══██║██╔══╝  ██║     ██║     
██████╔╝██║     ███████║██║  ██║███████╗███████╗███████╗
╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝                      
```

***D3Ext's Forwarded Shell*** it's a python3 script which use mkfifo to simulate a shell into the victim machine.
It creates a hidden directory in /dev/shm/.fs/ and there are stored the fifos. You can even have a tty over a webshell.

In case you want a good webshell with code obfuscation, login panel and more functions you have this [webshell](https://raw.githubusercontent.com/D3Ext/DFShell/main/obfuscated.php) (scripted by me), you can change the username and the password at the top of the file, it also have a little protection in case of beeing discovered because if the webshell is accessed from localhost it gives a 404 status code

### Why you should use DFShell?
To use other forwarded shells you have to edit the script to change the url and the parameter of the webshell, but **DFShell** use parameters to quickly pass the arguments to the script (-u/--url and -p/--parameter), the script have a pretty output with colors, you also have custom commands to upload and download files from the target, do port and host discovery, and it deletes the files created on the victim if you press Ctrl + C or simply exit from the shell.

*\*If you change the actual user from webshell (or anything get unstable) then execute: 'sh'\**

## Installation:

> Install with pip
```sh
pip3 install dfshell
```

> Install from source
```sh
git clone https://github.com/D3Ext/DFShell
cd DFShell
pip3 install -r requirements
```

> One-liner
```sh
git clone https://github.com/D3Ext/DFShell && cd DFShell && pip3 install -r requirements
```

## Usage:

It's simple, you pass the url of the webshell and the parameter that executes commands.
I recommend you the most simple [webshell](https://github.com/D3Ext/DFShell/blob/main/webshell.php)

```sh
python3 DFShell.py -u http://10.10.10.10/webshell.php -p cmd
```

## Demo:

<img src="https://raw.githubusercontent.com/D3Ext/DFShell/main/images/DFShell.png">

**If you consider this project has been useful, I would really appreciate supporting me by giving this repo a star or buying me a coffee.**

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/d3ext)

Copyright © 2022, *D3Ext*

