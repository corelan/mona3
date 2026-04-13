# MONA

This repository contains the necessary python files to run Mona v3 under WinDBG(X) and Immunity.

Mona is now compatible with Python 2.7.18, as well as Python3 versions as supported by PyKD and PyKD-ext. (3.9.13)

It runs in x86 and x64 debugging sessions.

Mona has been tested on Window7, Windows 10 and Windows 11



# Preparing your system to run Mona

## Install dependencies

For Windows 10 and up, you can use the `CorelanPyKDInstall.ps` powershell script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining)

In a nutshell, the script will

* Install Python 3.9 32bit and 64bit
* Install the pykd library via pip
* Install the pykd-extension for WinDBG
* Install VS runtime and register certain DLLs


## Install mona & windbglib

### WinDBG Classic

Download the `mona.py` and `windbglib.py` file from this repository and store the files inside the `x86` and `x64` folders of your WinDBG classic program folder.

For example, on Windows 11:
32bit: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
64bit: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`

Please verify that the files contain the actual python code, and not html ;-)

Note: we prefer to run the current version of `mona` with Python 3. 
If you don't need Python2, feel free to remove it from your system.



### WinDBGX


### Immunity Debugger

If you prefer to run `mona.py` under Immunity:

* Download the `mona.py` file and place it under `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`.   You do not need `windbglib.py`
* Install Python 2.7.18 32bit (not 64bit)
* Make sure the 32bit version of C:\Python27 is in your path system environment variable

(If you open a command prompt and type `python`, it should invoke the Python 2.7.18 32Bit interactive console)

As with previous versions of mona, you can now run `!mona` at the Immunity Debugger command prompt.




