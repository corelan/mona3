```
___  ________ _   _   ___          _____ 
|  \/  |  _  | \ | | / _ \        |____ |
| .  . | | | |  \| |/ /_\ \ __   __   / /
| |\/| | | | | . ` ||  _  | \ \ / /   \ \
| |  | \ \_/ / |\  || | | |  \ V /.___/ /
\_|  |_/\___/\_| \_/\_| |_/   \_/ \____/ 
                                         
                                         
```

# MONA v3

This repository contains the necessary python files to run Mona v3 under WinDBG(X) and Immunity.

Some highlights:
* Mona is compatible with Python3 versions as supported by PyKD and PyKD-ext. (i.e. up to (and including) Python 3.9.13).  
* Mona is backwards compatible and still runs on Python2.7.18 as well.
* Mona supports x86 and x64 debugging sessions. Please do keep in mind that not all mona commands are available in 64bit.
* Mona has been tested on Window7, Windows 10 and Windows 11.

---

# Preparing your system to run Mona

## 1. Install dependencies

For Windows 10 and up, you can use the `CorelanPyKDInstall.ps` powershell script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining)

In a nutshell, the script will

* Install Python 3.9 32bit and 64bit
* Install the pykd library via pip
* Install the pykd-ext bootstrapper WinDBG extension
* Install VS runtime and register certain DLLs

---


## 2. Install mona & windbglib

### 2.1. WinDBG Classic

Download the `mona.py` and `windbglib.py` file from this repository and store the files inside the `x86` and `x64` folders of your WinDBG classic program folder.

For example, on Windows 11:

* 32bit: store the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
* 64bit: store the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`

Please verify that the files contain the actual python code, and not html ;-)

Note: we prefer to run the current version of `mona` with Python 3. 
If you don't need Python2, feel free to remove it from your system.



### 2.2 WinDBGX


### 2.3 Immunity Debugger

If you would like to run `mona.py` under Immunity:

* Download the `mona.py` file and place it under `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`.   You do not need `windbglib.py`
* Install Python 2.7.18 32bit (not 64bit)
* Make sure the 32bit version of C:\Python27 is in your path system environment variable.   
    * If you prefer not to do so, see the chapter on "Running Mona in Immunity" for ideas on creating a launcher .bat file that temporarily sets up the PATH.
    * If you open a command prompt and type `python`, it should invoke the Python 2.7.18 32Bit interactive console


---


## 3. Running Mona

### 3.1. Running Mona in WinDBG Classic

Open WinDBG and attach it to the process you'd like to debug.
At the WinDBG Command Line, load the pykd bootstrapper extension
```
!load pykd
```
Now run mona using Python3.9:
```
!py -3.9 mona
```

Of course, you can also create an alias to make it easier to run mona commands:

```
as mona !py -3.9 mona
```
Now you can simply invoke mona by running `mona` at the WinDBG Command Line.


The procedure above works for both 32bit and 64bit debugging sessions.



### 3.2. Running Mona in WinDBGX


### 3.3. Running Mona in Immunity

Providing that your Python2 program folder is in the system path, you can simply launch Immunity Debugger and then run `!mona` at the Immunity Debugger command prompt.
If you prefer not to have C:\Python27 in your system PATH, you can also create a simple Immunity Debugger launcher script that temporarily sets up the Path environment variable:

runimmunity.bat

```
@echo off
c:
cd "C:\Program Files (x86)\Immunity Inc\Immunity Debugger"
set ORIGPATH=%PATH%
set PATH=C:\Python27;%PATH%
immunitydebugger.exe
set PATH=%ORIGPATH%
```

---

## Thank you

Mona v3 would not have been possible without the hard work & dedication done by @apl3b 


---


## Found a bug ?

If you find bugs, please open an issue and explain details on how to reproduce the problem you're seeing.