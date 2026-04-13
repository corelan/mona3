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

* Install Python 3.9.13 32bit and 64bit
* Install the pykd library for both Python versions
* Install the pykd-ext bootstrapper WinDBG extension
* Install VS runtime and register certain DLLs

---


## 2. Install mona & windbglib

It's quite common to run WinDBG Classic and WINDBGX on the same machine.  Perhaps you even have Immunity Debugger lying around.

You have the option to install a copy of `mona.py` and `windbglib.py` for each application individually. 

For WinDBG classic, this means that you need to put the 2 files in the WinDBG Program folder:

* 32bit: store the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
* 64bit: store the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`

For Immunity Debugger, you'll have to put `mona.py` under `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`
(You don't need `windbglib.py` in Immunity Debugger)

And for WinDBGX, you'll have to reference the script files from whatever folder you put them in.

An alternative approach would be to store the 2 files in a central location and to reference the files directly using their absolute path.
That way, there is only one copy on your system.  Each time you run `mona up`, you'll updating the scripts for all debuggers right away.

In order to avoid having to type the full path every time, we can define an alias in WinDBG Classic and WinDBGX
And for Immunity Debugger, we can use a simply symlink. 

Let's see what that looks like


### 2.1. Set up central location

Download the `mona.py` and `windbglib.py` file from this repository and store the files inside a folder under `C:\Tools\mona`.

(Of course, if you decide to pick a different folder, update the commands in the next chapters accordingly)

Please verify that the files contain the actual python code, and not html ;-)


### 2.2. Usage in WinDBG Classic / WinDBGX

In WinDBG Classic and WinDBGX,  we're going to reference the files directly from the `C:\Tools\mona` folder.  

We'll show how to use this in chapter 3

Also, please note that we prefer and recommend to run `mona` with Python 3.9 in WinDBG(X)
If you don't need Python2 (and not using Immunity Debugger), feel free to remove Python2 from your system.



### 2.3 Immunity Debugger

* Put a copy of `mona.py` file under `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands` with the following command: 
  * `mklink "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\mona.py" "C:\Tools\mona\mona.py"`   
* Install Python 2.7.18 32bit (not 64bit)
* Make sure the 32bit version of C:\Python27 is in your path system environment variable.   
    * If you prefer not to do so, see the chapter on "Running Mona in Immunity" for ideas on creating a launcher .bat file that temporarily sets up the PATH.
    * If you open a command prompt and type `python`, it should invoke the Python 2.7.18 32Bit interactive console

---


## 3. Running Mona

### 3.1. Running Mona in WinDBG Classic and WinDBGX

Open WinDBG(X) and attach it to the process you'd like to debug.
At the WinDBG(X) Command Line, load the pykd bootstrapper extension
```
!load pykd
```

Now run mona using Python3.9:
```
!py -3.9 C:\Tools\mona\mona.py
```

Of course, you can also create an alias to make it easier to run mona commands:

```
!as mona !py -3.9 C:\Tools\mona\mona.py
```
Now you can simply invoke mona by running `!mona` at the WinDBG(X) Command Line.


### 3.2. Auto loading pykd and creating an alias in WinDBG(X)

In WinDBG Classic, we can use the `-c` command line option to automatically load pykd and create the alias to the mona script.

Simply run windbg.exe -c "!load pykd;as !mona !py -3.9 c:\Tools\mona\mona.py"

While you can do the same thing when launching WinDBGX, you can also configure WinDBGX `Startup` settings to run the same commands.

Open `Files > Settings > Debugging settings > Startup` and paste in the following commands:

```
!load pykd
as !mona !py -3.9 c:\Tools\mona\mona.py
```

You only need to do the procedure above once, as WinDBGX adapts to 32 or 64 bit depending on the debugging target.


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

Mona v3 would not have been possible without the hard work & dedication done by [@apl3b](https://github.com/apl3b)


---


## Found a bug ?

If you find bugs, please open an issue and explain details on how to reproduce the problem you're seeing.