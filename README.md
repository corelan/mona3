![mona v3 banner](mona-banner.png)

# MONA v3

## Table of Contents

- [Preparing your system to run Mona](#preparing-your-system-to-run-mona)
  - [1. Install dependencies](#1-install-dependencies)
    - [1.1. Windows 10 and later](#11-windows-10-and-later)
    - [1.2. Windows 7](#12-windows-7)
    - [1.3. A note on 64bit](#13-a-note-on-64bit)
  - [2. Install mona & windbglib](#2-install-mona--windbglib)
    - [2.1. Distributed installation](#21-distributed-installation)
    - [2.2. Centralized installation (recommended)](#22-centralized-installation-recommended)
      - [Step 1: Set up central location](#step-1-set-up-central-location)
      - [Step 2: Configure for WinDBG Classic / WinDBGX](#step-2-configure-for-windbg-classic--windbgx)
      - [Step 3: Configure for Immunity Debugger](#step-3-configure-for-immunity-debugger)
  - [3. Running Mona](#3-running-mona)
    - [3.1. Running Mona in WinDBG(X)](#31-running-mona-in-windbgx)
    - [3.2. Auto loading pykd and creating an alias in WinDBG(X)](#32-auto-loading-pykd-and-creating-an-alias-in-windbgx)
    - [3.3. Running Mona in WinDBG Classic on Windows 7](#33-running-mona-in-windbg-classic-on-windows-7)
    - [3.4. Helping Python find its libraries](#34-helping-python-find-its-libraries)
    - [3.5. Running Mona in Immunity](#35-running-mona-in-immunity)
- [Thank you](#thank-you)
- [Found a bug?](#found-a-bug)
- [Want to contribute?](#want-to-contribute)

This repository contains the necessary Python files to run **Mona v3** under **WinDBG(X)** and **Immunity Debugger**.

### Highlights
* **Python 3 Support**: Compatible with **Python 3.9.13** (via PyKD and PyKD-ext)
* **Backwards Compatible**: Still runs on **Python 2.7.18** (via PyKD and PyKD-ext)
* **Multi-Architecture**: Supports both ***x86 and x64*** debugging sessions *(note: not all `mona`commands are available in 64-bit)*
* **Tested on**: Windows 7, Windows 10, and Windows 11

---
<br> <br> 

# Preparing your system to run Mona

<br> 

## 1. Install dependencies


### 1.1. Windows 10 and later

**For Windows 10 and later**, we recommend using the `CorelanPyKDInstall.ps` PowerShell script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining).

The script will automatically:

* ***Install*** **Python 3.9.13** (both 32-bit and 64-bit)
* ***Install*** **PyKD** Python library
* ***Install*** **Keystone-engine** Python library 
* ***Install*** **PyKD-ext** bootstrapper WinDBG extension
* ***Install*** **Visual Studio runtime** and register required DLLs


If you prefer to install those components by yourself, please verify (after installation) the desired Python3/PyKD behavior:

Open an administrator command prompt.

Run `py -3.9-32`

You should get a Python interactive shell running Python 3.9.13 32bit:

```batch
C:\>py -3.9-32
Python 3.9.13 (tags/v3.9.13:6de2ca5, May 17 2022, 16:24:45) [MSC v.1929 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Type the following commands and verify there are no warnings or errors:

```python
import pykd
import keystone
quit()
```


Next, run `py -3.9-64`

That should provide you with a Python interactive shell running Python 3.9.13 64bit

```batch
C:\>py -3.9-64
Python 3.9.13 (tags/v3.9.13:6de2ca5, May 17 2022, 16:36:42) [MSC v.1929 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>>
```

Type the following commands and verify there are no warnings or errors:

```python
import pykd
import keystone
quit()
```

<br> 

### 1.2. Windows 7

**Still running Windows 7 somewhere?**

Begin by installing Python 2.7.18.

Next, download a copy of the `CorelanWin7VMinstall.py` python script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining) and run it from an administrator command prompt.

This will install all required components to run `mona` on Windows 7.


### 1.3. A note on 64bit

The 64bit versions of WinDBG(X) don't actually support assembling 64bit mnemonics into opcode. 

We've hardcoded a few common instructions in an assembly "cache" inside windbglib.py, but we're also checking if your machine has the `keystone-engine` library installed.
 
If it is the case, windbglib will use it as needed to assemble.
If not, support for 64bit assembly will be limited, and some commands that take arbitrary assemby statements might fail.

---

<br> <br> 

## 2. Install mona & windbglib

You have two installation approaches: ***distributed*** (multiple copies) or ***centralized*** (recommended - single copy).

<br> 

### 2.1. Distributed installation 

Install separate copies of `mona.py` and `windbglib.py` for each debugger application. This approach is useful if you have multiple debuggers on the same machine.

**For WinDBG Classic:**
* **32-bit**: put the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
* **64-bit**: put the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`

**For Immunity Debugger:**
* Place `mona.py` in: `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`
* *Note: You do not need `windbglib.py` for Immunity*

**For WinDBGX:**
* Reference `mona.py` from ***any location*** of your choice

<br> 

### 2.2. Centralized installation (recommended) 

**Advantages**: Maintain a ***single copy*** on your system. Each `mona up` update applies to *all* debuggers immediately. 

> We're going to use WinDBG(X) aliases to avoid having to type the full path.

<br> 

#### Step 1: Set up central location

Create a central folder, for instance `C:\Tools\mona3`.

(If you decide to make another folder, please update the commands below accordingly)

**Download** `mona.py` and `windbglib.py` from this repository and ***store*** them in the central folder: `C:\Tools\mona3`

> **⚠️ Important**: Verify the downloaded files contain ***actual Python code***, not HTML

<br> 

#### Step 2: Configure for WinDBG Classic / WinDBGX

Reference the files directly from `C:\Tools\mona3` using aliases (see **Section 3.2** for auto-loading setup).

**Recommendation**: Use **Python 3.9** when running `mona` in WinDBG(X). 

If not using Immunity Debugger or Python2 scripts, feel free to safely ***remove Python 2*** from your system.

<br> 

#### Step 3: Configure for Immunity Debugger

**Option A: Create a symbolic link** (recommended)
```batch
mklink "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\mona.py" "C:\Tools\mona3\mona.py"
```

**Option B: Copy the file directly**
* Copy `mona.py` to: `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`

**Python 2 Setup** (required for Immunity):
* ***Install*** **Python 2.7.18** (***32-bit version only***)
* ***Ensure*** the 32-bit `C:\Python27` folder is in your system **PATH** environment variable
  * ***Verify*** by opening Command Prompt and typing `python` — it should launch Python 2.7.18 (32-bit)
  * *Alternative*: See **Section 3.3** for a launcher `.bat` file to temporarily set the PATH

---

<br> <br> 

## 3. Running Mona

<br> 

### 3.1. Running Mona in WinDBG(X)

**Step 1**: ***Open*** **WinDBG(X)** and ***attach*** it to your target process

**Step 2**: At the WinDBG(X) Command Line, ***load*** the **PyKD** bootstrapper extension:
```python
!load pykd
```

**Step 3**: ***Run*** **Mona** using **Python 3.9**:

On WinDBG(X):
```python
!py -3.9 C:\Tools\mona3\mona.py
```
(You can run the same command on 32bit and 64bit debugging sessions, WinDBG(X) will select the appropriate Python3.9.13 version)


**Convenience**: ***Create an alias*** to avoid typing the full path every time:
```python
!as !mona !py -3.9 C:\Tools\mona3\mona.py
```
Now you can simply type `!mona` at the WinDBG(X) Command Line.

<br> 

### 3.2. Auto loading pykd and creating an alias in WinDBG(X)

**For WinDBG Classic:**

***Launch*** with the `-c` flag to auto-load **PyKD** and ***create*** the **mona** alias. 

You could create a small batch file inside the WinDBG Program folders (both `x86` and `x64`) that has all the required command line arguments:

For example, create `w.bat`in the x86 folder,  with the following contents:

```batch
set "WINDBG_CMD=windbg.exe -hd -c '!load pykd; as !mona !py -3.9 C:\Tools\mona3\mona.py' "

%WINDBG_CMD% %*
```
Or, to launch a 64bit version of Python in WinDBG Classic 64bit:

```batch
set "WINDBG_CMD=windbg.exe -hd -c '!load pykd; as !mona !py -3.9-64 C:\Tools\mona3\mona.py' "

%WINDBG_CMD% %*
```


**For WinDBGX:**

In WinDBGX, we can use the "Startup Settings"

***Configure*** the **Startup settings** to auto-load on every session:
1. Navigate to: ***File > Settings > Debugging settings > Startup***
2. ***Paste*** the following commands:
```python
!load pykd
as !mona !py -3.9 C:\Tools\mona3\mona.py
```

> **Note**: You only need to configure this ***once***. WinDBGX will automatically adapt to 32-bit or 64-bit depending on your debugging target.

<br> 

### 3.3. Running Mona in WinDBG Classic on Windows 7

For Windows 7, we recommend using a small launcher script that sets a few Python related environment variables.

To run mona with Python3, you could create this `wpy3.bat` file and save it inside the WinDBG Program folder

```batch
@echo off
set ORIGPATH=%PATH%
set PYTHONHOME=%LOCALAPPDATA%\Programs\Python\Python38-32
set PATH=%PYTHONHOME%;%PATH%
set PYTHONPATH=%PYTHONHOME%\Lib

set WINDBG_CMD=windbg.exe -hd -c '!load pykd;as !mona !py -3 C:\Tools\mona3\mona.py'

%WINDBG_CMD% %*

set PATH=%ORIGPATH%
set PYTHONHOME=
set PYTHONPATH=
```

For Python2, the corresponding `wpy2.bat` file would look like this:

```batch
@echo off
set ORIGPATH=%PATH%
set PYTHONHOME=C:\Python27
set PATH=%PYTHONHOME%;%PATH%
set PYTHONPATH=%PYTHONHOME%\Lib

set WINDBG_CMD=windbg.exe -hd -c '!load pykd;as !mona !py -2 C:\Tools\mona3\mona.py'

%WINDBG_CMD% %*

set PATH=%ORIGPATH%
SET PYTHONHOME=
SET PYTHONPATH=
```

<br> 


### 3.4. Helping Python find its libraries

You can use similar batch files in Windows 11 as well.
This may be helpful in case you have various different Python versions installed on your system.
Although WinDBG(X) may be able to find a certain Python version, it still may fail to locate/load basic libraries (such as `socket` etc)

This is what the problem looks like:
```python
0:000> !pykd.info

pykd bootstrapper version: 2.0.0.24

Installed python:

Version:        Status:     Image:
------------------------------------------------------------------------------
  2.7 x86-64    Unloaded    C:\Windows\SYSTEM32\python27.dll
  3.9 x86-64    Unloaded    C:\Users\corelan\AppData\Local\Programs\Python\Python39\python39.dll
* 3.14 x86-64   Unloaded    C:\Users\corelan\AppData\Local\Programs\Python\Python314\python314.dll

0:000> !py -2.7
Python 2.7.18 (v2.7.18:8d21aa21f2, Apr 20 2020, 13:25:05) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> import socket
Traceback (most recent call last):
  File "<console>", line 1, in <module>
  File "C:\Python27\Lib\socket.py", line 47, in <module>
    import _socket
ImportError: DLL load failed: %1 is not a valid Win32 application.
>>>
```

As you can see, although WinDBG loaded the correct Python version/architecture (2.7.8 64bit), it still references libraries from the 32bit Python installation in `C:\Python27\Lib` instead of `C:\Python27-64\Lib`.

The fix is relatively easy. Set the `PYTHONHOME` and `PYTHONPATH`environment variables, and insert the correct folder into the `PATH`.

For example: Open WinDBG Classic and use Python 2.7.18 64bit (installed under `C:\Python27-64`):


```batch
@echo off
set ORIGPATH=%PATH%
set PYTHONHOME=C:\Python27-64
set PATH=%PYTHONHOME%;%PATH%
set PYTHONPATH=%PYTHONHOME%\Lib

set WINDBG_CMD=windbg.exe -hd -c '!load pykd;as !mona !py -2.7 C:\Tools\mona3\mona.py'

%WINDBG_CMD% %*

set PATH=%ORIGPATH%
SET PYTHONHOME=
SET PYTHONPATH=
```



### 3.5. Running Mona in Immunity

**If Python 2.7 is in your system PATH:**

Simply ***launch*** **Immunity Debugger** and type `!mona` at the command prompt.

**If you prefer NOT to have C:\\Python27 in your system PATH:**

***Create*** a launcher batch file (`runimmunity.bat`) that ***temporarily*** sets the PATH variable:

```batch
@echo off
c:
cd "C:\Program Files (x86)\Immunity Inc\Immunity Debugger"
set ORIGPATH=%PATH%
set PATH=C:\Python27;%PATH%
immunitydebugger.exe
set PATH=%ORIGPATH%
```

Run `runimmunity.bat` from an administrator prompt to ***launch*** **Immunity Debugger** with the correct Python path automatically configured.

Or create a shortcut on your desktop to the `runimmunity.bat` file, and configure it to ***run as administrator*** right away:

* Right click on the shortcut
* Choose ***Properties***
* Open the ***General*** tab and change the name to something like `Ìmmunity Debugger Py2`
* Open the ***Shortcut*** tab
* Click ***Advanced***
* Enable ***Run as administrator***
* Click OK to save the changes

If you'd like, you can also change the icon.  From the same ***Shortcut*** tab sheet:
* Click ***Change Icon***.  You'll probably get a warning because the script does not have icons. Click OK
* Use the ***Browse*** button and select the `immunitydebugger.exe` file inside `C:\Program Files (x86)\Immunity Inc\Immunity Debugger`
* Select the first icon in the list and click OK
* Click OK to save the changes




---
<br> <br> 

## Thank you

Mona v3 would not have been possible without the ***hard work and dedication*** of **[@apl3b](https://github.com/apl3b)**. Thank you! 🙏


<br> <br> 

## Found a bug?

If you discover a bug, please ***open an issue*** and provide ***detailed steps to reproduce*** the problem.

<br> <br> 

## Want to contribute?

Check our [CONTRIBUTING.md](CONTRIBUTING.md) file for more info

<br> 

## Posts and resources about Mona v3

* [Announcement on Corelan Blog](https://www.corelan.be/index.php/2026/05/01/mona-v3-released/)