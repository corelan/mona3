![mona v3 banner](mona-banner.png)

# MONA v3

<a id="table-of-contents"></a>
## 📑 Table of Contents

- 🛠️ [Setting up Mona](#setting-up-mona)
  - 📦 [1. Install dependencies](#1-install-dependencies)
    - [1.1. Windows 10 and later](#11-windows-10-and-later)
    - [1.2. Windows 7](#12-windows-7)
    - [1.3. A note on 64bit](#13-a-note-on-64bit)
    - [1.4. Can you help me run mona under Python 3.14.4?](#14-can-you-help-me-run-mona-under-python-3144)
  - 📥 [2. Install mona & windbglib](#2-install-mona-windbglib)
    - [2.1. Distributed installation](#21-distributed-installation)
    - [2.2. Centralized installation (recommended)](#22-centralized-installation-recommended)
      - [Step 1: Set up central location](#step-1-set-up-central-location)
      - [Step 2: Configure for WinDBG Classic / WinDBGX](#step-2-configure-for-windbg-classic-windbgx)
      - [Step 3: Configure for Immunity Debugger](#step-3-configure-for-immunity-debugger)
- ▶️ [Running Mona](#running-mona)
  - [A. Running Mona in WinDBG Classic and WinDBGX](#a-running-mona-in-windbg-classic-and-windbgx)
    - [WinDBG Classic](#windbg-classic)
    - [WinDBGX](#windbgx)
  - [B. Auto loading pykd and creating an alias in WinDBG Classic and WinDBGX](#b-auto-loading-pykd-and-creating-an-alias-in-windbg-classic-and-windbgx)
  - [C. Running Mona in WinDBG Classic on Windows 7](#c-running-mona-in-windbg-classic-on-windows-7)
  - [D. Helping Python find its libraries](#d-helping-python-find-its-libraries)
  - [E. Running Mona in Immunity](#e-running-mona-in-immunity)
  - [F. Output files](#f-output-files)
- 🧠 [AI integration](#ai-integration)
  - [Manual workflow](#manual-workflow)
  - [Automated workflow](#automated-workflow)
  - [Engines](#engines)
  - [Basic usage](#basic-usage)
- 📚 [More information](#more-information)
- 🙏 [Thank you](#thank-you)
- 🐛 [Found a bug?](#found-a-bug)
- 🤝 [Want to contribute?](#want-to-contribute)
- 📚 [Posts and resources about Mona v3](#posts-and-resources-about-mona-v3)


This repository contains the necessary Python files to run **Mona v3** under **WinDBG(X)** and **Immunity Debugger**.

### Highlights
* **Python 3 Support**: Compatible with **Python 3** (and tested with versions up to 3.14.4.) You'll need a recent version of the PyKD Python Library and the PyKD-ext bootstrapper. We recommend using pykd-ext bootstrapper version 2.0.0.25 or later.
* **Backwards Compatible**: Still runs on **Python 2.7.18** (via PyKD and PyKD-ext)
* **Multi-Architecture**: Supports both ***x86 and x64*** debugging sessions *(note: not all `mona`commands are available in 64-bit)*
* **Tested on**: Windows 7, Windows 10, and Windows 11

---
<br> <br> 

<a id="setting-up-mona"></a>
# 🛠️ Setting up Mona

<br> 

<a id="1-install-dependencies"></a>
## 📦 1. Install dependencies 


### 1.1. Windows 10 and later

**For Windows 10 and later**, we recommend using the `CorelanPyKDInstall.ps1` PowerShell script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining).

The script will automatically:

* ***Install*** **Python 3.9.13** (both 32-bit and 64-bit)
* ***Install*** **PyKD** Python library
* ***Install*** **Keystone-engine** Python library 
* ***Install*** **PyKD-ext** bootstrapper WinDBG extension
* ***Install*** **Visual Studio runtime** and register required DLLs


If you prefer to install those components yourself, after installation, verify that Python 3 and PyKD work as expected:

Open an Administrator Command Prompt.

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

If you are still using Windows 7:

Begin by installing [Python 2.7.18](https://www.python.org/ftp/python/2.7.18/python-2.7.18.msi).

Next, download a copy of the `CorelanWin7VMinstall.py` python script from [the CorelanTraining repo](https://github.com/corelan/CorelanTraining) and run it from an Administrator Command Prompt.
(let's say you have stored the file on your C: drive)

```batch
C:\>cd Python27
C:\Python27>python c:\CorelanWin7VMinstall.py
```

This will install all required components to run `mona` on Windows 7.

<br>

### 1.3. A note on 64bit

The 64-bit versions of WinDBG(X) do not support assembling 64-bit mnemonics into opcodes.

Mona includes a small assembly cache in `windbglib.py`... but that's not really good enough to meet all needs.   
 
If `keystone-engine` is installed, `windbglib.py` will use it when needed.
If not, support for 64-bit assembly will be very limited (to the items in the assembly cache), and some commands that take arbitrary assembly statements might fail.  

<br>

### 1.4. Can you help me run mona under Python 3.14.4?

Yes, of course. The `CorelanPyKDInstall.ps1` script mentioned earlier will install Python 3.14.4 and all required dependencies automatically. Ff you prefer to do things by hand, this is the step by step:

*1.4.1. Install Python 3.14.4 (both 32bit and 64bit)*

Download installers from the URLs below and run each installer

* x86: https://www.python.org/ftp/python/3.14.4/python-3.14.4.exe
* x64: https://www.python.org/ftp/python/3.14.4/python-3.14.4-amd64.exe

*1.4.2. Upgrade pip:*

```batch
py -3.14-32 -m pip install --upgrade pip
py -3.14 -m pip install --upgrade pip
```

*1.4.3. Install keystone engine:*

```batch
py -3.14-32 -m pip install keystone-engine
py -3.14 -m pip install keystone-engine
```

*1.4.4. Download the pykd library:*

  * x86: https://github.com/corelan/CorelanTraining/raw/refs/heads/master/pykd/pykd-python3.14-package-x86.zip
  * x64: https://github.com/corelan/CorelanTraining/raw/refs/heads/master/pykd/pykd-python3.14-package-x64.zip

  Extract the files, you'll get 2 .whl files (and some other files). Install the Python wheels (the .whl files) via pip.

From the folder that contains the extracted .whl files (verify the actual filenames):
```batch
py -3.14-32 -m pip install pykd-0.3.4.15+g19ddf62-cp314-win32.whl
py -3.14 -m pip install pykd-0.3.4.15+g19ddf62-cp314-win-amd64.whl
```

*1.4.5. Verify that you are running pykd-ext version 2.0.0.25*

Open WinDBG. Run `!load pykd` and then type `!pykd.info` to see the pykd-ext version.

If you're using an older version:

* Remove the existing pykd.dll files from `%LOCALAPPDATA%\DBG\EngineExtensions` and `%LOCALAPPDATA%\DBG\EngineExtensions32`
* Download the v2.0.0.25 version here:

  - x86: https://github.com/corelan/CorelanTraining/blob/master/pykd-ext/2.0.0.25/x86.zip
  - x64: https://github.com/corelan/CorelanTraining/blob/master/pykd-ext/2.0.0.25/x64.zip

* Put pykd.dll from the x86.zip file inside `%LOCALAPPDATA%\DBG\EngineExtensions32`
* Put pykd.dll from the x64.zip file inside `%LOCALAPPDATA%\DBG\EngineExtensions`

All set! That should do the trick. 

After loading pykd, you can now invoke `!py -3.14` to run mona.py.

Adjust the instructions in the procedure below accordingly. 

---

<br> <br> 

<a id="2-install-mona-windbglib"></a>
## 📥 2. Install mona & windbglib

You have two installation approaches:

* [***Distributed*** installation](#21-distributed-installation): multiple copies
* [***Centralized*** installation](#22-centralized-installation-recommended): recommended, single copy

<br> 

### 2.1. Distributed installation 

This setup involves installing separate copies of `mona.py` and `windbglib.py` for each debugger application.   
For the record, we do recommend and prefer using a **centralized location**, but in case your interested in how to make things work using individual copies of `mona.py` and `windbglib.py` for each debugger, you can follow the steps below. 

First of all, **download** `mona.py` and `windbglib.py` from this repository and store them somewhere. 
> **⚠️ Important**: Verify the downloaded files contain ***actual Python code***, not HTML

**For WinDBG Classic:**
* **32-bit**: put the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86`
* **64-bit**: put the 2 files under `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`

This technically allows you to reference `mona.py` without having to provide the absolute path, as it should be relative to the WinDBG Classic application.

**For Immunity Debugger:**
* Place `mona.py` in: `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`
* *Note: You do not need `windbglib.py` for Immunity*

**For WinDBGX:**
* Reference `mona.py` from ***any location*** of your choice. You will very likely have to reference one of the files in the WinDBG Classic program folders yourself. 


<br> 

### 2.2. Centralized installation (recommended) 

**Advantages**: Maintain a ***single copy*** on your system. Each `mona up` update applies to *all* debuggers immediately. By default, `mona up` also checks already-installed optional Python packages used by mona, such as `keystone-engine`, `openai`, `anthropic`, and `openai-agents`, and refreshes only the ones that are currently installed/importable.

If you want `mona up` to skip that optional package refresh step, set:

```text
!mona config -set pip_update false
```

Accepted values are case-insensitive and include `true`/`false`, `yes`/`no`, `on`/`off`, and `1`/`0`.

We will put the files in a central location. That means we'll have to refer to the files using their absolute path.

> Don't worry, we're going to use WinDBG(X) aliases to avoid having to type the full path.  In fact, the goal is to simply run `!mona`

<br> 

#### Step 1: Set up central location

Create a central folder, for instance `C:\Tools\mona3`.

(If you decide to make another folder, please update the commands below accordingly)

**Download** `mona.py` and `windbglib.py` from this repository and ***store*** them in the central folder: `C:\Tools\mona3`

> **⚠️ Important**: Verify the downloaded files contain ***actual Python code***, not HTML

<br> 

#### Step 2: Configure for WinDBG Classic / WinDBGX

Reference the files directly from `C:\Tools\mona3` using aliases (see [**Section B below**](#b-auto-loading-pykd-and-creating-an-alias-in-windbg-classic-and-windbgx) for auto-loading setup).

**Recommendation**: Use **Python 3.9** when running `mona` in WinDBG(X). 

If not using Immunity Debugger or Python2 scripts, feel free to safely ***remove Python 2*** from your system.

<br> 

#### Step 3: Configure for Immunity Debugger

**Option A: Create a symbolic link** (recommended)

From an Administrator Command Prompt:

```batch
mklink "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\mona.py" "C:\Tools\mona3\mona.py"
```

**Option B: Copy the file directly**
* Copy `mona.py` to: `C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands`

**Python 2 Setup** (required for Immunity):
* ***Install*** **Python 2.7.18** (***32-bit version only***)
* ***Ensure*** the 32-bit `C:\Python27` folder is in your system **PATH** environment variable
  * ***Verify*** by opening Command Prompt and typing `python` — it should launch Python 2.7.18 (32-bit)
  * *Alternative*: See **Section E below** for a launcher `.bat` file to temporarily set the PATH

---

<br> <br> 

<a id="running-mona"></a>
# ▶️ Running Mona

<br> 

### A. Running Mona in WinDBG Classic and WinDBGX

> **Note**: We recommend launching WinDBG Classic or WinDBGX from an Administrator Command Prompt. This ensures the debugger runs with administrator privileges and lets you pass command-line arguments more easily.


#### WinDBG Classic

**Step 1**: ***Open*** **WinDBG Classic** 

Run `windbg.exe` from the correct WinDBG Program Folder. The base path typically begins with `C:\Program Files (x86)\Windows Kits\10\Debuggers`, and inside that folder, you should find a `x86` and a `x64` folder, amongst others.
Make sure to run `windbg.exe` from the `x64` folder if you're going to attach to a 64bit process, and to run `windbg.exe` from the `x86` folder to open a 32bit debugging session.

Next, ***attach*** WinDBG Classic to your target process.

**Step 2**: At the WinDBG Classic Command Line, ***load*** the **PyKD** bootstrapper extension:
```python
!load pykd
```

**Step 3**: ***Run*** **Mona** using **Python 3.9**:
```python
!py -3.9 C:\Tools\mona3\mona.py
```

**Convenience**: ***Create an alias*** to avoid typing the full path every time:
```python
as !mona !py -3.9 C:\Tools\mona3\mona.py
```
Now you can simply type `!mona` at the WinDBG Command Line.



[Section B](#b-auto-loading-pykd-and-creating-an-alias-in-windbg-classic-and-windbgx) below shows how to automate this alias at startup.



#### WinDBGX

**Step 1**: ***Open*** **WinDBGX** by running `windbgx` and ***attach*** it to your target process.  WinDBGX will automatically select the right architecture based on the process you're attaching to.

**Step 2**: At the WinDBGX Command Line, ***load*** the **PyKD** bootstrapper extension:
```python
!load pykd
```

**Step 3**: ***Run*** **Mona** using **Python 3.9**:
```python
!py -3.9 C:\Tools\mona3\mona.py
```
(You can run the same command on 32bit and 64bit debugging sessions, WinDBGX will select the appropriate Python 3.9.13 version)

**Convenience**: ***Create an alias*** to avoid typing the full path every time:
```python
as !mona !py -3.9 C:\Tools\mona3\mona.py
```
Now you can simply type `!mona` at the WinDBG(X) Command Line as well.

<br> 



### B. Auto loading pykd and creating an alias in WinDBG Classic and WinDBGX

**For WinDBG Classic:**

***Launch*** `windbg.exe` from its program folder, and use the `-c` command-line flag to auto-load **PyKD** and ***create*** the **mona** alias. 

To make things even easier, you could consider creating a small batch file inside the WinDBG Program folders (both `x86` and `x64`) that has all the required command line arguments:

For example, create `w.bat` in the `x86` folder with the following contents:

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

In WinDBGX, use Startup Settings to run these commands at the start of each session.

***Configure*** the **Startup settings** to auto-load on every session:
1. Navigate to: ***File > Settings > Debugging settings > Startup***
2. ***Paste*** the following commands:
```python
!load pykd
as !mona !py -3.9 C:\Tools\mona3\mona.py
```

> **Note**: You only need to configure this ***once***. WinDBGX will automatically adapt to 32-bit or 64-bit depending on your debugging target.

<br> 

### C. Running Mona in WinDBG Classic on Windows 7

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


### D. Helping Python find its libraries

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

As you can see, although WinDBG loaded the correct Python version and architecture (Python 2.7.18, 64-bit), it still references libraries from the 32-bit Python installation in `C:\Python27\Lib` instead of `C:\Python27-64\Lib`.

The fix is relatively easy. Set the `PYTHONHOME` and `PYTHONPATH` environment variables, and insert the correct folder into the `PATH`.

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

<br>

### E. Running Mona in Immunity

**If Python 2.7 is in your system PATH:**

Simply ***launch*** **Immunity Debugger** and type `!mona` at the command prompt.

**If you do not want to keep `C:\\Python27` in your system `PATH`:**

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
* Open the ***General*** tab and change the name to something like `Immunity Debugger Py2`
* Open the ***Shortcut*** tab
* Click ***Advanced***
* Enable ***Run as administrator***
* Click OK to save the changes

If you'd like, you can also change the icon.  From the same ***Shortcut*** tab sheet:
* Click ***Change Icon***.  You'll probably get a warning because the script does not have icons. Click OK
* Use the ***Browse*** button and select the `immunitydebugger.exe` file inside `C:\Program Files (x86)\Immunity Inc\Immunity Debugger`
* Select the first icon in the list and click OK
* Click OK to save the changes

### F. Output files

Most `mona` output files are written as Markdown. If you configure a `workingfolder`, those files will be created there. Otherwise, they are written using Mona's normal relative/debugger-folder path resolution, which is not necessarily the same folder as `mona.ini`.

This is useful because the output can be viewed either as plain text or rendered as formatted Markdown with headings, tables, fenced blocks, and embedded images.

Recommended viewers/editors:

* **Visual Studio Code**: open the `.md` file and use **Markdown Preview** with `Ctrl+Shift+V`
* **Notepad++**: can render Markdown with a Markdown preview plugin
* **Typora**: native live Markdown rendering
* **Obsidian**: renders Markdown files directly
* **MarkText**: open source Markdown editor with live preview

If you are reviewing `mona` output regularly, using a Markdown-capable viewer will make files such as `rop.md`, `findmsp.md`, `heaplayout.md`, and AI prompt/output files much easier to read.


---

<a id="ai-integration"></a>
# 🧠 AI integration

Mona includes AI-assisted analysis through the `tellme` command. It can inspect the current WinDBG context, build a structured prompt from that context, and either save that prompt for manual use or submit it directly to a configured AI engine.

For a walkthrough and additional background, see the Corelan post: https://www.corelan.be/index.php/2026/05/14/mona-tellme/

There are two supported ways to use it:

* **Manual workflow**: `mona` builds the request and saves it to disk. You paste that request into ChatGPT, Claude, Grok, or another AI tool yourself.
* **Automated workflow**: `mona` builds the request and sends it directly to a configured provider or local endpoint.

This makes `tellme` useful even if you do not want to install SDKs, configure API keys, or make live requests from inside the debugger host.

## Manual workflow

If you use `-offline`, `tellme` will collect debugger context, build the full request, and save it to a file without contacting any provider.

That is the simplest setup and the default fallback when no provider-backed engine is configured correctly.

Example:

```python
!mona tellme -q 1 -offline
```

Typical use cases:

* You want to inspect the generated request before sending it anywhere
* You prefer browser-based AI tools over API access
* You do not want to configure keys, SDKs, or billing
* You want a workflow that still works when no engine is configured

## Automated workflow

If you want `mona` to submit requests directly, configure a default engine and the settings that engine needs. Configuration can live in `mona.ini` or in environment variables. If both are present, values from `mona.ini` take precedence.

When you omit `-e`, engine selection works like this:

1. `mona.ai.engine`
2. `MONA_AI_ENGINE`
3. if neither is set, `tellme` switches to offline mode by default

That fallback is intentional so you do not accidentally consume tokens.

For detailed setup, engine-specific examples, dependency requirements, bridge configuration, troubleshooting, and advanced options, see:

* Corelan blog post: https://www.corelan.be/index.php/2026/05/14/mona-tellme/
* Mona wiki: https://github.com/corelan/mona3/wiki

## Engines

In Mona, an **engine** is the backend that receives the generated AI request. Some engines are cloud APIs, some are local/self-hosted endpoints, and one is a bridge for the OpenAI Agents SDK.

Currently supported engines are:

* `offline`: save the request only; do not submit it
* `openai`: direct OpenAI API integration; by default Mona submits a plain text request, and `tellme -upload` switches that engine to OpenAI file-upload mode
* `openaiagents`: local bridge that uses the OpenAI Agents SDK and OpenAI Python library outside the debugger
* `anthropic`: direct Anthropic API integration without an Anthropic SDK dependency
* `ollama`: local or remote Ollama endpoint; supports either OpenAI-style `/v1/responses` or native `/api/generate`. Prefer `/api/generate` for the most reliable plain-text `tellme` output; use `/v1/responses` when you specifically want OpenAI-style compatibility and have confirmed the model returns final assistant text there.
* `customai`: generic POST JSON endpoint that sends `{"model": ..., "prompt": ...}` and can extract nested response text via `response_field`

Use `-e <engine>` to select one explicitly for a single request, or set `mona.ai.engine` to make one the default.

## Basic usage

The current `tellme` question profiles are:

* `-q 1`: analyze the current crash context
* `-q 2`: analyze the current function at the live instruction pointer, optionally plus a second location from `-a`
* `-q 3`: analyze whether a controlled heap chunk can steer execution to a target, or discover promising chunk-driven paths when `-t` is omitted
* `-q 9 -f <file>`: use a saved request template or a previously built prompt file

Basic examples:

```python
!mona tellme -q 1
!mona tellme -e openai -q 1 -offline
!mona tellme -e openai -q 2 -a kernel32!CreateFileW
!mona tellme -e openai -q 3 -c poi(esp+4) -t kernel32!CreateFileW
!mona tellme -e openai -q 1 -submit
```

If you omit `-q` while a provider-backed engine is selected, `tellme` will list the available models for that engine instead of building a request.

How to choose a mode:

* Use `!mona tellme -q 1` when you want help triaging the current crash.
* Use `!mona tellme -q 2` when execution is at a useful code location and you want help understanding the current function.
* Use `!mona tellme -q 3 -c <chunk>` when you already control a heap chunk and want Mona to reason about reachable targets or controlled-data sinks.
* Use `!mona tellme -q 8` when you want a ROP-focused assessment.
* Use `-a` with `-q 2` when you want to add a second known-good symbol or address to the function analysis.
* Use `-offline` when you want to manually submit the generated request to a browser-based AI session.
* For automated submission, `tellme` asks for confirmation before sending the request unless you pass `-submit`.
* For more advanced `tellme` modes and options such as `-upload`, `-q 9`, templates, model overrides, timeouts, and extra context files, see the blog post and wiki.

If `ai.q1`, `ai.q2`, `ai.q3`, or `ai.q8` do not exist yet, running the corresponding `-q 1`, `-q 2`, `-q 3`, or `-q 8` command will create them in the configured `workingfolder`, or in the same folder as `mona.ini` when no working folder is set.

For engine-specific setup, model recommendations, local/self-hosted examples, bridge configuration, advanced options, and troubleshooting, see the [Mona wiki](https://github.com/corelan/mona3/wiki).


---

<a id="more-information"></a>
# 📚 More information

For additional documentation, examples, and background information, check the [Mona wiki](https://github.com/corelan/mona3/wiki).



---
<br> <br> 

<a id="thank-you"></a>
## 🙏 Thank you

Mona v3 would not have been possible without the ***hard work and dedication*** of **[@apl3b](https://github.com/apl3b)**. Thank you! 🙏


<br> <br> 

<a id="found-a-bug"></a>
## 🐛 Found a bug?

If you discover a bug, please ***[open an issue](https://github.com/corelan/mona3/issues)*** and provide ***detailed steps to reproduce*** the problem.

<br> <br> 

<a id="want-to-contribute"></a>
## 🤝 Want to contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

If you are changing or debugging a specific `!mona` command, be aware that the repo also includes [`testing/runmonatests.cmd`](testing/runmonatests.cmd) to exercise that command across multiple test scenarios. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and usage details, including the requirement to run it from an elevated Administrator Command Prompt.

<br> <br> 

<a id="posts-and-resources-about-mona-v3"></a>
## 📚 Posts and resources about Mona v3

* [Mona v3 Release - Announcement on Corelan Blog](https://www.corelan.be/index.php/2026/05/01/mona-v3-released/)
* [Mona tellme - AI-assisted analysis with Mona](https://www.corelan.be/index.php/2026/05/14/mona-tellme/)
