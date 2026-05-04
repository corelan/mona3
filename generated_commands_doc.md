# Mona Commands

Reference for all mona commands, including debugger compatibility, architecture support, aliases, summaries, and argument details.

## Getting Help

To get help for a specific command, either run that command with `-h` or use `!mona help <command>`.

## Commands Overview

| Command | WinDBG | Immunity | x86 | x64 |
| --- | --- | --- | --- | --- |
| [?](#command-qmark) | ✅ | ✅ | ✅ | ✅ |
| [allocmem](#command-allocmem) | ✅ | 🚫 | ✅ | ✅ |
| [assemble](#command-assemble) | ✅ | ✅ | ✅ | ✅ |
| [bp](#command-bp) | ✅ | ✅ | ✅ | ✅ |
| [bpseh](#command-bpseh) | ✅ | ✅ | ✅ | 🚫 |
| [breakfunc](#command-breakfunc) | ✅ | ✅ | ✅ | ✅ |
| [bytearray](#command-bytearray) | ✅ | ✅ | ✅ | ✅ |
| [changeacl](#command-changeacl) | ✅ | 🚫 | ✅ | ✅ |
| [cleanlog](#command-cleanlog) | ✅ | ✅ | ✅ | ✅ |
| [compare](#command-compare) | ✅ | ✅ | ✅ | ✅ |
| [config](#command-config) | ✅ | ✅ | ✅ | ✅ |
| [copy](#command-copy) | ✅ | ✅ | ✅ | ✅ |
| [dump](#command-dump) | ✅ | ✅ | ✅ | ✅ |
| [dumplog](#command-dumplog) | ✅ | 🚫 | ✅ | ✅ |
| [dumpobj](#command-dumpobj) | ✅ | 🚫 | ✅ | ✅ |
| [egghunter](#command-egghunter) | ✅ | ✅ | ✅ | 🚫 |
| [encode](#command-encode) | ✅ | ✅ | ✅ | 🚫 |
| [filecompare](#command-filecompare) | ✅ | ✅ | ✅ | ✅ |
| [fillchunk](#command-fillchunk) | ✅ | ✅ | ✅ | ✅ |
| [find](#command-find) | ✅ | ✅ | ✅ | ✅ |
| [findmsp](#command-findmsp) | ✅ | ✅ | ✅ | ✅ |
| [findwild](#command-findwild) | ✅ | ✅ | ✅ | ✅ |
| [fwptr](#command-fwptr) | ✅ | ✅ | ✅ | 🚫 |
| [geteat](#command-geteat) | ✅ | ✅ | ✅ | ✅ |
| [getiat](#command-getiat) | ✅ | ✅ | ✅ | ✅ |
| [getpc](#command-getpc) | ✅ | ✅ | ✅ | ✅ |
| [gflags](#command-gflags) | ✅ | ✅ | ✅ | ✅ |
| [header](#command-header) | ✅ | ✅ | ✅ | ✅ |
| [heap](#command-heap) | ✅ | ✅ | ✅ | ✅ |
| [help](#command-help) | ✅ | ✅ | ✅ | ✅ |
| [hidedebug](#command-hidedebug) | ✅ | ✅ | ✅ | ✅ |
| [info](#command-info) | ✅ | ✅ | ✅ | ✅ |
| [infodump](#command-infodump) | ✅ | ✅ | ✅ | ✅ |
| [jmp](#command-jmp) | ✅ | ✅ | ✅ | ✅ |
| [jop](#command-jop) | ✅ | ✅ | ✅ | ✅ |
| [jseh](#command-jseh) | ✅ | ✅ | ✅ | 🚫 |
| [load](#command-load) | ✅ | ✅ | ✅ | ✅ |
| [moduleinfo](#command-moduleinfo) | ✅ | ✅ | ✅ | ✅ |
| [modules](#command-modules) | ✅ | ✅ | ✅ | ✅ |
| [offset](#command-offset) | ✅ | ✅ | ✅ | ✅ |
| [pageacl](#command-pageacl) | ✅ | ✅ | ✅ | ✅ |
| [pattern_create](#command-pattern-create) | ✅ | ✅ | ✅ | ✅ |
| [pattern_offset](#command-pattern-offset) | ✅ | ✅ | ✅ | ✅ |
| [peb](#command-peb) | ✅ | ✅ | ✅ | ✅ |
| [proclayout](#command-proclayout) | ✅ | ✅ | ✅ | ✅ |
| [rop](#command-rop) | ✅ | ✅ | ✅ | ✅ |
| [ropfunc](#command-ropfunc) | ✅ | ✅ | ✅ | ✅ |
| [seh](#command-seh) | ✅ | ✅ | ✅ | 🚫 |
| [sehchain](#command-sehchain) | ✅ | ✅ | ✅ | 🚫 |
| [skeleton](#command-skeleton) | ✅ | ✅ | ✅ | ✅ |
| [stackpivot](#command-stackpivot) | ✅ | ✅ | ✅ | ✅ |
| [stacks](#command-stacks) | ✅ | ✅ | ✅ | ✅ |
| [string](#command-string) | ✅ | ✅ | ✅ | ✅ |
| [stringpos](#command-stringpos) | ✅ | ✅ | ✅ | ✅ |
| [suggest](#command-suggest) | ✅ | ✅ | ✅ | ✅ |
| [sym](#command-sym) | ✅ | 🚫 | ✅ | ✅ |
| [tellme](#command-tellme) | ✅ | 🚫 | ✅ | ✅ |
| [teb](#command-teb) | ✅ | ✅ | ✅ | ✅ |
| [tobp](#command-tobp) | ✅ | 🚫 | ✅ | ✅ |
| [unicodealign](#command-unicodealign) | ✅ | ✅ | ✅ | 🚫 |
| [update](#command-update) | ✅ | ✅ | ✅ | ✅ |
| [write](#command-write) | ✅ | ✅ | ✅ | ✅ |

## Overview

This page is generated from the `MnCommand` registrations in `mona.py` and the corresponding `*Usage` variables inside `populateCommands()`.

Compatibility is derived from the registration itself: commands inside the WinDBG-only block are marked unsupported in Immunity Debugger, and architecture support comes from each command's `archs` list.

<a id="command-qmark"></a>
## 🔶 `?`

**Alias:** `eval`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Evaluates an expression*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Evaluates an expression
Arguments:
    <the expression to evaluate>

Accepted syntax includes: 
    hex values, decimal values (prefixed with 0n), registers, 
    module names, 'heap' ( = address of default process heap),
    module!functionname
    simple math operations
```

---

<a id="command-allocmem"></a>
## 🔶 `allocmem`

**Alias:** `alloc`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Allocate RWX memory in the debugged process.*

**Arguments**

- `-s <size>`: desired size of allocated chunk. VirtualAlloc will allocate at least 0x1000 bytes, but this size argument is only useful when used in combination with -fill. (optional).
- `-a <address>`: desired target location for allocation, set to start of chunk to allocate. (optional).
- `-acl <level>`: overrule default RWX memory protection. (optional).
- `-fill`: fill 'size' bytes (-s) of memory at specified address (-a) with A's. (optional).
- `-force`: use in combination with -fill, in case page was already mapped but you still want to fill the chunk at the desired location. (optional).
- `-b <byte>`: Specify what byte to write to the desired location. Defaults to '\\x41' (optional).

**Usage:**

```text
Allocate RWX memory in the debugged process.

Optional arguments:
    -s <size>    : desired size of allocated chunk. VirtualAlloc will allocate at least 0x1000 bytes,
                   but this size argument is only useful when used in combination with -fill.
    -a <address> : desired target location for allocation, set to start of chunk to allocate.
    -acl <level> : overrule default RWX memory protection.
    -fill        : fill 'size' bytes (-s) of memory at specified address (-a) with A's.
    -force       : use in combination with -fill, in case page was already mapped but you still want to
                   fill the chunk at the desired location.
    -b <byte>    : Specify what byte to write to the desired location. Defaults to '\\x41'
```

---

<a id="command-assemble"></a>
## 🔶 `assemble`

**Alias:** `asm`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Convert instructions to opcode. Separate multiple instructions with #.*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Convert instructions to opcode. Separate multiple instructions with #.

Mandatory argument : -s <instructions> : the sequence of instructions to assemble to opcode
```

---

<a id="command-bp"></a>
## 🔶 `bp`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Set a breakpoint at a given address. Without -t, sets a software breakpoint (INT 3). With -t, sets a hardware breakpoint (uses debug registers DR0-DR3 on Immunity, 'ba' on WinDBG).*

**Arguments**

- `-a <address>`: the address where to set the breakpoint (absolute address / register / module / module!function / symbol / expression with offsets) (mandatory).
- `-t <type>`: type of hardware breakpoint. Can be READ (R), WRITE (W) or EXE (X). READ/R : triggers on read, write, and execute (Access). WRITE/W : triggers on write only. EXE/X : triggers on execute only. If omitted, a software breakpoint is set instead. (optional).
- `-if <condition>`: condition expression for the breakpoint. WinDBG example: -if "eax==0" Immunity example: -if "EAX==0" (evaluated via LogBpHook) WinDBG only: (optional).
- `-c "windbg cmd;windbg cmd"`: windbg command(s) to execute when breakpoint gets hit The commands must be in between double quotes, and separated by semi-colons. If WinDBG truncates -c at the first ';', use '|' instead. Mona will convert '|' back to ';' before setting the breakpoint. (optional).

**Usage:**

```text
Set a breakpoint at a given address.
Without -t, sets a software breakpoint (INT 3).
With -t, sets a hardware breakpoint (uses debug registers DR0-DR3 on Immunity, 'ba' on WinDBG).

Hardware breakpoints use smart alignment (size 4 if 4-byte aligned, 2 if 2-byte aligned, else 1).
Execute type always uses size 1. On x64 WinDBG, size 8 is used for 8-byte aligned addresses.
On Immunity, max 4 hardware breakpoints can be active (DR0-DR3).

Mandatory arguments :
    -a <address> : the address where to set the breakpoint
                   (absolute address / register / module / module!function / symbol / expression with offsets)

Optional arguments :
    -t <type> : type of hardware breakpoint. Can be READ (R), WRITE (W) or EXE (X).
                READ/R  : triggers on read, write, and execute (Access).
                WRITE/W : triggers on write only.
                EXE/X   : triggers on execute only.
                If omitted, a software breakpoint is set instead.
    -if <condition> : condition expression for the breakpoint.
                     WinDBG example: -if "eax==0"
                     Immunity example: -if "EAX==0" (evaluated via LogBpHook)
 WinDBG only:
	    -c "windbg cmd;windbg cmd" : windbg command(s) to execute when breakpoint gets hit
			The commands must be in between double quotes, and separated by semi-colons.
			If WinDBG truncates -c at the first ';', use '|' instead.
			Mona will convert '|' back to ';' before setting the breakpoint.

			If a command needs double quotes, please replace them with #, 
			and I will convert them back to double quotes when setting the breakpoint.

			Example: -c ".printf #-----Breakpoint hit at 0x%p\\n#,@$ip|u @$ip L 1|r|.echo -----|gc"
```

---

<a id="command-bpseh"></a>
## 🔶 `bpseh`

**Alias:** `sehbp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Sets a breakpoint on all current SEH Handler function pointers*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Sets a breakpoint on all current SEH Handler function pointers
```

---

<a id="command-breakfunc"></a>
## 🔶 `breakfunc`

**Alias:** `bf`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Set a breakpoint on exported or imported function(s) of the selected modules.*

**Arguments**

- `-t <type>`: type of breakpoint action. Can be 'add', 'del' or 'list' (mandatory).
- `-f <function type>`: set to 'import' or 'export' to read IAT or EAT. Default : export (optional).
- `-s <func,func,func>`: specify function names. If you want a bp on all functions, set -s to * WinDBG only: (optional).
- `-c "windbg cmd;windbg cmd"`: windbg command(s) to execute when breakpoint gets hit The commands must be in between double quotes, and separated by semi-colons. If WinDBG truncates -c at the first ';', use '|' instead. Mona will convert '|' back to ';' before setting the breakpoint. (optional).

**Usage:**

```text
Set a breakpoint on exported or imported function(s) of the selected modules. 

Mandatory argument :
    -t <type> : type of breakpoint action. Can be 'add', 'del' or 'list'

Optional arguments:
    -f <function type> : set to 'import' or 'export' to read IAT or EAT. Default : export
    -s <func,func,func> : specify function names. 
                          If you want a bp on all functions, set -s to *
	    WinDBG only:
	    -c "windbg cmd;windbg cmd" : windbg command(s) to execute when breakpoint gets hit
			The commands must be in between double quotes, and separated by semi-colons.
			If WinDBG truncates -c at the first ';', use '|' instead.
			Mona will convert '|' back to ';' before setting the breakpoint.

			If a command needs double quotes, please replace them with #, 
			and I will convert them back to double quotes when setting the breakpoint.

			Example: -c ".printf #-----Breakpoint hit at 0x%p\\n#,@$ip|u @$ip L 1|r|.echo -----|gc"
```

---

<a id="command-bytearray"></a>
## 🔶 `bytearray`

**Alias:** `ba`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Creates a byte array, can be used to find bad characters*

**Arguments**

- `-cpb <bytes>`: bytes to exclude from the array. Example : '\\x00\\x0a\\x0d' Note: you can specify wildcards using .. Example: '\\x00\\x0a..\\x20\\x32\\x7f..\\xff' (optional).
- `-s`: optional starting hex, example: '\\x7f' (optional).
- `-e`: optional ending hex, example: '\\xff' Example: -s \\x01 -e \\x7f to have all bytes from 0x01 to 0x7f -s \\xff -e \\x7f to have all bytes from 0xff to 0x7f in reverse (optional).
- `-r`: show array backwards (reversed), starting at \\xff Output will be written to bytearray.txt (raw bytes + Python 2/3 code), and binary output will be written to bytearray.bin (optional).

**Usage:**

```text
Creates a byte array, can be used to find bad characters

Optional arguments:
    -cpb <bytes> : bytes to exclude from the array. Example : '\\x00\\x0a\\x0d'
                   Note: you can specify wildcards using .. 
                   Example: '\\x00\\x0a..\\x20\\x32\\x7f..\\xff'
    -s : optional starting hex, example: '\\x7f'
    -e : optional ending hex, example: '\\xff'
         Example: -s \\x01 -e \\x7f to have all bytes from 0x01 to 0x7f
                  -s \\xff -e \\x7f to have all bytes from 0xff to 0x7f in reverse
    -r : show array backwards (reversed), starting at \\xff
    Output will be written to bytearray.txt (raw bytes + Python 2/3 code),
    and binary output will be written to bytearray.bin
```

---

<a id="command-changeacl"></a>
## 🔶 `changeacl`

**Alias:** `ca`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Change the ACL of a given page.*

**Arguments**

- `-a <address>`: Address belonging to the page that needs to be changed (arguments).
- `-acl <level>`: New ACL. Valid values include N,R,RW,W,X,RX,RWX/RXW,XW,GUARD,NOCACHE,WC You can also use full names such as PAGE_READWRITE, PAGE_EXECUTE_READ, etc. (arguments).

**Usage:**

```text
Change the ACL of a given page.
Arguments:
    -a <address>   : Address belonging to the page that needs to be changed
	-acl <level>   : New ACL. Valid values include N,R,RW,W,X,RX,RWX/RXW,XW,GUARD,NOCACHE,WC
					 You can also use full names such as PAGE_READWRITE, PAGE_EXECUTE_READ, etc.
```

---

<a id="command-cleanlog"></a>
## 🔶 `cleanlog`

**Alias:** `clean`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Free up some diskspace by removing old log files from workingfolder This command only works if you have an active workingfolder set For instance: !mona config -set workingfolder c:\logs\%%p*

**Arguments**

- `-d <number>`: Minimum age of the log file to delete (default: 30). Set to -d 0 to do a full cleanup (optional).
- `-stat`: Show matching files and age/size statistics without deleting anything (optional).

**Usage:**

```text
Free up some diskspace by removing old log files from workingfolder
    This command only works if you have an active workingfolder set
    For instance: !mona config -set workingfolder c:\logs\%%p

    The script will delete:
    - *mona-windbg-debug.log
    - *.old
    - *.old2
    - *rop*progress*.log

    If you use -stat, the script will not delete any files.
    Instead, it will list all matching files and show size statistics by file age.
    Files older than the configured minimum age will be grouped together in one bucket.

Optional arguments:
    -d <number>  : Minimum age of the log file to delete (default: 30). Set to -d 0 to do a full cleanup
    -stat        : Show matching files and age/size statistics without deleting anything
```

---

<a id="command-compare"></a>
## 🔶 `compare`

**Alias:** `cmp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Compare a file created by mona's bytearray/msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory.*

**Arguments**

- `-f <filename>`: full path to input file (mandatory).
- `-a <address>`: the exact address of the bytes in memory (address or register). If you don't specify an address, I will try to locate the bytes in memory by looking at the first 8 bytes. (optional).
- `-s`: skip locations that belong to a module (optional).
- `-unicode`: perform unicode search. Note: input should *not* be unicode, it will be expanded automatically (optional).
- `-t`: input file type format. If no file type format is specified, I will try to guess the input file type format. (optional).

**Usage:**

```text
Compare a file created by mona's bytearray/msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory.

Mandatory argument :
    -f <filename> : full path to input file

Optional argument :
    -a <address> : the exact address of the bytes in memory (address or register). 
                   If you don't specify an address, I will try to locate the bytes in memory 
                   by looking at the first 8 bytes.
    -s : skip locations that belong to a module
    -unicode : perform unicode search. Note: input should *not* be unicode, it will be expanded automatically
    -t : input file type format. If no file type format is specified, I will try to guess the input file type format.

    Available formats:
    'raw', 'hexdump', 'js-unicode', 'dword', 'xxd', 'byte-array', 'hexstring', 'hexdump-C', 'classic-hexdump', 'escaped-hexes', 'msfvenom-powershell', 'gdb', 'ollydbg', 'msfvenom-ruby', 'msfvenom-c', 'msfvenom-carray', 'msfvenom-python'
```

---

<a id="command-config"></a>
## 🔶 `config`

**Alias:** `conf`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Change config of mona.py Available options are : -get   <parameter> -set   <parameter> <value> -add   <parameter> <value_to_add> -del   <parameter> <value_to_del> -clear <parameter> -list*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Change config of mona.py
Available options are : 
    -get   <parameter>
    -set   <parameter> <value>
    -add   <parameter> <value_to_add>
    -del   <parameter> <value_to_del>
    -clear <parameter>
	-list

If you run 'config' without options, it will show the list of options currently set.

Mona uses the following parameters:
   workingfolder
   excluded_modules
   author
   alias

The exclude_modules parameter takes a comma-separated list of module names. 
You can add items to the parameter using the -add option, and remove items using -del

The alias variable allow you to set the command you're using to launch mona.
This will affect clickable links and help output.

  For example, in WinDBG(X):
    !load pykd
    !py -3.9 c:\Tools\mona3\mona.py config -set alias #mona
    as !py -3.9 c:\Tools\mona3\mona.py !mona

    (note: the # (hashtag) will be replaced with !)
```

---

<a id="command-copy"></a>
## 🔶 `copy`

**Alias:** `cp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Copies bytes from one location to another.*

**Arguments**

- `-src <address>`: The source address (arguments).
- `-dst <address>`: The destination address (arguments).
- `-n <number>`: The number of bytes to copy (arguments).

**Usage:**

```text
Copies bytes from one location to another.

Arguments:
    -src <address>    : The source address
    -dst <address>    : The destination address
    -n <number>       : The number of bytes to copy
```

---

<a id="command-dump"></a>
## 🔶 `dump`

**Alias:** `dmp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Dump the specified memory range to a file. Either the end address or the size of buffer needs to be specified.*

**Arguments**

- `-s <address>`: start address (mandatory).
- `-f <filename>`: the name of the file where to write the bytes (mandatory).
- `-n <size>`: the number of bytes to copy (size of the buffer) (optional).
- `-e <address>`: the end address of the copy (optional).

**Usage:**

```text
Dump the specified memory range to a file. Either the end address or the size of
buffer needs to be specified.

Mandatory arguments :
    -s <address> : start address
    -f <filename> : the name of the file where to write the bytes

Optional arguments:
    -n <size> : the number of bytes to copy (size of the buffer)
    -e <address> : the end address of the copy
```

---

<a id="command-dumplog"></a>
## 🔶 `dumplog`

**Alias:** `dl`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Dump objects present in alloc/free log file*

**Arguments**

- `-f <path/to/logfile>`: Full path to the logfile (arguments).
- `-l <number>`: Recursively dump objects (optional).
- `-m <number>`: Size for recursive objects (default value: 0x28) (optional).
- `-s <number>`: Only take allocated chunks of this exact size into consideration (optional).
- `-nofree`: Ignore all free() events, show all allocations (including those that were freed) (optional).

**Usage:**

```text
Dump all objects recorded in an alloc/free log
Note: dumplog will only dump objects that have not been freed in the same logfile.
Expected syntax for log entries:
    Alloc : 'alloc(size in hex) = address'
    Free  : 'free(address)'
Additional text after the alloc & free info is fine.
Just make sure the syntax matches exactly with the examples above.
Arguments:
    -f <path/to/logfile> : Full path to the logfile

Optional arguments:
    -l <number>       : Recursively dump objects
    -m <number>       : Size for recursive objects (default value: 0x28)
    -s <number>       : Only take allocated chunks of this exact size into consideration
    -nofree           : Ignore all free() events, show all allocations (including those that were freed)
```

---

<a id="command-dumpobj"></a>
## 🔶 `dumpobj`

**Alias:** `do`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Dump the contents of an object.*

**Arguments**

- `-a <address>`: Address of object (arguments).
- `-s <number>`: Size of object (default value: 0x28 or size of chunk) (arguments).
- `-l <number>`: Recursively dump objects (optional).
- `-m <number>`: Size for recursive objects (default value: 0x28) (optional).

**Usage:**

```text
Dump the contents of an object.

Arguments:
    -a <address>      : Address of object
    -s <number>       : Size of object (default value: 0x28 or size of chunk)

Optional arguments:
    -l <number>       : Recursively dump objects
    -m <number>       : Size for recursive objects (default value: 0x28)
```

---

<a id="command-egghunter"></a>
## 🔶 `egghunter`

**Alias:** `egg`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Creates an egghunter routine*

**Arguments**

- `-t`: tag (ex: w00t). Default value is w00t (optional).
- `-c`: enable checksum routine. Only works in conjunction with parameter -f (optional).
- `-f <filename>`: file containing the shellcode (optional).
- `-startreg <reg>`: start searching at the address pointed by this reg (optional).
- `-wow64`: generate wow64 egghunter (Win7 and Win11/10). Default is traditional 32bit egghunter (optional).
- `-winver <ver>`: indicate Windows version for wow64 egghunter. Default is Windows 11/10. valid values are 7, 10 and 11. DEP Bypass options : (optional).
- `-depmethod <method>`: method can be "virtualprotect", "copy" or "copy_size" (optional).
- `-depreg <reg>`: sets the register that contains a pointer to the API function to bypass DEP. By default this register is set to ESI (optional).
- `-depsize <value>`: sets the size for the dep bypass routine (optional).
- `-depdest <reg>`: this register points to the location of the egghunter itself. When bypassing DEP, the egghunter is already marked as executable. So when using the copy or copy_size methods, the DEP bypass in the egghunter would do a "copy 2 self". In order to be able to do so, it needs a register where it can copy the shellcode to. If you leave this empty, the code will contain a GetPC routine. (optional).

**Usage:**

```text
Creates an egghunter routine

Optional arguments:
    -t : tag (ex: w00t). Default value is w00t
    -c : enable checksum routine. Only works in conjunction with parameter -f
    -f <filename> : file containing the shellcode
    -startreg <reg> : start searching at the address pointed by this reg
    -wow64 : generate wow64 egghunter (Win7 and Win11/10). Default is traditional 32bit egghunter
    -winver <ver> : indicate Windows version for wow64 egghunter. Default is Windows 11/10. 
                    valid values are 7, 10 and 11.	
DEP Bypass options :
    -depmethod <method> : method can be "virtualprotect", "copy" or "copy_size"
    -depreg <reg> : sets the register that contains a pointer to the API function to bypass DEP. 
                    By default this register is set to ESI
    -depsize <value> : sets the size for the dep bypass routine
    -depdest <reg> : this register points to the location of the egghunter itself.  
                     When bypassing DEP, the egghunter is already marked as executable. 
                     So when using the copy or copy_size methods, the DEP bypass in the egghunter 
                     would do a "copy 2 self".  In order to be able to do so, it needs a register 
                     where it can copy the shellcode to. 
                     If you leave this empty, the code will contain a GetPC routine.
```

---

<a id="command-encode"></a>
## 🔶 `encode`

**Alias:** `enc`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Encode a series of bytes*

**Arguments**

- `-t <type>`: Type of encoder to use.  Allowed value(s) are alphanum (arguments).
- `-s <bytes|asm>`: Bytes to encode (e.g. \\x41\\x42, 4142) or assembly (use # to separate instructions) (arguments).
- `-f <path to file>`: The full path to the binary file that contains the bytes to encode (arguments).

**Usage:**

```text
Encode a series of bytes
Arguments:
	    -t <type>         : Type of encoder to use.  Allowed value(s) are alphanum 
	    -s <bytes|asm>    : Bytes to encode (e.g. \\x41\\x42, 4142) or assembly (use # to separate instructions)
	    -f <path to file> : The full path to the binary file that contains the bytes to encode
```

---

<a id="command-filecompare"></a>
## 🔶 `filecompare`

**Alias:** `fc`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Compares 2 or more files created by mona using the same output commands Make sure to use files that are created with the same version of mona and contain the output of the same mona command.*

**Arguments**

- `-range <number>`: find overlapping ranges for all pointers + range. When using -range, the -contains and -nostrict options will be ignored (mandatory).
- `-ptronly`: only show matching pointers (slightly faster). Doesn't work when 'range' is used (mandatory).

**Usage:**

```text
Compares 2 or more files created by mona using the same output commands
Make sure to use files that are created with the same version of mona and 
contain the output of the same mona command.

Mandatory argument : -f \"file1,file2,...filen\"
Put all filenames between one set of double quotes, and separate files with comma's.
You can specify a foldername as well with -f, all files in the root of that folder will be part of the compare.
Output will be written to filecompare.txt and filecompare_not.txt (not matching pointers)
Optional parameters : 
    -contains \"INSTRUCTION\"  (will only list if instruction is found)
    -nostrict (will also list pointer is instructions don't match in all files)
    -range <number> : find overlapping ranges for all pointers + range. 
                      When using -range, the -contains and -nostrict options will be ignored
    -ptronly : only show matching pointers (slightly faster). Doesn't work when 'range' is used
```

---

<a id="command-fillchunk"></a>
## 🔶 `fillchunk`

**Alias:** `fchunk`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Fills a heap chunk, referenced by an address expression, with `A` bytes by default, or another byte you provide.*

The command first tries to resolve the target through Mona's cached heap/chunk map. If that succeeds, it fills the owning heap chunk even when the supplied address points somewhere inside the chunk. If that lookup fails, it falls back to `!heap -x`.

By default, if the beginning of the user chunk looks like a pointer into a loaded module, those first pointer-sized bytes are preserved to avoid clobbering a likely vftable pointer. Use `-force` to overwrite them anyway.

**Arguments**

- `-a <address>`: reference to heap chunk to fill (address, register, offset from register, etc) (mandatory).
- `-b <byte>`: fill byte to write. Accepts a character or a byte string such as `\x41` (optional).
- `-force`: overwrite the entire chunk even when the first pointer-sized bytes appear to be a module/vftable pointer (optional).
- `-strict`: start writing at the provided address instead of the beginning of the chunk (optional).
- `-s <size>`: if the referenced chunk is not found, and a size is defined with -s, memory will be filled anyway, up to the specified size (optional).

**Usage:**

```text
Fills a heap chunk, referenced by an address expression, with A's (or another character)

Mandatory arguments :
    -a <address> : reference to heap chunk to fill (address, register, offset from register, etc)
                   If the chunk at the address begins with what may be a vftable pointer,
                   that pointer will not be overwritten by default.
                   Even if the address is not the start of a chunk, the command will
                   normally write from the start of the owning chunk unless you specify -strict.

Optional arguments:
    -b <character or byte to use to fill up chunk>
    -force       : force overwrite of the full chunk, including an initial
                   pointer-sized value that looks like a module/vftable pointer
    -strict      : only write starting at the provided address forward instead of
                   starting from the beginning of the owning chunk
    -s <size>    : if the referenced chunk is not found, and a size is defined with -s,
                   memory will be filled anyway, up to the specified size
```

---

<a id="command-find"></a>
## 🔶 `find`

**Alias:** `f`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Find a sequence of bytes in memory.*

**Arguments**

- `-type <type>`: Type of pattern to search for : bin,asc,ptr,instr,file (optional).
- `-b <address>`: base/bottom address of the search range (optional).
- `-t <address>`: top address of the search range (optional).
- `-c`: skip consecutive pointers but show length of the pattern instead (optional).
- `-p2p`: show pointers to pointers to the pattern (might take a while !) this setting equals setting -level to 1 (optional).
- `-level <number>`: do recursive (p2p) searches, specify number of levels deep if you want to look for pointers to pointers, set level to 1 (optional).
- `-offset <number>`: subtract a value from a pointer at a certain level (optional).
- `-offsetlevel <number>`: level to subtract a value from a pointer (optional).
- `-r <number>`: if p2p is used, you can tell the find to also find close pointers by specifying -r with a value. This value indicates the number of bytes to step backwards for each search (optional).
- `-unicode`: used in conjunction with search type asc, this will convert the search pattern to unicode first (optional).
- `-ptronly`: Only show the pointers, skip showing info about the pointer (slightly faster) (optional).

**Usage:**

```text
Find a sequence of bytes in memory.

Mandatory argument : -s <pattern> : the sequence to search for. If you specified type 'file', then use -s to specify the file.
This file needs to be a file created with mona.py, containing pointers at the begin of each line.

Optional arguments:
    -type <type>    : Type of pattern to search for : bin,asc,ptr,instr,file
    -b <address> : base/bottom address of the search range
    -t <address> : top address of the search range
    -c : skip consecutive pointers but show length of the pattern instead
    -p2p : show pointers to pointers to the pattern (might take a while !)
           this setting equals setting -level to 1
    -level <number> : do recursive (p2p) searches, specify number of levels deep
                      if you want to look for pointers to pointers, set level to 1
    -offset <number> : subtract a value from a pointer at a certain level
    -offsetlevel <number> : level to subtract a value from a pointer
    -r <number> : if p2p is used, you can tell the find to also find close pointers by specifying -r with a value.
                  This value indicates the number of bytes to step backwards for each search
    -unicode : used in conjunction with search type asc, this will convert the search pattern to unicode first 
    -ptronly : Only show the pointers, skip showing info about the pointer (slightly faster)
```

---

<a id="command-findmsp"></a>
## 🔶 `findmsp`

**Alias:** `findmsf`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Find cyclic pattern in memory*

**Arguments**

- `-distance <value>`: distance from ESP, applies to search on the stack. Default : search entire stack Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use (optional).

**Usage:**

```text
Finds begin of a cyclic pattern in memory, looks if one of the registers contains (is overwritten) with a cyclic pattern
or points into a cyclic pattern. findmsp will also look if a SEH record is overwritten and finally, 
it will look for cyclic patterns on the stack, and pointers to cyclic pattern on the stack.

Optional argument :
    -distance <value> : distance from ESP, applies to search on the stack. Default : search entire stack
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use
```

---

<a id="command-findwild"></a>
## 🔶 `findwild`

**Alias:** `fw`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Find instructions in memory, accepts wildcards.*

**Arguments**

- `-b <address>`: base/bottom address of the search range (optional).
- `-t <address>`: top address of the search range (optional).
- `-depth <nr>`: number of instructions to go deep (8 by default) (optional).
- `-distance min=nr,max=nr`: global range for numeric offsets (default: 4 to 40 decimal) (optional).
- `-nx`: y    = specify the minimum and maximum number for this range specifically (same applies to +nx:y) imm = an immediate (number) in a range (uses the -distance values as well) immx:y = allows you to specify the range for this immediate (optional).

**Usage:**

```text
Find instructions in memory, accepts wildcards.

By default, findwild searches through the entire memory space and considers executable pages.
If you only want to search in executable pages that are part of modules, use the -m * argument

Mandatory arguments :
        -s <instruction#instruction#instruction>  (separate instructions with #)

Optional arguments:
        -b <address> : base/bottom address of the search range
        -t <address> : top address of the search range
        -depth <nr>  : number of instructions to go deep (8 by default)
        -distance min=nr,max=nr : global range for numeric offsets 
           (default: 4 to 40 decimal)		

  Inside the instructions string, you can use the following wildcards :
        *        = any instruction
        r32      = any 32bit register
        r64      = any 64bit register
        -n or +n = any number in a range (uses the -distance min, unless you specified a specific range)
        -nx:y    = specify the minimum and maximum number for this range specifically
		(same applies to +nx:y)
		imm      = an immediate (number) in a range (uses the -distance values as well)
		immx:y   = allows you to specify the range for this immediate

  Examples:
        pop r32#*#xor eax,eax#*#pop esi#ret
        push rbp#*#jmp rax
        mov eax, [eax+n4:20]#*#inc r32
        add esp,imm0x100:0x200#pop r32#retn
```

---

<a id="command-fwptr"></a>
## 🔶 `fwptr`

**Alias:** `fwp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Search for calls to pointers in a writeable location, will assist with finding a good target for 4byte arbitrary writes*

**Arguments**

- `-bp`: Set breakpoints on all found CALL instructions (optional).
- `-patch`: Patch the target of each CALL with 0x41414141 (optional).
- `-chunksize <nr>`: only list the pointer if location-8 bytes contains a size value larger than <nr> (size in blocks, not bytes) (optional).
- `-offset <nr>`: add <nr> bytes of offset within chunk, after flink/blink pointer (use in combination with -freelist and -chunksize <nr>) (optional).
- `-freelist`: Search for fwptr that are preceeded by 2 readable pointers that can act as flink/blink (optional).

**Usage:**

```text
Search for calls to pointers in a writeable location, 
will assist with finding a good target for 4byte arbitrary writes

Optional arguments:
    -bp : Set breakpoints on all found CALL instructions
    -patch : Patch the target of each CALL with 0x41414141
    -chunksize <nr> : only list the pointer if location-8 bytes contains a size value larger than <nr>
                      (size in blocks, not bytes)
    -offset <nr> : add <nr> bytes of offset within chunk, after flink/blink pointer 
                  (use in combination with -freelist and -chunksize <nr>)
    -freelist : Search for fwptr that are preceeded by 2 readable pointers that can act as flink/blink
```

---

<a id="command-geteat"></a>
## 🔶 `geteat`

**Alias:** `eat`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show EAT entries from selected module(s)*

**Arguments**

- `-s <keywords>`: only show EAT entries that contain one of these keywords (optional).

**Usage:**

```text
Show EAT entries from selected module(s)

Optional arguments:
    -s <keywords> : only show EAT entries that contain one of these keywords
```

---

<a id="command-getiat"></a>
## 🔶 `getiat`

**Alias:** `iat`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show IAT entries from selected module(s)*

**Arguments**

- `-s <keywords>`: only show IAT entries that contain one of these keywords (optional).

**Usage:**

```text
Show IAT entries from selected module(s)

Optional arguments:
    -s <keywords> : only show IAT entries that contain one of these keywords
```

---

<a id="command-getpc"></a>
## 🔶 `getpc`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Find getpc routine for specific register*

**Arguments**

- `-r`: register (ex: eax) (mandatory).

**Usage:**

```text
Find getpc routine for specific register

Mandatory argument :
    -r : register (ex: eax)
```

---

<a id="command-gflags"></a>
## 🔶 `gflags`

**Alias:** `gf`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Will show the currently set GFlags, based on the PEB.NtGlobalFlag value*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Will show the currently set GFlags, based on the PEB.NtGlobalFlag value
```

---

<a id="command-header"></a>
## 🔶 `header`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Convert contents of a binary file to code that can be run to produce the file*

**Arguments**

- `-f <filename>`: source filename (mandatory).
- `-t <type>`: specify type of output. Valid choices are 'python' (default) or 'ruby' (optional).

**Usage:**

```text
Convert contents of a binary file to code that can be run to produce the file

Mandatory argument :
    -f <filename> : source filename

Optional argument:
    -t <type>     : specify type of output. Valid choices are 'python' (default) or 'ruby'
```

---

<a id="command-heap"></a>
## 🔶 `heap`

**Alias:** `hp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show information about various heap chunk lists*

**Arguments**

- `-h <address>`: base address of the heap to query (mandatory).
- `-t <type>`: where type is 'segments', 'chunks', 'layout', 'fea' (let mona determine the frontend allocator), 'lal' (force display of LAL FEA, only on XP/2003), 'lfh' (force display of LFH FEA (Vista/Win7/...)), 'bea' (backend allocator, mona will automatically determine what it is), 'all' (show all information) Note: 'layout' will show all heap chunks and their vtables & strings. Use on WinDBG for maximum results. (mandatory).
- `-expand`: Works only in combination with 'layout', will include VA/LFH/... chunks in the search. VA/LFH chunks may be very big, so this might slow down the search. (optional).
- `-stat`: show statistics (also works in combination with -h heap, -t segments or -t chunks (optional).
- `-size <nr>`: only show strings of at least the specified size. Works in combination with 'layout' (optional).
- `-after <data>`: only show current & next chunk layout entries when an entry contains this data (Only works in combination with 'layout') (optional).
- `-v`: show data / write verbose info to the Log window (optional).

**Usage:**

```text
Show information about various heap chunk lists

Standalone argument (mutually exclusive with -h / -t):
    -a <address> : show _HEAP_ENTRY, UserPtr, UserSize, State, first 8 bytes at UserPtr,
                   Heap and Segment / LFH Subsegment / VABlock for the chunk that contains
                   <address> and its immediate predecessor and successor chunks.
                   <address> may be the chunk header, the user-data pointer, or any address
                   within the chunk's allocated range (hex, register, expression).

Mandatory arguments (heap-level queries):
    -h <address> : base address of the heap to query
    -t <type> : where type is 'segments', 'chunks', 'layout',
                'fea' (let mona determine the frontend allocator),
                'lal' (force display of LAL FEA, only on XP/2003),
                'lfh' (force display of LFH FEA (Vista/Win7/...)),
                'bea' (backend allocator, mona will automatically determine what it is),
                'all' (show all information)
    Note: 'layout' will show all heap chunks and their vtables & strings. Use on WinDBG for maximum results.

Optional arguments:
    -expand : Works only in combination with 'layout', will include VA/LFH/... chunks in the search.
              VA/LFH chunks may be very big, so this might slow down the search.
    -stat : show statistics (also works in combination with -h heap, -t segments or -t chunks
    -size <nr> : only show strings of at least the specified size. Works in combination with 'layout'
    -after <data> : only show current & next chunk layout entries when an entry contains this data
                    (Only works in combination with 'layout')
    -v : show data / write verbose info to the Log window
```

---

<a id="command-help"></a>
## 🔶 `help`

**Alias:** `h`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show help*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
   !mona help [command]
```

---

<a id="command-hidedebug"></a>
## 🔶 `hidedebug`

**Alias:** `hd`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Will attempt to hide the debugger from the process*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Will attempt to hide the debugger from the process
```

---

<a id="command-info"></a>
## 🔶 `info`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show information about a given address in the context of the loaded application*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Show information about a given address in the context of the loaded application

Mandatory argument : -a <address> : the address to query
```

---

<a id="command-infodump"></a>
## 🔶 `infodump`

**Alias:** `if`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Dumps contents of memory to file. Contents will include all pages that don't belong to stack, heap or loaded modules. Output will be written to infodump.xml*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Dumps contents of memory to file. Contents will include all pages that don't
belong to stack, heap or loaded modules.
Output will be written to infodump.xml
```

---

<a id="command-jmp"></a>
## 🔶 `jmp`

**Alias:** `j`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Default module criteria : non aslr, non rebase*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Default module criteria : non aslr, non rebase 

Mandatory argument :  -r <reg>  where reg is a valid register
```

---

<a id="command-jop"></a>
## 🔶 `jop`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Default module criteria : non aslr,non rebase,non os Optional parameters : -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 8)*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 8)
```

---

<a id="command-jseh"></a>
## 🔶 `jseh`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Finds gadgets that can be used to bypass SafeSEH*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
(look for jmp/call dword ptr[ebp/esp+nn and ebp-nn] + add esp,8+ret) 
Only addresses outside address range of modules will be listed unless parameter '-all' is given. 
In that case, all addresses will be listed. TRY THIS ONE !
```

---

<a id="command-load"></a>
## 🔶 `load`

**Alias:** `ld`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Read the contents from a file and write to a memory location*

**Arguments**

- `-f`: Full path to the file to read (arguments).
- `-a`: address (or register) to write to (arguments).

**Usage:**

```text
Read the contents from a file and write to a memory location
Arguments:
    -f     : Full path to the file to read 
    -a     : address (or register) to write to
```

---

<a id="command-moduleinfo"></a>
## 🔶 `moduleinfo`

**Alias:** `modinfo`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show detailed information about a specific loaded module.*

**Arguments**

- `-m <name>`: image name as shown in the modules table (e.g. kernel32.dll or kernel32) (mandatory).
- `-a <address>`: address within the module (hex, e.g. 0x77e40000) You can use a register name as well (mandatory).

**Usage:**

```text
Show detailed information about a specific loaded module.

Mandatory argument (one of):

    -m <name>    : image name as shown in the modules table (e.g. kernel32.dll or kernel32)
    -a <address> : address within the module (hex, e.g. 0x77e40000)
                   You can use a register name as well
```

---

<a id="command-modules"></a>
## 🔶 `modules`

**Alias:** `mod`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Shows information about the loaded modules. Check the global options above to filter modules as needed.*

**Arguments**

- `-peborder <list>`: select which PEB LDR_DATA list to walk (default: load) load - InLoadOrderModuleList (DLL load order) memory - InMemoryOrderModuleList init - InInitializationOrderModuleList (DllMain call order) (optional).
- `-sort <spec>`: sort the output using a compound sort specifier. Each key is optionally followed by a suffix: Bool columns (rebase,safeseh,aslr,cfg,nx,os): '+' = has the flag (True first) '-' = does not have the flag (False first) [default] Numeric columns (base,size): '+' = low first (ascending) [default] '-' = high first (descending) No suffix uses the column default (bool: does not have the flag first; numeric: low first). Separator styles (combinable): Commas: -sort aslr-,safeseh- (comma acts as delimiter, MUST have no spaces, no suffix sets default direction for each key) Concatenated: -sort aslr-safeseh- (+/- suffix acts as delimiter; every key MUST have a suffix) Spaces: -sort "aslr safeseh" (no suffix, default direction for each key) Valid keys: base, size, rebase, safeseh, aslr, cfg, nx, os (optional).

**Usage:**

```text
Shows information about the loaded modules.
Check the global options above to filter modules as needed.

Optional arguments :

    -peborder <list>   : select which PEB LDR_DATA list to walk (default: load)
                           load   - InLoadOrderModuleList (DLL load order)
                           memory - InMemoryOrderModuleList
                           init   - InInitializationOrderModuleList (DllMain call order)

    -sort <spec>       : sort the output using a compound sort specifier.
                         Each key is optionally followed by a suffix:
                           Bool columns  (rebase,safeseh,aslr,cfg,nx,os):
                             '+' = has the flag (True first)
                             '-' = does not have the flag (False first)  [default]
                           Numeric columns (base,size):
                             '+' = low first (ascending)  [default]
                             '-' = high first (descending)
                         No suffix uses the column default (bool: does not have the flag first; numeric: low first).
                         Separator styles (combinable):
                           Commas:        -sort aslr-,safeseh- (comma acts as delimiter, MUST have no spaces, no suffix sets default direction for each key)
                           Concatenated:  -sort aslr-safeseh-   (+/- suffix acts as delimiter; every key MUST have a suffix)
                           Spaces:        -sort "aslr safeseh" (no suffix, default direction for each key)
                         Valid keys: base, size, rebase, safeseh, aslr, cfg, nx, os
                         Examples:
                           -sort aslr-          : modules without ASLR first (default)
                           -sort aslr+          : modules with ASLR first
                           -sort aslr-,safeseh- : no-ASLR first, then no-SafeSEH first
                           -sort "aslr safeseh" : same, using default direction (no flag first) for each key
                           -sort base+          : ascending base address (low first)
```

---

<a id="command-offset"></a>
## 🔶 `offset`

**Alias:** `os`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Calculate the number of bytes between two addresses. In addition to plain addresses, you can also specify registers, modules, module!functionnames, etc.*

**Arguments**

- `-a1 <address>`: the first address/register (mandatory).
- `-a2 <address>`: the second address/register (mandatory).

**Usage:**

```text
Calculate the number of bytes between two addresses. 
In addition to plain addresses, you can also specify registers, modules, module!functionnames, etc.

Mandatory arguments :
    -a1 <address> : the first address/register
    -a2 <address> : the second address/register
```

---

<a id="command-pageacl"></a>
## 🔶 `pageacl`

**Alias:** `pacl`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*List all mapped pages and show the ACL associated with each page*

**Arguments**

- `-a <address>`: only show page information around this address. (Page before, current page and page after will be displayed) (optional).

**Usage:**

```text
List all mapped pages and show the ACL associated with each page

Optional arguments: 
    -a <address> : only show page information around this address.
                   (Page before, current page and page after will be displayed)
```

---

<a id="command-pattern-create"></a>
## 🔶 `pattern_create`

**Alias:** `pc`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Create a cyclic pattern of a given size. Output will be written to pattern.txt in ascii, hex and unescape() javascript format*

**Arguments**

- Mandatory: size (numberic value)
- `-extended`: extend the 3rd characterset (numbers) with punctuation marks etc (optional).
- `-c1 <chars>`: set the first charset to this string of characters (optional).
- `-c2 <chars>`: set the second charset to this string of characters (optional).
- `-c3 <chars>`: set the third charset to this string of characters (optional).

**Usage:**

```text
Create a cyclic pattern of a given size. Output will be written to pattern.txt
in ascii, hex and unescape() javascript format

Mandatory argument : size (numberic value)

Optional arguments:
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters
```

---

<a id="command-pattern-offset"></a>
## 🔶 `pattern_offset`

**Alias:** `po`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Find the location of 4 bytes in a cyclic pattern*

**Arguments**

- Mandatory: the 4 bytes to look for
- `-extended`: extend the 3rd characterset (numbers) with punctuation marks etc (optional).
- `-c1 <chars>`: set the first charset to this string of characters (optional).
- `-c2 <chars>`: set the second charset to this string of characters (optional).
- `-c3 <chars>`: set the third charset to this string of characters Note : the charset must match the charset that was used to create the pattern ! (optional).

**Usage:**

```text
Find the location of 4 bytes in a cyclic pattern

Mandatory argument : the 4 bytes to look for
Note :  you can also specify a register

Optional arguments:
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters
Note : the charset must match the charset that was used to create the pattern !
```

---

<a id="command-peb"></a>
## 🔶 `peb`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show the address of the Process Environment Block (PEB)*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Show the address of the Process Environment Block (PEB)
```

---

<a id="command-proclayout"></a>
## 🔶 `proclayout`

**Alias:** `pl`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show a unified process memory layout map (PEB, TEB, modules, stacks, heaps)*

**Arguments**

- `-t <type>`: Show only the specified category or categories (comma-separated). Without -t the default view is shown: PEB, TEB, Module, Stack, Heap, Segment, VADBlock (only Chunk is hidden by default). (optional).
- `-tree`: Show ancestor context rows above the selected categories so the full parent chain is visible (base sort only; ignored with -s elements). Parents are indented one level above their children: PEB Heap Segment Chunk Example: !mona pl -t chunk -tree (PEB -> Heap -> Segment -> Chunk) Example: !mona pl -t vablock -tree (PEB -> Heap -> VADBlock) Example: !mona pl -t segment -tree (PEB -> Heap -> Segment) (optional).
- `-a <addr>`: Highlight the row (entity) whose address range contains <addr> in bold (WinDBG) or with a >>> prefix (Immunity). Useful for locating a specific chunk, segment, or block in the tree. This automatically activates `-tree` mode. Example: !mona pl -t chunk -a 0x12345678 (optional).
- `-s <mode>`: Sort/layout mode. Valid values: base (default) Flat list sorted by address. elements Hierarchical: TEB->Stack, Heap->Segment->Chunk. Example: !mona pl -s elements (optional).

**Usage:**

```text
Show a unified process memory layout map (PEB, TEB, modules, stacks, heaps)

Optional arguments:
    -t <type>  : Show only the specified category or categories (comma-separated).
                 Without -t the default view is shown: PEB, TEB, Module, Stack,
                 Heap, Segment, VADBlock (only Chunk is hidden by default).

                 Available types (each shows only its own rows, no implicit parents):
                   peb      - Process Environment Block
                   teb      - Thread Environment Block(s)
                   mod      - Loaded modules
                   stack    - Thread stacks
                   heap     - Heap headers only
                   segment  - Heap segment entries only
                   chunk    - Heap chunks only
                   vablock  - Virtual-allocated heap blocks only
                   all      - Every category

                 Combine types with commas to show multiple at once.
                 Example: !mona pl -t heap,segment
                 Example: !mona pl -t chunk
                 Example: !mona pl -t heap,segment,chunk
                 Example: !mona pl -t all

    -tree      : Show ancestor context rows above the selected categories so the
                 full parent chain is visible (base sort only; ignored with -s elements).
                 Parents are indented one level above their children:
                   PEB
                     Heap
                       Segment
                         Chunk
                 Example: !mona pl -t chunk -tree   (PEB -> Heap -> Segment -> Chunk)
                 Example: !mona pl -t vablock -tree (PEB -> Heap -> VADBlock)
                 Example: !mona pl -t segment -tree (PEB -> Heap -> Segment)

    -a <addr>  : Highlight the row (entity) whose address range contains
                 <addr> in bold (WinDBG) or with a >>> prefix (Immunity).
                 Useful for locating a specific chunk, segment, or block in the tree.
                 Example: !mona pl -t chunk -a 0x12345678
                 (note: this will activate -tree mode)

    -s <mode>  : Sort/layout mode. Valid values:
                   base     (default) Flat list sorted by address.
                   elements           Hierarchical: TEB->Stack, Heap->Segment->Chunk.
                 Example: !mona pl -s elements
```

---

<a id="command-rop"></a>
## 🔶 `rop`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Finds gadgets that can be used in a ROP chain and perhaps do some ROP magic with them*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value>             : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value>           : define the minimum distance for stackpivots (integer, default : 8).
                                  If you want to specify a min and max distance, set the value to min,max
    -depth <value>              : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)
    -split                      : write gadgets to individual files, grouped by the module the gadget belongs to
    -fast                       : skip the 'non-interesting' gadgets
    -cfg                        : Identify valid CFG target gadgets and write them to a separate output file
                                  (this may slow down the overall process a bit)
    -end <instruction(s)>       : specify one or more instructions that will be used as chain end. 
                                  (Separate instructions with #). Default ending is RETN
    -f \"file1,file2,..filen\"    : use mona generated rop files as input instead of searching in memory
    -rva                        : use RVA's in rop chain
    -s <technique>              : only create a ROP chain for the selected technique (options: virtualalloc, virtualprotect)    
    -sort                       : sort the output in rop.txt (sort on pointer value)
```

---

<a id="command-ropfunc"></a>
## 🔶 `ropfunc`

**Alias:** `rf`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Default module criteria : non aslr, non rebase, non os Output will be written to ropfunc.txt*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Default module criteria : non aslr, non rebase, non os
Output will be written to ropfunc.txt
```

---

<a id="command-seh"></a>
## 🔶 `seh`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Default module criteria : non safeseh, non aslr, non rebase This function will retrieve all stackpivot pointers that will bring you back to nseh in a seh overwrite exploit*

**Arguments**

- `-all`: also search outside of loaded modules (optional).

**Usage:**

```text
Default module criteria : non safeseh, non aslr, non rebase
This function will retrieve all stackpivot pointers that will bring you back to nseh in a seh overwrite exploit

Optional argument: 

    -all : also search outside of loaded modules
```

---

<a id="command-sehchain"></a>
## 🔶 `sehchain`

**Alias:** `exchain`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Displays the SEH chain for the current thread. This command will also attempt to display offsets and suggest a payload structure in case a cyclic pattern was used to overwrite the chain.*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Displays the SEH chain for the current thread.
This command will also attempt to display offsets and suggest a payload structure
in case a cyclic pattern was used to overwrite the chain.
```

---

<a id="command-skeleton"></a>
## 🔶 `skeleton`

**Alias:** `skel`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Creates a Metasploit exploit module skeleton for a specific type of exploit*

**Arguments**

- `-t <type`: arg> : skeletontype. Valid types are : tcpclient:port, udpclient:port, fileformat:extension Examples : -t tcpclient:21 (mandatory).
- `-t fileformat`: pdf (mandatory).
- `-s`: size of the cyclic pattern (default : 5000) (optional).

**Usage:**

```text
Creates a Metasploit exploit module skeleton for a specific type of exploit

Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf

Optional arguments:
    -s : size of the cyclic pattern (default : 5000)
```

---

<a id="command-stackpivot"></a>
## 🔶 `stackpivot`

**Alias:** `sp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Finds stackpivots (move stackpointer to controlled area)*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8)
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)
```

---

<a id="command-stacks"></a>
## 🔶 `stacks`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Shows all stacks for each thread in the running application*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Shows all stacks for each thread in the running application
```

---

<a id="command-string"></a>
## 🔶 `string`

**Alias:** `str`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Read a string from memory or write a string to memory*

**Arguments**

- `-r`: Read a string, use in combination with -a (arguments).
- `-w`: Write a string, use in combination with -a and -s (arguments).
- `-noterminate`: Do not terminate the string (using in combination with -w) (arguments).
- `-u`: use UTF-16 (Unicode) mode (arguments).
- `-s <string>`: The string to write (arguments).
- `-a <address>`: The location to read from or write to (arguments).

**Usage:**

```text
Read a string from memory or write a string to memory
Arguments:
    -r                : Read a string, use in combination with -a
    -w                : Write a string, use in combination with -a and -s
    -noterminate      : Do not terminate the string (using in combination with -w)
    -u                : use UTF-16 (Unicode) mode
    -s <string>       : The string to write
    -a <address>      : The location to read from or write to
```

---

<a id="command-stringpos"></a>
## 🔶 `stringpos`

**Alias:** `strpos`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Finds the position of the contents at the provided address in the string it is part of.*

**Arguments**

- `-a <address>`: address to inspect (arguments).

**Usage:**

```text
Finds the position of the contents at the provided address in the string it is part of.
Arguments:
    -a <address>   : address to inspect

The command reads bytes at the given address (4 bytes on 32-bit, 8 bytes on 64-bit)
and checks whether those bytes appear to be part of:
    - an ASCII string
    - a UTF-16LE / Unicode string made of printable ASCII characters + null bytes

If a string is found, mona will:
    - determine whether it is ASCII or Unicode
    - walk backwards to find the start of the string
    - calculate the offset of the supplied address inside that string
    - calculate the full string length in characters and bytes
    - show the PTR_SIZE-sized value at the supplied address in string form

Notes:
    - this command currently uses the default "all" matching mode
    - the address may be a literal address, register, symbol, or expression accepted by getAddyArg()

Examples:
    !mona stringpos -a 0x41414141
    !mona strpos -a rsp
    !mona strpos -a [esp]
```

---

<a id="command-suggest"></a>
## 🔶 `suggest`

**Alias:** `sg`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Suggests an exploit buffer structure based on pointers to a cyclic pattern Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use*

**Arguments**

- `-t <type`: arg> : skeletontype. Valid types are : tcpclient:port, udpclient:port, fileformat:extension Examples : -t tcpclient:21 (mandatory).
- `-t fileformat`: pdf (mandatory).

**Usage:**

```text
Suggests an exploit buffer structure based on pointers to a cyclic pattern
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use

Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf
```

---

<a id="command-sym"></a>
## 🔶 `sym`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Manage symbols: list status, fetch from server, or clean cache.*

**Arguments**

- `-list (-l)`: Show symbol availability for all modules (arguments).
- `-fetch (-f)`: Download missing symbols from symbol server (arguments).
- `-clean (-c)`: Remove .error files from symbol cache folders (arguments).
- `-m <filter>`: Filter by module name (supports wildcards) (optional).
- `-cm <spec>`: Filter by module criteria (e.g. aslr=true,os=false) (optional).
- `-o`: Exclude OS modules (optional).
- `-sort <spec>`: Sort output by module base address or other supported sort keys; for example, `-sort base+` sorts in ascending base-address order (optional).
- `-m <filter>`: Filter by module name (supports wildcards) (optional).
- `-cm <spec>`: Filter by module criteria (e.g. aslr=true,os=false) (optional).
- `-o`: Exclude OS modules (optional).
- `-s <index>`: Use only server #N from sympath table (see -list) Without -s, tries all configured servers (optional).
- `-force`: Download symbols via direct HTTP instead of .reload /f If .reload /f fails, falls back to direct HTTP download (optional).
- `-p <path/folder>`: Remove .error files from this specific folder (default: scan all symbol cache directories) (optional).

**Usage:**

```text
Manage symbols: list status, fetch from server, or clean cache.

Arguments:
    -list (-l)   :  Show symbol availability for all modules
    -fetch (-f)  :  Download missing symbols from symbol server
    -clean (-c)  :  Remove .error files from symbol cache folders

Optional arguments (for -list):
    -m <filter>  :  Filter by module name (supports wildcards)
    -cm <spec>   :  Filter by module criteria (e.g. aslr=true,os=false)
    -o           :  Exclude OS modules
    -sort <spec> :  Sort output (base, size, rebase, safeseh, aslr, cfg, nx, os)
                    e.g. -sort base+   (ascending base address)

Optional arguments (for -fetch):
    -m <filter>  :  Filter by module name (supports wildcards)
    -cm <spec>   :  Filter by module criteria (e.g. aslr=true,os=false)
    -o           :  Exclude OS modules
    -s <index>   :  Use only server #N from sympath table (see -list)
                    Without -s, tries all configured servers
    -force       :  Download symbols via direct HTTP instead of .reload /f
                    If .reload /f fails, falls back to direct HTTP download

Optional arguments (for -clean):
    -p <path/folder>   :  Remove .error files from this specific folder
                          (default: scan all symbol cache directories)

NOTE: -clean will delete files automatically, without asking for confirmation.
```

---

<a id="command-tellme"></a>
## 🔶 `tellme`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Ask an AI engine to analyze the current WinDBG debugger context.*

**Arguments**

- `-ai <engine>`: AI engine to use. If omitted, mona uses the first available installed engine. Supported values: `openai`, `anthropic`. (optional).
- `-model <id>`: Optional explicit model override. If specified, this wins over mona.ini and environment variables for the current request. (optional).
- `-q <number>`: Required prompt profile. `1` = analyse the crash context, `2` = analyse the current function, `9` = load a request template from `-f <file>`. (mandatory).
- `-a <address>`: Optional code address/register/module!symbol/expression to analyse. Primarily useful with `-q 2` when `EIP`/`RIP` is already corrupted. (optional).
- `-l <files>`: Optional comma-separated heapdynamics files, for example `-l "file1,file2"`. If omitted, mona will look for `c:\alloc.txt`. Matching files are added to the request in the order given. (optional).
- `-f <file>`: Required for `-q 9`. Template file whose placeholders become named request variables. (conditional).
- `-dryrun`: Build the full request and write it to `dryrun.txt`, but do not call the API. (optional).
- `-test`: Override the configured model with a lower-cost test model. (optional).

**Usage:**

```text
Ask an AI engine to analyze the current WinDBG debugger context.

Supported engines:
    - openai
    - anthropic

Configuration:
    Choose one of these approaches:

    1. Store settings in mona.ini:
    !mona config -set openai.key <your OpenAI API key>
    !mona config -set openai.model gpt-5.4
    !mona config -set anthropic.key <your Anthropic API key>
    !mona config -set anthropic.model claude-opus-4-20250514

    2. Or use environment variables instead:
    - OPENAI_API_KEY
    - OPENAI_MODEL
    - ANTHROPIC_API_KEY
    - ANTHROPIC_MODEL

Precedence:
    If both are present, mona.ini values take precedence over environment variables

For a single request, -model overrides both config and environment values

Default models:
    - OpenAI   : gpt-5.4
    - Anthropic: claude-opus-4-20250514

Common models:
    - OpenAI   : gpt-5.5, gpt-5.4, gpt-5.4-mini, gpt-5.4-nano
    - Anthropic: claude-opus-4-1-20250805, claude-opus-4-20250514, claude-sonnet-4-20250514, claude-3-5-haiku-20241022

Arguments:
    -ai <engine> : AI engine to use. If omitted, mona uses the first available engine
    -model <id>  : Optional explicit model override. If specified, this wins over mona.ini and environment variables
    -q <number>  : Required. Prompt profile to use:
                   1 = analyse the crash context
                   2 = analyse the current function
                   9 = load a request template from -f <file>
    -a <address> : Optional code address/register/module!symbol/expression to analyse.
                   Primarily useful with -q 2 when EIP/RIP is already corrupted
    -l <files>   : Optional comma-separated heapdynamics files, for example -l "file1,file2"
                   If omitted, tellme will look for c:\\alloc.txt
                   If a file contains at least one referenced register value, the full file
                   contents are added to the request as heapdynamics context in the order given
    -f <file>    : Required for -q 9. Template file whose placeholders become named request variables
    -dryrun      : Build and display the full prompt/context, but do not call the API
    -test        : Override the configured model with a lower-cost test model

Examples:
    !mona tellme -ai openai -q 1
    !mona tellme -ai anthropic -q 2
    !mona tellme -ai openai -q 2 -a kernel32!CreateFileW
    !mona tellme -ai openai -q 2 -a eip
    !mona tellme -ai openai -model gpt-5.4-mini -q 1
    !mona tellme -ai openai -q 9 -f request.txt
    !mona tellme -ai openai -q 1 -dryrun
    !mona tellme -ai openai -q 1 -test

Template placeholders for -q 9:
    [regs]     = current registers and values
    [stack]    = current stack contents near the stack pointer
    [heap]     = all heaps and their segments
    [segments] = all heaps and their segments
    [chunks]   = all chunks and virtual-allocated blocks in the process
    [modules]  = all loaded modules with mitigation properties
    [pattern]  = cyclic pattern of 20280 bytes

For -q 9, placeholders are not pasted inline.
They are converted into named variables such as {{regs}} and {{stack}},
and the final request sent to the AI contains:
    - the template text with those variable references
    - a separate variables object with the expanded values

Question notes:
    -q 1 collects crash context, cyclic-pattern hints, and extra context for registers referenced by the current instruction.
         This includes instruction windows around the current PC, pointer dumps and nearby memory for referenced registers,
         and heap chunk/VAD metadata when those registers point into known heap-managed regions.
         If heapdynamics files are provided with -l, or c:\\alloc.txt exists, matching alloc/free entries are also added.
         Matching heapdynamics entries include full file contents, saved return pointers from alloc/free lines,
         nearest symbol information, backward and forward disassembly, and !heap -p -a / !ext.heap -p -a output for matching addresses.
    -q 2 requires a valid current instruction at the selected target address. If the current PC is corrupted, use -a with a known-good code address.
    tellme is always registered under WinDBG. If the AI SDK import fails at runtime, mona will report the actual import error instead of hiding the command.

Test model overrides:
    - OpenAI   : gpt-5.4-nano
    - Anthropic: claude-3-haiku-20240307
```

---

<a id="command-teb"></a>
## 🔶 `teb`

**Alias:** None  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Show the address of the Thread Environment Block (TEB) for the current thread*

**Arguments**

- No documented command-specific arguments.

**Usage:**

```text
Show the address of the Thread Environment Block (TEB) for the current thread
```

---

<a id="command-tobp"></a>
## 🔶 `tobp`

**Alias:** `2bp`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | 🚫 Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Generate WinDBG syntax to set a logging breakpoint at a given location*

**Arguments**

- `-a <address>`: Location (address, register) for logging breakpoint (arguments).
- `-e`: Execute breakpoint command right away (optional).

**Usage:**

```text
Generate WinDBG syntax to set a logging breakpoint at a given location
Arguments:
    -a <address>      : Location (address, register) for logging breakpoint

Optional arguments:
    -e                : Execute breakpoint command right away
```

---

<a id="command-unicodealign"></a>
## 🔶 `unicodealign`

**Alias:** `ua`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | 🚫 x64

**Summary**

*Generates a venetian shellcode alignment stub which can be placed directly before unicode shellcode.*

**Arguments**

- `-a <address>`: Specify the address where the alignment code will start/be placed : If -a is not specified, the current value in EIP will be used. (arguments).
- `-l`: Prepend alignment with a null byte compensating nop equivalent (Use this if the last instruction before the alignment routine 'leaks' a null byte) (arguments).
- `-b <reg>`: Set the bufferregister, defaults to eax (arguments).
- `-t <seconds>`: Time in seconds to run heuristics (defaults to 15) (arguments).
- `-ebp <value>`: Overrule the use of the 'current' value of ebp, ebp/address will be used to calculate offset to shellcode (arguments).

**Usage:**

```text
Generates a venetian shellcode alignment stub which can be placed directly before unicode shellcode.

Arguments:
    -a <address>      : Specify the address where the alignment code will start/be placed
                      : If -a is not specified, the current value in EIP will be used.
    -l                : Prepend alignment with a null byte compensating nop equivalent
                        (Use this if the last instruction before the alignment routine 'leaks' a null byte)
    -b <reg>          : Set the bufferregister, defaults to eax
    -t <seconds>      : Time in seconds to run heuristics (defaults to 15)
    -ebp <value>      : Overrule the use of the 'current' value of ebp, 
                        ebp/address will be used to calculate offset to shellcode
```

---

<a id="command-update"></a>
## 🔶 `update`

**Alias:** `up`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Update mona to the latest version*

**Arguments**

- `-simul`: Check for updates and simulate updating. Will show release notes if available. (optional).
- `-force`: Always overwrite local file(s) with downloaded copy if version/revision info is present. (optional).

**Usage:**

```text
Update mona to the latest version
	Optional argument:
	     -simul    	  : Check for updates and simulate updating. Will show release notes if available.	
	     -force    	  : Always overwrite local file(s) with downloaded copy if version/revision info is present.
```

---

<a id="command-write"></a>
## 🔶 `write`

**Alias:** `w`  
**Debugger compatibility:** ✅ WinDBG Classic / WinDBGX | ✅ Immunity Debugger  
**Architectures:** ✅ x86 | ✅ x64

**Summary**

*Write a byte sequence to a memory location.*

**Arguments**

- `-a <address>`: the destination address (arguments).
- `-s <bytes|asm>`: bytes to write (arguments).

**Usage:**

```text
Write a byte sequence to a memory location.

Arguments:
    -a <address>      : the destination address
    -s <bytes|asm>    : bytes to write
```
