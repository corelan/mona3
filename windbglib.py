# -*- coding: utf-8 -*-
"""
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
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN GCV BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$Revision: 3333
"""

__VERSION__ = '3.0'
__REV__ = 3013

#
# Wrapper library around pykd
# (partial immlib logic port)
#
# This library allows you to run mona.py
# under WinDBG, using the pykd extension
#
import pykd
import os
import binascii
import struct
import traceback
import pickle
import ctypes
import array
import re
import inspect
import sys
import datetime

DEBUG_MODE = False

PY3 = sys.version_info[0] == 3
try:
	xrange
except NameError:
	xrange = range

global MemoryPages
global AsmCache
global disAsmCache
global OpcodeCache
global InstructionCache
global PageSections
global ModuleCache
global FuncCache
global NativeCommandCache
global disasmFwCache
global disasmFwCacheRequests
global disasmFwCacheHits
global UnreadableMemoryProbeCache
global UnreadableMemoryProbeCacheRequests
global UnreadableMemoryProbeCacheHits

global currentPID
global currentTEBAddress
global cpebaddress

global keystoneLoaded
keystoneLoaded = False

global windbgflavor
windbgflavor = ""

arch = 32

currentPID = 0
currentTEBAddress = 0
cpebaddress = 0

MemoryPages = {}
AsmCache = {}
PageSections = {}
ModuleCache = {}
FuncCache = {}
disAsmCache = {}
disasmFwCache = {}
disasmFwCacheRequests = 0
disasmFwCacheHits = 0
OpcodeCache = {}
InstructionCache = {}
NativeCommandCache = {}
UnreadableMemoryProbeCache = {}
UnreadableMemoryProbeCacheRequests = 0
UnreadableMemoryProbeCacheHits = 0

Registers32BitsOrder = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
Registers64BitsOrder = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
						"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

if pykd.is64bitSystem():
	arch = 64

try:
	import keystone
	keystoneLoaded = True
except:
	keystoneLoaded = False


TOP_USERLAND = 0x7fffffff if arch == 32 else 0x7FFFFFFFFFFF
PTR_SIZE = 4 if arch == 32 else 8
PTR_FMT = '<L' if arch == 32 else '<Q'
PTR_PRINT = "0x%08x" if arch == 32 else "0x%016x"
PTR_PRINT_ADDRESSONLY = "%08x" if arch == 32 else "%016x"

# Architecture index: 0 = x86, 1 = x64
_arch_idx = 0 if arch == 32 else 1

# TEB field offsets: (x86, x64)
TEB_PEB               = (0x30, 0x60)
TEB_CLIENT_ID_PROCESS = (0x20, 0x40)

# PEB field offsets: (x86, x64)
PEB_LDR               = (0x0C, 0x18)
PEB_PROCESS_PARAMETERS = (0x10, 0x20)
PEB_NUMBER_OF_HEAPS   = (0x88, 0xE8)
PEB_PROCESS_HEAPS     = (0x90, 0xF0)
PEB_OS_MAJOR_VERSION  = (0xA4, 0x118)
PEB_OS_MINOR_VERSION  = (0xA8, 0x11C)
PEB_OS_BUILD_NUMBER   = (0xAC, 0x120)

# PEB_LDR_DATA list head offsets: (x86, x64)
LDR_IN_LOAD_ORDER     = (0x0C, 0x10)

# LDR_DATA_TABLE_ENTRY field offsets: (x86, x64)
LDR_DLL_BASE          = (0x18, 0x30)
LDR_FULL_DLL_NAME     = (0x24, 0x48)
LDR_BASE_DLL_NAME     = (0x2C, 0x58)

# Utility functions

DEBUG_MODE = False

def set_debug_mode(enabled):
    global DEBUG_MODE
    DEBUG_MODE = bool(enabled)

def set_windbgflavor(flavor):
	global windbgflavor
	windbgflavor = flavor

def dbgp(s, errormode=False):
	# print debug information
	msgprefix = ""
	if errormode:
		msgprefix = " - ERR"
	if DEBUG_MODE:
		try:
			print("[WINDBGLIB DEBUG%s] %s | %s" % (msgprefix, get_current_datetime(),s))
		except Exception as e:
			print("[WINDBGLIB DEBUG - error] %s | %s" % (get_current_datetime(), str(e)))
			pass

def get_current_datetime():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
	

def ensure_bytes(s, encoding='latin-1'):
	if isinstance(s, bytes):
		return s
	return s.encode(encoding)

def ensure_text(s, encoding='latin-1'):
	if isinstance(s, str):
		return s
	return s.decode(encoding)

def iter_byte_values(data):
	data = ensure_bytes(data)
	if PY3:
		return data
	return [ord(c) for c in data]

def rstrip_nulls(s):
	if isinstance(s, bytes):
		return s.rstrip(b'\x00')
	return s.rstrip('\x00')

def getOSVersion():
	dbgp(get_current_function_name())

	osversions = {}
	osversions["5.0"] = "2000"
	osversions["5.1"] = "xp"
	osversions["5.2"] = "2003"
	osversions["6.0"] = "vista"
	osversions["6.1"] = "win7"
	osversions["6.2"] = "win8"
	osversions["6.3"] = "win8.1"
	peb = getPEBAddress()
	majorversion = int(pykd.ptrDWord(peb + PEB_OS_MAJOR_VERSION[_arch_idx]))
	minorversion = int(pykd.ptrDWord(peb + PEB_OS_MINOR_VERSION[_arch_idx]))
	buildversion = int(pykd.ptrWord(peb + PEB_OS_BUILD_NUMBER[_arch_idx]))
	thisversion = str(majorversion)+"." + str(minorversion)
	if thisversion == "10.0":
		if buildversion >= 22000:
			return "win11"
		return "win10"
	if thisversion in osversions:
		return osversions[thisversion]
	else:
		return "unknown"

def getArchitecture():
	dbgp(get_current_function_name())
	if not pykd.is64bitSystem():
		return 32
	else:
		return 64

def getSymbolPath():
	"""Return the current symbol path string."""
	return pykd.getSymbolPath()

def setSymbolPath(path):
	"""Set the symbol path."""
	pykd.dbgCommand(".sympath %s" % path)


_default_downstream_store = None

def _get_default_downstream_store():
	"""Resolve WinDBG's default downstream symbol store.

	When a sympath entry is 'srv*<url>' with no explicit cache,
	WinDBG uses a default downstream store.  WinDBGX typically uses
	C:\\ProgramData\\Dbg\\sym, classic WinDBG uses the 'sym' subfolder
	of the debugger install directory.

	We detect it by running '.symfix' and parsing the resulting .sympath.
	"""
	global _default_downstream_store
	if _default_downstream_store is not None:
		return _default_downstream_store

	try:
		# Save current sympath, run .symfix to get default, then restore
		original = pykd.getSymbolPath()
		pykd.dbgCommand(".symfix")
		fixed = pykd.getSymbolPath()
		# Restore original
		pykd.dbgCommand(".sympath %s" % original)

		# .symfix sets path to srv*<default_cache>*<ms_server>
		for part in fixed.split(";"):
			part = part.strip()
			pieces = part.split("*")
			tag = pieces[0].strip().lower()
			if tag in ("srv", "cache") and len(pieces) >= 3:
				candidate = pieces[1].strip().strip('"')
				if candidate and not candidate.lower().startswith("http"):
					_default_downstream_store = candidate
					return _default_downstream_store
	except Exception:
		pass

	_default_downstream_store = ""
	return _default_downstream_store


def getSymPaths(windbgflavor=None):
	"""Parse the WinDBG symbol path and return (cache_dirs, servers, entries).

	cache_dirs : list of str   -- unique local directories where symbols are stored
	servers    : list of str   -- unique symbol server URLs
	entries    : list of dict  -- per-entry detail, each with keys:
	               "cache"  : str or "" -- local cache directory
	               "server" : str or "" -- symbol server URL
	               "raw"    : str       -- original .sympath entry

	Handles formats:
		srv*<cache>*<url>       -> cache + url
		cache*<cache>*<url>     -> cache + url
		symsrv*handler*<url>*<cache> -> cache + url
		srv*<url>               -> url only (no local cache)
		<plain_path>            -> cache only (no server)
	"""
	dbgp(get_current_function_name())

	raw = pykd.getSymbolPath()
	cache_dirs = []
	servers = []
	entries = []
	seen_dirs = set()
	seen_srvs = set()

	for entry in raw.split(";"):
		entry = entry.strip()
		if not entry:
			continue

		parts = entry.split("*")
		tag = parts[0].strip().lower()

		e_cache = ""
		e_server = ""

		if tag in ("srv", "cache") and len(parts) >= 3:
			# srv*<local_cache>*<url>[*<url2>...]
			local = parts[1].strip().strip('"')
			if local:
				e_cache = local
				if local.lower() not in seen_dirs:
					seen_dirs.add(local.lower())
					cache_dirs.append(local)
			for p in parts[2:]:
				url = p.strip().strip('"')
				if url:
					if not e_server:
						e_server = url
					if url.lower() not in seen_srvs:
						seen_srvs.add(url.lower())
						servers.append(url)

		elif tag == "symsrv" and len(parts) >= 4:
			# symsrv*symsrv.dll*<url>*<cache>
			for p in parts[2:]:
				v = p.strip().strip('"')
				if not v:
					continue
				if v.lower().startswith("http://") or v.lower().startswith("https://"):
					if not e_server:
						e_server = v
					if v.lower() not in seen_srvs:
						seen_srvs.add(v.lower())
						servers.append(v)
				else:
					if not e_cache:
						e_cache = v
					if v.lower() not in seen_dirs:
						seen_dirs.add(v.lower())
						cache_dirs.append(v)

		elif tag == "srv" and len(parts) == 2:
			# srv*<url>  (no local cache, default downstream store)
			url = parts[1].strip().strip('"')
			if url:
				e_server = url
				if url.lower() not in seen_srvs:
					seen_srvs.add(url.lower())
					servers.append(url)
				# Resolve WinDBG's default downstream store
				ds = _get_default_downstream_store()
				if ds:
					e_cache = ds
					if ds.lower() not in seen_dirs:
						seen_dirs.add(ds.lower())
						cache_dirs.append(ds)

		else:
			# plain directory path
			path = entry.strip().strip('"')
			if path:
				e_cache = path
				if path.lower() not in seen_dirs:
					seen_dirs.add(path.lower())
					cache_dirs.append(path)

		entries.append({"cache": e_cache, "server": e_server, "raw": entry})

	if windbgflavor == "windbgx":
		ms_symbol_server = "https://msdl.microsoft.com/download/symbols"
		programdata_dbg = os.path.abspath(os.path.expandvars(r"%PROGRAMDATA%\Dbg\Sym"))
		if programdata_dbg and "%" not in programdata_dbg:
			if programdata_dbg.lower() not in seen_dirs:
				seen_dirs.add(programdata_dbg.lower())
				cache_dirs.append(programdata_dbg)
				entries.append({
					"cache": programdata_dbg,
					"server": ms_symbol_server,
					"raw": r"srv*%s*%s" % (programdata_dbg, ms_symbol_server),
				})
			if ms_symbol_server.lower() not in seen_srvs:
				seen_srvs.add(ms_symbol_server.lower())
				servers.append(ms_symbol_server)

	return cache_dirs, servers, entries


def fetchSymbol(module_name, pdbname="", guidage="", cache_dir=None, windbgflavor=None):
	"""Force WinDBG to download symbols for a loaded module.

	Uses '.reload /f <module>' which triggers WinDBG's built-in symbol
	server client.  This handles compression, authentication, retries,
	and all configured symbol servers automatically.

	Parameters:
		module_name : str -- module name as known to WinDBG (e.g. 'ntdll')
		pdbname     : str -- PDB filename, used only to verify the download
		guidage     : str -- GUID+Age string, used only to verify the download
		cache_dir   : str or None -- cache dir to check for the PDB after
		              download.  If None, uses the first from getSymPaths().

	Returns:
		(success, local_path, message) tuple.
		success    : bool
		local_path : str -- path to the cached PDB (or expected path on failure)
		message    : str -- status/error description
	"""
	dbgp(get_current_function_name())

	if not module_name:
		return False, "", "module_name is required"

	# Resolve cache dir for verification
	if cache_dir is None and pdbname and guidage:
		_dirs, _srvs, _ = getSymPaths(windbgflavor)
		if _dirs:
			cache_dir = _dirs[0]

	# Expected PDB path for pre/post check
	local_path = ""
	if cache_dir and pdbname and guidage:
		local_path = os.path.join(cache_dir, pdbname, guidage, pdbname)
		if os.path.isfile(local_path):
			return True, local_path, "Already cached"

	# Force WinDBG to download symbols
	try:
		output = pykd.dbgCommand(".reload /f %s" % module_name)
		dbgp("fetchSymbol .reload output: %s" % output)
	except Exception as e:
		return False, local_path, ".reload failed: %s" % str(e)

	# Verify download by checking cache or asking WinDBG for symbol status
	if local_path and os.path.isfile(local_path):
		return True, local_path, "Downloaded via .reload /f"

	# Also scan all cache dirs in case it landed in a different one
	if pdbname and guidage:
		_dirs, _, _ = getSymPaths(windbgflavor)
		for cdir in _dirs:
			candidate = os.path.join(cdir, pdbname, guidage, pdbname)
			if os.path.isfile(candidate):
				return True, candidate, "Downloaded via .reload /f"

	# Check via lm if WinDBG loaded symbols at all
	found, sym_path = _lmCheckSymbols(module_name)
	if found:
		if sym_path and os.path.isfile(sym_path):
			return True, sym_path, "Downloaded via .reload /f"
		return True, local_path, "Loaded (confirmed by lm)"

	# Retry with .dll extension — some WinDBG versions require it
	try:
		output = pykd.dbgCommand(".reload /f %s.dll" % module_name)
		dbgp("fetchSymbol .reload /f %s.dll output: %s" % (module_name, output))
	except:
		pass

	# Re-check cache
	if pdbname and guidage:
		_dirs, _, _ = getSymPaths(windbgflavor)
		for cdir in _dirs:
			candidate = os.path.join(cdir, pdbname, guidage, pdbname)
			if os.path.isfile(candidate):
				return True, candidate, "Downloaded via .reload /f"

	# Re-check lm
	found, sym_path = _lmCheckSymbols(module_name)
	if found:
		if sym_path and os.path.isfile(sym_path):
			return True, sym_path, "Downloaded via .reload /f"
		return True, local_path, "Loaded (confirmed by lm)"

	return False, local_path, "Symbol download failed for %s" % module_name


def _lmCheckSymbols(module_name):
	"""Parse 'lm vm <module>' to check if PDB symbols are loaded.

	Returns (found, sym_path) where found is True if PDB symbols are
	confirmed, and sym_path is the extracted path (or empty string).
	"""
	try:
		lm_out = pykd.dbgCommand("lm vm %s" % module_name)
		dbgp("_lmCheckSymbols lm vm output:\n%s" % (lm_out or "(None)"))
	except Exception:
		return False, ""

	if not lm_out:
		return False, ""

	lm_lower = lm_out.lower()
	pdb_markers = ["(pdb symbols)", "(private pdb symbols)"]

	# Check if any PDB marker is present
	has_pdb = False
	for marker in pdb_markers:
		if marker in lm_lower:
			has_pdb = True
			break
	if not has_pdb:
		return False, ""

	# Try to extract path from summary line: "... (pdb symbols)   <path>"
	for line in lm_out.splitlines():
		ll = line.lower()
		for marker in pdb_markers:
			idx = ll.find(marker)
			if idx >= 0:
				after = line[idx + len(marker):].strip()
				if after:
					dbgp("_lmCheckSymbols summary path: %s" % after)
					return True, after

	# Fallback: extract from "Mapped_file name:" or "Symbol file name:" lines
	for line in lm_out.splitlines():
		stripped = line.strip()
		ll = stripped.lower()
		for prefix in ["symbol file name:", "mapped_file name:"]:
			if ll.startswith(prefix):
				# Handle Windows paths with drive letter (C:\...)
				# split on first ":" gives ["Symbol file name", " C:\..."]
				# but we need "C:\..." — so split on prefix instead
				path = stripped[len(prefix):].strip()
				if path:
					dbgp("_lmCheckSymbols file line path: %s" % path)
					return True, path

	return True, ""

def getNtHeaders(modulebase):
	dbgp(get_current_function_name())

	class _DirEntry(object):
		def __init__(self, va=0, size=0):
			self.VirtualAddress = va
			self.Size = size

	class _FileHeader(object):
		def __init__(self, number_of_sections=0, size_of_optional_header=0):
			self.NumberOfSections = number_of_sections
			self.SizeOfOptionalHeader = size_of_optional_header

	class _OptionalHeader(object):
		def __init__(self, address=0, size_of_image=0, entrypoint=0, directories=None):
			self._address = address
			self.SizeOfImage = size_of_image
			self.AddressOfEntryPoint = entrypoint
			self.DataDirectory = directories or []

		def getAddress(self):
			return self._address

	class _NtHeaders(object):
		def __init__(self, file_header=None, optional_header=None):
			self.FileHeader = file_header
			self.OptionalHeader = optional_header

	nth = None
	try:
		e_lfanew = pykd.ptrDWord(modulebase + 0x3c)
		pebase = modulebase + e_lfanew
		sig = pykd.ptrDWord(pebase)
		if sig != 0x4550:
			dbgp("ERROR: invalid PE signature 0x%x at 0x%x" % (sig, pebase), errormode=False)
			return None

		number_of_sections = pykd.ptrWord(pebase + 0x6)
		size_of_optional_header = pykd.ptrWord(pebase + 0x14)
		optional_header_addr = pebase + 0x18
		magic = pykd.ptrWord(optional_header_addr)
		if magic == 0x20b:
			size_of_image_off = 0x38
			address_of_entrypoint_off = 0x10
			number_of_rva_and_sizes_off = 0x6c
			data_directory_off = 0x70
		else:
			size_of_image_off = 0x38
			address_of_entrypoint_off = 0x10
			number_of_rva_and_sizes_off = 0x5c
			data_directory_off = 0x60

		size_of_image = pykd.ptrDWord(optional_header_addr + size_of_image_off)
		address_of_entrypoint = pykd.ptrDWord(optional_header_addr + address_of_entrypoint_off)
		number_of_rva_and_sizes = pykd.ptrDWord(optional_header_addr + number_of_rva_and_sizes_off)
		directory_count = min(int(number_of_rva_and_sizes), 16)
		directories = []
		for idx in range(directory_count):
			entry_addr = optional_header_addr + data_directory_off + (idx * 8)
			directories.append(_DirEntry(
				pykd.ptrDWord(entry_addr),
				pykd.ptrDWord(entry_addr + 4)
			))
		while len(directories) < 16:
			directories.append(_DirEntry())

		nth = _NtHeaders(
			_FileHeader(number_of_sections, size_of_optional_header),
			_OptionalHeader(optional_header_addr, size_of_image, address_of_entrypoint, directories)
		)
	except Exception as e:
		dbgp("ERROR: %s" % str(e), errormode=False)
	return nth


def clearvars():
	dbgp(get_current_function_name())

	def _get_global(name, default):
		return globals().get(name, default)
		
	global MemoryPages
	global AsmCache
	global disAsmCache
	global disasmFwCache
	global disasmFwCacheRequests
	global disasmFwCacheHits
	global OpcodeCache
	global InstructionCache
	global PageSections
	global ModuleCache
	global FuncCache
	global UnreadableMemoryProbeCache
	global UnreadableMemoryProbeCacheRequests
	global UnreadableMemoryProbeCacheHits
	global currentPID
	global currentTEBAddress
	global cpebaddress

	MemoryPages = _get_global("MemoryPages", {})
	AsmCache = _get_global("AsmCache", {})
	disAsmCache = _get_global("disAsmCache", {})
	disasmFwCache = _get_global("disasmFwCache", {})
	disasmFwCacheRequests = _get_global("disasmFwCacheRequests", 0)
	disasmFwCacheHits = _get_global("disasmFwCacheHits", 0)
	OpcodeCache = _get_global("OpcodeCache", {})
	InstructionCache = _get_global("InstructionCache", {})
	PageSections = _get_global("PageSections", {})
	ModuleCache = _get_global("ModuleCache", {})
	FuncCache = _get_global("FuncCache", {})
	UnreadableMemoryProbeCache = _get_global("UnreadableMemoryProbeCache", {})
	UnreadableMemoryProbeCacheRequests = _get_global("UnreadableMemoryProbeCacheRequests", 0)
	UnreadableMemoryProbeCacheHits = _get_global("UnreadableMemoryProbeCacheHits", 0)

	memory_pages_count = len(MemoryPages) if isinstance(MemoryPages, dict) else 0
	asm_cache_count = len(AsmCache) if isinstance(AsmCache, dict) else 0
	disasm_cache_count = len(disAsmCache) if isinstance(disAsmCache, dict) else 0
	disasm_fw_cache_count = len(disasmFwCache) if isinstance(disasmFwCache, dict) else 0
	disasm_fw_cache_requests = disasmFwCacheRequests if isinstance(disasmFwCacheRequests, int) else 0
	disasm_fw_cache_hits = disasmFwCacheHits if isinstance(disasmFwCacheHits, int) else 0
	disasm_fw_cache_pct = (float(disasm_fw_cache_hits) / float(disasm_fw_cache_requests) * 100.0) if disasm_fw_cache_requests else 0.0
	opcode_cache_count = len(OpcodeCache) if isinstance(OpcodeCache, dict) else 0
	instruction_cache_count = len(InstructionCache) if isinstance(InstructionCache, dict) else 0
	page_sections_count = len(PageSections) if isinstance(PageSections, dict) else 0
	module_cache_count = len(ModuleCache) if isinstance(ModuleCache, dict) else 0
	func_cache_count = len(FuncCache) if isinstance(FuncCache, dict) else 0
	unreadable_probe_cache_count = len(UnreadableMemoryProbeCache) if isinstance(UnreadableMemoryProbeCache, dict) else 0
	unreadable_probe_cache_requests = UnreadableMemoryProbeCacheRequests if isinstance(UnreadableMemoryProbeCacheRequests, int) else 0
	unreadable_probe_cache_hits = UnreadableMemoryProbeCacheHits if isinstance(UnreadableMemoryProbeCacheHits, int) else 0
	unreadable_probe_cache_pct = (float(unreadable_probe_cache_hits) / float(unreadable_probe_cache_requests) * 100.0) if unreadable_probe_cache_requests else 0.0

	dbgp("clearvars: MemoryPages keys before clear: %d" % memory_pages_count)
	dbgp("clearvars: AsmCache keys before clear: %d" % asm_cache_count)
	dbgp("clearvars: disAsmCache keys before clear: %d" % disasm_cache_count)
	dbgp("clearvars: disasmFwCache keys before clear: %d" % disasm_fw_cache_count)
	dbgp("clearvars: disasmForward cache hits: %d / %d (%.2f%%)" % (disasm_fw_cache_hits, disasm_fw_cache_requests, disasm_fw_cache_pct))
	dbgp("clearvars: OpcodeCache keys before clear: %d" % opcode_cache_count)
	dbgp("clearvars: InstructionCache keys before clear: %d" % instruction_cache_count)
	dbgp("clearvars: PageSections keys before clear: %d" % page_sections_count)
	dbgp("clearvars: ModuleCache keys before clear: %d" % module_cache_count)
	dbgp("clearvars: FuncCache keys before clear: %d" % func_cache_count)
	dbgp("clearvars: UnreadableMemoryProbeCache keys before clear: %d" % unreadable_probe_cache_count)
	dbgp("clearvars: UnreadableMemoryProbeCache hits: %d / %d (%.2f%%)" % (
		unreadable_probe_cache_hits,
		unreadable_probe_cache_requests,
		unreadable_probe_cache_pct
	))

	MemoryPages = {}
	AsmCache = {}
	disAsmCache = {}
	disasmFwCache = {}
	disasmFwCacheRequests = 0
	disasmFwCacheHits = 0
	OpcodeCache = {}
	InstructionCache = {}
	PageSections = {}
	ModuleCache = {}
	FuncCache = {}
	UnreadableMemoryProbeCache = {}
	UnreadableMemoryProbeCacheRequests = 0
	UnreadableMemoryProbeCacheHits = 0
	currentPID = 0
	currentTEBAddress = 0
	cpebaddress = 0
	return


def clearUnreadableMemoryProbeCache():
	dbgp(get_current_function_name())
	global UnreadableMemoryProbeCache
	UnreadableMemoryProbeCache = {}
	return


def _getUnreadableMemoryProbeCacheKey(address, fallback_size=0x1000):
	dbgp(get_current_function_name())
	global MemoryPages
	try:
		address = int(address)
	except Exception:
		return None

	if isinstance(MemoryPages, dict):
		for pagestart in MemoryPages:
			try:
				thispage = MemoryPages[pagestart]
				if thispage.begin <= address < thispage.end:
					return (int(thispage.begin), int(thispage.size))
			except Exception:
				continue

	page_base = address & ~0xfff
	page_size = fallback_size if isinstance(fallback_size, int) and fallback_size > 0 else 0x1000
	return (int(page_base), int(page_size))


def isUnreadableMemoryProbeCached(address, fallback_size=0x1000):
	dbgp(get_current_function_name())
	global UnreadableMemoryProbeCache
	global UnreadableMemoryProbeCacheRequests
	global UnreadableMemoryProbeCacheHits
	cache_key = _getUnreadableMemoryProbeCacheKey(address, fallback_size=fallback_size)
	if cache_key is None:
		return False
	UnreadableMemoryProbeCacheRequests += 1
	if cache_key in UnreadableMemoryProbeCache:
		UnreadableMemoryProbeCacheHits += 1
		return True
	return False


def markUnreadableMemoryProbeCached(address, fallback_size=0x1000):
	dbgp(get_current_function_name())
	global UnreadableMemoryProbeCache
	cache_key = _getUnreadableMemoryProbeCacheKey(address, fallback_size=fallback_size)
	if cache_key is None:
		return None
	UnreadableMemoryProbeCache[cache_key] = True
	return cache_key


def getTEBInfo():
	dbgp(get_current_function_name())
	return pykd.typedVar("_TEB", pykd.getImplicitThread())


def getTEBAddress():
	dbgp(get_current_function_name())

	global currentTEBAddress
	global currentPID
	global cpebaddress
	new_teb = int(pykd.getImplicitThread())
	if currentTEBAddress != new_teb:
		currentTEBAddress = new_teb
		# Context switched to another thread/process; drop dependent caches.
		currentPID = 0
		cpebaddress = 0
		clearUnreadableMemoryProbeCache()
	return currentTEBAddress


def getPEBAddress():
	dbgp(get_current_function_name())

	global cpebaddress
	if cpebaddress == 0:
		teb = getTEBAddress()
		cpebaddress = pykd.ptrPtr(teb + TEB_PEB[_arch_idx])
	return cpebaddress


def bin2hex(binbytes):
	dbgp(get_current_function_name())

	"""
	Converts a binary string to a string of space-separated hexadecimal bytes.
	"""
	return ' '.join('%02x' % b for b in iter_byte_values(binbytes))

def hexptr2bin(hexptr):
	dbgp(get_current_function_name())

	"""
	Input must be a int
	output : bytes in little endian
	"""
	return struct.pack('<L',hexptr)


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
		valtoreturn = int(inputstr,16)
	except:
		valtoreturn = 0
	return valtoreturn

def addrToInt(address):

	"""
	Convert a textual address to an integer

	Arguments:
	address - the address

	Return:
	int - the address value
	"""
	
	address = address.replace("\\x","").replace('`', '')
	return hexStrToInt(address)

def isAddress(address):
	dbgp(get_current_function_name())

	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	address = address.replace("\\x","")
	if len(address) > 16:
		return False

	return set(address.upper()) <= set("ABCDEF1234567890")

def intToHex(address):

	if arch == 32:
		return "0x%08x" % address
	if arch == 64:
		return "0x%016x" % address

def intToHexWinDbgFormat(address):

	if arch == 32:
		return "%08x" % address
	if arch == 64:
		formatted_hex = "%016x" % address
		formatted_hex = formatted_hex[:8] + '`' + formatted_hex[8:]
		return formatted_hex

def toHexByte(n):
	dbgp(get_current_function_name())

	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def hex2bin(pattern):
	dbgp(get_current_function_name())

	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
	pattern = pattern.replace(" ", "")
	if isinstance(pattern, str):
		pattern = pattern.encode("ascii")
	return binascii.unhexlify(pattern)


def getPyKDVersion():
	dbgp(get_current_function_name())

	currentversion = pykd.version
	currversion = ""
	for versionpart in currentversion:
		if versionpart != " ":
			if versionpart == ",":
				currversion += "."
			else:
				currversion += str(versionpart)
	currversion = currversion.strip(".")
	return currversion

def isPyKDVersionCompatible(currentversion,requiredversion):
	dbgp(get_current_function_name())

	# current version should be at least requiredversion
	if currentversion == requiredversion:
		return True
	else:
		currentparts = currentversion.split(".")
		requiredparts = requiredversion.split(".")
		if len(requiredparts) > len(currentparts):
			delta = len(requiredparts) - len(currentparts)
			cnt = 0
			while cnt < delta:
				currentparts.append("0")
				cnt += 1

		cnt = 0
		while cnt < len(requiredparts):
			if int(currentparts[cnt]) < int(requiredparts[cnt]):
				return False
			if int(currentparts[cnt]) > int(requiredparts[cnt]):
				return True
			cnt += 1
		return True
		
def checkVersion():
	dbgp(get_current_function_name())
	pykdversion_needed = "0.2.0.29"
	if arch == 64:
		pykdversion_needed = "0.2.0.29"
	currversion = getPyKDVersion()
	if not isPyKDVersionCompatible(currversion,pykdversion_needed):
		print("*******************************************************************************************")
		print("  You are running the wrong version of PyKD, please update ")
		print("   Installed version : %s " % currversion)
		print("   Required version : %s" % pykdversion_needed)
		print("*******************************************************************************************")
		import sys
		sys.exit()
		return
	return


def getModulesFromDebugger():
	"""Enumerate loaded modules via the debug engine (lm command).

	Returns a list of (dll_base, base_name, full_path) tuples, matching
	the format of PEB-based module walks.  This works even when the PEB
	loader list is corrupted (e.g. ntdll overwritten).
	"""
	dbgp(get_current_function_name())

	results = []
	try:
		lm_out = pykd.dbgCommand("lm")
	except Exception:
		return results

	for line in lm_out.splitlines():
		line = line.strip()
		if not line:
			continue
		# lm output format:
		#   x86: <start> <end>   <name>    (deferred)
		#   x64: <start>`<high> <end>`<high>   <name>    (deferred)
		# Skip header/separator lines
		parts = line.split()
		if len(parts) < 3:
			continue
		try:
			base_addr = int(parts[0].replace('`', ''), 16)
		except (ValueError, IndexError):
			continue
		modname = parts[2]
		# Get the full path from lm vm <module>
		full_path = ""
		try:
			vm_out = pykd.dbgCommand("lm vm %s" % modname)
			for vm_line in vm_out.splitlines():
				vm_line = vm_line.strip()
				if vm_line.lower().startswith("image path:"):
					full_path = vm_line.split(":", 1)[1].strip()
					break
				elif vm_line.lower().startswith("mapped memory image path:"):
					full_path = vm_line.split(":", 1)[1].strip()
					break
		except Exception:
			pass
		base_name = os.path.basename(full_path) if full_path else modname
		results.append((base_addr, base_name, full_path))

	return results


def getModuleFromAddress(address):
	dbgp(get_current_function_name())

	global ModuleCache
	try:
		thismod = pykd.module(address)
		if thismod is not None:
			modbase = thismod.begin()
			modsize = thismod.size()
			ModuleCache[thismod.image()] = [modbase, modsize]
			if modbase <= address <= modbase + modsize:
				return thismod
	except:
		pass

	for modname in ModuleCache:
		modbase = ModuleCache[modname][0]
		modsize = ModuleCache[modname][1]
		if modbase <= address <= modbase + modsize:
			try:
				return pykd.module(modname)
			except:
				pass
	return None

# Classes

class Debugger:

	MemoryPages = {}
	AsmCache = {}
	disAsmCache = {}
	OpcodeCache = {} 

	def __init__(self):
		self.MemoryPages = {}
		self.AsmCache = {}
		self.allmodules = {}
		self._allmodules_lower = {}
		self.OpcodeCache = {}
		self.ModCache = {}
		self._peb_list = None
		self._teb_addr = None
		self._peb_addr = None
		self.fillAsmCache()
		self.knowledgedb = "windbglib.db"

	def setKBDB(self,filename = "windbglib.db"):
		self.knowledgedb = filename
		return

	def getKBDB(self):
		return self.knowledgedb

	def remoteVirtualAlloc(self, size=0x10000,interactive=False):
		dbgp(get_current_function_name())

		PAGE_EXECUTE_READWRITE = 0x40
		VIRTUAL_MEM = ( 0x1000 | 0x2000 )
		vaddr = self.rVirtualAlloc(0,size,VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)
		return vaddr

	def rVirtualAlloc(self, lpAddress, dwSize, flAllocationType, flProtect):
		dbgp(get_current_function_name())

		PROCESS_VM_OPERATION = 0x0008
		kernel32 = ctypes.windll.kernel32
		pid = self.getDebuggedPid()
		hprocess = kernel32.OpenProcess(PROCESS_VM_OPERATION, False, pid)

		kernel32.VirtualAllocEx.argtypes = [
			ctypes.c_void_p,
			ctypes.c_void_p,
			ctypes.c_size_t,
			ctypes.c_ulong,
			ctypes.c_ulong
		]
		kernel32.VirtualAllocEx.restype = ctypes.c_void_p

		vaddr = kernel32.VirtualAllocEx(
			ctypes.c_void_p(hprocess),
			ctypes.c_void_p(lpAddress),
			ctypes.c_size_t(dwSize),
			ctypes.c_ulong(flAllocationType),
			ctypes.c_ulong(flProtect)
		)

		kernel32.CloseHandle(hprocess)

		if vaddr:
			# Invalidate cached page map so subsequent page queries reflect
			# the new allocation immediately.
			self.MemoryPages = {}
			clearUnreadableMemoryProbeCache()
			return int(vaddr)
		return 0

	def rVirtualProtect(self, lpAddress, dwSize, flNewProtect, lpflOldProtect=0):
		dbgp(get_current_function_name())

		PROCESS_VM_OPERATION = 0x0008
		kernel32 = ctypes.windll.kernel32
		pid = self.getDebuggedPid()
		hprocess = kernel32.OpenProcess(PROCESS_VM_OPERATION, False, pid)

		kernel32.VirtualProtectEx.argtypes = [
			ctypes.c_void_p,
			ctypes.c_void_p,
			ctypes.c_size_t,
			ctypes.c_ulong,
			ctypes.POINTER(ctypes.c_ulong)
		]
		kernel32.VirtualProtectEx.restype = ctypes.c_long

		oldprotect = ctypes.c_ulong(0)

		dbgp("Calling VirtualProtectEx for PID %d with args (lpAddress: 0x%08x, dwSize: 0x%x, flNewProtect: 0x%x)" % (pid, lpAddress, dwSize, flNewProtect))

		returnval = kernel32.VirtualProtectEx(
			ctypes.c_void_p(hprocess),
			ctypes.c_void_p(lpAddress),
			ctypes.c_size_t(dwSize),
			ctypes.c_ulong(flNewProtect),
			ctypes.byref(oldprotect)
		)

		kernel32.CloseHandle(hprocess)
		if returnval:
			# Invalidate cached page map so ACL changes are visible right away.
			self.MemoryPages = {}
			clearUnreadableMemoryProbeCache()
		return returnval


	def getAddress(self, functionname):
		dbgp(get_current_function_name())
	
		functionparts = functionname.split(".")
		if len(functionparts) > 1:
			modulename = functionparts[0]
			functionname = functionparts[1]
			funcref = "%s!%s" % (modulename,functionname)			
			cmd2run = "ln %s" % funcref
			output = self.nativeCommand(cmd2run)
			if "Exact matches" in output:
				outputlines = output.split("\n")
				for outputline in outputlines:
					if "(" in outputline.lower():
						lineparts = outputline.split(")")
						address = lineparts[0].replace("(","")
						return hexStrToInt(address)
			else:
				return 0
		else:
			return 0

	"""
	AsmCache
	"""

	def fillAsmCache(self):
		dbgp(get_current_function_name())

		# 32bit

		self.AsmCache["push eax"] = b"\x50"
		self.AsmCache["push ecx"] = b"\x51"
		self.AsmCache["push edx"] = b"\x52"
		self.AsmCache["push ebx"] = b"\x53"
		self.AsmCache["push esp"] = b"\x54"
		self.AsmCache["push ebp"] = b"\x55"
		self.AsmCache["push esi"] = b"\x56"		
		self.AsmCache["push edi"] = b"\x57"

		self.AsmCache["pop eax"] = b"\x58"
		self.AsmCache["pop ecx"] = b"\x59"
		self.AsmCache["pop edx"] = b"\x5a"
		self.AsmCache["pop ebx"] = b"\x5b"
		self.AsmCache["pop esp"] = b"\x5c"
		self.AsmCache["pop ebp"] = b"\x5d"
		self.AsmCache["pop esi"] = b"\x5e"
		self.AsmCache["pop edi"] = b"\x5f"

		self.AsmCache["inc eax"] = b"\x40"
		self.AsmCache["inc ecx"] = b"\x41"
		self.AsmCache["inc edx"] = b"\x42"
		self.AsmCache["inc ebx"] = b"\x43"
		self.AsmCache["inc esp"] = b"\x44"
		self.AsmCache["inc ebp"] = b"\x45"
		self.AsmCache["inc esi"] = b"\x46"
		self.AsmCache["inc edi"] = b"\x47"

		self.AsmCache["dec eax"] = b"\x48"
		self.AsmCache["dec ecx"] = b"\x49"
		self.AsmCache["dec edx"] = b"\x4a"
		self.AsmCache["dec ebx"] = b"\x4b"
		self.AsmCache["dec esp"] = b"\x4c"
		self.AsmCache["dec ebp"] = b"\x4d"
		self.AsmCache["dec esi"] = b"\x4e"
		self.AsmCache["dec edi"] = b"\x4f"

		self.AsmCache["jmp eax"] = b"\xff\xe0"
		self.AsmCache["jmp ecx"] = b"\xff\xe1"
		self.AsmCache["jmp edx"] = b"\xff\xe2"
		self.AsmCache["jmp ebx"] = b"\xff\xe3"
		self.AsmCache["jmp esp"] = b"\xff\xe4"
		self.AsmCache["jmp ebp"] = b"\xff\xe5"
		self.AsmCache["jmp esi"] = b"\xff\xe6"		
		self.AsmCache["jmp edi"] = b"\xff\xe7"

		self.AsmCache["call eax"] = b"\xff\xd0"
		self.AsmCache["call ecx"] = b"\xff\xd1"
		self.AsmCache["call edx"] = b"\xff\xd2"
		self.AsmCache["call ebx"] = b"\xff\xd3"
		self.AsmCache["call esp"] = b"\xff\xd4"
		self.AsmCache["call ebp"] = b"\xff\xd5"
		self.AsmCache["call esi"] = b"\xff\xd6"		
		self.AsmCache["call edi"] = b"\xff\xd7"

		self.AsmCache["jmp [eax]"] = b"\xff\x20"
		self.AsmCache["jmp [ecx]"] = b"\xff\x21"
		self.AsmCache["jmp [edx]"] = b"\xff\x22"
		self.AsmCache["jmp [ebx]"] = b"\xff\x23"
		self.AsmCache["jmp [esp]"] = b"\xff\x24"
		self.AsmCache["jmp [ebp]"] = b"\xff\x25"
		self.AsmCache["jmp [esi]"] = b"\xff\x26"
		self.AsmCache["jmp [edi]"] = b"\xff\x27"

		self.AsmCache["call [eax]"] = b"\xff\x10"
		self.AsmCache["call [ecx]"] = b"\xff\x11"
		self.AsmCache["call [edx]"] = b"\xff\x12"
		self.AsmCache["call [ebx]"] = b"\xff\x13"
		self.AsmCache["call [esp]"] = b"\xff\x14"
		self.AsmCache["call [ebp]"] = b"\xff\x15"
		self.AsmCache["call [esi]"] = b"\xff\x16"
		self.AsmCache["call [edi]"] = b"\xff\x17"

		self.AsmCache["xchg eax,esp"] = b"\x94"
		self.AsmCache["xchg ecx,esp"] = b"\x87\xcc"
		self.AsmCache["xchg edx,esp"] = b"\x87\xd4"
		self.AsmCache["xchg ebx,esp"] = b"\x87\xdc"
		self.AsmCache["xchg ebp,esp"] = b"\x87\xec"
		self.AsmCache["xchg edi,esp"] = b"\x87\xfc"
		self.AsmCache["xchg esi,esp"] = b"\x87\xf4"
		self.AsmCache["xchg esp,eax"] = b"\x94"
		self.AsmCache["xchg esp,ecx"] = b"\x87\xcc"
		self.AsmCache["xchg esp,edx"] = b"\x87\xd4"
		self.AsmCache["xchg esp,ebx"] = b"\x87\xdc"
		self.AsmCache["xchg esp,ebp"] = b"\x87\xec"
		self.AsmCache["xchg esp,edi"] = b"\x87\xfc"
		self.AsmCache["xchg esp,esi"] = b"\x87\xf4"		

		self.AsmCache["mov eax,eax"] = b"\x89\xc0"
		self.AsmCache["mov eax,ecx"] = b"\x89\xc8"
		self.AsmCache["mov eax,edx"] = b"\x89\xd0"
		self.AsmCache["mov eax,ebx"] = b"\x89\xd8"
		self.AsmCache["mov eax,esp"] = b"\x89\xe0"
		self.AsmCache["mov eax,ebp"] = b"\x89\xe8"
		self.AsmCache["mov eax,esi"] = b"\x89\xf0"
		self.AsmCache["mov eax,edi"] = b"\x89\xf8"
		self.AsmCache["mov eax,r8d"] = b"\x44\x89\xc0"
		self.AsmCache["mov eax,r9d"] = b"\x44\x89\xc8"
		self.AsmCache["mov eax,r10d"] = b"\x44\x89\xd0"
		self.AsmCache["mov eax,r11d"] = b"\x44\x89\xd8"
		self.AsmCache["mov eax,r12d"] = b"\x44\x89\xe0"
		self.AsmCache["mov eax,r13d"] = b"\x44\x89\xe8"
		self.AsmCache["mov eax,r14d"] = b"\x44\x89\xf0"
		self.AsmCache["mov eax,r15d"] = b"\x44\x89\xf8"
		self.AsmCache["mov ecx,eax"] = b"\x89\xc1"
		self.AsmCache["mov ecx,ecx"] = b"\x89\xc9"
		self.AsmCache["mov ecx,edx"] = b"\x89\xd1"
		self.AsmCache["mov ecx,ebx"] = b"\x89\xd9"
		self.AsmCache["mov ecx,esp"] = b"\x89\xe1"
		self.AsmCache["mov ecx,ebp"] = b"\x89\xe9"
		self.AsmCache["mov ecx,esi"] = b"\x89\xf1"
		self.AsmCache["mov ecx,edi"] = b"\x89\xf9"
		self.AsmCache["mov ecx,r8d"] = b"\x44\x89\xc1"
		self.AsmCache["mov ecx,r9d"] = b"\x44\x89\xc9"
		self.AsmCache["mov ecx,r10d"] = b"\x44\x89\xd1"
		self.AsmCache["mov ecx,r11d"] = b"\x44\x89\xd9"
		self.AsmCache["mov ecx,r12d"] = b"\x44\x89\xe1"
		self.AsmCache["mov ecx,r13d"] = b"\x44\x89\xe9"
		self.AsmCache["mov ecx,r14d"] = b"\x44\x89\xf1"
		self.AsmCache["mov ecx,r15d"] = b"\x44\x89\xf9"
		self.AsmCache["mov edx,eax"] = b"\x89\xc2"
		self.AsmCache["mov edx,ecx"] = b"\x89\xca"
		self.AsmCache["mov edx,edx"] = b"\x89\xd2"
		self.AsmCache["mov edx,ebx"] = b"\x89\xda"
		self.AsmCache["mov edx,esp"] = b"\x89\xe2"
		self.AsmCache["mov edx,ebp"] = b"\x89\xea"
		self.AsmCache["mov edx,esi"] = b"\x89\xf2"
		self.AsmCache["mov edx,edi"] = b"\x89\xfa"
		self.AsmCache["mov edx,r8d"] = b"\x44\x89\xc2"
		self.AsmCache["mov edx,r9d"] = b"\x44\x89\xca"
		self.AsmCache["mov edx,r10d"] = b"\x44\x89\xd2"
		self.AsmCache["mov edx,r11d"] = b"\x44\x89\xda"
		self.AsmCache["mov edx,r12d"] = b"\x44\x89\xe2"
		self.AsmCache["mov edx,r13d"] = b"\x44\x89\xea"
		self.AsmCache["mov edx,r14d"] = b"\x44\x89\xf2"
		self.AsmCache["mov edx,r15d"] = b"\x44\x89\xfa"
		self.AsmCache["mov ebx,eax"] = b"\x89\xc3"
		self.AsmCache["mov ebx,ecx"] = b"\x89\xcb"
		self.AsmCache["mov ebx,edx"] = b"\x89\xd3"
		self.AsmCache["mov ebx,ebx"] = b"\x89\xdb"
		self.AsmCache["mov ebx,esp"] = b"\x89\xe3"
		self.AsmCache["mov ebx,ebp"] = b"\x89\xeb"
		self.AsmCache["mov ebx,esi"] = b"\x89\xf3"
		self.AsmCache["mov ebx,edi"] = b"\x89\xfb"
		self.AsmCache["mov ebx,r8d"] = b"\x44\x89\xc3"
		self.AsmCache["mov ebx,r9d"] = b"\x44\x89\xcb"
		self.AsmCache["mov ebx,r10d"] = b"\x44\x89\xd3"
		self.AsmCache["mov ebx,r11d"] = b"\x44\x89\xdb"
		self.AsmCache["mov ebx,r12d"] = b"\x44\x89\xe3"
		self.AsmCache["mov ebx,r13d"] = b"\x44\x89\xeb"
		self.AsmCache["mov ebx,r14d"] = b"\x44\x89\xf3"
		self.AsmCache["mov ebx,r15d"] = b"\x44\x89\xfb"
		self.AsmCache["mov esp,eax"] = b"\x89\xc4"
		self.AsmCache["mov esp,ecx"] = b"\x89\xcc"
		self.AsmCache["mov esp,edx"] = b"\x89\xd4"
		self.AsmCache["mov esp,ebx"] = b"\x89\xdc"
		self.AsmCache["mov esp,esp"] = b"\x89\xe4"
		self.AsmCache["mov esp,ebp"] = b"\x89\xec"
		self.AsmCache["mov esp,esi"] = b"\x89\xf4"
		self.AsmCache["mov esp,edi"] = b"\x89\xfc"
		self.AsmCache["mov esp,r8d"] = b"\x44\x89\xc4"
		self.AsmCache["mov esp,r9d"] = b"\x44\x89\xcc"
		self.AsmCache["mov esp,r10d"] = b"\x44\x89\xd4"
		self.AsmCache["mov esp,r11d"] = b"\x44\x89\xdc"
		self.AsmCache["mov esp,r12d"] = b"\x44\x89\xe4"
		self.AsmCache["mov esp,r13d"] = b"\x44\x89\xec"
		self.AsmCache["mov esp,r14d"] = b"\x44\x89\xf4"
		self.AsmCache["mov esp,r15d"] = b"\x44\x89\xfc"
		self.AsmCache["mov ebp,eax"] = b"\x89\xc5"
		self.AsmCache["mov ebp,ecx"] = b"\x89\xcd"
		self.AsmCache["mov ebp,edx"] = b"\x89\xd5"
		self.AsmCache["mov ebp,ebx"] = b"\x89\xdd"
		self.AsmCache["mov ebp,esp"] = b"\x89\xe5"
		self.AsmCache["mov ebp,ebp"] = b"\x89\xed"
		self.AsmCache["mov ebp,esi"] = b"\x89\xf5"
		self.AsmCache["mov ebp,edi"] = b"\x89\xfd"
		self.AsmCache["mov ebp,r8d"] = b"\x44\x89\xc5"
		self.AsmCache["mov ebp,r9d"] = b"\x44\x89\xcd"
		self.AsmCache["mov ebp,r10d"] = b"\x44\x89\xd5"
		self.AsmCache["mov ebp,r11d"] = b"\x44\x89\xdd"
		self.AsmCache["mov ebp,r12d"] = b"\x44\x89\xe5"
		self.AsmCache["mov ebp,r13d"] = b"\x44\x89\xed"
		self.AsmCache["mov ebp,r14d"] = b"\x44\x89\xf5"
		self.AsmCache["mov ebp,r15d"] = b"\x44\x89\xfd"
		self.AsmCache["mov esi,eax"] = b"\x89\xc6"
		self.AsmCache["mov esi,ecx"] = b"\x89\xce"
		self.AsmCache["mov esi,edx"] = b"\x89\xd6"
		self.AsmCache["mov esi,ebx"] = b"\x89\xde"
		self.AsmCache["mov esi,esp"] = b"\x89\xe6"
		self.AsmCache["mov esi,ebp"] = b"\x89\xee"
		self.AsmCache["mov esi,esi"] = b"\x89\xf6"
		self.AsmCache["mov esi,edi"] = b"\x89\xfe"
		self.AsmCache["mov esi,r8d"] = b"\x44\x89\xc6"
		self.AsmCache["mov esi,r9d"] = b"\x44\x89\xce"
		self.AsmCache["mov esi,r10d"] = b"\x44\x89\xd6"
		self.AsmCache["mov esi,r11d"] = b"\x44\x89\xde"
		self.AsmCache["mov esi,r12d"] = b"\x44\x89\xe6"
		self.AsmCache["mov esi,r13d"] = b"\x44\x89\xee"
		self.AsmCache["mov esi,r14d"] = b"\x44\x89\xf6"
		self.AsmCache["mov esi,r15d"] = b"\x44\x89\xfe"
		self.AsmCache["mov edi,eax"] = b"\x89\xc7"
		self.AsmCache["mov edi,ecx"] = b"\x89\xcf"
		self.AsmCache["mov edi,edx"] = b"\x89\xd7"
		self.AsmCache["mov edi,ebx"] = b"\x89\xdf"
		self.AsmCache["mov edi,esp"] = b"\x89\xe7"
		self.AsmCache["mov edi,ebp"] = b"\x89\xef"
		self.AsmCache["mov edi,esi"] = b"\x89\xf7"
		self.AsmCache["mov edi,edi"] = b"\x89\xff"
		self.AsmCache["mov edi,r8d"] = b"\x44\x89\xc7"
		self.AsmCache["mov edi,r9d"] = b"\x44\x89\xcf"
		self.AsmCache["mov edi,r10d"] = b"\x44\x89\xd7"
		self.AsmCache["mov edi,r11d"] = b"\x44\x89\xdf"
		self.AsmCache["mov edi,r12d"] = b"\x44\x89\xe7"
		self.AsmCache["mov edi,r13d"] = b"\x44\x89\xef"
		self.AsmCache["mov edi,r14d"] = b"\x44\x89\xf7"
		self.AsmCache["mov edi,r15d"] = b"\x44\x89\xff"
		self.AsmCache["mov r8d,eax"] = b"\x41\x89\xc0"
		self.AsmCache["mov r8d,ecx"] = b"\x41\x89\xc8"
		self.AsmCache["mov r8d,edx"] = b"\x41\x89\xd0"
		self.AsmCache["mov r8d,ebx"] = b"\x41\x89\xd8"
		self.AsmCache["mov r8d,esp"] = b"\x41\x89\xe0"
		self.AsmCache["mov r8d,ebp"] = b"\x41\x89\xe8"
		self.AsmCache["mov r8d,esi"] = b"\x41\x89\xf0"
		self.AsmCache["mov r8d,edi"] = b"\x41\x89\xf8"
		self.AsmCache["mov r8d,r8d"] = b"\x45\x89\xc0"
		self.AsmCache["mov r8d,r9d"] = b"\x45\x89\xc8"
		self.AsmCache["mov r8d,r10d"] = b"\x45\x89\xd0"
		self.AsmCache["mov r8d,r11d"] = b"\x45\x89\xd8"
		self.AsmCache["mov r8d,r12d"] = b"\x45\x89\xe0"
		self.AsmCache["mov r8d,r13d"] = b"\x45\x89\xe8"
		self.AsmCache["mov r8d,r14d"] = b"\x45\x89\xf0"
		self.AsmCache["mov r8d,r15d"] = b"\x45\x89\xf8"
		self.AsmCache["mov r9d,eax"] = b"\x41\x89\xc1"
		self.AsmCache["mov r9d,ecx"] = b"\x41\x89\xc9"
		self.AsmCache["mov r9d,edx"] = b"\x41\x89\xd1"
		self.AsmCache["mov r9d,ebx"] = b"\x41\x89\xd9"
		self.AsmCache["mov r9d,esp"] = b"\x41\x89\xe1"
		self.AsmCache["mov r9d,ebp"] = b"\x41\x89\xe9"
		self.AsmCache["mov r9d,esi"] = b"\x41\x89\xf1"
		self.AsmCache["mov r9d,edi"] = b"\x41\x89\xf9"
		self.AsmCache["mov r9d,r8d"] = b"\x45\x89\xc1"
		self.AsmCache["mov r9d,r9d"] = b"\x45\x89\xc9"
		self.AsmCache["mov r9d,r10d"] = b"\x45\x89\xd1"
		self.AsmCache["mov r9d,r11d"] = b"\x45\x89\xd9"
		self.AsmCache["mov r9d,r12d"] = b"\x45\x89\xe1"
		self.AsmCache["mov r9d,r13d"] = b"\x45\x89\xe9"
		self.AsmCache["mov r9d,r14d"] = b"\x45\x89\xf1"
		self.AsmCache["mov r9d,r15d"] = b"\x45\x89\xf9"
		self.AsmCache["mov r10d,eax"] = b"\x41\x89\xc2"
		self.AsmCache["mov r10d,ecx"] = b"\x41\x89\xca"
		self.AsmCache["mov r10d,edx"] = b"\x41\x89\xd2"
		self.AsmCache["mov r10d,ebx"] = b"\x41\x89\xda"
		self.AsmCache["mov r10d,esp"] = b"\x41\x89\xe2"
		self.AsmCache["mov r10d,ebp"] = b"\x41\x89\xea"
		self.AsmCache["mov r10d,esi"] = b"\x41\x89\xf2"
		self.AsmCache["mov r10d,edi"] = b"\x41\x89\xfa"
		self.AsmCache["mov r10d,r8d"] = b"\x45\x89\xc2"
		self.AsmCache["mov r10d,r9d"] = b"\x45\x89\xca"
		self.AsmCache["mov r10d,r10d"] = b"\x45\x89\xd2"
		self.AsmCache["mov r10d,r11d"] = b"\x45\x89\xda"
		self.AsmCache["mov r10d,r12d"] = b"\x45\x89\xe2"
		self.AsmCache["mov r10d,r13d"] = b"\x45\x89\xea"
		self.AsmCache["mov r10d,r14d"] = b"\x45\x89\xf2"
		self.AsmCache["mov r10d,r15d"] = b"\x45\x89\xfa"
		self.AsmCache["mov r11d,eax"] = b"\x41\x89\xc3"
		self.AsmCache["mov r11d,ecx"] = b"\x41\x89\xcb"
		self.AsmCache["mov r11d,edx"] = b"\x41\x89\xd3"
		self.AsmCache["mov r11d,ebx"] = b"\x41\x89\xdb"
		self.AsmCache["mov r11d,esp"] = b"\x41\x89\xe3"
		self.AsmCache["mov r11d,ebp"] = b"\x41\x89\xeb"
		self.AsmCache["mov r11d,esi"] = b"\x41\x89\xf3"
		self.AsmCache["mov r11d,edi"] = b"\x41\x89\xfb"
		self.AsmCache["mov r11d,r8d"] = b"\x45\x89\xc3"
		self.AsmCache["mov r11d,r9d"] = b"\x45\x89\xcb"
		self.AsmCache["mov r11d,r10d"] = b"\x45\x89\xd3"
		self.AsmCache["mov r11d,r11d"] = b"\x45\x89\xdb"
		self.AsmCache["mov r11d,r12d"] = b"\x45\x89\xe3"
		self.AsmCache["mov r11d,r13d"] = b"\x45\x89\xeb"
		self.AsmCache["mov r11d,r14d"] = b"\x45\x89\xf3"
		self.AsmCache["mov r11d,r15d"] = b"\x45\x89\xfb"
		self.AsmCache["mov r12d,eax"] = b"\x41\x89\xc4"
		self.AsmCache["mov r12d,ecx"] = b"\x41\x89\xcc"
		self.AsmCache["mov r12d,edx"] = b"\x41\x89\xd4"
		self.AsmCache["mov r12d,ebx"] = b"\x41\x89\xdc"
		self.AsmCache["mov r12d,esp"] = b"\x41\x89\xe4"
		self.AsmCache["mov r12d,ebp"] = b"\x41\x89\xec"
		self.AsmCache["mov r12d,esi"] = b"\x41\x89\xf4"
		self.AsmCache["mov r12d,edi"] = b"\x41\x89\xfc"
		self.AsmCache["mov r12d,r8d"] = b"\x45\x89\xc4"
		self.AsmCache["mov r12d,r9d"] = b"\x45\x89\xcc"
		self.AsmCache["mov r12d,r10d"] = b"\x45\x89\xd4"
		self.AsmCache["mov r12d,r11d"] = b"\x45\x89\xdc"
		self.AsmCache["mov r12d,r12d"] = b"\x45\x89\xe4"
		self.AsmCache["mov r12d,r13d"] = b"\x45\x89\xec"
		self.AsmCache["mov r12d,r14d"] = b"\x45\x89\xf4"
		self.AsmCache["mov r12d,r15d"] = b"\x45\x89\xfc"
		self.AsmCache["mov r13d,eax"] = b"\x41\x89\xc5"
		self.AsmCache["mov r13d,ecx"] = b"\x41\x89\xcd"
		self.AsmCache["mov r13d,edx"] = b"\x41\x89\xd5"
		self.AsmCache["mov r13d,ebx"] = b"\x41\x89\xdd"
		self.AsmCache["mov r13d,esp"] = b"\x41\x89\xe5"
		self.AsmCache["mov r13d,ebp"] = b"\x41\x89\xed"
		self.AsmCache["mov r13d,esi"] = b"\x41\x89\xf5"
		self.AsmCache["mov r13d,edi"] = b"\x41\x89\xfd"
		self.AsmCache["mov r13d,r8d"] = b"\x45\x89\xc5"
		self.AsmCache["mov r13d,r9d"] = b"\x45\x89\xcd"
		self.AsmCache["mov r13d,r10d"] = b"\x45\x89\xd5"
		self.AsmCache["mov r13d,r11d"] = b"\x45\x89\xdd"
		self.AsmCache["mov r13d,r12d"] = b"\x45\x89\xe5"
		self.AsmCache["mov r13d,r13d"] = b"\x45\x89\xed"
		self.AsmCache["mov r13d,r14d"] = b"\x45\x89\xf5"
		self.AsmCache["mov r13d,r15d"] = b"\x45\x89\xfd"
		self.AsmCache["mov r14d,eax"] = b"\x41\x89\xc6"
		self.AsmCache["mov r14d,ecx"] = b"\x41\x89\xce"
		self.AsmCache["mov r14d,edx"] = b"\x41\x89\xd6"
		self.AsmCache["mov r14d,ebx"] = b"\x41\x89\xde"
		self.AsmCache["mov r14d,esp"] = b"\x41\x89\xe6"
		self.AsmCache["mov r14d,ebp"] = b"\x41\x89\xee"
		self.AsmCache["mov r14d,esi"] = b"\x41\x89\xf6"
		self.AsmCache["mov r14d,edi"] = b"\x41\x89\xfe"
		self.AsmCache["mov r14d,r8d"] = b"\x45\x89\xc6"
		self.AsmCache["mov r14d,r9d"] = b"\x45\x89\xce"
		self.AsmCache["mov r14d,r10d"] = b"\x45\x89\xd6"
		self.AsmCache["mov r14d,r11d"] = b"\x45\x89\xde"
		self.AsmCache["mov r14d,r12d"] = b"\x45\x89\xe6"
		self.AsmCache["mov r14d,r13d"] = b"\x45\x89\xee"
		self.AsmCache["mov r14d,r14d"] = b"\x45\x89\xf6"
		self.AsmCache["mov r14d,r15d"] = b"\x45\x89\xfe"
		self.AsmCache["mov r15d,eax"] = b"\x41\x89\xc7"
		self.AsmCache["mov r15d,ecx"] = b"\x41\x89\xcf"
		self.AsmCache["mov r15d,edx"] = b"\x41\x89\xd7"
		self.AsmCache["mov r15d,ebx"] = b"\x41\x89\xdf"
		self.AsmCache["mov r15d,esp"] = b"\x41\x89\xe7"
		self.AsmCache["mov r15d,ebp"] = b"\x41\x89\xef"
		self.AsmCache["mov r15d,esi"] = b"\x41\x89\xf7"
		self.AsmCache["mov r15d,edi"] = b"\x41\x89\xff"
		self.AsmCache["mov r15d,r8d"] = b"\x45\x89\xc7"
		self.AsmCache["mov r15d,r9d"] = b"\x45\x89\xcf"
		self.AsmCache["mov r15d,r10d"] = b"\x45\x89\xd7"
		self.AsmCache["mov r15d,r11d"] = b"\x45\x89\xdf"
		self.AsmCache["mov r15d,r12d"] = b"\x45\x89\xe7"
		self.AsmCache["mov r15d,r13d"] = b"\x45\x89\xef"
		self.AsmCache["mov r15d,r14d"] = b"\x45\x89\xf7"
		self.AsmCache["mov r15d,r15d"] = b"\x45\x89\xff"

		self.AsmCache["mov ax,ax"] = b"\x66\x89\xc0"
		self.AsmCache["mov ax,cx"] = b"\x66\x89\xc8"
		self.AsmCache["mov ax,dx"] = b"\x66\x89\xd0"
		self.AsmCache["mov ax,bx"] = b"\x66\x89\xd8"
		self.AsmCache["mov ax,sp"] = b"\x66\x89\xe0"
		self.AsmCache["mov ax,bp"] = b"\x66\x89\xe8"
		self.AsmCache["mov ax,si"] = b"\x66\x89\xf0"
		self.AsmCache["mov ax,di"] = b"\x66\x89\xf8"
		self.AsmCache["mov ax,r8w"] = b"\x66\x44\x89\xc0"
		self.AsmCache["mov ax,r9w"] = b"\x66\x44\x89\xc8"
		self.AsmCache["mov ax,r10w"] = b"\x66\x44\x89\xd0"
		self.AsmCache["mov ax,r11w"] = b"\x66\x44\x89\xd8"
		self.AsmCache["mov ax,r12w"] = b"\x66\x44\x89\xe0"
		self.AsmCache["mov ax,r13w"] = b"\x66\x44\x89\xe8"
		self.AsmCache["mov ax,r14w"] = b"\x66\x44\x89\xf0"
		self.AsmCache["mov ax,r15w"] = b"\x66\x44\x89\xf8"
		self.AsmCache["mov cx,ax"] = b"\x66\x89\xc1"
		self.AsmCache["mov cx,cx"] = b"\x66\x89\xc9"
		self.AsmCache["mov cx,dx"] = b"\x66\x89\xd1"
		self.AsmCache["mov cx,bx"] = b"\x66\x89\xd9"
		self.AsmCache["mov cx,sp"] = b"\x66\x89\xe1"
		self.AsmCache["mov cx,bp"] = b"\x66\x89\xe9"
		self.AsmCache["mov cx,si"] = b"\x66\x89\xf1"
		self.AsmCache["mov cx,di"] = b"\x66\x89\xf9"
		self.AsmCache["mov cx,r8w"] = b"\x66\x44\x89\xc1"
		self.AsmCache["mov cx,r9w"] = b"\x66\x44\x89\xc9"
		self.AsmCache["mov cx,r10w"] = b"\x66\x44\x89\xd1"
		self.AsmCache["mov cx,r11w"] = b"\x66\x44\x89\xd9"
		self.AsmCache["mov cx,r12w"] = b"\x66\x44\x89\xe1"
		self.AsmCache["mov cx,r13w"] = b"\x66\x44\x89\xe9"
		self.AsmCache["mov cx,r14w"] = b"\x66\x44\x89\xf1"
		self.AsmCache["mov cx,r15w"] = b"\x66\x44\x89\xf9"
		self.AsmCache["mov dx,ax"] = b"\x66\x89\xc2"
		self.AsmCache["mov dx,cx"] = b"\x66\x89\xca"
		self.AsmCache["mov dx,dx"] = b"\x66\x89\xd2"
		self.AsmCache["mov dx,bx"] = b"\x66\x89\xda"
		self.AsmCache["mov dx,sp"] = b"\x66\x89\xe2"
		self.AsmCache["mov dx,bp"] = b"\x66\x89\xea"
		self.AsmCache["mov dx,si"] = b"\x66\x89\xf2"
		self.AsmCache["mov dx,di"] = b"\x66\x89\xfa"
		self.AsmCache["mov dx,r8w"] = b"\x66\x44\x89\xc2"
		self.AsmCache["mov dx,r9w"] = b"\x66\x44\x89\xca"
		self.AsmCache["mov dx,r10w"] = b"\x66\x44\x89\xd2"
		self.AsmCache["mov dx,r11w"] = b"\x66\x44\x89\xda"
		self.AsmCache["mov dx,r12w"] = b"\x66\x44\x89\xe2"
		self.AsmCache["mov dx,r13w"] = b"\x66\x44\x89\xea"
		self.AsmCache["mov dx,r14w"] = b"\x66\x44\x89\xf2"
		self.AsmCache["mov dx,r15w"] = b"\x66\x44\x89\xfa"
		self.AsmCache["mov bx,ax"] = b"\x66\x89\xc3"
		self.AsmCache["mov bx,cx"] = b"\x66\x89\xcb"
		self.AsmCache["mov bx,dx"] = b"\x66\x89\xd3"
		self.AsmCache["mov bx,bx"] = b"\x66\x89\xdb"
		self.AsmCache["mov bx,sp"] = b"\x66\x89\xe3"
		self.AsmCache["mov bx,bp"] = b"\x66\x89\xeb"
		self.AsmCache["mov bx,si"] = b"\x66\x89\xf3"
		self.AsmCache["mov bx,di"] = b"\x66\x89\xfb"
		self.AsmCache["mov bx,r8w"] = b"\x66\x44\x89\xc3"
		self.AsmCache["mov bx,r9w"] = b"\x66\x44\x89\xcb"
		self.AsmCache["mov bx,r10w"] = b"\x66\x44\x89\xd3"
		self.AsmCache["mov bx,r11w"] = b"\x66\x44\x89\xdb"
		self.AsmCache["mov bx,r12w"] = b"\x66\x44\x89\xe3"
		self.AsmCache["mov bx,r13w"] = b"\x66\x44\x89\xeb"
		self.AsmCache["mov bx,r14w"] = b"\x66\x44\x89\xf3"
		self.AsmCache["mov bx,r15w"] = b"\x66\x44\x89\xfb"
		self.AsmCache["mov sp,ax"] = b"\x66\x89\xc4"
		self.AsmCache["mov sp,cx"] = b"\x66\x89\xcc"
		self.AsmCache["mov sp,dx"] = b"\x66\x89\xd4"
		self.AsmCache["mov sp,bx"] = b"\x66\x89\xdc"
		self.AsmCache["mov sp,sp"] = b"\x66\x89\xe4"
		self.AsmCache["mov sp,bp"] = b"\x66\x89\xec"
		self.AsmCache["mov sp,si"] = b"\x66\x89\xf4"
		self.AsmCache["mov sp,di"] = b"\x66\x89\xfc"
		self.AsmCache["mov sp,r8w"] = b"\x66\x44\x89\xc4"
		self.AsmCache["mov sp,r9w"] = b"\x66\x44\x89\xcc"
		self.AsmCache["mov sp,r10w"] = b"\x66\x44\x89\xd4"
		self.AsmCache["mov sp,r11w"] = b"\x66\x44\x89\xdc"
		self.AsmCache["mov sp,r12w"] = b"\x66\x44\x89\xe4"
		self.AsmCache["mov sp,r13w"] = b"\x66\x44\x89\xec"
		self.AsmCache["mov sp,r14w"] = b"\x66\x44\x89\xf4"
		self.AsmCache["mov sp,r15w"] = b"\x66\x44\x89\xfc"
		self.AsmCache["mov bp,ax"] = b"\x66\x89\xc5"
		self.AsmCache["mov bp,cx"] = b"\x66\x89\xcd"
		self.AsmCache["mov bp,dx"] = b"\x66\x89\xd5"
		self.AsmCache["mov bp,bx"] = b"\x66\x89\xdd"
		self.AsmCache["mov bp,sp"] = b"\x66\x89\xe5"
		self.AsmCache["mov bp,bp"] = b"\x66\x89\xed"
		self.AsmCache["mov bp,si"] = b"\x66\x89\xf5"
		self.AsmCache["mov bp,di"] = b"\x66\x89\xfd"
		self.AsmCache["mov bp,r8w"] = b"\x66\x44\x89\xc5"
		self.AsmCache["mov bp,r9w"] = b"\x66\x44\x89\xcd"
		self.AsmCache["mov bp,r10w"] = b"\x66\x44\x89\xd5"
		self.AsmCache["mov bp,r11w"] = b"\x66\x44\x89\xdd"
		self.AsmCache["mov bp,r12w"] = b"\x66\x44\x89\xe5"
		self.AsmCache["mov bp,r13w"] = b"\x66\x44\x89\xed"
		self.AsmCache["mov bp,r14w"] = b"\x66\x44\x89\xf5"
		self.AsmCache["mov bp,r15w"] = b"\x66\x44\x89\xfd"
		self.AsmCache["mov si,ax"] = b"\x66\x89\xc6"
		self.AsmCache["mov si,cx"] = b"\x66\x89\xce"
		self.AsmCache["mov si,dx"] = b"\x66\x89\xd6"
		self.AsmCache["mov si,bx"] = b"\x66\x89\xde"
		self.AsmCache["mov si,sp"] = b"\x66\x89\xe6"
		self.AsmCache["mov si,bp"] = b"\x66\x89\xee"
		self.AsmCache["mov si,si"] = b"\x66\x89\xf6"
		self.AsmCache["mov si,di"] = b"\x66\x89\xfe"
		self.AsmCache["mov si,r8w"] = b"\x66\x44\x89\xc6"
		self.AsmCache["mov si,r9w"] = b"\x66\x44\x89\xce"
		self.AsmCache["mov si,r10w"] = b"\x66\x44\x89\xd6"
		self.AsmCache["mov si,r11w"] = b"\x66\x44\x89\xde"
		self.AsmCache["mov si,r12w"] = b"\x66\x44\x89\xe6"
		self.AsmCache["mov si,r13w"] = b"\x66\x44\x89\xee"
		self.AsmCache["mov si,r14w"] = b"\x66\x44\x89\xf6"
		self.AsmCache["mov si,r15w"] = b"\x66\x44\x89\xfe"
		self.AsmCache["mov di,ax"] = b"\x66\x89\xc7"
		self.AsmCache["mov di,cx"] = b"\x66\x89\xcf"
		self.AsmCache["mov di,dx"] = b"\x66\x89\xd7"
		self.AsmCache["mov di,bx"] = b"\x66\x89\xdf"
		self.AsmCache["mov di,sp"] = b"\x66\x89\xe7"
		self.AsmCache["mov di,bp"] = b"\x66\x89\xef"
		self.AsmCache["mov di,si"] = b"\x66\x89\xf7"
		self.AsmCache["mov di,di"] = b"\x66\x89\xff"
		self.AsmCache["mov di,r8w"] = b"\x66\x44\x89\xc7"
		self.AsmCache["mov di,r9w"] = b"\x66\x44\x89\xcf"
		self.AsmCache["mov di,r10w"] = b"\x66\x44\x89\xd7"
		self.AsmCache["mov di,r11w"] = b"\x66\x44\x89\xdf"
		self.AsmCache["mov di,r12w"] = b"\x66\x44\x89\xe7"
		self.AsmCache["mov di,r13w"] = b"\x66\x44\x89\xef"
		self.AsmCache["mov di,r14w"] = b"\x66\x44\x89\xf7"
		self.AsmCache["mov di,r15w"] = b"\x66\x44\x89\xff"
		self.AsmCache["mov r8w,ax"] = b"\x66\x41\x89\xc0"
		self.AsmCache["mov r8w,cx"] = b"\x66\x41\x89\xc8"
		self.AsmCache["mov r8w,dx"] = b"\x66\x41\x89\xd0"
		self.AsmCache["mov r8w,bx"] = b"\x66\x41\x89\xd8"
		self.AsmCache["mov r8w,sp"] = b"\x66\x41\x89\xe0"
		self.AsmCache["mov r8w,bp"] = b"\x66\x41\x89\xe8"
		self.AsmCache["mov r8w,si"] = b"\x66\x41\x89\xf0"
		self.AsmCache["mov r8w,di"] = b"\x66\x41\x89\xf8"
		self.AsmCache["mov r8w,r8w"] = b"\x66\x45\x89\xc0"
		self.AsmCache["mov r8w,r9w"] = b"\x66\x45\x89\xc8"
		self.AsmCache["mov r8w,r10w"] = b"\x66\x45\x89\xd0"
		self.AsmCache["mov r8w,r11w"] = b"\x66\x45\x89\xd8"
		self.AsmCache["mov r8w,r12w"] = b"\x66\x45\x89\xe0"
		self.AsmCache["mov r8w,r13w"] = b"\x66\x45\x89\xe8"
		self.AsmCache["mov r8w,r14w"] = b"\x66\x45\x89\xf0"
		self.AsmCache["mov r8w,r15w"] = b"\x66\x45\x89\xf8"
		self.AsmCache["mov r9w,ax"] = b"\x66\x41\x89\xc1"
		self.AsmCache["mov r9w,cx"] = b"\x66\x41\x89\xc9"
		self.AsmCache["mov r9w,dx"] = b"\x66\x41\x89\xd1"
		self.AsmCache["mov r9w,bx"] = b"\x66\x41\x89\xd9"
		self.AsmCache["mov r9w,sp"] = b"\x66\x41\x89\xe1"
		self.AsmCache["mov r9w,bp"] = b"\x66\x41\x89\xe9"
		self.AsmCache["mov r9w,si"] = b"\x66\x41\x89\xf1"
		self.AsmCache["mov r9w,di"] = b"\x66\x41\x89\xf9"
		self.AsmCache["mov r9w,r8w"] = b"\x66\x45\x89\xc1"
		self.AsmCache["mov r9w,r9w"] = b"\x66\x45\x89\xc9"
		self.AsmCache["mov r9w,r10w"] = b"\x66\x45\x89\xd1"
		self.AsmCache["mov r9w,r11w"] = b"\x66\x45\x89\xd9"
		self.AsmCache["mov r9w,r12w"] = b"\x66\x45\x89\xe1"
		self.AsmCache["mov r9w,r13w"] = b"\x66\x45\x89\xe9"
		self.AsmCache["mov r9w,r14w"] = b"\x66\x45\x89\xf1"
		self.AsmCache["mov r9w,r15w"] = b"\x66\x45\x89\xf9"
		self.AsmCache["mov r10w,ax"] = b"\x66\x41\x89\xc2"
		self.AsmCache["mov r10w,cx"] = b"\x66\x41\x89\xca"
		self.AsmCache["mov r10w,dx"] = b"\x66\x41\x89\xd2"
		self.AsmCache["mov r10w,bx"] = b"\x66\x41\x89\xda"
		self.AsmCache["mov r10w,sp"] = b"\x66\x41\x89\xe2"
		self.AsmCache["mov r10w,bp"] = b"\x66\x41\x89\xea"
		self.AsmCache["mov r10w,si"] = b"\x66\x41\x89\xf2"
		self.AsmCache["mov r10w,di"] = b"\x66\x41\x89\xfa"
		self.AsmCache["mov r10w,r8w"] = b"\x66\x45\x89\xc2"
		self.AsmCache["mov r10w,r9w"] = b"\x66\x45\x89\xca"
		self.AsmCache["mov r10w,r10w"] = b"\x66\x45\x89\xd2"
		self.AsmCache["mov r10w,r11w"] = b"\x66\x45\x89\xda"
		self.AsmCache["mov r10w,r12w"] = b"\x66\x45\x89\xe2"
		self.AsmCache["mov r10w,r13w"] = b"\x66\x45\x89\xea"
		self.AsmCache["mov r10w,r14w"] = b"\x66\x45\x89\xf2"
		self.AsmCache["mov r10w,r15w"] = b"\x66\x45\x89\xfa"
		self.AsmCache["mov r11w,ax"] = b"\x66\x41\x89\xc3"
		self.AsmCache["mov r11w,cx"] = b"\x66\x41\x89\xcb"
		self.AsmCache["mov r11w,dx"] = b"\x66\x41\x89\xd3"
		self.AsmCache["mov r11w,bx"] = b"\x66\x41\x89\xdb"
		self.AsmCache["mov r11w,sp"] = b"\x66\x41\x89\xe3"
		self.AsmCache["mov r11w,bp"] = b"\x66\x41\x89\xeb"
		self.AsmCache["mov r11w,si"] = b"\x66\x41\x89\xf3"
		self.AsmCache["mov r11w,di"] = b"\x66\x41\x89\xfb"
		self.AsmCache["mov r11w,r8w"] = b"\x66\x45\x89\xc3"
		self.AsmCache["mov r11w,r9w"] = b"\x66\x45\x89\xcb"
		self.AsmCache["mov r11w,r10w"] = b"\x66\x45\x89\xd3"
		self.AsmCache["mov r11w,r11w"] = b"\x66\x45\x89\xdb"
		self.AsmCache["mov r11w,r12w"] = b"\x66\x45\x89\xe3"
		self.AsmCache["mov r11w,r13w"] = b"\x66\x45\x89\xeb"
		self.AsmCache["mov r11w,r14w"] = b"\x66\x45\x89\xf3"
		self.AsmCache["mov r11w,r15w"] = b"\x66\x45\x89\xfb"
		self.AsmCache["mov r12w,ax"] = b"\x66\x41\x89\xc4"
		self.AsmCache["mov r12w,cx"] = b"\x66\x41\x89\xcc"
		self.AsmCache["mov r12w,dx"] = b"\x66\x41\x89\xd4"
		self.AsmCache["mov r12w,bx"] = b"\x66\x41\x89\xdc"
		self.AsmCache["mov r12w,sp"] = b"\x66\x41\x89\xe4"
		self.AsmCache["mov r12w,bp"] = b"\x66\x41\x89\xec"
		self.AsmCache["mov r12w,si"] = b"\x66\x41\x89\xf4"
		self.AsmCache["mov r12w,di"] = b"\x66\x41\x89\xfc"
		self.AsmCache["mov r12w,r8w"] = b"\x66\x45\x89\xc4"
		self.AsmCache["mov r12w,r9w"] = b"\x66\x45\x89\xcc"
		self.AsmCache["mov r12w,r10w"] = b"\x66\x45\x89\xd4"
		self.AsmCache["mov r12w,r11w"] = b"\x66\x45\x89\xdc"
		self.AsmCache["mov r12w,r12w"] = b"\x66\x45\x89\xe4"
		self.AsmCache["mov r12w,r13w"] = b"\x66\x45\x89\xec"
		self.AsmCache["mov r12w,r14w"] = b"\x66\x45\x89\xf4"
		self.AsmCache["mov r12w,r15w"] = b"\x66\x45\x89\xfc"
		self.AsmCache["mov r13w,ax"] = b"\x66\x41\x89\xc5"
		self.AsmCache["mov r13w,cx"] = b"\x66\x41\x89\xcd"
		self.AsmCache["mov r13w,dx"] = b"\x66\x41\x89\xd5"
		self.AsmCache["mov r13w,bx"] = b"\x66\x41\x89\xdd"
		self.AsmCache["mov r13w,sp"] = b"\x66\x41\x89\xe5"
		self.AsmCache["mov r13w,bp"] = b"\x66\x41\x89\xed"
		self.AsmCache["mov r13w,si"] = b"\x66\x41\x89\xf5"
		self.AsmCache["mov r13w,di"] = b"\x66\x41\x89\xfd"
		self.AsmCache["mov r13w,r8w"] = b"\x66\x45\x89\xc5"
		self.AsmCache["mov r13w,r9w"] = b"\x66\x45\x89\xcd"
		self.AsmCache["mov r13w,r10w"] = b"\x66\x45\x89\xd5"
		self.AsmCache["mov r13w,r11w"] = b"\x66\x45\x89\xdd"
		self.AsmCache["mov r13w,r12w"] = b"\x66\x45\x89\xe5"
		self.AsmCache["mov r13w,r13w"] = b"\x66\x45\x89\xed"
		self.AsmCache["mov r13w,r14w"] = b"\x66\x45\x89\xf5"
		self.AsmCache["mov r13w,r15w"] = b"\x66\x45\x89\xfd"
		self.AsmCache["mov r14w,ax"] = b"\x66\x41\x89\xc6"
		self.AsmCache["mov r14w,cx"] = b"\x66\x41\x89\xce"
		self.AsmCache["mov r14w,dx"] = b"\x66\x41\x89\xd6"
		self.AsmCache["mov r14w,bx"] = b"\x66\x41\x89\xde"
		self.AsmCache["mov r14w,sp"] = b"\x66\x41\x89\xe6"
		self.AsmCache["mov r14w,bp"] = b"\x66\x41\x89\xee"
		self.AsmCache["mov r14w,si"] = b"\x66\x41\x89\xf6"
		self.AsmCache["mov r14w,di"] = b"\x66\x41\x89\xfe"
		self.AsmCache["mov r14w,r8w"] = b"\x66\x45\x89\xc6"
		self.AsmCache["mov r14w,r9w"] = b"\x66\x45\x89\xce"
		self.AsmCache["mov r14w,r10w"] = b"\x66\x45\x89\xd6"
		self.AsmCache["mov r14w,r11w"] = b"\x66\x45\x89\xde"
		self.AsmCache["mov r14w,r12w"] = b"\x66\x45\x89\xe6"
		self.AsmCache["mov r14w,r13w"] = b"\x66\x45\x89\xee"
		self.AsmCache["mov r14w,r14w"] = b"\x66\x45\x89\xf6"
		self.AsmCache["mov r14w,r15w"] = b"\x66\x45\x89\xfe"
		self.AsmCache["mov r15w,ax"] = b"\x66\x41\x89\xc7"
		self.AsmCache["mov r15w,cx"] = b"\x66\x41\x89\xcf"
		self.AsmCache["mov r15w,dx"] = b"\x66\x41\x89\xd7"
		self.AsmCache["mov r15w,bx"] = b"\x66\x41\x89\xdf"
		self.AsmCache["mov r15w,sp"] = b"\x66\x41\x89\xe7"
		self.AsmCache["mov r15w,bp"] = b"\x66\x41\x89\xef"
		self.AsmCache["mov r15w,si"] = b"\x66\x41\x89\xf7"
		self.AsmCache["mov r15w,di"] = b"\x66\x41\x89\xff"
		self.AsmCache["mov r15w,r8w"] = b"\x66\x45\x89\xc7"
		self.AsmCache["mov r15w,r9w"] = b"\x66\x45\x89\xcf"
		self.AsmCache["mov r15w,r10w"] = b"\x66\x45\x89\xd7"
		self.AsmCache["mov r15w,r11w"] = b"\x66\x45\x89\xdf"
		self.AsmCache["mov r15w,r12w"] = b"\x66\x45\x89\xe7"
		self.AsmCache["mov r15w,r13w"] = b"\x66\x45\x89\xef"
		self.AsmCache["mov r15w,r14w"] = b"\x66\x45\x89\xf7"
		self.AsmCache["mov r15w,r15w"] = b"\x66\x45\x89\xff"


		self.AsmCache["pushad"] = b"\x60"
		self.AsmCache["popad"] = b"\x61"

		# 64-bit register opcodes
		# jmp reg        = FF /4
		# call reg       = FF /2
		# push reg; ret  = 50+reg, C3
		#
		# For r8-r15, a REX.B prefix (0x41) is needed.

		regEnc64 = {}
		regIndex = 0
		for regName in Registers64BitsOrder:
			regEnc64[regName] = regIndex
			regIndex += 1

		# ------------------------------------------------------------
		# JMP reg
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			modrm = 0xE0 | (regIndex & 7)  # /4, mod=11
			self.AsmCache["jmp %s" % regName] = prefix + struct.pack("BB", 0xFF, modrm)

		# ------------------------------------------------------------
		# CALL reg
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			modrm = 0xD0 | (regIndex & 7)  # /2, mod=11
			self.AsmCache["call %s" % regName] = prefix + struct.pack("BB", 0xFF, modrm)

		# ------------------------------------------------------------
		# JMP [reg]
		# FF /4 with modrm selecting memory operand [reg]
		# Note: [rsp] and [r12] require SIB byte 0x24
		# Note: [rbp] and [r13] with mod=00 do not encode plain [rbp]/[r13],
		#       so use mod=01 with disp8=00 instead.
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			rm = regIndex & 7
			if rm == 4:
				# [rsp] and [r12] require a SIB byte 0x24
				self.AsmCache["jmp [%s]" % regName] = prefix + struct.pack("BBB", 0xFF, 0x24, 0x24)
			elif rm == 5:
				# [rbp] and [r13] require disp8=00 with mod=01
				self.AsmCache["jmp [%s]" % regName] = prefix + struct.pack("BBB", 0xFF, 0x65, 0x00)
			else:
				modrm = 0x20 | rm
				self.AsmCache["jmp [%s]" % regName] = prefix + struct.pack("BB", 0xFF, modrm)

		# ------------------------------------------------------------
		# CALL [reg]
		# FF /2 with modrm selecting memory operand [reg]
		# Same encoding caveats as above for rsp/r12 and rbp/r13
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			rm = regIndex & 7
			if rm == 4:
				self.AsmCache["call [%s]" % regName] = prefix + struct.pack("BBB", 0xFF, 0x14, 0x24)
			elif rm == 5:
				self.AsmCache["call [%s]" % regName] = prefix + struct.pack("BBB", 0xFF, 0x55, 0x00)
			else:
				modrm = 0x10 | rm
				self.AsmCache["call [%s]" % regName] = prefix + struct.pack("BB", 0xFF, modrm)


		# ------------------------------------------------------------
		# PUSH reg (x64)
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			self.AsmCache["push %s" % regName] = prefix + struct.pack("B", 0x50 + (regIndex & 7))

		# ------------------------------------------------------------
		# POP reg (x64)
		# ------------------------------------------------------------
		for regName in Registers64BitsOrder:
			regIndex = regEnc64[regName]
			prefix = b"" if regIndex < 8 else b"\x41"
			self.AsmCache["pop %s" % regName] = prefix + struct.pack("B", 0x58 + (regIndex & 7))

		self.AsmCache["inc rax"] = b"\x48\xff\xc0"
		self.AsmCache["inc rcx"] = b"\x48\xff\xc1"
		self.AsmCache["inc rdx"] = b"\x48\xff\xc2"
		self.AsmCache["inc rbx"] = b"\x48\xff\xc3"
		self.AsmCache["inc rsp"] = b"\x48\xff\xc4"
		self.AsmCache["inc rbp"] = b"\x48\xff\xc5"
		self.AsmCache["inc rsi"] = b"\x48\xff\xc6"
		self.AsmCache["inc rdi"] = b"\x48\xff\xc7"
		self.AsmCache["inc r8"]  = b"\x49\xff\xc0"
		self.AsmCache["inc r9"]  = b"\x49\xff\xc1"
		self.AsmCache["inc r10"] = b"\x49\xff\xc2"
		self.AsmCache["inc r11"] = b"\x49\xff\xc3"
		self.AsmCache["inc r12"] = b"\x49\xff\xc4"
		self.AsmCache["inc r13"] = b"\x49\xff\xc5"
		self.AsmCache["inc r14"] = b"\x49\xff\xc6"
		self.AsmCache["inc r15"] = b"\x49\xff\xc7"

		self.AsmCache["dec rax"] = b"\x48\xff\xc8"
		self.AsmCache["dec rcx"] = b"\x48\xff\xc9"
		self.AsmCache["dec rdx"] = b"\x48\xff\xca"
		self.AsmCache["dec rbx"] = b"\x48\xff\xcb"
		self.AsmCache["dec rsp"] = b"\x48\xff\xcc"
		self.AsmCache["dec rbp"] = b"\x48\xff\xcd"
		self.AsmCache["dec rsi"] = b"\x48\xff\xce"
		self.AsmCache["dec rdi"] = b"\x48\xff\xcf"
		self.AsmCache["dec r8"]  = b"\x49\xff\xc8"
		self.AsmCache["dec r9"]  = b"\x49\xff\xc9"
		self.AsmCache["dec r10"] = b"\x49\xff\xca"
		self.AsmCache["dec r11"] = b"\x49\xff\xcb"
		self.AsmCache["dec r12"] = b"\x49\xff\xcc"
		self.AsmCache["dec r13"] = b"\x49\xff\xcd"
		self.AsmCache["dec r14"] = b"\x49\xff\xce"
		self.AsmCache["dec r15"] = b"\x49\xff\xcf"

		# ------------------------------------------------------------
		# MOV & XCHG reg,reg (x64)
		# ------------------------------------------------------------
		self.AsmCache["mov rax,rax"] = b"\x48\x89\xc0"
		self.AsmCache["mov rax,rcx"] = b"\x48\x89\xc8"
		self.AsmCache["mov rax,rdx"] = b"\x48\x89\xd0"
		self.AsmCache["mov rax,rbx"] = b"\x48\x89\xd8"
		self.AsmCache["mov rax,rsp"] = b"\x48\x89\xe0"
		self.AsmCache["mov rax,rbp"] = b"\x48\x89\xe8"
		self.AsmCache["mov rax,rsi"] = b"\x48\x89\xf0"
		self.AsmCache["mov rax,rdi"] = b"\x48\x89\xf8"
		self.AsmCache["mov rax,r8"] = b"\x4c\x89\xc0"
		self.AsmCache["mov rax,r9"] = b"\x4c\x89\xc8"
		self.AsmCache["mov rax,r10"] = b"\x4c\x89\xd0"
		self.AsmCache["mov rax,r11"] = b"\x4c\x89\xd8"
		self.AsmCache["mov rax,r12"] = b"\x4c\x89\xe0"
		self.AsmCache["mov rax,r13"] = b"\x4c\x89\xe8"
		self.AsmCache["mov rax,r14"] = b"\x4c\x89\xf0"
		self.AsmCache["mov rax,r15"] = b"\x4c\x89\xf8"
		self.AsmCache["mov rcx,rax"] = b"\x48\x89\xc1"
		self.AsmCache["mov rcx,rcx"] = b"\x48\x89\xc9"
		self.AsmCache["mov rcx,rdx"] = b"\x48\x89\xd1"
		self.AsmCache["mov rcx,rbx"] = b"\x48\x89\xd9"
		self.AsmCache["mov rcx,rsp"] = b"\x48\x89\xe1"
		self.AsmCache["mov rcx,rbp"] = b"\x48\x89\xe9"
		self.AsmCache["mov rcx,rsi"] = b"\x48\x89\xf1"
		self.AsmCache["mov rcx,rdi"] = b"\x48\x89\xf9"
		self.AsmCache["mov rcx,r8"] = b"\x4c\x89\xc1"
		self.AsmCache["mov rcx,r9"] = b"\x4c\x89\xc9"
		self.AsmCache["mov rcx,r10"] = b"\x4c\x89\xd1"
		self.AsmCache["mov rcx,r11"] = b"\x4c\x89\xd9"
		self.AsmCache["mov rcx,r12"] = b"\x4c\x89\xe1"
		self.AsmCache["mov rcx,r13"] = b"\x4c\x89\xe9"
		self.AsmCache["mov rcx,r14"] = b"\x4c\x89\xf1"
		self.AsmCache["mov rcx,r15"] = b"\x4c\x89\xf9"
		self.AsmCache["mov rdx,rax"] = b"\x48\x89\xc2"
		self.AsmCache["mov rdx,rcx"] = b"\x48\x89\xca"
		self.AsmCache["mov rdx,rdx"] = b"\x48\x89\xd2"
		self.AsmCache["mov rdx,rbx"] = b"\x48\x89\xda"
		self.AsmCache["mov rdx,rsp"] = b"\x48\x89\xe2"
		self.AsmCache["mov rdx,rbp"] = b"\x48\x89\xea"
		self.AsmCache["mov rdx,rsi"] = b"\x48\x89\xf2"
		self.AsmCache["mov rdx,rdi"] = b"\x48\x89\xfa"
		self.AsmCache["mov rdx,r8"] = b"\x4c\x89\xc2"
		self.AsmCache["mov rdx,r9"] = b"\x4c\x89\xca"
		self.AsmCache["mov rdx,r10"] = b"\x4c\x89\xd2"
		self.AsmCache["mov rdx,r11"] = b"\x4c\x89\xda"
		self.AsmCache["mov rdx,r12"] = b"\x4c\x89\xe2"
		self.AsmCache["mov rdx,r13"] = b"\x4c\x89\xea"
		self.AsmCache["mov rdx,r14"] = b"\x4c\x89\xf2"
		self.AsmCache["mov rdx,r15"] = b"\x4c\x89\xfa"
		self.AsmCache["mov rbx,rax"] = b"\x48\x89\xc3"
		self.AsmCache["mov rbx,rcx"] = b"\x48\x89\xcb"
		self.AsmCache["mov rbx,rdx"] = b"\x48\x89\xd3"
		self.AsmCache["mov rbx,rbx"] = b"\x48\x89\xdb"
		self.AsmCache["mov rbx,rsp"] = b"\x48\x89\xe3"
		self.AsmCache["mov rbx,rbp"] = b"\x48\x89\xeb"
		self.AsmCache["mov rbx,rsi"] = b"\x48\x89\xf3"
		self.AsmCache["mov rbx,rdi"] = b"\x48\x89\xfb"
		self.AsmCache["mov rbx,r8"] = b"\x4c\x89\xc3"
		self.AsmCache["mov rbx,r9"] = b"\x4c\x89\xcb"
		self.AsmCache["mov rbx,r10"] = b"\x4c\x89\xd3"
		self.AsmCache["mov rbx,r11"] = b"\x4c\x89\xdb"
		self.AsmCache["mov rbx,r12"] = b"\x4c\x89\xe3"
		self.AsmCache["mov rbx,r13"] = b"\x4c\x89\xeb"
		self.AsmCache["mov rbx,r14"] = b"\x4c\x89\xf3"
		self.AsmCache["mov rbx,r15"] = b"\x4c\x89\xfb"
		self.AsmCache["mov rsp,rax"] = b"\x48\x89\xc4"
		self.AsmCache["mov rsp,rcx"] = b"\x48\x89\xcc"
		self.AsmCache["mov rsp,rdx"] = b"\x48\x89\xd4"
		self.AsmCache["mov rsp,rbx"] = b"\x48\x89\xdc"
		self.AsmCache["mov rsp,rsp"] = b"\x48\x89\xe4"
		self.AsmCache["mov rsp,rbp"] = b"\x48\x89\xec"
		self.AsmCache["mov rsp,rsi"] = b"\x48\x89\xf4"
		self.AsmCache["mov rsp,rdi"] = b"\x48\x89\xfc"
		self.AsmCache["mov rsp,r8"] = b"\x4c\x89\xc4"
		self.AsmCache["mov rsp,r9"] = b"\x4c\x89\xcc"
		self.AsmCache["mov rsp,r10"] = b"\x4c\x89\xd4"
		self.AsmCache["mov rsp,r11"] = b"\x4c\x89\xdc"
		self.AsmCache["mov rsp,r12"] = b"\x4c\x89\xe4"
		self.AsmCache["mov rsp,r13"] = b"\x4c\x89\xec"
		self.AsmCache["mov rsp,r14"] = b"\x4c\x89\xf4"
		self.AsmCache["mov rsp,r15"] = b"\x4c\x89\xfc"
		self.AsmCache["mov rbp,rax"] = b"\x48\x89\xc5"
		self.AsmCache["mov rbp,rcx"] = b"\x48\x89\xcd"
		self.AsmCache["mov rbp,rdx"] = b"\x48\x89\xd5"
		self.AsmCache["mov rbp,rbx"] = b"\x48\x89\xdd"
		self.AsmCache["mov rbp,rsp"] = b"\x48\x89\xe5"
		self.AsmCache["mov rbp,rbp"] = b"\x48\x89\xed"
		self.AsmCache["mov rbp,rsi"] = b"\x48\x89\xf5"
		self.AsmCache["mov rbp,rdi"] = b"\x48\x89\xfd"
		self.AsmCache["mov rbp,r8"] = b"\x4c\x89\xc5"
		self.AsmCache["mov rbp,r9"] = b"\x4c\x89\xcd"
		self.AsmCache["mov rbp,r10"] = b"\x4c\x89\xd5"
		self.AsmCache["mov rbp,r11"] = b"\x4c\x89\xdd"
		self.AsmCache["mov rbp,r12"] = b"\x4c\x89\xe5"
		self.AsmCache["mov rbp,r13"] = b"\x4c\x89\xed"
		self.AsmCache["mov rbp,r14"] = b"\x4c\x89\xf5"
		self.AsmCache["mov rbp,r15"] = b"\x4c\x89\xfd"
		self.AsmCache["mov rsi,rax"] = b"\x48\x89\xc6"
		self.AsmCache["mov rsi,rcx"] = b"\x48\x89\xce"
		self.AsmCache["mov rsi,rdx"] = b"\x48\x89\xd6"
		self.AsmCache["mov rsi,rbx"] = b"\x48\x89\xde"
		self.AsmCache["mov rsi,rsp"] = b"\x48\x89\xe6"
		self.AsmCache["mov rsi,rbp"] = b"\x48\x89\xee"
		self.AsmCache["mov rsi,rsi"] = b"\x48\x89\xf6"
		self.AsmCache["mov rsi,rdi"] = b"\x48\x89\xfe"
		self.AsmCache["mov rsi,r8"] = b"\x4c\x89\xc6"
		self.AsmCache["mov rsi,r9"] = b"\x4c\x89\xce"
		self.AsmCache["mov rsi,r10"] = b"\x4c\x89\xd6"
		self.AsmCache["mov rsi,r11"] = b"\x4c\x89\xde"
		self.AsmCache["mov rsi,r12"] = b"\x4c\x89\xe6"
		self.AsmCache["mov rsi,r13"] = b"\x4c\x89\xee"
		self.AsmCache["mov rsi,r14"] = b"\x4c\x89\xf6"
		self.AsmCache["mov rsi,r15"] = b"\x4c\x89\xfe"
		self.AsmCache["mov rdi,rax"] = b"\x48\x89\xc7"
		self.AsmCache["mov rdi,rcx"] = b"\x48\x89\xcf"
		self.AsmCache["mov rdi,rdx"] = b"\x48\x89\xd7"
		self.AsmCache["mov rdi,rbx"] = b"\x48\x89\xdf"
		self.AsmCache["mov rdi,rsp"] = b"\x48\x89\xe7"
		self.AsmCache["mov rdi,rbp"] = b"\x48\x89\xef"
		self.AsmCache["mov rdi,rsi"] = b"\x48\x89\xf7"
		self.AsmCache["mov rdi,rdi"] = b"\x48\x89\xff"
		self.AsmCache["mov rdi,r8"] = b"\x4c\x89\xc7"
		self.AsmCache["mov rdi,r9"] = b"\x4c\x89\xcf"
		self.AsmCache["mov rdi,r10"] = b"\x4c\x89\xd7"
		self.AsmCache["mov rdi,r11"] = b"\x4c\x89\xdf"
		self.AsmCache["mov rdi,r12"] = b"\x4c\x89\xe7"
		self.AsmCache["mov rdi,r13"] = b"\x4c\x89\xef"
		self.AsmCache["mov rdi,r14"] = b"\x4c\x89\xf7"
		self.AsmCache["mov rdi,r15"] = b"\x4c\x89\xff"
		self.AsmCache["mov r8,rax"] = b"\x49\x89\xc0"
		self.AsmCache["mov r8,rcx"] = b"\x49\x89\xc8"
		self.AsmCache["mov r8,rdx"] = b"\x49\x89\xd0"
		self.AsmCache["mov r8,rbx"] = b"\x49\x89\xd8"
		self.AsmCache["mov r8,rsp"] = b"\x49\x89\xe0"
		self.AsmCache["mov r8,rbp"] = b"\x49\x89\xe8"
		self.AsmCache["mov r8,rsi"] = b"\x49\x89\xf0"
		self.AsmCache["mov r8,rdi"] = b"\x49\x89\xf8"
		self.AsmCache["mov r8,r8"] = b"\x4d\x89\xc0"
		self.AsmCache["mov r8,r9"] = b"\x4d\x89\xc8"
		self.AsmCache["mov r8,r10"] = b"\x4d\x89\xd0"
		self.AsmCache["mov r8,r11"] = b"\x4d\x89\xd8"
		self.AsmCache["mov r8,r12"] = b"\x4d\x89\xe0"
		self.AsmCache["mov r8,r13"] = b"\x4d\x89\xe8"
		self.AsmCache["mov r8,r14"] = b"\x4d\x89\xf0"
		self.AsmCache["mov r8,r15"] = b"\x4d\x89\xf8"
		self.AsmCache["mov r9,rax"] = b"\x49\x89\xc1"
		self.AsmCache["mov r9,rcx"] = b"\x49\x89\xc9"
		self.AsmCache["mov r9,rdx"] = b"\x49\x89\xd1"
		self.AsmCache["mov r9,rbx"] = b"\x49\x89\xd9"
		self.AsmCache["mov r9,rsp"] = b"\x49\x89\xe1"
		self.AsmCache["mov r9,rbp"] = b"\x49\x89\xe9"
		self.AsmCache["mov r9,rsi"] = b"\x49\x89\xf1"
		self.AsmCache["mov r9,rdi"] = b"\x49\x89\xf9"
		self.AsmCache["mov r9,r8"] = b"\x4d\x89\xc1"
		self.AsmCache["mov r9,r9"] = b"\x4d\x89\xc9"
		self.AsmCache["mov r9,r10"] = b"\x4d\x89\xd1"
		self.AsmCache["mov r9,r11"] = b"\x4d\x89\xd9"
		self.AsmCache["mov r9,r12"] = b"\x4d\x89\xe1"
		self.AsmCache["mov r9,r13"] = b"\x4d\x89\xe9"
		self.AsmCache["mov r9,r14"] = b"\x4d\x89\xf1"
		self.AsmCache["mov r9,r15"] = b"\x4d\x89\xf9"
		self.AsmCache["mov r10,rax"] = b"\x49\x89\xc2"
		self.AsmCache["mov r10,rcx"] = b"\x49\x89\xca"
		self.AsmCache["mov r10,rdx"] = b"\x49\x89\xd2"
		self.AsmCache["mov r10,rbx"] = b"\x49\x89\xda"
		self.AsmCache["mov r10,rsp"] = b"\x49\x89\xe2"
		self.AsmCache["mov r10,rbp"] = b"\x49\x89\xea"
		self.AsmCache["mov r10,rsi"] = b"\x49\x89\xf2"
		self.AsmCache["mov r10,rdi"] = b"\x49\x89\xfa"
		self.AsmCache["mov r10,r8"] = b"\x4d\x89\xc2"
		self.AsmCache["mov r10,r9"] = b"\x4d\x89\xca"
		self.AsmCache["mov r10,r10"] = b"\x4d\x89\xd2"
		self.AsmCache["mov r10,r11"] = b"\x4d\x89\xda"
		self.AsmCache["mov r10,r12"] = b"\x4d\x89\xe2"
		self.AsmCache["mov r10,r13"] = b"\x4d\x89\xea"
		self.AsmCache["mov r10,r14"] = b"\x4d\x89\xf2"
		self.AsmCache["mov r10,r15"] = b"\x4d\x89\xfa"
		self.AsmCache["mov r11,rax"] = b"\x49\x89\xc3"
		self.AsmCache["mov r11,rcx"] = b"\x49\x89\xcb"
		self.AsmCache["mov r11,rdx"] = b"\x49\x89\xd3"
		self.AsmCache["mov r11,rbx"] = b"\x49\x89\xdb"
		self.AsmCache["mov r11,rsp"] = b"\x49\x89\xe3"
		self.AsmCache["mov r11,rbp"] = b"\x49\x89\xeb"
		self.AsmCache["mov r11,rsi"] = b"\x49\x89\xf3"
		self.AsmCache["mov r11,rdi"] = b"\x49\x89\xfb"
		self.AsmCache["mov r11,r8"] = b"\x4d\x89\xc3"
		self.AsmCache["mov r11,r9"] = b"\x4d\x89\xcb"
		self.AsmCache["mov r11,r10"] = b"\x4d\x89\xd3"
		self.AsmCache["mov r11,r11"] = b"\x4d\x89\xdb"
		self.AsmCache["mov r11,r12"] = b"\x4d\x89\xe3"
		self.AsmCache["mov r11,r13"] = b"\x4d\x89\xeb"
		self.AsmCache["mov r11,r14"] = b"\x4d\x89\xf3"
		self.AsmCache["mov r11,r15"] = b"\x4d\x89\xfb"
		self.AsmCache["mov r12,rax"] = b"\x49\x89\xc4"
		self.AsmCache["mov r12,rcx"] = b"\x49\x89\xcc"
		self.AsmCache["mov r12,rdx"] = b"\x49\x89\xd4"
		self.AsmCache["mov r12,rbx"] = b"\x49\x89\xdc"
		self.AsmCache["mov r12,rsp"] = b"\x49\x89\xe4"
		self.AsmCache["mov r12,rbp"] = b"\x49\x89\xec"
		self.AsmCache["mov r12,rsi"] = b"\x49\x89\xf4"
		self.AsmCache["mov r12,rdi"] = b"\x49\x89\xfc"
		self.AsmCache["mov r12,r8"] = b"\x4d\x89\xc4"
		self.AsmCache["mov r12,r9"] = b"\x4d\x89\xcc"
		self.AsmCache["mov r12,r10"] = b"\x4d\x89\xd4"
		self.AsmCache["mov r12,r11"] = b"\x4d\x89\xdc"
		self.AsmCache["mov r12,r12"] = b"\x4d\x89\xe4"
		self.AsmCache["mov r12,r13"] = b"\x4d\x89\xec"
		self.AsmCache["mov r12,r14"] = b"\x4d\x89\xf4"
		self.AsmCache["mov r12,r15"] = b"\x4d\x89\xfc"
		self.AsmCache["mov r13,rax"] = b"\x49\x89\xc5"
		self.AsmCache["mov r13,rcx"] = b"\x49\x89\xcd"
		self.AsmCache["mov r13,rdx"] = b"\x49\x89\xd5"
		self.AsmCache["mov r13,rbx"] = b"\x49\x89\xdd"
		self.AsmCache["mov r13,rsp"] = b"\x49\x89\xe5"
		self.AsmCache["mov r13,rbp"] = b"\x49\x89\xed"
		self.AsmCache["mov r13,rsi"] = b"\x49\x89\xf5"
		self.AsmCache["mov r13,rdi"] = b"\x49\x89\xfd"
		self.AsmCache["mov r13,r8"] = b"\x4d\x89\xc5"
		self.AsmCache["mov r13,r9"] = b"\x4d\x89\xcd"
		self.AsmCache["mov r13,r10"] = b"\x4d\x89\xd5"
		self.AsmCache["mov r13,r11"] = b"\x4d\x89\xdd"
		self.AsmCache["mov r13,r12"] = b"\x4d\x89\xe5"
		self.AsmCache["mov r13,r13"] = b"\x4d\x89\xed"
		self.AsmCache["mov r13,r14"] = b"\x4d\x89\xf5"
		self.AsmCache["mov r13,r15"] = b"\x4d\x89\xfd"
		self.AsmCache["mov r14,rax"] = b"\x49\x89\xc6"
		self.AsmCache["mov r14,rcx"] = b"\x49\x89\xce"
		self.AsmCache["mov r14,rdx"] = b"\x49\x89\xd6"
		self.AsmCache["mov r14,rbx"] = b"\x49\x89\xde"
		self.AsmCache["mov r14,rsp"] = b"\x49\x89\xe6"
		self.AsmCache["mov r14,rbp"] = b"\x49\x89\xee"
		self.AsmCache["mov r14,rsi"] = b"\x49\x89\xf6"
		self.AsmCache["mov r14,rdi"] = b"\x49\x89\xfe"
		self.AsmCache["mov r14,r8"] = b"\x4d\x89\xc6"
		self.AsmCache["mov r14,r9"] = b"\x4d\x89\xce"
		self.AsmCache["mov r14,r10"] = b"\x4d\x89\xd6"
		self.AsmCache["mov r14,r11"] = b"\x4d\x89\xde"
		self.AsmCache["mov r14,r12"] = b"\x4d\x89\xe6"
		self.AsmCache["mov r14,r13"] = b"\x4d\x89\xee"
		self.AsmCache["mov r14,r14"] = b"\x4d\x89\xf6"
		self.AsmCache["mov r14,r15"] = b"\x4d\x89\xfe"
		self.AsmCache["mov r15,rax"] = b"\x49\x89\xc7"
		self.AsmCache["mov r15,rcx"] = b"\x49\x89\xcf"
		self.AsmCache["mov r15,rdx"] = b"\x49\x89\xd7"
		self.AsmCache["mov r15,rbx"] = b"\x49\x89\xdf"
		self.AsmCache["mov r15,rsp"] = b"\x49\x89\xe7"
		self.AsmCache["mov r15,rbp"] = b"\x49\x89\xef"
		self.AsmCache["mov r15,rsi"] = b"\x49\x89\xf7"
		self.AsmCache["mov r15,rdi"] = b"\x49\x89\xff"



		# ------------------------------------------------------------
		# Core single-byte instructions
		# ------------------------------------------------------------
		self.AsmCache["nop"] = b"\x90"
		self.AsmCache["ret"] = b"\xc3"
		self.AsmCache["retn"] = b"\xc3"
		self.AsmCache["leave"] = b"\xc9"

		# ------------------------------------------------------------
		# TEST reg,reg (32-bit)
		# 85 /r
		# ------------------------------------------------------------
		self.AsmCache["test eax,eax"] = b"\x85\xc0"
		self.AsmCache["test eax,ecx"] = b"\x85\xc8"
		self.AsmCache["test eax,edx"] = b"\x85\xd0"
		self.AsmCache["test eax,ebx"] = b"\x85\xd8"
		self.AsmCache["test eax,esp"] = b"\x85\xe0"
		self.AsmCache["test eax,ebp"] = b"\x85\xe8"
		self.AsmCache["test eax,esi"] = b"\x85\xf0"
		self.AsmCache["test eax,edi"] = b"\x85\xf8"
		self.AsmCache["test ecx,eax"] = b"\x85\xc1"
		self.AsmCache["test ecx,ecx"] = b"\x85\xc9"
		self.AsmCache["test ecx,edx"] = b"\x85\xd1"
		self.AsmCache["test ecx,ebx"] = b"\x85\xd9"
		self.AsmCache["test ecx,esp"] = b"\x85\xe1"
		self.AsmCache["test ecx,ebp"] = b"\x85\xe9"
		self.AsmCache["test ecx,esi"] = b"\x85\xf1"
		self.AsmCache["test ecx,edi"] = b"\x85\xf9"
		self.AsmCache["test edx,eax"] = b"\x85\xc2"
		self.AsmCache["test edx,ecx"] = b"\x85\xca"
		self.AsmCache["test edx,edx"] = b"\x85\xd2"
		self.AsmCache["test edx,ebx"] = b"\x85\xda"
		self.AsmCache["test edx,esp"] = b"\x85\xe2"
		self.AsmCache["test edx,ebp"] = b"\x85\xea"
		self.AsmCache["test edx,esi"] = b"\x85\xf2"
		self.AsmCache["test edx,edi"] = b"\x85\xfa"
		self.AsmCache["test ebx,eax"] = b"\x85\xc3"
		self.AsmCache["test ebx,ecx"] = b"\x85\xcb"
		self.AsmCache["test ebx,edx"] = b"\x85\xd3"
		self.AsmCache["test ebx,ebx"] = b"\x85\xdb"
		self.AsmCache["test ebx,esp"] = b"\x85\xe3"
		self.AsmCache["test ebx,ebp"] = b"\x85\xeb"
		self.AsmCache["test ebx,esi"] = b"\x85\xf3"
		self.AsmCache["test ebx,edi"] = b"\x85\xfb"
		self.AsmCache["test esp,eax"] = b"\x85\xc4"
		self.AsmCache["test esp,ecx"] = b"\x85\xcc"
		self.AsmCache["test esp,edx"] = b"\x85\xd4"
		self.AsmCache["test esp,ebx"] = b"\x85\xdc"
		self.AsmCache["test esp,esp"] = b"\x85\xe4"
		self.AsmCache["test esp,ebp"] = b"\x85\xec"
		self.AsmCache["test esp,esi"] = b"\x85\xf4"
		self.AsmCache["test esp,edi"] = b"\x85\xfc"
		self.AsmCache["test ebp,eax"] = b"\x85\xc5"
		self.AsmCache["test ebp,ecx"] = b"\x85\xcd"
		self.AsmCache["test ebp,edx"] = b"\x85\xd5"
		self.AsmCache["test ebp,ebx"] = b"\x85\xdd"
		self.AsmCache["test ebp,esp"] = b"\x85\xe5"
		self.AsmCache["test ebp,ebp"] = b"\x85\xed"
		self.AsmCache["test ebp,esi"] = b"\x85\xf5"
		self.AsmCache["test ebp,edi"] = b"\x85\xfd"
		self.AsmCache["test esi,eax"] = b"\x85\xc6"
		self.AsmCache["test esi,ecx"] = b"\x85\xce"
		self.AsmCache["test esi,edx"] = b"\x85\xd6"
		self.AsmCache["test esi,ebx"] = b"\x85\xde"
		self.AsmCache["test esi,esp"] = b"\x85\xe6"
		self.AsmCache["test esi,ebp"] = b"\x85\xee"
		self.AsmCache["test esi,esi"] = b"\x85\xf6"
		self.AsmCache["test esi,edi"] = b"\x85\xfe"
		self.AsmCache["test edi,eax"] = b"\x85\xc7"
		self.AsmCache["test edi,ecx"] = b"\x85\xcf"
		self.AsmCache["test edi,edx"] = b"\x85\xd7"
		self.AsmCache["test edi,ebx"] = b"\x85\xdf"
		self.AsmCache["test edi,esp"] = b"\x85\xe7"
		self.AsmCache["test edi,ebp"] = b"\x85\xef"
		self.AsmCache["test edi,esi"] = b"\x85\xf7"
		self.AsmCache["test edi,edi"] = b"\x85\xff"

		# ------------------------------------------------------------
		# TEST reg,reg (64-bit)
		# 48 85 /r
		# ------------------------------------------------------------
		self.AsmCache["test rax,rax"] = b"\x48\x85\xc0"
		self.AsmCache["test rax,rcx"] = b"\x48\x85\xc8"
		self.AsmCache["test rax,rdx"] = b"\x48\x85\xd0"
		self.AsmCache["test rax,rbx"] = b"\x48\x85\xd8"
		self.AsmCache["test rax,rsp"] = b"\x48\x85\xe0"
		self.AsmCache["test rax,rbp"] = b"\x48\x85\xe8"
		self.AsmCache["test rax,rsi"] = b"\x48\x85\xf0"
		self.AsmCache["test rax,rdi"] = b"\x48\x85\xf8"
		self.AsmCache["test rax,r8"] = b"\x4c\x85\xc0"
		self.AsmCache["test rax,r9"] = b"\x4c\x85\xc8"
		self.AsmCache["test rax,r10"] = b"\x4c\x85\xd0"
		self.AsmCache["test rax,r11"] = b"\x4c\x85\xd8"
		self.AsmCache["test rax,r12"] = b"\x4c\x85\xe0"
		self.AsmCache["test rax,r13"] = b"\x4c\x85\xe8"
		self.AsmCache["test rax,r14"] = b"\x4c\x85\xf0"
		self.AsmCache["test rax,r15"] = b"\x4c\x85\xf8"
		self.AsmCache["test rcx,rax"] = b"\x48\x85\xc1"
		self.AsmCache["test rcx,rcx"] = b"\x48\x85\xc9"
		self.AsmCache["test rcx,rdx"] = b"\x48\x85\xd1"
		self.AsmCache["test rcx,rbx"] = b"\x48\x85\xd9"
		self.AsmCache["test rcx,rsp"] = b"\x48\x85\xe1"
		self.AsmCache["test rcx,rbp"] = b"\x48\x85\xe9"
		self.AsmCache["test rcx,rsi"] = b"\x48\x85\xf1"
		self.AsmCache["test rcx,rdi"] = b"\x48\x85\xf9"
		self.AsmCache["test rcx,r8"] = b"\x4c\x85\xc1"
		self.AsmCache["test rcx,r9"] = b"\x4c\x85\xc9"
		self.AsmCache["test rcx,r10"] = b"\x4c\x85\xd1"
		self.AsmCache["test rcx,r11"] = b"\x4c\x85\xd9"
		self.AsmCache["test rcx,r12"] = b"\x4c\x85\xe1"
		self.AsmCache["test rcx,r13"] = b"\x4c\x85\xe9"
		self.AsmCache["test rcx,r14"] = b"\x4c\x85\xf1"
		self.AsmCache["test rcx,r15"] = b"\x4c\x85\xf9"
		self.AsmCache["test rdx,rax"] = b"\x48\x85\xc2"
		self.AsmCache["test rdx,rcx"] = b"\x48\x85\xca"
		self.AsmCache["test rdx,rdx"] = b"\x48\x85\xd2"
		self.AsmCache["test rdx,rbx"] = b"\x48\x85\xda"
		self.AsmCache["test rdx,rsp"] = b"\x48\x85\xe2"
		self.AsmCache["test rdx,rbp"] = b"\x48\x85\xea"
		self.AsmCache["test rdx,rsi"] = b"\x48\x85\xf2"
		self.AsmCache["test rdx,rdi"] = b"\x48\x85\xfa"
		self.AsmCache["test rdx,r8"] = b"\x4c\x85\xc2"
		self.AsmCache["test rdx,r9"] = b"\x4c\x85\xca"
		self.AsmCache["test rdx,r10"] = b"\x4c\x85\xd2"
		self.AsmCache["test rdx,r11"] = b"\x4c\x85\xda"
		self.AsmCache["test rdx,r12"] = b"\x4c\x85\xe2"
		self.AsmCache["test rdx,r13"] = b"\x4c\x85\xea"
		self.AsmCache["test rdx,r14"] = b"\x4c\x85\xf2"
		self.AsmCache["test rdx,r15"] = b"\x4c\x85\xfa"
		self.AsmCache["test rbx,rax"] = b"\x48\x85\xc3"
		self.AsmCache["test rbx,rcx"] = b"\x48\x85\xcb"
		self.AsmCache["test rbx,rdx"] = b"\x48\x85\xd3"
		self.AsmCache["test rbx,rbx"] = b"\x48\x85\xdb"
		self.AsmCache["test rbx,rsp"] = b"\x48\x85\xe3"
		self.AsmCache["test rbx,rbp"] = b"\x48\x85\xeb"
		self.AsmCache["test rbx,rsi"] = b"\x48\x85\xf3"
		self.AsmCache["test rbx,rdi"] = b"\x48\x85\xfb"
		self.AsmCache["test rbx,r8"] = b"\x4c\x85\xc3"
		self.AsmCache["test rbx,r9"] = b"\x4c\x85\xcb"
		self.AsmCache["test rbx,r10"] = b"\x4c\x85\xd3"
		self.AsmCache["test rbx,r11"] = b"\x4c\x85\xdb"
		self.AsmCache["test rbx,r12"] = b"\x4c\x85\xe3"
		self.AsmCache["test rbx,r13"] = b"\x4c\x85\xeb"
		self.AsmCache["test rbx,r14"] = b"\x4c\x85\xf3"
		self.AsmCache["test rbx,r15"] = b"\x4c\x85\xfb"
		self.AsmCache["test rsp,rax"] = b"\x48\x85\xc4"
		self.AsmCache["test rsp,rcx"] = b"\x48\x85\xcc"
		self.AsmCache["test rsp,rdx"] = b"\x48\x85\xd4"
		self.AsmCache["test rsp,rbx"] = b"\x48\x85\xdc"
		self.AsmCache["test rsp,rsp"] = b"\x48\x85\xe4"
		self.AsmCache["test rsp,rbp"] = b"\x48\x85\xec"
		self.AsmCache["test rsp,rsi"] = b"\x48\x85\xf4"
		self.AsmCache["test rsp,rdi"] = b"\x48\x85\xfc"
		self.AsmCache["test rsp,r8"] = b"\x4c\x85\xc4"
		self.AsmCache["test rsp,r9"] = b"\x4c\x85\xcc"
		self.AsmCache["test rsp,r10"] = b"\x4c\x85\xd4"
		self.AsmCache["test rsp,r11"] = b"\x4c\x85\xdc"
		self.AsmCache["test rsp,r12"] = b"\x4c\x85\xe4"
		self.AsmCache["test rsp,r13"] = b"\x4c\x85\xec"
		self.AsmCache["test rsp,r14"] = b"\x4c\x85\xf4"
		self.AsmCache["test rsp,r15"] = b"\x4c\x85\xfc"
		self.AsmCache["test rbp,rax"] = b"\x48\x85\xc5"
		self.AsmCache["test rbp,rcx"] = b"\x48\x85\xcd"
		self.AsmCache["test rbp,rdx"] = b"\x48\x85\xd5"
		self.AsmCache["test rbp,rbx"] = b"\x48\x85\xdd"
		self.AsmCache["test rbp,rsp"] = b"\x48\x85\xe5"
		self.AsmCache["test rbp,rbp"] = b"\x48\x85\xed"
		self.AsmCache["test rbp,rsi"] = b"\x48\x85\xf5"
		self.AsmCache["test rbp,rdi"] = b"\x48\x85\xfd"
		self.AsmCache["test rbp,r8"] = b"\x4c\x85\xc5"
		self.AsmCache["test rbp,r9"] = b"\x4c\x85\xcd"
		self.AsmCache["test rbp,r10"] = b"\x4c\x85\xd5"
		self.AsmCache["test rbp,r11"] = b"\x4c\x85\xdd"
		self.AsmCache["test rbp,r12"] = b"\x4c\x85\xe5"
		self.AsmCache["test rbp,r13"] = b"\x4c\x85\xed"
		self.AsmCache["test rbp,r14"] = b"\x4c\x85\xf5"
		self.AsmCache["test rbp,r15"] = b"\x4c\x85\xfd"
		self.AsmCache["test rsi,rax"] = b"\x48\x85\xc6"
		self.AsmCache["test rsi,rcx"] = b"\x48\x85\xce"
		self.AsmCache["test rsi,rdx"] = b"\x48\x85\xd6"
		self.AsmCache["test rsi,rbx"] = b"\x48\x85\xde"
		self.AsmCache["test rsi,rsp"] = b"\x48\x85\xe6"
		self.AsmCache["test rsi,rbp"] = b"\x48\x85\xee"
		self.AsmCache["test rsi,rsi"] = b"\x48\x85\xf6"
		self.AsmCache["test rsi,rdi"] = b"\x48\x85\xfe"
		self.AsmCache["test rsi,r8"] = b"\x4c\x85\xc6"
		self.AsmCache["test rsi,r9"] = b"\x4c\x85\xce"
		self.AsmCache["test rsi,r10"] = b"\x4c\x85\xd6"
		self.AsmCache["test rsi,r11"] = b"\x4c\x85\xde"
		self.AsmCache["test rsi,r12"] = b"\x4c\x85\xe6"
		self.AsmCache["test rsi,r13"] = b"\x4c\x85\xee"
		self.AsmCache["test rsi,r14"] = b"\x4c\x85\xf6"
		self.AsmCache["test rsi,r15"] = b"\x4c\x85\xfe"
		self.AsmCache["test rdi,rax"] = b"\x48\x85\xc7"
		self.AsmCache["test rdi,rcx"] = b"\x48\x85\xcf"
		self.AsmCache["test rdi,rdx"] = b"\x48\x85\xd7"
		self.AsmCache["test rdi,rbx"] = b"\x48\x85\xdf"
		self.AsmCache["test rdi,rsp"] = b"\x48\x85\xe7"
		self.AsmCache["test rdi,rbp"] = b"\x48\x85\xef"
		self.AsmCache["test rdi,rsi"] = b"\x48\x85\xf7"
		self.AsmCache["test rdi,rdi"] = b"\x48\x85\xff"
		self.AsmCache["test rdi,r8"] = b"\x4c\x85\xc7"
		self.AsmCache["test rdi,r9"] = b"\x4c\x85\xcf"
		self.AsmCache["test rdi,r10"] = b"\x4c\x85\xd7"
		self.AsmCache["test rdi,r11"] = b"\x4c\x85\xdf"
		self.AsmCache["test rdi,r12"] = b"\x4c\x85\xe7"
		self.AsmCache["test rdi,r13"] = b"\x4c\x85\xef"
		self.AsmCache["test rdi,r14"] = b"\x4c\x85\xf7"
		self.AsmCache["test rdi,r15"] = b"\x4c\x85\xff"
		self.AsmCache["test r8,rax"] = b"\x49\x85\xc0"
		self.AsmCache["test r8,rcx"] = b"\x49\x85\xc8"
		self.AsmCache["test r8,rdx"] = b"\x49\x85\xd0"
		self.AsmCache["test r8,rbx"] = b"\x49\x85\xd8"
		self.AsmCache["test r8,rsp"] = b"\x49\x85\xe0"
		self.AsmCache["test r8,rbp"] = b"\x49\x85\xe8"
		self.AsmCache["test r8,rsi"] = b"\x49\x85\xf0"
		self.AsmCache["test r8,rdi"] = b"\x49\x85\xf8"
		self.AsmCache["test r8,r8"] = b"\x4d\x85\xc0"
		self.AsmCache["test r8,r9"] = b"\x4d\x85\xc8"
		self.AsmCache["test r8,r10"] = b"\x4d\x85\xd0"
		self.AsmCache["test r8,r11"] = b"\x4d\x85\xd8"
		self.AsmCache["test r8,r12"] = b"\x4d\x85\xe0"
		self.AsmCache["test r8,r13"] = b"\x4d\x85\xe8"
		self.AsmCache["test r8,r14"] = b"\x4d\x85\xf0"
		self.AsmCache["test r8,r15"] = b"\x4d\x85\xf8"
		self.AsmCache["test r9,rax"] = b"\x49\x85\xc1"
		self.AsmCache["test r9,rcx"] = b"\x49\x85\xc9"
		self.AsmCache["test r9,rdx"] = b"\x49\x85\xd1"
		self.AsmCache["test r9,rbx"] = b"\x49\x85\xd9"
		self.AsmCache["test r9,rsp"] = b"\x49\x85\xe1"
		self.AsmCache["test r9,rbp"] = b"\x49\x85\xe9"
		self.AsmCache["test r9,rsi"] = b"\x49\x85\xf1"
		self.AsmCache["test r9,rdi"] = b"\x49\x85\xf9"
		self.AsmCache["test r9,r8"] = b"\x4d\x85\xc1"
		self.AsmCache["test r9,r9"] = b"\x4d\x85\xc9"
		self.AsmCache["test r9,r10"] = b"\x4d\x85\xd1"
		self.AsmCache["test r9,r11"] = b"\x4d\x85\xd9"
		self.AsmCache["test r9,r12"] = b"\x4d\x85\xe1"
		self.AsmCache["test r9,r13"] = b"\x4d\x85\xe9"
		self.AsmCache["test r9,r14"] = b"\x4d\x85\xf1"
		self.AsmCache["test r9,r15"] = b"\x4d\x85\xf9"
		self.AsmCache["test r10,rax"] = b"\x49\x85\xc2"
		self.AsmCache["test r10,rcx"] = b"\x49\x85\xca"
		self.AsmCache["test r10,rdx"] = b"\x49\x85\xd2"
		self.AsmCache["test r10,rbx"] = b"\x49\x85\xda"
		self.AsmCache["test r10,rsp"] = b"\x49\x85\xe2"
		self.AsmCache["test r10,rbp"] = b"\x49\x85\xea"
		self.AsmCache["test r10,rsi"] = b"\x49\x85\xf2"
		self.AsmCache["test r10,rdi"] = b"\x49\x85\xfa"
		self.AsmCache["test r10,r8"] = b"\x4d\x85\xc2"
		self.AsmCache["test r10,r9"] = b"\x4d\x85\xca"
		self.AsmCache["test r10,r10"] = b"\x4d\x85\xd2"
		self.AsmCache["test r10,r11"] = b"\x4d\x85\xda"
		self.AsmCache["test r10,r12"] = b"\x4d\x85\xe2"
		self.AsmCache["test r10,r13"] = b"\x4d\x85\xea"
		self.AsmCache["test r10,r14"] = b"\x4d\x85\xf2"
		self.AsmCache["test r10,r15"] = b"\x4d\x85\xfa"
		self.AsmCache["test r11,rax"] = b"\x49\x85\xc3"
		self.AsmCache["test r11,rcx"] = b"\x49\x85\xcb"
		self.AsmCache["test r11,rdx"] = b"\x49\x85\xd3"
		self.AsmCache["test r11,rbx"] = b"\x49\x85\xdb"
		self.AsmCache["test r11,rsp"] = b"\x49\x85\xe3"
		self.AsmCache["test r11,rbp"] = b"\x49\x85\xeb"
		self.AsmCache["test r11,rsi"] = b"\x49\x85\xf3"
		self.AsmCache["test r11,rdi"] = b"\x49\x85\xfb"
		self.AsmCache["test r11,r8"] = b"\x4d\x85\xc3"
		self.AsmCache["test r11,r9"] = b"\x4d\x85\xcb"
		self.AsmCache["test r11,r10"] = b"\x4d\x85\xd3"
		self.AsmCache["test r11,r11"] = b"\x4d\x85\xdb"
		self.AsmCache["test r11,r12"] = b"\x4d\x85\xe3"
		self.AsmCache["test r11,r13"] = b"\x4d\x85\xeb"
		self.AsmCache["test r11,r14"] = b"\x4d\x85\xf3"
		self.AsmCache["test r11,r15"] = b"\x4d\x85\xfb"
		self.AsmCache["test r12,rax"] = b"\x49\x85\xc4"
		self.AsmCache["test r12,rcx"] = b"\x49\x85\xcc"
		self.AsmCache["test r12,rdx"] = b"\x49\x85\xd4"
		self.AsmCache["test r12,rbx"] = b"\x49\x85\xdc"
		self.AsmCache["test r12,rsp"] = b"\x49\x85\xe4"
		self.AsmCache["test r12,rbp"] = b"\x49\x85\xec"
		self.AsmCache["test r12,rsi"] = b"\x49\x85\xf4"
		self.AsmCache["test r12,rdi"] = b"\x49\x85\xfc"
		self.AsmCache["test r12,r8"] = b"\x4d\x85\xc4"
		self.AsmCache["test r12,r9"] = b"\x4d\x85\xcc"
		self.AsmCache["test r12,r10"] = b"\x4d\x85\xd4"
		self.AsmCache["test r12,r11"] = b"\x4d\x85\xdc"
		self.AsmCache["test r12,r12"] = b"\x4d\x85\xe4"
		self.AsmCache["test r12,r13"] = b"\x4d\x85\xec"
		self.AsmCache["test r12,r14"] = b"\x4d\x85\xf4"
		self.AsmCache["test r12,r15"] = b"\x4d\x85\xfc"
		self.AsmCache["test r13,rax"] = b"\x49\x85\xc5"
		self.AsmCache["test r13,rcx"] = b"\x49\x85\xcd"
		self.AsmCache["test r13,rdx"] = b"\x49\x85\xd5"
		self.AsmCache["test r13,rbx"] = b"\x49\x85\xdd"
		self.AsmCache["test r13,rsp"] = b"\x49\x85\xe5"
		self.AsmCache["test r13,rbp"] = b"\x49\x85\xed"
		self.AsmCache["test r13,rsi"] = b"\x49\x85\xf5"
		self.AsmCache["test r13,rdi"] = b"\x49\x85\xfd"
		self.AsmCache["test r13,r8"] = b"\x4d\x85\xc5"
		self.AsmCache["test r13,r9"] = b"\x4d\x85\xcd"
		self.AsmCache["test r13,r10"] = b"\x4d\x85\xd5"
		self.AsmCache["test r13,r11"] = b"\x4d\x85\xdd"
		self.AsmCache["test r13,r12"] = b"\x4d\x85\xe5"
		self.AsmCache["test r13,r13"] = b"\x4d\x85\xed"
		self.AsmCache["test r13,r14"] = b"\x4d\x85\xf5"
		self.AsmCache["test r13,r15"] = b"\x4d\x85\xfd"
		self.AsmCache["test r14,rax"] = b"\x49\x85\xc6"
		self.AsmCache["test r14,rcx"] = b"\x49\x85\xce"
		self.AsmCache["test r14,rdx"] = b"\x49\x85\xd6"
		self.AsmCache["test r14,rbx"] = b"\x49\x85\xde"
		self.AsmCache["test r14,rsp"] = b"\x49\x85\xe6"
		self.AsmCache["test r14,rbp"] = b"\x49\x85\xee"
		self.AsmCache["test r14,rsi"] = b"\x49\x85\xf6"
		self.AsmCache["test r14,rdi"] = b"\x49\x85\xfe"
		self.AsmCache["test r14,r8"] = b"\x4d\x85\xc6"
		self.AsmCache["test r14,r9"] = b"\x4d\x85\xce"
		self.AsmCache["test r14,r10"] = b"\x4d\x85\xd6"
		self.AsmCache["test r14,r11"] = b"\x4d\x85\xde"
		self.AsmCache["test r14,r12"] = b"\x4d\x85\xe6"
		self.AsmCache["test r14,r13"] = b"\x4d\x85\xee"
		self.AsmCache["test r14,r14"] = b"\x4d\x85\xf6"
		self.AsmCache["test r14,r15"] = b"\x4d\x85\xfe"
		self.AsmCache["test r15,rax"] = b"\x49\x85\xc7"
		self.AsmCache["test r15,rcx"] = b"\x49\x85\xcf"
		self.AsmCache["test r15,rdx"] = b"\x49\x85\xd7"
		self.AsmCache["test r15,rbx"] = b"\x49\x85\xdf"
		self.AsmCache["test r15,rsp"] = b"\x49\x85\xe7"
		self.AsmCache["test r15,rbp"] = b"\x49\x85\xef"
		self.AsmCache["test r15,rsi"] = b"\x49\x85\xf7"
		self.AsmCache["test r15,rdi"] = b"\x49\x85\xff"
		self.AsmCache["test r15,r8"] = b"\x4d\x85\xc7"
		self.AsmCache["test r15,r9"] = b"\x4d\x85\xcf"
		self.AsmCache["test r15,r10"] = b"\x4d\x85\xd7"
		self.AsmCache["test r15,r11"] = b"\x4d\x85\xdf"
		self.AsmCache["test r15,r12"] = b"\x4d\x85\xe7"
		self.AsmCache["test r15,r13"] = b"\x4d\x85\xef"
		self.AsmCache["test r15,r14"] = b"\x4d\x85\xf7"
		self.AsmCache["test r15,r15"] = b"\x4d\x85\xff"

		# ------------------------------------------------------------
		# XOR reg,reg (64-bit)
		# 48 31 /r
		# ------------------------------------------------------------
		for dstReg in Registers64BitsOrder:
			for srcReg in Registers64BitsOrder:
				dstEnc = regEnc64[dstReg]
				srcEnc = regEnc64[srcReg]
				rex = 0x48
				if (srcEnc & 8) == 8:
					rex |= 0x04  # REX.R
				if (dstEnc & 8) == 8:
					rex |= 0x01  # REX.B
				modrm = 0xC0 | ((srcEnc & 7) << 3) | (dstEnc & 7)
				self.AsmCache["xor %s,%s" % (dstReg, srcReg)] = struct.pack("BBB", rex, 0x31, modrm)

		# ------------------------------------------------------------
		# ADD reg,reg (32-bit)
		# 01 /r
		# ------------------------------------------------------------
		self.AsmCache["add eax,eax"] = b"\x01\xc0"
		self.AsmCache["add eax,ecx"] = b"\x01\xc8"
		self.AsmCache["add eax,edx"] = b"\x01\xd0"
		self.AsmCache["add eax,ebx"] = b"\x01\xd8"
		self.AsmCache["add eax,esp"] = b"\x01\xe0"
		self.AsmCache["add eax,ebp"] = b"\x01\xe8"
		self.AsmCache["add eax,esi"] = b"\x01\xf0"
		self.AsmCache["add eax,edi"] = b"\x01\xf8"
		self.AsmCache["add ecx,eax"] = b"\x01\xc1"
		self.AsmCache["add ecx,ecx"] = b"\x01\xc9"
		self.AsmCache["add ecx,edx"] = b"\x01\xd1"
		self.AsmCache["add ecx,ebx"] = b"\x01\xd9"
		self.AsmCache["add ecx,esp"] = b"\x01\xe1"
		self.AsmCache["add ecx,ebp"] = b"\x01\xe9"
		self.AsmCache["add ecx,esi"] = b"\x01\xf1"
		self.AsmCache["add ecx,edi"] = b"\x01\xf9"
		self.AsmCache["add edx,eax"] = b"\x01\xc2"
		self.AsmCache["add edx,ecx"] = b"\x01\xca"
		self.AsmCache["add edx,edx"] = b"\x01\xd2"
		self.AsmCache["add edx,ebx"] = b"\x01\xda"
		self.AsmCache["add edx,esp"] = b"\x01\xe2"
		self.AsmCache["add edx,ebp"] = b"\x01\xea"
		self.AsmCache["add edx,esi"] = b"\x01\xf2"
		self.AsmCache["add edx,edi"] = b"\x01\xfa"
		self.AsmCache["add ebx,eax"] = b"\x01\xc3"
		self.AsmCache["add ebx,ecx"] = b"\x01\xcb"
		self.AsmCache["add ebx,edx"] = b"\x01\xd3"
		self.AsmCache["add ebx,ebx"] = b"\x01\xdb"
		self.AsmCache["add ebx,esp"] = b"\x01\xe3"
		self.AsmCache["add ebx,ebp"] = b"\x01\xeb"
		self.AsmCache["add ebx,esi"] = b"\x01\xf3"
		self.AsmCache["add ebx,edi"] = b"\x01\xfb"
		self.AsmCache["add esp,eax"] = b"\x01\xc4"
		self.AsmCache["add esp,ecx"] = b"\x01\xcc"
		self.AsmCache["add esp,edx"] = b"\x01\xd4"
		self.AsmCache["add esp,ebx"] = b"\x01\xdc"
		self.AsmCache["add esp,esp"] = b"\x01\xe4"
		self.AsmCache["add esp,ebp"] = b"\x01\xec"
		self.AsmCache["add esp,esi"] = b"\x01\xf4"
		self.AsmCache["add esp,edi"] = b"\x01\xfc"
		self.AsmCache["add ebp,eax"] = b"\x01\xc5"
		self.AsmCache["add ebp,ecx"] = b"\x01\xcd"
		self.AsmCache["add ebp,edx"] = b"\x01\xd5"
		self.AsmCache["add ebp,ebx"] = b"\x01\xdd"
		self.AsmCache["add ebp,esp"] = b"\x01\xe5"
		self.AsmCache["add ebp,ebp"] = b"\x01\xed"
		self.AsmCache["add ebp,esi"] = b"\x01\xf5"
		self.AsmCache["add ebp,edi"] = b"\x01\xfd"
		self.AsmCache["add esi,eax"] = b"\x01\xc6"
		self.AsmCache["add esi,ecx"] = b"\x01\xce"
		self.AsmCache["add esi,edx"] = b"\x01\xd6"
		self.AsmCache["add esi,ebx"] = b"\x01\xde"
		self.AsmCache["add esi,esp"] = b"\x01\xe6"
		self.AsmCache["add esi,ebp"] = b"\x01\xee"
		self.AsmCache["add esi,esi"] = b"\x01\xf6"
		self.AsmCache["add esi,edi"] = b"\x01\xfe"
		self.AsmCache["add edi,eax"] = b"\x01\xc7"
		self.AsmCache["add edi,ecx"] = b"\x01\xcf"
		self.AsmCache["add edi,edx"] = b"\x01\xd7"
		self.AsmCache["add edi,ebx"] = b"\x01\xdf"
		self.AsmCache["add edi,esp"] = b"\x01\xe7"
		self.AsmCache["add edi,ebp"] = b"\x01\xef"
		self.AsmCache["add edi,esi"] = b"\x01\xf7"
		self.AsmCache["add edi,edi"] = b"\x01\xff"

		# ------------------------------------------------------------
		# ADD reg,reg (64-bit)
		# 48 01 /r
		# ------------------------------------------------------------
		self.AsmCache["add rax,rax"] = b"\x48\x01\xc0"
		self.AsmCache["add rax,rcx"] = b"\x48\x01\xc8"
		self.AsmCache["add rax,rdx"] = b"\x48\x01\xd0"
		self.AsmCache["add rax,rbx"] = b"\x48\x01\xd8"
		self.AsmCache["add rax,rsp"] = b"\x48\x01\xe0"
		self.AsmCache["add rax,rbp"] = b"\x48\x01\xe8"
		self.AsmCache["add rax,rsi"] = b"\x48\x01\xf0"
		self.AsmCache["add rax,rdi"] = b"\x48\x01\xf8"
		self.AsmCache["add rax,r8"] = b"\x4c\x01\xc0"
		self.AsmCache["add rax,r9"] = b"\x4c\x01\xc8"
		self.AsmCache["add rax,r10"] = b"\x4c\x01\xd0"
		self.AsmCache["add rax,r11"] = b"\x4c\x01\xd8"
		self.AsmCache["add rax,r12"] = b"\x4c\x01\xe0"
		self.AsmCache["add rax,r13"] = b"\x4c\x01\xe8"
		self.AsmCache["add rax,r14"] = b"\x4c\x01\xf0"
		self.AsmCache["add rax,r15"] = b"\x4c\x01\xf8"
		self.AsmCache["add rcx,rax"] = b"\x48\x01\xc1"
		self.AsmCache["add rcx,rcx"] = b"\x48\x01\xc9"
		self.AsmCache["add rcx,rdx"] = b"\x48\x01\xd1"
		self.AsmCache["add rcx,rbx"] = b"\x48\x01\xd9"
		self.AsmCache["add rcx,rsp"] = b"\x48\x01\xe1"
		self.AsmCache["add rcx,rbp"] = b"\x48\x01\xe9"
		self.AsmCache["add rcx,rsi"] = b"\x48\x01\xf1"
		self.AsmCache["add rcx,rdi"] = b"\x48\x01\xf9"
		self.AsmCache["add rcx,r8"] = b"\x4c\x01\xc1"
		self.AsmCache["add rcx,r9"] = b"\x4c\x01\xc9"
		self.AsmCache["add rcx,r10"] = b"\x4c\x01\xd1"
		self.AsmCache["add rcx,r11"] = b"\x4c\x01\xd9"
		self.AsmCache["add rcx,r12"] = b"\x4c\x01\xe1"
		self.AsmCache["add rcx,r13"] = b"\x4c\x01\xe9"
		self.AsmCache["add rcx,r14"] = b"\x4c\x01\xf1"
		self.AsmCache["add rcx,r15"] = b"\x4c\x01\xf9"
		self.AsmCache["add rdx,rax"] = b"\x48\x01\xc2"
		self.AsmCache["add rdx,rcx"] = b"\x48\x01\xca"
		self.AsmCache["add rdx,rdx"] = b"\x48\x01\xd2"
		self.AsmCache["add rdx,rbx"] = b"\x48\x01\xda"
		self.AsmCache["add rdx,rsp"] = b"\x48\x01\xe2"
		self.AsmCache["add rdx,rbp"] = b"\x48\x01\xea"
		self.AsmCache["add rdx,rsi"] = b"\x48\x01\xf2"
		self.AsmCache["add rdx,rdi"] = b"\x48\x01\xfa"
		self.AsmCache["add rdx,r8"] = b"\x4c\x01\xc2"
		self.AsmCache["add rdx,r9"] = b"\x4c\x01\xca"
		self.AsmCache["add rdx,r10"] = b"\x4c\x01\xd2"
		self.AsmCache["add rdx,r11"] = b"\x4c\x01\xda"
		self.AsmCache["add rdx,r12"] = b"\x4c\x01\xe2"
		self.AsmCache["add rdx,r13"] = b"\x4c\x01\xea"
		self.AsmCache["add rdx,r14"] = b"\x4c\x01\xf2"
		self.AsmCache["add rdx,r15"] = b"\x4c\x01\xfa"
		self.AsmCache["add rbx,rax"] = b"\x48\x01\xc3"
		self.AsmCache["add rbx,rcx"] = b"\x48\x01\xcb"
		self.AsmCache["add rbx,rdx"] = b"\x48\x01\xd3"
		self.AsmCache["add rbx,rbx"] = b"\x48\x01\xdb"
		self.AsmCache["add rbx,rsp"] = b"\x48\x01\xe3"
		self.AsmCache["add rbx,rbp"] = b"\x48\x01\xeb"
		self.AsmCache["add rbx,rsi"] = b"\x48\x01\xf3"
		self.AsmCache["add rbx,rdi"] = b"\x48\x01\xfb"
		self.AsmCache["add rbx,r8"] = b"\x4c\x01\xc3"
		self.AsmCache["add rbx,r9"] = b"\x4c\x01\xcb"
		self.AsmCache["add rbx,r10"] = b"\x4c\x01\xd3"
		self.AsmCache["add rbx,r11"] = b"\x4c\x01\xdb"
		self.AsmCache["add rbx,r12"] = b"\x4c\x01\xe3"
		self.AsmCache["add rbx,r13"] = b"\x4c\x01\xeb"
		self.AsmCache["add rbx,r14"] = b"\x4c\x01\xf3"
		self.AsmCache["add rbx,r15"] = b"\x4c\x01\xfb"
		self.AsmCache["add rsp,rax"] = b"\x48\x01\xc4"
		self.AsmCache["add rsp,rcx"] = b"\x48\x01\xcc"
		self.AsmCache["add rsp,rdx"] = b"\x48\x01\xd4"
		self.AsmCache["add rsp,rbx"] = b"\x48\x01\xdc"
		self.AsmCache["add rsp,rsp"] = b"\x48\x01\xe4"
		self.AsmCache["add rsp,rbp"] = b"\x48\x01\xec"
		self.AsmCache["add rsp,rsi"] = b"\x48\x01\xf4"
		self.AsmCache["add rsp,rdi"] = b"\x48\x01\xfc"
		self.AsmCache["add rsp,r8"] = b"\x4c\x01\xc4"
		self.AsmCache["add rsp,r9"] = b"\x4c\x01\xcc"
		self.AsmCache["add rsp,r10"] = b"\x4c\x01\xd4"
		self.AsmCache["add rsp,r11"] = b"\x4c\x01\xdc"
		self.AsmCache["add rsp,r12"] = b"\x4c\x01\xe4"
		self.AsmCache["add rsp,r13"] = b"\x4c\x01\xec"
		self.AsmCache["add rsp,r14"] = b"\x4c\x01\xf4"
		self.AsmCache["add rsp,r15"] = b"\x4c\x01\xfc"
		self.AsmCache["add rbp,rax"] = b"\x48\x01\xc5"
		self.AsmCache["add rbp,rcx"] = b"\x48\x01\xcd"
		self.AsmCache["add rbp,rdx"] = b"\x48\x01\xd5"
		self.AsmCache["add rbp,rbx"] = b"\x48\x01\xdd"
		self.AsmCache["add rbp,rsp"] = b"\x48\x01\xe5"
		self.AsmCache["add rbp,rbp"] = b"\x48\x01\xed"
		self.AsmCache["add rbp,rsi"] = b"\x48\x01\xf5"
		self.AsmCache["add rbp,rdi"] = b"\x48\x01\xfd"
		self.AsmCache["add rbp,r8"] = b"\x4c\x01\xc5"
		self.AsmCache["add rbp,r9"] = b"\x4c\x01\xcd"
		self.AsmCache["add rbp,r10"] = b"\x4c\x01\xd5"
		self.AsmCache["add rbp,r11"] = b"\x4c\x01\xdd"
		self.AsmCache["add rbp,r12"] = b"\x4c\x01\xe5"
		self.AsmCache["add rbp,r13"] = b"\x4c\x01\xed"
		self.AsmCache["add rbp,r14"] = b"\x4c\x01\xf5"
		self.AsmCache["add rbp,r15"] = b"\x4c\x01\xfd"
		self.AsmCache["add rsi,rax"] = b"\x48\x01\xc6"
		self.AsmCache["add rsi,rcx"] = b"\x48\x01\xce"
		self.AsmCache["add rsi,rdx"] = b"\x48\x01\xd6"
		self.AsmCache["add rsi,rbx"] = b"\x48\x01\xde"
		self.AsmCache["add rsi,rsp"] = b"\x48\x01\xe6"
		self.AsmCache["add rsi,rbp"] = b"\x48\x01\xee"
		self.AsmCache["add rsi,rsi"] = b"\x48\x01\xf6"
		self.AsmCache["add rsi,rdi"] = b"\x48\x01\xfe"
		self.AsmCache["add rsi,r8"] = b"\x4c\x01\xc6"
		self.AsmCache["add rsi,r9"] = b"\x4c\x01\xce"
		self.AsmCache["add rsi,r10"] = b"\x4c\x01\xd6"
		self.AsmCache["add rsi,r11"] = b"\x4c\x01\xde"
		self.AsmCache["add rsi,r12"] = b"\x4c\x01\xe6"
		self.AsmCache["add rsi,r13"] = b"\x4c\x01\xee"
		self.AsmCache["add rsi,r14"] = b"\x4c\x01\xf6"
		self.AsmCache["add rsi,r15"] = b"\x4c\x01\xfe"
		self.AsmCache["add rdi,rax"] = b"\x48\x01\xc7"
		self.AsmCache["add rdi,rcx"] = b"\x48\x01\xcf"
		self.AsmCache["add rdi,rdx"] = b"\x48\x01\xd7"
		self.AsmCache["add rdi,rbx"] = b"\x48\x01\xdf"
		self.AsmCache["add rdi,rsp"] = b"\x48\x01\xe7"
		self.AsmCache["add rdi,rbp"] = b"\x48\x01\xef"
		self.AsmCache["add rdi,rsi"] = b"\x48\x01\xf7"
		self.AsmCache["add rdi,rdi"] = b"\x48\x01\xff"
		self.AsmCache["add rdi,r8"] = b"\x4c\x01\xc7"
		self.AsmCache["add rdi,r9"] = b"\x4c\x01\xcf"
		self.AsmCache["add rdi,r10"] = b"\x4c\x01\xd7"
		self.AsmCache["add rdi,r11"] = b"\x4c\x01\xdf"
		self.AsmCache["add rdi,r12"] = b"\x4c\x01\xe7"
		self.AsmCache["add rdi,r13"] = b"\x4c\x01\xef"
		self.AsmCache["add rdi,r14"] = b"\x4c\x01\xf7"
		self.AsmCache["add rdi,r15"] = b"\x4c\x01\xff"
		self.AsmCache["add r8,rax"] = b"\x49\x01\xc0"
		self.AsmCache["add r8,rcx"] = b"\x49\x01\xc8"
		self.AsmCache["add r8,rdx"] = b"\x49\x01\xd0"
		self.AsmCache["add r8,rbx"] = b"\x49\x01\xd8"
		self.AsmCache["add r8,rsp"] = b"\x49\x01\xe0"
		self.AsmCache["add r8,rbp"] = b"\x49\x01\xe8"
		self.AsmCache["add r8,rsi"] = b"\x49\x01\xf0"
		self.AsmCache["add r8,rdi"] = b"\x49\x01\xf8"
		self.AsmCache["add r8,r8"] = b"\x4d\x01\xc0"
		self.AsmCache["add r8,r9"] = b"\x4d\x01\xc8"
		self.AsmCache["add r8,r10"] = b"\x4d\x01\xd0"
		self.AsmCache["add r8,r11"] = b"\x4d\x01\xd8"
		self.AsmCache["add r8,r12"] = b"\x4d\x01\xe0"
		self.AsmCache["add r8,r13"] = b"\x4d\x01\xe8"
		self.AsmCache["add r8,r14"] = b"\x4d\x01\xf0"
		self.AsmCache["add r8,r15"] = b"\x4d\x01\xf8"
		self.AsmCache["add r9,rax"] = b"\x49\x01\xc1"
		self.AsmCache["add r9,rcx"] = b"\x49\x01\xc9"
		self.AsmCache["add r9,rdx"] = b"\x49\x01\xd1"
		self.AsmCache["add r9,rbx"] = b"\x49\x01\xd9"
		self.AsmCache["add r9,rsp"] = b"\x49\x01\xe1"
		self.AsmCache["add r9,rbp"] = b"\x49\x01\xe9"
		self.AsmCache["add r9,rsi"] = b"\x49\x01\xf1"
		self.AsmCache["add r9,rdi"] = b"\x49\x01\xf9"
		self.AsmCache["add r9,r8"] = b"\x4d\x01\xc1"
		self.AsmCache["add r9,r9"] = b"\x4d\x01\xc9"
		self.AsmCache["add r9,r10"] = b"\x4d\x01\xd1"
		self.AsmCache["add r9,r11"] = b"\x4d\x01\xd9"
		self.AsmCache["add r9,r12"] = b"\x4d\x01\xe1"
		self.AsmCache["add r9,r13"] = b"\x4d\x01\xe9"
		self.AsmCache["add r9,r14"] = b"\x4d\x01\xf1"
		self.AsmCache["add r9,r15"] = b"\x4d\x01\xf9"
		self.AsmCache["add r10,rax"] = b"\x49\x01\xc2"
		self.AsmCache["add r10,rcx"] = b"\x49\x01\xca"
		self.AsmCache["add r10,rdx"] = b"\x49\x01\xd2"
		self.AsmCache["add r10,rbx"] = b"\x49\x01\xda"
		self.AsmCache["add r10,rsp"] = b"\x49\x01\xe2"
		self.AsmCache["add r10,rbp"] = b"\x49\x01\xea"
		self.AsmCache["add r10,rsi"] = b"\x49\x01\xf2"
		self.AsmCache["add r10,rdi"] = b"\x49\x01\xfa"
		self.AsmCache["add r10,r8"] = b"\x4d\x01\xc2"
		self.AsmCache["add r10,r9"] = b"\x4d\x01\xca"
		self.AsmCache["add r10,r10"] = b"\x4d\x01\xd2"
		self.AsmCache["add r10,r11"] = b"\x4d\x01\xda"
		self.AsmCache["add r10,r12"] = b"\x4d\x01\xe2"
		self.AsmCache["add r10,r13"] = b"\x4d\x01\xea"
		self.AsmCache["add r10,r14"] = b"\x4d\x01\xf2"
		self.AsmCache["add r10,r15"] = b"\x4d\x01\xfa"
		self.AsmCache["add r11,rax"] = b"\x49\x01\xc3"
		self.AsmCache["add r11,rcx"] = b"\x49\x01\xcb"
		self.AsmCache["add r11,rdx"] = b"\x49\x01\xd3"
		self.AsmCache["add r11,rbx"] = b"\x49\x01\xdb"
		self.AsmCache["add r11,rsp"] = b"\x49\x01\xe3"
		self.AsmCache["add r11,rbp"] = b"\x49\x01\xeb"
		self.AsmCache["add r11,rsi"] = b"\x49\x01\xf3"
		self.AsmCache["add r11,rdi"] = b"\x49\x01\xfb"
		self.AsmCache["add r11,r8"] = b"\x4d\x01\xc3"
		self.AsmCache["add r11,r9"] = b"\x4d\x01\xcb"
		self.AsmCache["add r11,r10"] = b"\x4d\x01\xd3"
		self.AsmCache["add r11,r11"] = b"\x4d\x01\xdb"
		self.AsmCache["add r11,r12"] = b"\x4d\x01\xe3"
		self.AsmCache["add r11,r13"] = b"\x4d\x01\xeb"
		self.AsmCache["add r11,r14"] = b"\x4d\x01\xf3"
		self.AsmCache["add r11,r15"] = b"\x4d\x01\xfb"
		self.AsmCache["add r12,rax"] = b"\x49\x01\xc4"
		self.AsmCache["add r12,rcx"] = b"\x49\x01\xcc"
		self.AsmCache["add r12,rdx"] = b"\x49\x01\xd4"
		self.AsmCache["add r12,rbx"] = b"\x49\x01\xdc"
		self.AsmCache["add r12,rsp"] = b"\x49\x01\xe4"
		self.AsmCache["add r12,rbp"] = b"\x49\x01\xec"
		self.AsmCache["add r12,rsi"] = b"\x49\x01\xf4"
		self.AsmCache["add r12,rdi"] = b"\x49\x01\xfc"
		self.AsmCache["add r12,r8"] = b"\x4d\x01\xc4"
		self.AsmCache["add r12,r9"] = b"\x4d\x01\xcc"
		self.AsmCache["add r12,r10"] = b"\x4d\x01\xd4"
		self.AsmCache["add r12,r11"] = b"\x4d\x01\xdc"
		self.AsmCache["add r12,r12"] = b"\x4d\x01\xe4"
		self.AsmCache["add r12,r13"] = b"\x4d\x01\xec"
		self.AsmCache["add r12,r14"] = b"\x4d\x01\xf4"
		self.AsmCache["add r12,r15"] = b"\x4d\x01\xfc"
		self.AsmCache["add r13,rax"] = b"\x49\x01\xc5"
		self.AsmCache["add r13,rcx"] = b"\x49\x01\xcd"
		self.AsmCache["add r13,rdx"] = b"\x49\x01\xd5"
		self.AsmCache["add r13,rbx"] = b"\x49\x01\xdd"
		self.AsmCache["add r13,rsp"] = b"\x49\x01\xe5"
		self.AsmCache["add r13,rbp"] = b"\x49\x01\xed"
		self.AsmCache["add r13,rsi"] = b"\x49\x01\xf5"
		self.AsmCache["add r13,rdi"] = b"\x49\x01\xfd"
		self.AsmCache["add r13,r8"] = b"\x4d\x01\xc5"
		self.AsmCache["add r13,r9"] = b"\x4d\x01\xcd"
		self.AsmCache["add r13,r10"] = b"\x4d\x01\xd5"
		self.AsmCache["add r13,r11"] = b"\x4d\x01\xdd"
		self.AsmCache["add r13,r12"] = b"\x4d\x01\xe5"
		self.AsmCache["add r13,r13"] = b"\x4d\x01\xed"
		self.AsmCache["add r13,r14"] = b"\x4d\x01\xf5"
		self.AsmCache["add r13,r15"] = b"\x4d\x01\xfd"
		self.AsmCache["add r14,rax"] = b"\x49\x01\xc6"
		self.AsmCache["add r14,rcx"] = b"\x49\x01\xce"
		self.AsmCache["add r14,rdx"] = b"\x49\x01\xd6"
		self.AsmCache["add r14,rbx"] = b"\x49\x01\xde"
		self.AsmCache["add r14,rsp"] = b"\x49\x01\xe6"
		self.AsmCache["add r14,rbp"] = b"\x49\x01\xee"
		self.AsmCache["add r14,rsi"] = b"\x49\x01\xf6"
		self.AsmCache["add r14,rdi"] = b"\x49\x01\xfe"
		self.AsmCache["add r14,r8"] = b"\x4d\x01\xc6"
		self.AsmCache["add r14,r9"] = b"\x4d\x01\xce"
		self.AsmCache["add r14,r10"] = b"\x4d\x01\xd6"
		self.AsmCache["add r14,r11"] = b"\x4d\x01\xde"
		self.AsmCache["add r14,r12"] = b"\x4d\x01\xe6"
		self.AsmCache["add r14,r13"] = b"\x4d\x01\xee"
		self.AsmCache["add r14,r14"] = b"\x4d\x01\xf6"
		self.AsmCache["add r14,r15"] = b"\x4d\x01\xfe"
		self.AsmCache["add r15,rax"] = b"\x49\x01\xc7"
		self.AsmCache["add r15,rcx"] = b"\x49\x01\xcf"
		self.AsmCache["add r15,rdx"] = b"\x49\x01\xd7"
		self.AsmCache["add r15,rbx"] = b"\x49\x01\xdf"
		self.AsmCache["add r15,rsp"] = b"\x49\x01\xe7"
		self.AsmCache["add r15,rbp"] = b"\x49\x01\xef"
		self.AsmCache["add r15,rsi"] = b"\x49\x01\xf7"
		self.AsmCache["add r15,rdi"] = b"\x49\x01\xff"
		self.AsmCache["add r15,r8"] = b"\x4d\x01\xc7"
		self.AsmCache["add r15,r9"] = b"\x4d\x01\xcf"
		self.AsmCache["add r15,r10"] = b"\x4d\x01\xd7"
		self.AsmCache["add r15,r11"] = b"\x4d\x01\xdf"
		self.AsmCache["add r15,r12"] = b"\x4d\x01\xe7"
		self.AsmCache["add r15,r13"] = b"\x4d\x01\xef"
		self.AsmCache["add r15,r14"] = b"\x4d\x01\xf7"
		self.AsmCache["add r15,r15"] = b"\x4d\x01\xff"

		# ------------------------------------------------------------
		# SUB reg,reg (32-bit)
		# 29 /r
		# ------------------------------------------------------------
		self.AsmCache["sub eax,eax"] = b"\x29\xc0"
		self.AsmCache["sub eax,ecx"] = b"\x29\xc8"
		self.AsmCache["sub eax,edx"] = b"\x29\xd0"
		self.AsmCache["sub eax,ebx"] = b"\x29\xd8"
		self.AsmCache["sub eax,esp"] = b"\x29\xe0"
		self.AsmCache["sub eax,ebp"] = b"\x29\xe8"
		self.AsmCache["sub eax,esi"] = b"\x29\xf0"
		self.AsmCache["sub eax,edi"] = b"\x29\xf8"
		self.AsmCache["sub ecx,eax"] = b"\x29\xc1"
		self.AsmCache["sub ecx,ecx"] = b"\x29\xc9"
		self.AsmCache["sub ecx,edx"] = b"\x29\xd1"
		self.AsmCache["sub ecx,ebx"] = b"\x29\xd9"
		self.AsmCache["sub ecx,esp"] = b"\x29\xe1"
		self.AsmCache["sub ecx,ebp"] = b"\x29\xe9"
		self.AsmCache["sub ecx,esi"] = b"\x29\xf1"
		self.AsmCache["sub ecx,edi"] = b"\x29\xf9"
		self.AsmCache["sub edx,eax"] = b"\x29\xc2"
		self.AsmCache["sub edx,ecx"] = b"\x29\xca"
		self.AsmCache["sub edx,edx"] = b"\x29\xd2"
		self.AsmCache["sub edx,ebx"] = b"\x29\xda"
		self.AsmCache["sub edx,esp"] = b"\x29\xe2"
		self.AsmCache["sub edx,ebp"] = b"\x29\xea"
		self.AsmCache["sub edx,esi"] = b"\x29\xf2"
		self.AsmCache["sub edx,edi"] = b"\x29\xfa"
		self.AsmCache["sub ebx,eax"] = b"\x29\xc3"
		self.AsmCache["sub ebx,ecx"] = b"\x29\xcb"
		self.AsmCache["sub ebx,edx"] = b"\x29\xd3"
		self.AsmCache["sub ebx,ebx"] = b"\x29\xdb"
		self.AsmCache["sub ebx,esp"] = b"\x29\xe3"
		self.AsmCache["sub ebx,ebp"] = b"\x29\xeb"
		self.AsmCache["sub ebx,esi"] = b"\x29\xf3"
		self.AsmCache["sub ebx,edi"] = b"\x29\xfb"
		self.AsmCache["sub esp,eax"] = b"\x29\xc4"
		self.AsmCache["sub esp,ecx"] = b"\x29\xcc"
		self.AsmCache["sub esp,edx"] = b"\x29\xd4"
		self.AsmCache["sub esp,ebx"] = b"\x29\xdc"
		self.AsmCache["sub esp,esp"] = b"\x29\xe4"
		self.AsmCache["sub esp,ebp"] = b"\x29\xec"
		self.AsmCache["sub esp,esi"] = b"\x29\xf4"
		self.AsmCache["sub esp,edi"] = b"\x29\xfc"
		self.AsmCache["sub ebp,eax"] = b"\x29\xc5"
		self.AsmCache["sub ebp,ecx"] = b"\x29\xcd"
		self.AsmCache["sub ebp,edx"] = b"\x29\xd5"
		self.AsmCache["sub ebp,ebx"] = b"\x29\xdd"
		self.AsmCache["sub ebp,esp"] = b"\x29\xe5"
		self.AsmCache["sub ebp,ebp"] = b"\x29\xed"
		self.AsmCache["sub ebp,esi"] = b"\x29\xf5"
		self.AsmCache["sub ebp,edi"] = b"\x29\xfd"
		self.AsmCache["sub esi,eax"] = b"\x29\xc6"
		self.AsmCache["sub esi,ecx"] = b"\x29\xce"
		self.AsmCache["sub esi,edx"] = b"\x29\xd6"
		self.AsmCache["sub esi,ebx"] = b"\x29\xde"
		self.AsmCache["sub esi,esp"] = b"\x29\xe6"
		self.AsmCache["sub esi,ebp"] = b"\x29\xee"
		self.AsmCache["sub esi,esi"] = b"\x29\xf6"
		self.AsmCache["sub esi,edi"] = b"\x29\xfe"
		self.AsmCache["sub edi,eax"] = b"\x29\xc7"
		self.AsmCache["sub edi,ecx"] = b"\x29\xcf"
		self.AsmCache["sub edi,edx"] = b"\x29\xd7"
		self.AsmCache["sub edi,ebx"] = b"\x29\xdf"
		self.AsmCache["sub edi,esp"] = b"\x29\xe7"
		self.AsmCache["sub edi,ebp"] = b"\x29\xef"
		self.AsmCache["sub edi,esi"] = b"\x29\xf7"
		self.AsmCache["sub edi,edi"] = b"\x29\xff"

		# ------------------------------------------------------------
		# SUB reg,reg (64-bit)
		# 48 29 /r
		# ------------------------------------------------------------
		self.AsmCache["sub rax,rax"] = b"\x48\x29\xc0"
		self.AsmCache["sub rax,rcx"] = b"\x48\x29\xc8"
		self.AsmCache["sub rax,rdx"] = b"\x48\x29\xd0"
		self.AsmCache["sub rax,rbx"] = b"\x48\x29\xd8"
		self.AsmCache["sub rax,rsp"] = b"\x48\x29\xe0"
		self.AsmCache["sub rax,rbp"] = b"\x48\x29\xe8"
		self.AsmCache["sub rax,rsi"] = b"\x48\x29\xf0"
		self.AsmCache["sub rax,rdi"] = b"\x48\x29\xf8"
		self.AsmCache["sub rax,r8"] = b"\x4c\x29\xc0"
		self.AsmCache["sub rax,r9"] = b"\x4c\x29\xc8"
		self.AsmCache["sub rax,r10"] = b"\x4c\x29\xd0"
		self.AsmCache["sub rax,r11"] = b"\x4c\x29\xd8"
		self.AsmCache["sub rax,r12"] = b"\x4c\x29\xe0"
		self.AsmCache["sub rax,r13"] = b"\x4c\x29\xe8"
		self.AsmCache["sub rax,r14"] = b"\x4c\x29\xf0"
		self.AsmCache["sub rax,r15"] = b"\x4c\x29\xf8"
		self.AsmCache["sub rcx,rax"] = b"\x48\x29\xc1"
		self.AsmCache["sub rcx,rcx"] = b"\x48\x29\xc9"
		self.AsmCache["sub rcx,rdx"] = b"\x48\x29\xd1"
		self.AsmCache["sub rcx,rbx"] = b"\x48\x29\xd9"
		self.AsmCache["sub rcx,rsp"] = b"\x48\x29\xe1"
		self.AsmCache["sub rcx,rbp"] = b"\x48\x29\xe9"
		self.AsmCache["sub rcx,rsi"] = b"\x48\x29\xf1"
		self.AsmCache["sub rcx,rdi"] = b"\x48\x29\xf9"
		self.AsmCache["sub rcx,r8"] = b"\x4c\x29\xc1"
		self.AsmCache["sub rcx,r9"] = b"\x4c\x29\xc9"
		self.AsmCache["sub rcx,r10"] = b"\x4c\x29\xd1"
		self.AsmCache["sub rcx,r11"] = b"\x4c\x29\xd9"
		self.AsmCache["sub rcx,r12"] = b"\x4c\x29\xe1"
		self.AsmCache["sub rcx,r13"] = b"\x4c\x29\xe9"
		self.AsmCache["sub rcx,r14"] = b"\x4c\x29\xf1"
		self.AsmCache["sub rcx,r15"] = b"\x4c\x29\xf9"
		self.AsmCache["sub rdx,rax"] = b"\x48\x29\xc2"
		self.AsmCache["sub rdx,rcx"] = b"\x48\x29\xca"
		self.AsmCache["sub rdx,rdx"] = b"\x48\x29\xd2"
		self.AsmCache["sub rdx,rbx"] = b"\x48\x29\xda"
		self.AsmCache["sub rdx,rsp"] = b"\x48\x29\xe2"
		self.AsmCache["sub rdx,rbp"] = b"\x48\x29\xea"
		self.AsmCache["sub rdx,rsi"] = b"\x48\x29\xf2"
		self.AsmCache["sub rdx,rdi"] = b"\x48\x29\xfa"
		self.AsmCache["sub rdx,r8"] = b"\x4c\x29\xc2"
		self.AsmCache["sub rdx,r9"] = b"\x4c\x29\xca"
		self.AsmCache["sub rdx,r10"] = b"\x4c\x29\xd2"
		self.AsmCache["sub rdx,r11"] = b"\x4c\x29\xda"
		self.AsmCache["sub rdx,r12"] = b"\x4c\x29\xe2"
		self.AsmCache["sub rdx,r13"] = b"\x4c\x29\xea"
		self.AsmCache["sub rdx,r14"] = b"\x4c\x29\xf2"
		self.AsmCache["sub rdx,r15"] = b"\x4c\x29\xfa"
		self.AsmCache["sub rbx,rax"] = b"\x48\x29\xc3"
		self.AsmCache["sub rbx,rcx"] = b"\x48\x29\xcb"
		self.AsmCache["sub rbx,rdx"] = b"\x48\x29\xd3"
		self.AsmCache["sub rbx,rbx"] = b"\x48\x29\xdb"
		self.AsmCache["sub rbx,rsp"] = b"\x48\x29\xe3"
		self.AsmCache["sub rbx,rbp"] = b"\x48\x29\xeb"
		self.AsmCache["sub rbx,rsi"] = b"\x48\x29\xf3"
		self.AsmCache["sub rbx,rdi"] = b"\x48\x29\xfb"
		self.AsmCache["sub rbx,r8"] = b"\x4c\x29\xc3"
		self.AsmCache["sub rbx,r9"] = b"\x4c\x29\xcb"
		self.AsmCache["sub rbx,r10"] = b"\x4c\x29\xd3"
		self.AsmCache["sub rbx,r11"] = b"\x4c\x29\xdb"
		self.AsmCache["sub rbx,r12"] = b"\x4c\x29\xe3"
		self.AsmCache["sub rbx,r13"] = b"\x4c\x29\xeb"
		self.AsmCache["sub rbx,r14"] = b"\x4c\x29\xf3"
		self.AsmCache["sub rbx,r15"] = b"\x4c\x29\xfb"
		self.AsmCache["sub rsp,rax"] = b"\x48\x29\xc4"
		self.AsmCache["sub rsp,rcx"] = b"\x48\x29\xcc"
		self.AsmCache["sub rsp,rdx"] = b"\x48\x29\xd4"
		self.AsmCache["sub rsp,rbx"] = b"\x48\x29\xdc"
		self.AsmCache["sub rsp,rsp"] = b"\x48\x29\xe4"
		self.AsmCache["sub rsp,rbp"] = b"\x48\x29\xec"
		self.AsmCache["sub rsp,rsi"] = b"\x48\x29\xf4"
		self.AsmCache["sub rsp,rdi"] = b"\x48\x29\xfc"
		self.AsmCache["sub rsp,r8"] = b"\x4c\x29\xc4"
		self.AsmCache["sub rsp,r9"] = b"\x4c\x29\xcc"
		self.AsmCache["sub rsp,r10"] = b"\x4c\x29\xd4"
		self.AsmCache["sub rsp,r11"] = b"\x4c\x29\xdc"
		self.AsmCache["sub rsp,r12"] = b"\x4c\x29\xe4"
		self.AsmCache["sub rsp,r13"] = b"\x4c\x29\xec"
		self.AsmCache["sub rsp,r14"] = b"\x4c\x29\xf4"
		self.AsmCache["sub rsp,r15"] = b"\x4c\x29\xfc"
		self.AsmCache["sub rbp,rax"] = b"\x48\x29\xc5"
		self.AsmCache["sub rbp,rcx"] = b"\x48\x29\xcd"
		self.AsmCache["sub rbp,rdx"] = b"\x48\x29\xd5"
		self.AsmCache["sub rbp,rbx"] = b"\x48\x29\xdd"
		self.AsmCache["sub rbp,rsp"] = b"\x48\x29\xe5"
		self.AsmCache["sub rbp,rbp"] = b"\x48\x29\xed"
		self.AsmCache["sub rbp,rsi"] = b"\x48\x29\xf5"
		self.AsmCache["sub rbp,rdi"] = b"\x48\x29\xfd"
		self.AsmCache["sub rbp,r8"] = b"\x4c\x29\xc5"
		self.AsmCache["sub rbp,r9"] = b"\x4c\x29\xcd"
		self.AsmCache["sub rbp,r10"] = b"\x4c\x29\xd5"
		self.AsmCache["sub rbp,r11"] = b"\x4c\x29\xdd"
		self.AsmCache["sub rbp,r12"] = b"\x4c\x29\xe5"
		self.AsmCache["sub rbp,r13"] = b"\x4c\x29\xed"
		self.AsmCache["sub rbp,r14"] = b"\x4c\x29\xf5"
		self.AsmCache["sub rbp,r15"] = b"\x4c\x29\xfd"
		self.AsmCache["sub rsi,rax"] = b"\x48\x29\xc6"
		self.AsmCache["sub rsi,rcx"] = b"\x48\x29\xce"
		self.AsmCache["sub rsi,rdx"] = b"\x48\x29\xd6"
		self.AsmCache["sub rsi,rbx"] = b"\x48\x29\xde"
		self.AsmCache["sub rsi,rsp"] = b"\x48\x29\xe6"
		self.AsmCache["sub rsi,rbp"] = b"\x48\x29\xee"
		self.AsmCache["sub rsi,rsi"] = b"\x48\x29\xf6"
		self.AsmCache["sub rsi,rdi"] = b"\x48\x29\xfe"
		self.AsmCache["sub rsi,r8"] = b"\x4c\x29\xc6"
		self.AsmCache["sub rsi,r9"] = b"\x4c\x29\xce"
		self.AsmCache["sub rsi,r10"] = b"\x4c\x29\xd6"
		self.AsmCache["sub rsi,r11"] = b"\x4c\x29\xde"
		self.AsmCache["sub rsi,r12"] = b"\x4c\x29\xe6"
		self.AsmCache["sub rsi,r13"] = b"\x4c\x29\xee"
		self.AsmCache["sub rsi,r14"] = b"\x4c\x29\xf6"
		self.AsmCache["sub rsi,r15"] = b"\x4c\x29\xfe"
		self.AsmCache["sub rdi,rax"] = b"\x48\x29\xc7"
		self.AsmCache["sub rdi,rcx"] = b"\x48\x29\xcf"
		self.AsmCache["sub rdi,rdx"] = b"\x48\x29\xd7"
		self.AsmCache["sub rdi,rbx"] = b"\x48\x29\xdf"
		self.AsmCache["sub rdi,rsp"] = b"\x48\x29\xe7"
		self.AsmCache["sub rdi,rbp"] = b"\x48\x29\xef"
		self.AsmCache["sub rdi,rsi"] = b"\x48\x29\xf7"
		self.AsmCache["sub rdi,rdi"] = b"\x48\x29\xff"
		self.AsmCache["sub rdi,r8"] = b"\x4c\x29\xc7"
		self.AsmCache["sub rdi,r9"] = b"\x4c\x29\xcf"
		self.AsmCache["sub rdi,r10"] = b"\x4c\x29\xd7"
		self.AsmCache["sub rdi,r11"] = b"\x4c\x29\xdf"
		self.AsmCache["sub rdi,r12"] = b"\x4c\x29\xe7"
		self.AsmCache["sub rdi,r13"] = b"\x4c\x29\xef"
		self.AsmCache["sub rdi,r14"] = b"\x4c\x29\xf7"
		self.AsmCache["sub rdi,r15"] = b"\x4c\x29\xff"
		self.AsmCache["sub r8,rax"] = b"\x49\x29\xc0"
		self.AsmCache["sub r8,rcx"] = b"\x49\x29\xc8"
		self.AsmCache["sub r8,rdx"] = b"\x49\x29\xd0"
		self.AsmCache["sub r8,rbx"] = b"\x49\x29\xd8"
		self.AsmCache["sub r8,rsp"] = b"\x49\x29\xe0"
		self.AsmCache["sub r8,rbp"] = b"\x49\x29\xe8"
		self.AsmCache["sub r8,rsi"] = b"\x49\x29\xf0"
		self.AsmCache["sub r8,rdi"] = b"\x49\x29\xf8"
		self.AsmCache["sub r8,r8"] = b"\x4d\x29\xc0"
		self.AsmCache["sub r8,r9"] = b"\x4d\x29\xc8"
		self.AsmCache["sub r8,r10"] = b"\x4d\x29\xd0"
		self.AsmCache["sub r8,r11"] = b"\x4d\x29\xd8"
		self.AsmCache["sub r8,r12"] = b"\x4d\x29\xe0"
		self.AsmCache["sub r8,r13"] = b"\x4d\x29\xe8"
		self.AsmCache["sub r8,r14"] = b"\x4d\x29\xf0"
		self.AsmCache["sub r8,r15"] = b"\x4d\x29\xf8"
		self.AsmCache["sub r9,rax"] = b"\x49\x29\xc1"
		self.AsmCache["sub r9,rcx"] = b"\x49\x29\xc9"
		self.AsmCache["sub r9,rdx"] = b"\x49\x29\xd1"
		self.AsmCache["sub r9,rbx"] = b"\x49\x29\xd9"
		self.AsmCache["sub r9,rsp"] = b"\x49\x29\xe1"
		self.AsmCache["sub r9,rbp"] = b"\x49\x29\xe9"
		self.AsmCache["sub r9,rsi"] = b"\x49\x29\xf1"
		self.AsmCache["sub r9,rdi"] = b"\x49\x29\xf9"
		self.AsmCache["sub r9,r8"] = b"\x4d\x29\xc1"
		self.AsmCache["sub r9,r9"] = b"\x4d\x29\xc9"
		self.AsmCache["sub r9,r10"] = b"\x4d\x29\xd1"
		self.AsmCache["sub r9,r11"] = b"\x4d\x29\xd9"
		self.AsmCache["sub r9,r12"] = b"\x4d\x29\xe1"
		self.AsmCache["sub r9,r13"] = b"\x4d\x29\xe9"
		self.AsmCache["sub r9,r14"] = b"\x4d\x29\xf1"
		self.AsmCache["sub r9,r15"] = b"\x4d\x29\xf9"
		self.AsmCache["sub r10,rax"] = b"\x49\x29\xc2"
		self.AsmCache["sub r10,rcx"] = b"\x49\x29\xca"
		self.AsmCache["sub r10,rdx"] = b"\x49\x29\xd2"
		self.AsmCache["sub r10,rbx"] = b"\x49\x29\xda"
		self.AsmCache["sub r10,rsp"] = b"\x49\x29\xe2"
		self.AsmCache["sub r10,rbp"] = b"\x49\x29\xea"
		self.AsmCache["sub r10,rsi"] = b"\x49\x29\xf2"
		self.AsmCache["sub r10,rdi"] = b"\x49\x29\xfa"
		self.AsmCache["sub r10,r8"] = b"\x4d\x29\xc2"
		self.AsmCache["sub r10,r9"] = b"\x4d\x29\xca"
		self.AsmCache["sub r10,r10"] = b"\x4d\x29\xd2"
		self.AsmCache["sub r10,r11"] = b"\x4d\x29\xda"
		self.AsmCache["sub r10,r12"] = b"\x4d\x29\xe2"
		self.AsmCache["sub r10,r13"] = b"\x4d\x29\xea"
		self.AsmCache["sub r10,r14"] = b"\x4d\x29\xf2"
		self.AsmCache["sub r10,r15"] = b"\x4d\x29\xfa"
		self.AsmCache["sub r11,rax"] = b"\x49\x29\xc3"
		self.AsmCache["sub r11,rcx"] = b"\x49\x29\xcb"
		self.AsmCache["sub r11,rdx"] = b"\x49\x29\xd3"
		self.AsmCache["sub r11,rbx"] = b"\x49\x29\xdb"
		self.AsmCache["sub r11,rsp"] = b"\x49\x29\xe3"
		self.AsmCache["sub r11,rbp"] = b"\x49\x29\xeb"
		self.AsmCache["sub r11,rsi"] = b"\x49\x29\xf3"
		self.AsmCache["sub r11,rdi"] = b"\x49\x29\xfb"
		self.AsmCache["sub r11,r8"] = b"\x4d\x29\xc3"
		self.AsmCache["sub r11,r9"] = b"\x4d\x29\xcb"
		self.AsmCache["sub r11,r10"] = b"\x4d\x29\xd3"
		self.AsmCache["sub r11,r11"] = b"\x4d\x29\xdb"
		self.AsmCache["sub r11,r12"] = b"\x4d\x29\xe3"
		self.AsmCache["sub r11,r13"] = b"\x4d\x29\xeb"
		self.AsmCache["sub r11,r14"] = b"\x4d\x29\xf3"
		self.AsmCache["sub r11,r15"] = b"\x4d\x29\xfb"
		self.AsmCache["sub r12,rax"] = b"\x49\x29\xc4"
		self.AsmCache["sub r12,rcx"] = b"\x49\x29\xcc"
		self.AsmCache["sub r12,rdx"] = b"\x49\x29\xd4"
		self.AsmCache["sub r12,rbx"] = b"\x49\x29\xdc"
		self.AsmCache["sub r12,rsp"] = b"\x49\x29\xe4"
		self.AsmCache["sub r12,rbp"] = b"\x49\x29\xec"
		self.AsmCache["sub r12,rsi"] = b"\x49\x29\xf4"
		self.AsmCache["sub r12,rdi"] = b"\x49\x29\xfc"
		self.AsmCache["sub r12,r8"] = b"\x4d\x29\xc4"
		self.AsmCache["sub r12,r9"] = b"\x4d\x29\xcc"
		self.AsmCache["sub r12,r10"] = b"\x4d\x29\xd4"
		self.AsmCache["sub r12,r11"] = b"\x4d\x29\xdc"
		self.AsmCache["sub r12,r12"] = b"\x4d\x29\xe4"
		self.AsmCache["sub r12,r13"] = b"\x4d\x29\xec"
		self.AsmCache["sub r12,r14"] = b"\x4d\x29\xf4"
		self.AsmCache["sub r12,r15"] = b"\x4d\x29\xfc"
		self.AsmCache["sub r13,rax"] = b"\x49\x29\xc5"
		self.AsmCache["sub r13,rcx"] = b"\x49\x29\xcd"
		self.AsmCache["sub r13,rdx"] = b"\x49\x29\xd5"
		self.AsmCache["sub r13,rbx"] = b"\x49\x29\xdd"
		self.AsmCache["sub r13,rsp"] = b"\x49\x29\xe5"
		self.AsmCache["sub r13,rbp"] = b"\x49\x29\xed"
		self.AsmCache["sub r13,rsi"] = b"\x49\x29\xf5"
		self.AsmCache["sub r13,rdi"] = b"\x49\x29\xfd"
		self.AsmCache["sub r13,r8"] = b"\x4d\x29\xc5"
		self.AsmCache["sub r13,r9"] = b"\x4d\x29\xcd"
		self.AsmCache["sub r13,r10"] = b"\x4d\x29\xd5"
		self.AsmCache["sub r13,r11"] = b"\x4d\x29\xdd"
		self.AsmCache["sub r13,r12"] = b"\x4d\x29\xe5"
		self.AsmCache["sub r13,r13"] = b"\x4d\x29\xed"
		self.AsmCache["sub r13,r14"] = b"\x4d\x29\xf5"
		self.AsmCache["sub r13,r15"] = b"\x4d\x29\xfd"
		self.AsmCache["sub r14,rax"] = b"\x49\x29\xc6"
		self.AsmCache["sub r14,rcx"] = b"\x49\x29\xce"
		self.AsmCache["sub r14,rdx"] = b"\x49\x29\xd6"
		self.AsmCache["sub r14,rbx"] = b"\x49\x29\xde"
		self.AsmCache["sub r14,rsp"] = b"\x49\x29\xe6"
		self.AsmCache["sub r14,rbp"] = b"\x49\x29\xee"
		self.AsmCache["sub r14,rsi"] = b"\x49\x29\xf6"
		self.AsmCache["sub r14,rdi"] = b"\x49\x29\xfe"
		self.AsmCache["sub r14,r8"] = b"\x4d\x29\xc6"
		self.AsmCache["sub r14,r9"] = b"\x4d\x29\xce"
		self.AsmCache["sub r14,r10"] = b"\x4d\x29\xd6"
		self.AsmCache["sub r14,r11"] = b"\x4d\x29\xde"
		self.AsmCache["sub r14,r12"] = b"\x4d\x29\xe6"
		self.AsmCache["sub r14,r13"] = b"\x4d\x29\xee"
		self.AsmCache["sub r14,r14"] = b"\x4d\x29\xf6"
		self.AsmCache["sub r14,r15"] = b"\x4d\x29\xfe"
		self.AsmCache["sub r15,rax"] = b"\x49\x29\xc7"
		self.AsmCache["sub r15,rcx"] = b"\x49\x29\xcf"
		self.AsmCache["sub r15,rdx"] = b"\x49\x29\xd7"
		self.AsmCache["sub r15,rbx"] = b"\x49\x29\xdf"
		self.AsmCache["sub r15,rsp"] = b"\x49\x29\xe7"
		self.AsmCache["sub r15,rbp"] = b"\x49\x29\xef"
		self.AsmCache["sub r15,rsi"] = b"\x49\x29\xf7"
		self.AsmCache["sub r15,rdi"] = b"\x49\x29\xff"
		self.AsmCache["sub r15,r8"] = b"\x4d\x29\xc7"
		self.AsmCache["sub r15,r9"] = b"\x4d\x29\xcf"
		self.AsmCache["sub r15,r10"] = b"\x4d\x29\xd7"
		self.AsmCache["sub r15,r11"] = b"\x4d\x29\xdf"
		self.AsmCache["sub r15,r12"] = b"\x4d\x29\xe7"
		self.AsmCache["sub r15,r13"] = b"\x4d\x29\xef"
		self.AsmCache["sub r15,r14"] = b"\x4d\x29\xf7"
		self.AsmCache["sub r15,r15"] = b"\x4d\x29\xff"
		self.AsmCache["mov r15,r8"] = b"\x4d\x89\xc7"
		self.AsmCache["mov r15,r9"] = b"\x4d\x89\xcf"
		self.AsmCache["mov r15,r10"] = b"\x4d\x89\xd7"
		self.AsmCache["mov r15,r11"] = b"\x4d\x89\xdf"
		self.AsmCache["mov r15,r12"] = b"\x4d\x89\xe7"
		self.AsmCache["mov r15,r13"] = b"\x4d\x89\xef"
		self.AsmCache["mov r15,r14"] = b"\x4d\x89\xf7"
		self.AsmCache["mov r15,r15"] = b"\x4d\x89\xff"

		self.AsmCache["xchg rax,rcx"] = b"\x48\x87\xc8"
		self.AsmCache["xchg rax,rdx"] = b"\x48\x87\xd0"
		self.AsmCache["xchg rax,rbx"] = b"\x48\x87\xd8"
		self.AsmCache["xchg rax,rsp"] = b"\x48\x87\xe0"
		self.AsmCache["xchg rax,rbp"] = b"\x48\x87\xe8"
		self.AsmCache["xchg rax,rsi"] = b"\x48\x87\xf0"
		self.AsmCache["xchg rax,rdi"] = b"\x48\x87\xf8"
		self.AsmCache["xchg rax,r8"] = b"\x4c\x87\xc0"
		self.AsmCache["xchg rax,r9"] = b"\x4c\x87\xc8"
		self.AsmCache["xchg rax,r10"] = b"\x4c\x87\xd0"
		self.AsmCache["xchg rax,r11"] = b"\x4c\x87\xd8"
		self.AsmCache["xchg rax,r12"] = b"\x4c\x87\xe0"
		self.AsmCache["xchg rax,r13"] = b"\x4c\x87\xe8"
		self.AsmCache["xchg rax,r14"] = b"\x4c\x87\xf0"
		self.AsmCache["xchg rax,r15"] = b"\x4c\x87\xf8"
		self.AsmCache["xchg rcx,rax"] = b"\x48\x87\xc1"
		self.AsmCache["xchg rcx,rdx"] = b"\x48\x87\xd1"
		self.AsmCache["xchg rcx,rbx"] = b"\x48\x87\xd9"
		self.AsmCache["xchg rcx,rsp"] = b"\x48\x87\xe1"
		self.AsmCache["xchg rcx,rbp"] = b"\x48\x87\xe9"
		self.AsmCache["xchg rcx,rsi"] = b"\x48\x87\xf1"
		self.AsmCache["xchg rcx,rdi"] = b"\x48\x87\xf9"
		self.AsmCache["xchg rcx,r8"] = b"\x4c\x87\xc1"
		self.AsmCache["xchg rcx,r9"] = b"\x4c\x87\xc9"
		self.AsmCache["xchg rcx,r10"] = b"\x4c\x87\xd1"
		self.AsmCache["xchg rcx,r11"] = b"\x4c\x87\xd9"
		self.AsmCache["xchg rcx,r12"] = b"\x4c\x87\xe1"
		self.AsmCache["xchg rcx,r13"] = b"\x4c\x87\xe9"
		self.AsmCache["xchg rcx,r14"] = b"\x4c\x87\xf1"
		self.AsmCache["xchg rcx,r15"] = b"\x4c\x87\xf9"
		self.AsmCache["xchg rdx,rax"] = b"\x48\x87\xc2"
		self.AsmCache["xchg rdx,rcx"] = b"\x48\x87\xca"
		self.AsmCache["xchg rdx,rbx"] = b"\x48\x87\xda"
		self.AsmCache["xchg rdx,rsp"] = b"\x48\x87\xe2"
		self.AsmCache["xchg rdx,rbp"] = b"\x48\x87\xea"
		self.AsmCache["xchg rdx,rsi"] = b"\x48\x87\xf2"
		self.AsmCache["xchg rdx,rdi"] = b"\x48\x87\xfa"
		self.AsmCache["xchg rdx,r8"] = b"\x4c\x87\xc2"
		self.AsmCache["xchg rdx,r9"] = b"\x4c\x87\xca"
		self.AsmCache["xchg rdx,r10"] = b"\x4c\x87\xd2"
		self.AsmCache["xchg rdx,r11"] = b"\x4c\x87\xda"
		self.AsmCache["xchg rdx,r12"] = b"\x4c\x87\xe2"
		self.AsmCache["xchg rdx,r13"] = b"\x4c\x87\xea"
		self.AsmCache["xchg rdx,r14"] = b"\x4c\x87\xf2"
		self.AsmCache["xchg rdx,r15"] = b"\x4c\x87\xfa"
		self.AsmCache["xchg rbx,rax"] = b"\x48\x87\xc3"
		self.AsmCache["xchg rbx,rcx"] = b"\x48\x87\xcb"
		self.AsmCache["xchg rbx,rdx"] = b"\x48\x87\xd3"
		self.AsmCache["xchg rbx,rsp"] = b"\x48\x87\xe3"
		self.AsmCache["xchg rbx,rbp"] = b"\x48\x87\xeb"
		self.AsmCache["xchg rbx,rsi"] = b"\x48\x87\xf3"
		self.AsmCache["xchg rbx,rdi"] = b"\x48\x87\xfb"
		self.AsmCache["xchg rbx,r8"] = b"\x4c\x87\xc3"
		self.AsmCache["xchg rbx,r9"] = b"\x4c\x87\xcb"
		self.AsmCache["xchg rbx,r10"] = b"\x4c\x87\xd3"
		self.AsmCache["xchg rbx,r11"] = b"\x4c\x87\xdb"
		self.AsmCache["xchg rbx,r12"] = b"\x4c\x87\xe3"
		self.AsmCache["xchg rbx,r13"] = b"\x4c\x87\xeb"
		self.AsmCache["xchg rbx,r14"] = b"\x4c\x87\xf3"
		self.AsmCache["xchg rbx,r15"] = b"\x4c\x87\xfb"
		self.AsmCache["xchg rsp,rax"] = b"\x48\x87\xc4"
		self.AsmCache["xchg rsp,rcx"] = b"\x48\x87\xcc"
		self.AsmCache["xchg rsp,rdx"] = b"\x48\x87\xd4"
		self.AsmCache["xchg rsp,rbx"] = b"\x48\x87\xdc"
		self.AsmCache["xchg rsp,rbp"] = b"\x48\x87\xec"
		self.AsmCache["xchg rsp,rsi"] = b"\x48\x87\xf4"
		self.AsmCache["xchg rsp,rdi"] = b"\x48\x87\xfc"
		self.AsmCache["xchg rsp,r8"] = b"\x4c\x87\xc4"
		self.AsmCache["xchg rsp,r9"] = b"\x4c\x87\xcc"
		self.AsmCache["xchg rsp,r10"] = b"\x4c\x87\xd4"
		self.AsmCache["xchg rsp,r11"] = b"\x4c\x87\xdc"
		self.AsmCache["xchg rsp,r12"] = b"\x4c\x87\xe4"
		self.AsmCache["xchg rsp,r13"] = b"\x4c\x87\xec"
		self.AsmCache["xchg rsp,r14"] = b"\x4c\x87\xf4"
		self.AsmCache["xchg rsp,r15"] = b"\x4c\x87\xfc"
		self.AsmCache["xchg rbp,rax"] = b"\x48\x87\xc5"
		self.AsmCache["xchg rbp,rcx"] = b"\x48\x87\xcd"
		self.AsmCache["xchg rbp,rdx"] = b"\x48\x87\xd5"
		self.AsmCache["xchg rbp,rbx"] = b"\x48\x87\xdd"
		self.AsmCache["xchg rbp,rsp"] = b"\x48\x87\xe5"
		self.AsmCache["xchg rbp,rsi"] = b"\x48\x87\xf5"
		self.AsmCache["xchg rbp,rdi"] = b"\x48\x87\xfd"
		self.AsmCache["xchg rbp,r8"] = b"\x4c\x87\xc5"
		self.AsmCache["xchg rbp,r9"] = b"\x4c\x87\xcd"
		self.AsmCache["xchg rbp,r10"] = b"\x4c\x87\xd5"
		self.AsmCache["xchg rbp,r11"] = b"\x4c\x87\xdd"
		self.AsmCache["xchg rbp,r12"] = b"\x4c\x87\xe5"
		self.AsmCache["xchg rbp,r13"] = b"\x4c\x87\xed"
		self.AsmCache["xchg rbp,r14"] = b"\x4c\x87\xf5"
		self.AsmCache["xchg rbp,r15"] = b"\x4c\x87\xfd"
		self.AsmCache["xchg rsi,rax"] = b"\x48\x87\xc6"
		self.AsmCache["xchg rsi,rcx"] = b"\x48\x87\xce"
		self.AsmCache["xchg rsi,rdx"] = b"\x48\x87\xd6"
		self.AsmCache["xchg rsi,rbx"] = b"\x48\x87\xde"
		self.AsmCache["xchg rsi,rsp"] = b"\x48\x87\xe6"
		self.AsmCache["xchg rsi,rbp"] = b"\x48\x87\xee"
		self.AsmCache["xchg rsi,rdi"] = b"\x48\x87\xfe"
		self.AsmCache["xchg rsi,r8"] = b"\x4c\x87\xc6"
		self.AsmCache["xchg rsi,r9"] = b"\x4c\x87\xce"
		self.AsmCache["xchg rsi,r10"] = b"\x4c\x87\xd6"
		self.AsmCache["xchg rsi,r11"] = b"\x4c\x87\xde"
		self.AsmCache["xchg rsi,r12"] = b"\x4c\x87\xe6"
		self.AsmCache["xchg rsi,r13"] = b"\x4c\x87\xee"
		self.AsmCache["xchg rsi,r14"] = b"\x4c\x87\xf6"
		self.AsmCache["xchg rsi,r15"] = b"\x4c\x87\xfe"
		self.AsmCache["xchg rdi,rax"] = b"\x48\x87\xc7"
		self.AsmCache["xchg rdi,rcx"] = b"\x48\x87\xcf"
		self.AsmCache["xchg rdi,rdx"] = b"\x48\x87\xd7"
		self.AsmCache["xchg rdi,rbx"] = b"\x48\x87\xdf"
		self.AsmCache["xchg rdi,rsp"] = b"\x48\x87\xe7"
		self.AsmCache["xchg rdi,rbp"] = b"\x48\x87\xef"
		self.AsmCache["xchg rdi,rsi"] = b"\x48\x87\xf7"
		self.AsmCache["xchg rdi,r8"] = b"\x4c\x87\xc7"
		self.AsmCache["xchg rdi,r9"] = b"\x4c\x87\xcf"
		self.AsmCache["xchg rdi,r10"] = b"\x4c\x87\xd7"
		self.AsmCache["xchg rdi,r11"] = b"\x4c\x87\xdf"
		self.AsmCache["xchg rdi,r12"] = b"\x4c\x87\xe7"
		self.AsmCache["xchg rdi,r13"] = b"\x4c\x87\xef"
		self.AsmCache["xchg rdi,r14"] = b"\x4c\x87\xf7"
		self.AsmCache["xchg rdi,r15"] = b"\x4c\x87\xff"
		self.AsmCache["xchg r8,rax"] = b"\x49\x87\xc0"
		self.AsmCache["xchg r8,rcx"] = b"\x49\x87\xc8"
		self.AsmCache["xchg r8,rdx"] = b"\x49\x87\xd0"
		self.AsmCache["xchg r8,rbx"] = b"\x49\x87\xd8"
		self.AsmCache["xchg r8,rsp"] = b"\x49\x87\xe0"
		self.AsmCache["xchg r8,rbp"] = b"\x49\x87\xe8"
		self.AsmCache["xchg r8,rsi"] = b"\x49\x87\xf0"
		self.AsmCache["xchg r8,rdi"] = b"\x49\x87\xf8"
		self.AsmCache["xchg r8,r9"] = b"\x4d\x87\xc8"
		self.AsmCache["xchg r8,r10"] = b"\x4d\x87\xd0"
		self.AsmCache["xchg r8,r11"] = b"\x4d\x87\xd8"
		self.AsmCache["xchg r8,r12"] = b"\x4d\x87\xe0"
		self.AsmCache["xchg r8,r13"] = b"\x4d\x87\xe8"
		self.AsmCache["xchg r8,r14"] = b"\x4d\x87\xf0"
		self.AsmCache["xchg r8,r15"] = b"\x4d\x87\xf8"
		self.AsmCache["xchg r9,rax"] = b"\x49\x87\xc1"
		self.AsmCache["xchg r9,rcx"] = b"\x49\x87\xc9"
		self.AsmCache["xchg r9,rdx"] = b"\x49\x87\xd1"
		self.AsmCache["xchg r9,rbx"] = b"\x49\x87\xd9"
		self.AsmCache["xchg r9,rsp"] = b"\x49\x87\xe1"
		self.AsmCache["xchg r9,rbp"] = b"\x49\x87\xe9"
		self.AsmCache["xchg r9,rsi"] = b"\x49\x87\xf1"
		self.AsmCache["xchg r9,rdi"] = b"\x49\x87\xf9"
		self.AsmCache["xchg r9,r8"] = b"\x4d\x87\xc1"
		self.AsmCache["xchg r9,r10"] = b"\x4d\x87\xd1"
		self.AsmCache["xchg r9,r11"] = b"\x4d\x87\xd9"
		self.AsmCache["xchg r9,r12"] = b"\x4d\x87\xe1"
		self.AsmCache["xchg r9,r13"] = b"\x4d\x87\xe9"
		self.AsmCache["xchg r9,r14"] = b"\x4d\x87\xf1"
		self.AsmCache["xchg r9,r15"] = b"\x4d\x87\xf9"
		self.AsmCache["xchg r10,rax"] = b"\x49\x87\xc2"
		self.AsmCache["xchg r10,rcx"] = b"\x49\x87\xca"
		self.AsmCache["xchg r10,rdx"] = b"\x49\x87\xd2"
		self.AsmCache["xchg r10,rbx"] = b"\x49\x87\xda"
		self.AsmCache["xchg r10,rsp"] = b"\x49\x87\xe2"
		self.AsmCache["xchg r10,rbp"] = b"\x49\x87\xea"
		self.AsmCache["xchg r10,rsi"] = b"\x49\x87\xf2"
		self.AsmCache["xchg r10,rdi"] = b"\x49\x87\xfa"
		self.AsmCache["xchg r10,r8"] = b"\x4d\x87\xc2"
		self.AsmCache["xchg r10,r9"] = b"\x4d\x87\xca"
		self.AsmCache["xchg r10,r11"] = b"\x4d\x87\xda"
		self.AsmCache["xchg r10,r12"] = b"\x4d\x87\xe2"
		self.AsmCache["xchg r10,r13"] = b"\x4d\x87\xea"
		self.AsmCache["xchg r10,r14"] = b"\x4d\x87\xf2"
		self.AsmCache["xchg r10,r15"] = b"\x4d\x87\xfa"
		self.AsmCache["xchg r11,rax"] = b"\x49\x87\xc3"
		self.AsmCache["xchg r11,rcx"] = b"\x49\x87\xcb"
		self.AsmCache["xchg r11,rdx"] = b"\x49\x87\xd3"
		self.AsmCache["xchg r11,rbx"] = b"\x49\x87\xdb"
		self.AsmCache["xchg r11,rsp"] = b"\x49\x87\xe3"
		self.AsmCache["xchg r11,rbp"] = b"\x49\x87\xeb"
		self.AsmCache["xchg r11,rsi"] = b"\x49\x87\xf3"
		self.AsmCache["xchg r11,rdi"] = b"\x49\x87\xfb"
		self.AsmCache["xchg r11,r8"] = b"\x4d\x87\xc3"
		self.AsmCache["xchg r11,r9"] = b"\x4d\x87\xcb"
		self.AsmCache["xchg r11,r10"] = b"\x4d\x87\xd3"
		self.AsmCache["xchg r11,r12"] = b"\x4d\x87\xe3"
		self.AsmCache["xchg r11,r13"] = b"\x4d\x87\xeb"
		self.AsmCache["xchg r11,r14"] = b"\x4d\x87\xf3"
		self.AsmCache["xchg r11,r15"] = b"\x4d\x87\xfb"
		self.AsmCache["xchg r12,rax"] = b"\x49\x87\xc4"
		self.AsmCache["xchg r12,rcx"] = b"\x49\x87\xcc"
		self.AsmCache["xchg r12,rdx"] = b"\x49\x87\xd4"
		self.AsmCache["xchg r12,rbx"] = b"\x49\x87\xdc"
		self.AsmCache["xchg r12,rsp"] = b"\x49\x87\xe4"
		self.AsmCache["xchg r12,rbp"] = b"\x49\x87\xec"
		self.AsmCache["xchg r12,rsi"] = b"\x49\x87\xf4"
		self.AsmCache["xchg r12,rdi"] = b"\x49\x87\xfc"
		self.AsmCache["xchg r12,r8"] = b"\x4d\x87\xc4"
		self.AsmCache["xchg r12,r9"] = b"\x4d\x87\xcc"
		self.AsmCache["xchg r12,r10"] = b"\x4d\x87\xd4"
		self.AsmCache["xchg r12,r11"] = b"\x4d\x87\xdc"
		self.AsmCache["xchg r12,r13"] = b"\x4d\x87\xec"
		self.AsmCache["xchg r12,r14"] = b"\x4d\x87\xf4"
		self.AsmCache["xchg r12,r15"] = b"\x4d\x87\xfc"
		self.AsmCache["xchg r13,rax"] = b"\x49\x87\xc5"
		self.AsmCache["xchg r13,rcx"] = b"\x49\x87\xcd"
		self.AsmCache["xchg r13,rdx"] = b"\x49\x87\xd5"
		self.AsmCache["xchg r13,rbx"] = b"\x49\x87\xdd"
		self.AsmCache["xchg r13,rsp"] = b"\x49\x87\xe5"
		self.AsmCache["xchg r13,rbp"] = b"\x49\x87\xed"
		self.AsmCache["xchg r13,rsi"] = b"\x49\x87\xf5"
		self.AsmCache["xchg r13,rdi"] = b"\x49\x87\xfd"
		self.AsmCache["xchg r13,r8"] = b"\x4d\x87\xc5"
		self.AsmCache["xchg r13,r9"] = b"\x4d\x87\xcd"
		self.AsmCache["xchg r13,r10"] = b"\x4d\x87\xd5"
		self.AsmCache["xchg r13,r11"] = b"\x4d\x87\xdd"
		self.AsmCache["xchg r13,r12"] = b"\x4d\x87\xe5"
		self.AsmCache["xchg r13,r14"] = b"\x4d\x87\xf5"
		self.AsmCache["xchg r13,r15"] = b"\x4d\x87\xfd"
		self.AsmCache["xchg r14,rax"] = b"\x49\x87\xc6"
		self.AsmCache["xchg r14,rcx"] = b"\x49\x87\xce"
		self.AsmCache["xchg r14,rdx"] = b"\x49\x87\xd6"
		self.AsmCache["xchg r14,rbx"] = b"\x49\x87\xde"
		self.AsmCache["xchg r14,rsp"] = b"\x49\x87\xe6"
		self.AsmCache["xchg r14,rbp"] = b"\x49\x87\xee"
		self.AsmCache["xchg r14,rsi"] = b"\x49\x87\xf6"
		self.AsmCache["xchg r14,rdi"] = b"\x49\x87\xfe"
		self.AsmCache["xchg r14,r8"] = b"\x4d\x87\xc6"
		self.AsmCache["xchg r14,r9"] = b"\x4d\x87\xce"
		self.AsmCache["xchg r14,r10"] = b"\x4d\x87\xd6"
		self.AsmCache["xchg r14,r11"] = b"\x4d\x87\xde"
		self.AsmCache["xchg r14,r12"] = b"\x4d\x87\xe6"
		self.AsmCache["xchg r14,r13"] = b"\x4d\x87\xee"
		self.AsmCache["xchg r14,r15"] = b"\x4d\x87\xfe"
		self.AsmCache["xchg r15,rax"] = b"\x49\x87\xc7"
		self.AsmCache["xchg r15,rcx"] = b"\x49\x87\xcf"
		self.AsmCache["xchg r15,rdx"] = b"\x49\x87\xd7"
		self.AsmCache["xchg r15,rbx"] = b"\x49\x87\xdf"
		self.AsmCache["xchg r15,rsp"] = b"\x49\x87\xe7"
		self.AsmCache["xchg r15,rbp"] = b"\x49\x87\xef"
		self.AsmCache["xchg r15,rsi"] = b"\x49\x87\xf7"
		self.AsmCache["xchg r15,rdi"] = b"\x49\x87\xff"
		self.AsmCache["xchg r15,r8"] = b"\x4d\x87\xc7"
		self.AsmCache["xchg r15,r9"] = b"\x4d\x87\xcf"
		self.AsmCache["xchg r15,r10"] = b"\x4d\x87\xd7"
		self.AsmCache["xchg r15,r11"] = b"\x4d\x87\xdf"
		self.AsmCache["xchg r15,r12"] = b"\x4d\x87\xe7"
		self.AsmCache["xchg r15,r13"] = b"\x4d\x87\xef"
		self.AsmCache["xchg r15,r14"] = b"\x4d\x87\xf7"



		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		for offset in xrange(4,80,4):
			thisasm = b"\x83\xc4" + hex2bin("%02x" % offset)
			self.AsmCache["add esp,%02x" % offset] = thisasm
			self.AsmCache["add esp,%x" % offset] = thisasm
			thisasm64 = b"\x48\x83\xc4" + hex2bin("%02x" % offset)
			self.AsmCache["add rsp,%02x" % offset] = thisasm64
			self.AsmCache["add rsp,%x" % offset] = thisasm64

		# ------------------------------------------------------------
		# ADD reg,imm8 (64-bit)
		# 48 83 /0 ib  (imm8 sign-extended)
		# Build cache for add r64, 4..100 (increment 1)
		# ------------------------------------------------------------
		for offset in xrange(4,101,1):
			for regName in Registers64BitsOrder:
				regIndex = regEnc64[regName]
				rex = 0x48 | (0x01 if (regIndex & 8) == 8 else 0x00)  # REX.W (+ REX.B for r8-r15)
				modrm = 0xC0 | (regIndex & 7)  # /0, mod=11
				thisasm64 = struct.pack("BBBB", rex, 0x83, modrm, offset)
				self.AsmCache["add %s,%02x" % (regName, offset)] = thisasm64
				self.AsmCache["add %s,%x" % (regName, offset)] = thisasm64
				self.AsmCache["add %s,%d" % (regName, offset)] = thisasm64

		self.AsmCache["retn"] = b"\xc3"
		self.AsmCache["retf"] = b"\xdb"
		for offset in xrange(0,80,2):
			thisasm = b"\xc2" + hex2bin("%02x" % offset) + b"\x00"
			self.AsmCache["retn %02x" % offset] = thisasm
			self.AsmCache["retn %x" % offset] = thisasm
			self.AsmCache["retn 0x%02x" % offset] = thisasm
		return

	"""
	Knowledge
	"""
	def addKnowledge(self, id, object, force_add = 0):
		dbgp(get_current_function_name())
		
		allk = self.readKnowledgeDB()
		if not id in allk:	
			allk[id] = object
		else:
			if object.__class__.__name__ == "dict":
				for odictkey in object:
					allk[id][odictkey] = object[odictkey] 
		with open(self.knowledgedb,"wb") as fh:
			pickle.dump(allk,fh,-1)
		return

	def getKnowledge(self,id):
		dbgp(get_current_function_name())

		allk = self.readKnowledgeDB()
		if id in allk:
			return allk[id]
		else:
			return None

	def readKnowledgeDB(self):
		dbgp(get_current_function_name())

		allk = {}
		try:
			with open(self.knowledgedb,"rb") as fh:
				allk = pickle.load(fh)
		except:
			pass
		return allk

	def listKnowledge(self):
		dbgp(get_current_function_name())

		allk = self.readKnowledgeDB()
		allid = []
		for thisk in allk:
			allid.append(thisk)
		return allid

	def cleanKnowledge(self):
		dbgp(get_current_function_name())

		try:
			os.remove(self.knowledgedb)
		except:
			try:	
				with open(self.knowledgedb,"wb") as fh:
					pickle.dump({},fh,-1)
			except:
				pass
			pass
		return

	def forgetKnowledge(self,id,entry=""):
		dbgp(get_current_function_name())

		allk = self.readKnowledgeDB()
		if entry == "":
			if id in allk:
				del allk[id]
		else:
			# find the entry
			if id in allk:
				thisidkb = allk[id]
				if entry in thisidkb:
					del thisidkb[entry]
				allk[id] = thisidkb
		with open(self.knowledgedb,"wb") as fh:
			pickle.dump(allk,fh,-1)
		return

	"""
	LOGGING
	"""
	def toAsciiOnly(self, message):

		message = ensure_text(message)
		newchar = []
		for thischar in message:
			if ord(thischar) >= 20 and ord(thischar) <= 126:
				newchar.append(thischar)
			else:
				newchar.append(".")
		return "".join(newchar)

	def createLogWindow(self):
		dbgp(get_current_function_name())

		return
	
	def log(self, message="", highlight=0, address=None, focus=0):
		if not address == None:
			message = intToHex(address) + " | " + message
		showdml = False
		if "link cmd" in message:
			showdml = True
		if highlight == 1:
			showdml = True
			message = "<b>" + message + "</b>"
		else:
			if "<b>" in message and "</b>" in message:
				showdml = True
		pykd.dprintln(self.toAsciiOnly(message), showdml)


	def logLines(self, message="", highlight=0, address=None, focus=0):
		allLines = message.split('\n')
		linecnt = 0
		messageprefix = ""
		if not address == None:
			messageprefix = " " * 10
			messageprefix += " | "
		for line in allLines:
			if linecnt == 0:
				self.log(line,highlight,address)
			else:
				self.log(messageprefix+line,highlight)
			linecnt += 1

	def updateLog(self):
		return
		
	def setStatusBar(self, message):
		return
		
	def error(self, message):
		return
		
		
	"""
	Process stuff
	"""
	
	def getDebuggedName(self):
		dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		# http://www.nirsoft.net/kernel_struct/vista/RTL_USER_PROCESS_PARAMETERS.html
		peb = self.get_peb_addr()
		ProcessParameters = pykd.ptrPtr(peb + PEB_PROCESS_PARAMETERS[_arch_idx])
		# _RTL_USER_PROCESS_PARAMETERS.ImagePathName(_UNICODE_STRING)
		offset = 0x60 if arch == 64 else 0x38
		sImageFile = ensure_text(pykd.loadUnicodeString(int(ProcessParameters) + offset))
		sImageFilepieces = sImageFile.split("\\")
		return sImageFilepieces[len(sImageFilepieces)-1]
		
	def getDebuggedPid(self):
		dbgp(get_current_function_name())

		global currentPID
		teb = self.get_teb_addr()

		# Prefer debugger engine PID for the current implicit process.
		try:
			pid_from_engine = int(pykd.getProcessSystemID())
		except:
			pid_from_engine = 0

		pid_from_teb = 0
		try:
			pid_from_teb = int(pykd.ptrDWord(teb + TEB_CLIENT_ID_PROCESS[_arch_idx]))
		except:
			pid_from_teb = 0

		if pid_from_engine != 0:
			currentPID = pid_from_engine
		elif pid_from_teb != 0:
			currentPID = pid_from_teb
		else:
			currentPID = 0

		return currentPID

	
	"""
	OS stuff
	"""
	def getOsRelease(self):
		dbgp(get_current_function_name())

		peb = self.get_peb_addr()
		majorversion = int(pykd.ptrDWord(peb + PEB_OS_MAJOR_VERSION[_arch_idx]))
		minorversion = int(pykd.ptrDWord(peb + PEB_OS_MINOR_VERSION[_arch_idx]))
		buildversion = int(pykd.ptrWord(peb + PEB_OS_BUILD_NUMBER[_arch_idx]))
		osversion = str(majorversion)+"."+str(minorversion)+"."+str(buildversion)
		return osversion
	
	def getOsVersion(self):
		return getOSVersion()

	def getPyKDVersionNr(self):
		return getPyKDVersion()

	def getTypeSize(self, typename):
		"""Get the size of a type from debugger symbols.

		Arguments:
			typename - str, qualified type name (e.g. 'ntdll!_PEB')

		Return:
			int - size in bytes, or 0 if type info is unavailable
		"""
		try:
			return pykd.typeInfo(typename).size()
		except:
			return 0
		
	"""
	Registers
	"""
	
	def getRegs(self):
		dbgp(get_current_function_name())

		regs = []
		if arch == 32:
			regs = Registers32BitsOrder[:]
			regs.append("eip")
		if arch == 64:
			regs = Registers64BitsOrder[:]
			regs.append("rip")
		reginfo = {}
		for thisreg in regs:
			reginfo[thisreg.lower()] = int(pykd.reg(thisreg.lower()))
		return reginfo
	

	"""
	Commands
	"""
	def nativeCommand(self,cmd2run):
		# nativecommands are heavy
		# keep statistics
		if DEBUG_MODE:
			funcname = get_current_function_name()
			dbgp(funcname)
			global NativeCommandCache
			if not cmd2run in NativeCommandCache:
				NativeCommandCache[cmd2run] = [funcname]
			else:
				NativeCommandCache[cmd2run].append(funcname)

		try:
			dbgp("nativeCommand: %s" % cmd2run)
			output = pykd.dbgCommand(cmd2run)
			dbgp("command output: %s" % output)
			if output is None:
				output = ""
			dbgp("returning '%s'" % output)
			return output
		except Exception as e:
			dbgp("Error executing command '%s': %s" % (cmd2run, str(e)), errormode=False)
			dbgp("%s" % traceback.format_exc(), errormode=False)
			return ""

	def getNativeCommandStatistics(self, minval=1):
		dbgp(get_current_function_name())
		global NativeCommandCache

		if not NativeCommandCache:
			dbgp("No nativeCommand statistics available")
			return

		dbgp("nativeCommand statistics (commands called more than %d times)" % minval)
		dbgp("-" * 80)

		stats = []
		for cmd2run, callers in NativeCommandCache.items():
			total_calls = len(callers)
			if total_calls <= minval:
				continue

			per_caller = {}
			for caller in callers:
				if caller not in per_caller:
					per_caller[caller] = 0
				per_caller[caller] += 1

			stats.append((total_calls, cmd2run, per_caller))

		if len(stats) == 0:
			dbgp("No nativeCommand entries matched the minimum threshold")
			return

		stats.sort(key=lambda item: (-item[0], item[1]))

		for total_calls, cmd2run, per_caller in stats:
			dbgp("[%d] %s" % (total_calls, cmd2run))
			caller_stats = sorted(per_caller.items(), key=lambda item: (-item[1], item[0]))
			for caller, caller_count in caller_stats:
				dbgp("    - %d x %s" % (caller_count, caller))
		dbgp("-" * 80)


	"""
	SEH
	"""

	def getSehChain(self):
		dbgp(get_current_function_name())
	
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/NT_TIB.html
		# http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_REGISTRATION_RECORD.html

		# x64 has no SEH chain
		if arch == 64:
			return []
		sehchain = []
		# get top of chain
		teb = self.get_teb_addr()
		# _TEB.NtTib(NT_TIB).ExceptionList(PEXCEPTION_REGISTRATION_RECORD)
		nextrecord = pykd.ptrPtr(teb)
		validrecord = True
		while nextrecord != 0xffffffff and pykd.isValid(nextrecord):
			# _EXCEPTION_REGISTRATION_RECORD.Next(PEXCEPTION_REGISTRATION_RECORD)
			nseh = pykd.ptrPtr(nextrecord)
			# _EXCEPTION_REGISTRATION_RECORD.Handler(PEXCEPTION_DISPOSITION)
			seh = pykd.ptrPtr(nextrecord+4)
			sehrecord = [nextrecord,seh]
			sehchain.append(sehrecord)
			nextrecord = nseh
		return sehchain
	
	"""
	Memory
	"""

	def readMemory(self, location, size):
		try:
			data = bytes(bytearray(pykd.loadBytes(location, size)))
			return ensure_bytes(data)
		except:
			return ensure_bytes(b"")

	def readString(self,location):
		#dbgp("readString(%s) called" % (PTR_PRINT % location))
		if pykd.isValid(location):
			try:
				result = pykd.loadCStr(location)
				dbgp("readString(%s) loadCStr returned %r" % (PTR_PRINT % location, result))
				return result
			except pykd.MemoryException as e:
				dbgp("readString(%s) loadCStr MemoryException: %s" % (PTR_PRINT % location, str(e)))
				try:
					result = pykd.loadChars(location, 0x100)
					dbgp("readString(%s) loadChars returned %r" % (PTR_PRINT % location, result))
					return result
				except Exception as inner_e:
					dbgp("readString(%s) loadChars exception: %s" % (PTR_PRINT % location, str(inner_e)))
					rawbytes = bytearray()
					nextloc = location
					while pykd.isValid(nextloc):
						chunk = self.readMemory(nextloc, 4)
						dbgp("readString(%s) chunk @ %s -> %s" % (PTR_PRINT % location, PTR_PRINT % nextloc, binascii.hexlify(chunk).decode('ascii') if chunk else "<empty>"))
						if not chunk:
							break
						for thisbyte in iter_byte_values(chunk):
							if thisbyte < 0x20 or thisbyte > 0x7e:
								result = ensure_text(bytes(rawbytes))
								dbgp("readString(%s) terminated on byte 0x%02x, returning %r" % (PTR_PRINT % location, thisbyte, result))
								return result
							rawbytes.append(thisbyte)
						nextloc += len(chunk)
					result = ensure_text(bytes(rawbytes))
					dbgp("readString(%s) exhausted readable memory, returning %r" % (PTR_PRINT % location, result))
					return result
			except Exception as e:
				dbgp("readString(%s) loadCStr general exception: %s" % (PTR_PRINT % location, str(e)))
				rawbytes = bytearray()
				nextloc = location
				while pykd.isValid(nextloc):
					chunk = self.readMemory(nextloc, 4)
					dbgp("readString(%s) chunk @ %s -> %s" % (PTR_PRINT % location, PTR_PRINT % nextloc, binascii.hexlify(chunk).decode('ascii') if chunk else "<empty>"))
					if not chunk:
						break
					for thisbyte in iter_byte_values(chunk):
						if thisbyte < 0x20 or thisbyte > 0x7e:
							result = ensure_text(bytes(rawbytes))
							dbgp("readString(%s) terminated on byte 0x%02x, returning %r" % (PTR_PRINT % location, thisbyte, result))
							return result
						rawbytes.append(thisbyte)
					nextloc += len(chunk)
				result = ensure_text(bytes(rawbytes))
				dbgp("readString(%s) exhausted readable memory, returning %r" % (PTR_PRINT % location, result))
				return result
		else:
			dbgp("readString(%s) invalid address" % (PTR_PRINT % location))
			return ""

	def readWString(self,location):
		if pykd.isValid(location):
			try:
				return pykd.loadWStr(location)
			except pykd.MemoryException:
				return pykd.loadWChars(location, 0x100)
			except:
				return ""
		return


	def readUntil(self,start,end):
		if start > end:
			tmp = start
			start = end
			end = tmp
		size = end-start
		return self.readMemory(start,size)

	def readLong(self,location):
		return pykd.ptrDWord(location)


	def writeMemory(self, location, data):
		dbgp(get_current_function_name())

		data = ensure_bytes(data)

		pykd.writeBytes(location, list(bytearray(data)))
		return

	def writeLong(self,location,dword):
		bytesdword = hexptr2bin(dword)
		self.writeMemory(location,bytesdword)
		return


	def getMemoryPages(self):
		dbgp(get_current_function_name())

		if not self.MemoryPages:
			# Prefer VirtualQueryEx so recent VirtualAlloc/VirtualProtect changes
			# are reflected immediately and independently from !address formatting.
			self.MemoryPages = self._getMemoryPagesVQE()

			# Fallback to !address parsing if VirtualQueryEx path fails.
			if not self.MemoryPages:
				address_output = pykd.dbgCommand("!address")
				if address_output is None:
					address_output = ""
				address_output_lines = address_output.splitlines()

				row_regex = re.compile(
					r'^\s*\+?\s*'                    # optional leading "+"
					r'([0-9A-Fa-f`]+)\s+'            # BaseAddress
					r'([0-9A-Fa-f`]+)\s+'            # EndAddress+1
					r'([0-9A-Fa-f`]+)\s+'            # RegionSize
					r'(\S*)\s+'                      # Type (may be blank)
					r'(\S*)\s+'                      # State (may be blank)
					r'(\S*)\s+'                      # Protect (may be blank)
					r'(.+?)\s*$'                     # Usage (rest of line)
				)

				for memory_page_info in address_output_lines:
					memory_page_info = memory_page_info.rstrip()
					m = row_regex.match(memory_page_info)
					if not m:
						continue

					starting_address = int(m.group(1).replace('`', ''), 16)
					size = int(m.group(3).replace('`', ''), 16)
					pageusage = m.group(7).strip()

					page_obj = wpage(starting_address, size, pageusage)
					self.MemoryPages[starting_address] = page_obj

		return self.MemoryPages

	def _getMemoryPagesVQE(self):
		"""Enumerate memory pages via VirtualQueryEx (ctypes).

		Enumerates all regions (Free/Reserve/Commit) and annotates a basic usage.
		"""
		dbgp(get_current_function_name())

		pages = {}
		kernel32 = ctypes.windll.kernel32

		PROCESS_QUERY_INFORMATION = 0x0400
		PROCESS_VM_READ = 0x0010
		pid = self.getDebuggedPid()
		hprocess = kernel32.OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
		if not hprocess:
			return pages

		class MEMORY_BASIC_INFORMATION(ctypes.Structure):
			_fields_ = [
				("BaseAddress",       ctypes.c_void_p),
				("AllocationBase",    ctypes.c_void_p),
				("AllocationProtect", ctypes.c_ulong),
				("RegionSize",        ctypes.c_size_t),
				("State",             ctypes.c_ulong),
				("Protect",           ctypes.c_ulong),
				("Type",              ctypes.c_ulong),
			]

		MEM_COMMIT = 0x1000
		MEM_RESERVE = 0x2000
		MEM_FREE = 0x10000
		MEM_PRIVATE = 0x20000
		MEM_MAPPED = 0x40000
		MEM_IMAGE = 0x1000000
		mbi = MEMORY_BASIC_INFORMATION()
		mbi_size = ctypes.sizeof(mbi)
		address = 0

		kernel32.VirtualQueryEx.argtypes = [
			ctypes.c_void_p, ctypes.c_void_p,
			ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
		kernel32.VirtualQueryEx.restype = ctypes.c_size_t

		try:
			while True:
				result = kernel32.VirtualQueryEx(
					ctypes.c_void_p(hprocess),
					ctypes.c_void_p(address),
					ctypes.byref(mbi), mbi_size)
				if result == 0:
					break

				if mbi.RegionSize > 0:
					base = int(mbi.BaseAddress) if mbi.BaseAddress else 0
					usage = ""
					if mbi.State == MEM_FREE:
						usage = "Free"
					elif mbi.State == MEM_RESERVE:
						usage = "Reserve"
					elif mbi.State == MEM_COMMIT:
						if mbi.Type == MEM_IMAGE:
							usage = "Image"
						elif mbi.Type == MEM_MAPPED:
							usage = "Mapped"
						elif mbi.Type == MEM_PRIVATE:
							usage = "Private"
						else:
							usage = "Commit"

					page_obj = wpage(base, int(mbi.RegionSize), usage)
					if mbi.State == MEM_COMMIT and mbi.Protect != 0:
						page_obj.protect = int(mbi.Protect)
					elif mbi.State == MEM_RESERVE and mbi.AllocationProtect != 0:
						page_obj.protect = int(mbi.AllocationProtect)
					else:
						page_obj.protect = 0x1
					pages[base] = page_obj

				address += mbi.RegionSize
				if address > TOP_USERLAND:
					break
		finally:
			kernel32.CloseHandle(ctypes.c_void_p(hprocess))

		return pages



	def getMemoryPageByAddress(self,address):

		if len(self.MemoryPages) == 0:
			# may never get hit
			self.MemoryPages = self.getMemoryPages()

		startaddress = self.getPageContains(address)
		if startaddress in self.MemoryPages:
			return self.MemoryPages[startaddress]
		else:
			page = wpage(startaddress,0,"")
			return page

	def getPageContains(self,address):
		if len(self.MemoryPages) == 0:
			self.MemoryPages = self.getMemoryPages()
		for pagestart in self.MemoryPages:
			thispage = self.MemoryPages[pagestart]
			pageend = pagestart + thispage.getSize()
			if address >= pagestart and address < pageend:
				return pagestart
		return 0

	def getHeapsAddress(self):
		dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		allheaps = []
		peb = self.get_peb_addr()
		try:
			nrofheaps = int(pykd.ptrDWord(peb + PEB_NUMBER_OF_HEAPS[_arch_idx]))
			processheaps = int(pykd.ptrPtr(peb + PEB_PROCESS_HEAPS[_arch_idx]))
		except:
			return allheaps

		# PEB.ProcessHeaps points into ntdll .data (RtlpProcessHeaps).
		# If ntdll is corrupted, nrofheaps or processheaps may be garbage.
		MAX_HEAPS = 1000
		if nrofheaps > MAX_HEAPS or nrofheaps < 0:
			dbgp("NumberOfHeaps looks corrupted (%d), capping at %d" % (nrofheaps, MAX_HEAPS))
			nrofheaps = MAX_HEAPS
		if processheaps == 0 or processheaps > TOP_USERLAND:
			dbgp("ProcessHeaps pointer looks corrupted (0x%x)" % processheaps)
			return allheaps

		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		ptr_size = arch // 8
		for i in xrange(nrofheaps):
			# _PEB.ProcessHeaps[i](VOID*)
			try:
				nextheap = pykd.ptrPtr(processheaps + (i * ptr_size))
			except:
				break
			if nextheap == 0x00000000:
				break
			# Validate: must be in userland and page-aligned (heaps are)
			if nextheap > TOP_USERLAND or (nextheap & 0xFFF) != 0:
				dbgp("Skipping corrupted heap pointer at index %d: 0x%x" % (i, nextheap))
				continue
			if not nextheap in allheaps:
				allheaps.append(nextheap)
		return allheaps


	def getHeap(self,address):
		dbgp(get_current_function_name())

		return wheap(address)

	def getAllThreads(self):
		dbgp(get_current_function_name())

		allthreads = []
		seen_tebs = set()

		try:
			for thisthread in pykd.getProcessThreads():
				teb = 0
				try:
					candidate = int(thisthread)
				except Exception:
					candidate = 0
				if candidate > 0 and pykd.isValid(candidate):
					try:
						# A real TEB should expose a valid PEB pointer at the known offset.
						pykd.ptrPtr(candidate + TEB_PEB[_arch_idx])
						teb = candidate
					except Exception:
						teb = 0
				if teb != 0 and teb not in seen_tebs:
					allthreads.append(_ThreadEntry(teb))
					seen_tebs.add(teb)
		except Exception as e:
			dbgp("getProcessThreads() enumeration failed: %s" % str(e))

		if len(allthreads) > 0:
			return allthreads

		try:
			thread_output = pykd.dbgCommand("~")
			for line in ensure_text(thread_output).splitlines():
				match = re.search(r"\bTeb:\s*([0-9A-Fa-f`]+)", line)
				if not match:
					continue
				try:
					teb = addrToInt(match.group(1))
				except Exception:
					teb = 0
				if teb != 0 and teb not in seen_tebs:
					allthreads.append(_ThreadEntry(teb))
					seen_tebs.add(teb)
		except Exception as e:
			dbgp("WinDBG thread list fallback failed: %s" % str(e))

		if len(allthreads) == 0:
			try:
				teb = self.get_teb_addr()
				if teb:
					allthreads.append(_ThreadEntry(teb))
			except Exception as e:
				dbgp("Current-thread fallback failed: %s" % str(e))
		return allthreads

	"""
	Modules
	"""
	def get_teb_addr(self):
		"""
		Return the TEB address for the current thread.
		Delegates to getTEBAddress() which caches in the module-level
		currentTEBAddress global. Also cached on self._teb_addr.
		"""
		if self._teb_addr is not None:
			return self._teb_addr
		self._teb_addr = getTEBAddress()
		return self._teb_addr

	def get_peb_addr(self):
		"""
		Return the PEB address.
		Delegates to getPEBAddress() which caches in the module-level
		cpebaddress global. Also cached on self._peb_addr.
		"""
		if self._peb_addr is not None:
			return self._peb_addr
		self._peb_addr = getPEBAddress()
		return self._peb_addr

	def _peb_walk(self):
		"""
		Yield (dll_base, base_name, full_path) for every entry in
		PEB.InLoadOrderModuleList using only self.readMemory.

		Results are cached in self._peb_list after the first walk.

		LDR_DATA_TABLE_ENTRY offsets:
		  x86: DllBase +0x18, FullDllName +0x24, BaseDllName +0x2C
		  x64: DllBase +0x30, FullDllName +0x48, BaseDllName +0x58
		"""
		if self._peb_list is not None:
			for entry in self._peb_list:
				yield entry
			return

		ptr_size = 8 if arch == 64 else 4
		fmt_ptr  = '<Q' if arch == 64 else '<L'

		def _ptr(addr):
			data = bytes(bytearray(self.readMemory(addr, ptr_size)))
			if len(data) < ptr_size:
				return None
			return struct.unpack(fmt_ptr, data)[0]

		def _wstr(entry, off):
			data = bytes(bytearray(self.readMemory(entry + off, 2)))
			if len(data) < 2:
				return ""
			length  = struct.unpack('<H', data)[0]
			buf_ptr = _ptr(entry + off + ptr_size)
			if not buf_ptr or length == 0:
				return ""
			raw = bytes(bytearray(self.readMemory(buf_ptr, length)))
			return raw.decode('utf-16-le', errors='replace')

		peb_addr = self.get_peb_addr()
		if peb_addr == 0:
			return
		ldr_addr = _ptr(peb_addr + PEB_LDR[_arch_idx])
		if not ldr_addr:
			results = getModulesFromDebugger()
			self._peb_list = results
			for entry in results:
				yield entry
			return
		list_head = ldr_addr + LDR_IN_LOAD_ORDER[_arch_idx]

		dll_base_off  = LDR_DLL_BASE[_arch_idx]
		full_name_off = LDR_FULL_DLL_NAME[_arch_idx]
		base_name_off = LDR_BASE_DLL_NAME[_arch_idx]

		flink = _ptr(list_head)
		results = []
		while flink and flink != list_head:
			dll_base  = _ptr(flink + dll_base_off)
			if dll_base is None:
				break
			full_path = _wstr(flink, full_name_off)
			base_name = _wstr(flink, base_name_off)
			results.append((dll_base, base_name, full_path))
			flink = _ptr(flink)
			if flink is None:
				break

		# Fallback: if PEB walk failed (e.g. ntdll corrupted), use debug engine
		if not results:
			results = getModulesFromDebugger()

		self._peb_list = results
		for entry in self._peb_list:
			yield entry

	def getModule(self, modulename, from_memory=False):
		dbgp(get_current_function_name())
		dbgp("------")
		dbgp("Transform '%s' into Module object" % modulename)

		wmod = None
		self.origmodname = modulename
		fname = os.path.splitext(modulename)[0].lower()
		try:
			dll_base = 0
			fullpath = ""
			for _base, base_name, full_path in self._peb_walk():
				bname = os.path.splitext(base_name)[0].lower()
				bname_sane = bname.replace("+","_").replace("-","_").replace(".","_")
				if bname == fname or bname_sane == fname:
					dll_base = _base
					fullpath = full_path
					break

			if dll_base == 0 and fname in self._allmodules_lower:
				return self._allmodules_lower[fname]

			if dll_base == 0:
				dbgp("Module '%s' not found via PEB walk" % modulename)
				#pykd.dprintln("I was not able to find '%s' via PEB walk" % modulename)
				return None

			thismodname = base_name if base_name else os.path.basename(fullpath)
			thismodbase = dll_base
			thismodsize = 0
			ntHeader = getNtHeaders(dll_base)
			if ntHeader is not None:
				try:
					thismodsize = int(ntHeader.OptionalHeader.SizeOfImage)
				except Exception:
					thismodsize = 0

			dbgp("       image: %s" % fullpath)
			dbgp("       name: %s"  % thismodname)
			dbgp("       begin: 0x%08x" % thismodbase)
			dbgp("       size: 0x%08x"  % thismodsize)
			dbgp("    Building wmodule for %s. Base: 0x%08x" % (thismodname, thismodbase))

			wmod = wmodule(thismodname)
			wmod.setBaseAddress(thismodbase)
			wmod.setPath(fullpath)
			wmod.setSize(thismodsize)
		except:
			pykd.dprintln("** Error trying to process module %s" % modulename)
			pykd.dprintln(traceback.format_exc())
			wmod = None

		return wmod
		

	def getAllModules(self, from_memory=False, peb_order="load"):
		dbgp(get_current_function_name())

		if len(self.allmodules) == 0:
			seen_names = []
			for dll_base, base_name, full_path in self._peb_walk():
				modulename = os.path.basename(full_path)
				imagename, _ = os.path.splitext(modulename)
				imagename = imagename.replace("+","_").replace("-","_").replace(".","_")
				if imagename in seen_names:
					imagename = imagename + "_%08x" % dll_base
				seen_names.append(imagename)
				try:
					ntHeader = getNtHeaders(dll_base)
					modsize = 0
					if ntHeader is not None:
						try:
							modsize = int(ntHeader.OptionalHeader.SizeOfImage)
						except Exception:
							modsize = 0
					wmod = wmodule(base_name if base_name else modulename)
					wmod.setBaseAddress(dll_base)
					wmod.setPath(full_path)
					wmod.setSize(modsize)
					self.allmodules[imagename] = wmod
					self._allmodules_lower[imagename.lower()] = wmod
				except:
					continue
		return self.allmodules


	def getImageNameForModule(self, modulename):
		dbgp(get_current_function_name())

		fname = os.path.splitext(modulename)[0].lower()
		try:
			for dll_base, base_name, _ in self._peb_walk():
				if os.path.splitext(base_name)[0].lower() == fname:
					return base_name
		except:
			pykd.dprintln(traceback.format_exc())
		return None

	"""
	Assembly & Disassembly related routes
	"""

	def disasm(self,address):
		return self.getOpcode(address)

	def disasmSizeOnly(self,address):
		return self.getOpcode(address)

	def disasmForward(self,address,depth=0):
		# go to correct location
		cmd2run = "u 0x%08x L%d" % (address,depth+1)
		try:
			global disasmFwCache
			global disasmFwCacheRequests
			global disasmFwCacheHits
			disasmFwCacheRequests += 1
			if cmd2run in disasmFwCache:
				disasmFwCacheHits += 1
				disasmlist = disasmFwCache[cmd2run]
			else:
				disasmlist = pykd.dbgCommand(cmd2run)
				disasmFwCache[cmd2run] = disasmlist
			disasmLinesTmp = disasmlist.split("\n")
			disasmLines = []
			for line in disasmLinesTmp:
				if line.replace(" ","") != "":
					disasmLines.append(line.lower())
			lineindex = len(disasmLines)-1
			if lineindex > -1:
				asmline = disasmLines[lineindex]
				pointer_str = asmline[0:8] if arch == 32 else asmline.replace('`', '')[0:16]
				pointer = int(pointer_str, 16)
				if pointer > address:
					return self.getOpcode(pointer)
				else:
					return self.getOpcode(address)
			else:
				return self.getOpcode(address)
		except Exception as e:
			# probably invalid instruction, so fake by returning itself
			# caller should check if address is different than what was provided
			dbgp("Error disasmForward for 0x%x: %s" % (address, str(e)), errormode=False)
			dbgp(traceback.format_exc(), errormode=False)
			return self.getOpcode(address)


	def disasmForwardAddressOnly(self,address,depth):
		# go to correct location, get address of next after current address
		return self.disasmForward(address,depth).getAddress()

	def disasmBackward(self,address,depth):
		while True:
			cmd2run = "ub 0x%08x L%d" % (address,depth)
			#dbgp("cmd2run: %s" % cmd2run)
			try:
				disasmlist = pykd.dbgCommand(cmd2run)
				disasmLinesTmp = disasmlist.split("\n")
				disasmLines = []
				for line in disasmLinesTmp:
					if line.replace(" ","") != "":
						disasmLines.append(line.lower())
				lineindex = len(disasmLines)-depth
				if lineindex > -1:
					asmline = disasmLines[lineindex]
					pointer = asmline[0:8] if arch == 32 else asmline[0:17]
					return self.getOpcode(addrToInt(pointer))
				else:
					return self.getOpcode(address)
			except Exception as e:
				dbgp("Error disassembling backwards, %s" % str(e), errormode=False)
				dbgp(traceback.format_exc(), errormode=False)
				dbgp("Depth: %d" % depth, errormode=False)
				# probably invalid instruction, so fake by returning itself
				# caller should check if address is different than what was provided
				if depth == 1:
					dbgp("Depth 1, returning opcode at 0x%x" % address, errormode=False)
					return self.getOpcode(address)
			depth -= 1


	def reg64to32(self, thisinstruction):
		subst = {}
		for reg in Registers64BitsOrder:
			if len(reg) > 2:
				regsubst = reg.replace("r","e")
				subst[reg] = regsubst

		for reg in subst:
			thisinstruction = thisinstruction.replace(reg,subst[reg])

		return thisinstruction


	def cleanInstruction(self,thisinstruction):

		thisinstruction = thisinstruction.strip(" ").lstrip(" ").lower()
		thisinstruction = thisinstruction.replace("  "," ")
		if thisinstruction.startswith("ret") and not thisinstruction.startswith("retf"):
			thisinstruction = thisinstruction.replace("retn","ret").replace("ret","retn")
		thisinstruction = thisinstruction.replace(" ,",",").replace(", ",",")
		
		return thisinstruction


	def assemble(self,instructions):
		allbytes = b""
		address = pykd.reg("eip") if arch == 32 else pykd.reg("rip")
		origbytes = b""
		read_success = True
		
		dbgp("instructions: %s" % instructions)
		

		allinstructions = instructions.lower().split("\n")
		
		dbgp("allinstructions: %s" % allinstructions)
		dbgp("origbytes: %s" % bin2hex(origbytes))

		# in most cases, we just need to assemble one instruction.  if it's cached, we don't even need to check for an address
		if len(allinstructions) == 1:
			thisinstruction = allinstructions[0]
			thisinstruction = self.cleanInstruction(thisinstruction)
			# Ensure thisinstruction is ASCII for PyKD compatibility
			if PY3:
				ascii_instruction = thisinstruction.encode('ascii', 'ignore').decode('ascii')
			else:
				ascii_instruction = thisinstruction.encode('ascii', 'ignore')
			if ascii_instruction in self.AsmCache:
				dbgp("Single instruction '%s' found in cache, returning cached bytes" % ascii_instruction)
				dbgp("Cached entry: %s" % bin2hex(self.AsmCache[ascii_instruction]))
				return self.AsmCache[ascii_instruction]


		# either not cached or more than one instruction
		# loop through all instructions
		
		ks = None
		origbytes = b""
		read_success = False
		read_size = 20 if arch == 32 else 40

		if keystoneLoaded:
			ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
			if arch == 64:
				ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
		else:
			dbgp("Keystone-engine not found, using address to assemble if needed: %s" % (PTR_PRINT % address))
			dbgp("First, make a backup of the original bytes")
			attempts = 0
			while not read_success and attempts < 2:
				if pykd.isValid(address):
					try:
						origbytes = self.readMemory(address, read_size)
						dbgp("Successfully made a backup of the original bytes at address %s" % (PTR_PRINT % address))
						read_success = True
					except Exception as e:
						dbgp("Failed to read from valid address %s: %s" % (PTR_PRINT % address, str(e)), errormode=False)
						# If read fails, use fallback address
						read_success = False
				else:
					read_success = False

				if not read_success or origbytes == b"":
					dbgp("Selecting fallback address. Previous address (%s) didn't work" % (PTR_PRINT))
					thismod = pykd.module("ntdll")
					thismodbase = thismod.begin()
					ntHeader = getNtHeaders(thismodbase)
					entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
					
					# Only add 0x1000 if entrypoint is 0
					if entrypoint == 0:
						address = thismodbase + 0x1000
						dbgp("Fallback address set to: %s (module base: %s + 0x1000, entrypoint was 0)" % (PTR_PRINT % address, PTR_PRINT % thismodbase))
					else:
						address = thismodbase + entrypoint
						dbgp("Fallback address set to: %s (module base: %s + entrypoint: %s)" % (PTR_PRINT % address, PTR_PRINT % thismodbase, intToHex(entrypoint)))
					
					try:
						origbytes = self.readMemory(address, read_size)
						dbgp("Successfully read from fallback address %s" % (PTR_PRINT % address))
						read_success = True
					except Exception as e:
						dbgp("Failed to read from fallback address %s: %s" % (PTR_PRINT % address, str(e)), errormode=False)
						origbytes = b""
				attempts += 1

			if not read_success and attempts == 2:
				dbgp("Sorry, failed to read from any of the addresses, won't be able to assemble")
				return b""


		for thisinstruction in allinstructions:	

			# if cached, return from cache first
			dbgp("Current instruction to assemble : %s" % thisinstruction)
			thisinstruction = self.cleanInstruction(thisinstruction)

			# Ensure thisinstruction is ASCII for compatibility
			if PY3:
				ascii_instruction = thisinstruction.encode('ascii', 'ignore').decode('ascii')
			else:
				ascii_instruction = thisinstruction.encode('ascii', 'ignore')

			if ascii_instruction in self.AsmCache:
				dbgp("Found instruction '%s' in cache" % ascii_instruction)
				dbgp("Cached entry: %s" % bin2hex(self.AsmCache[ascii_instruction]))
				allbytes += self.AsmCache[ascii_instruction]
			else:
				dbgp("Instruction '%s' not found in cache" % ascii_instruction)
				# if keystone-engine is installed, use that first
				if keystoneLoaded:
					try:
						encodedinstruction, count = ks.asm(ascii_instruction)
						# keystone returns a list of ints. Convert to raw bytes for both py2/py3.
						if PY3:
							thesebytes = bytes(encodedinstruction)
						else:
							thesebytes = ''.join(chr(b & 0xff) for b in encodedinstruction)
						dbgp("Keystone: Instruction '%s' assembled to bytes: %s" % (ascii_instruction, bin2hex(thesebytes)))
						allbytes += thesebytes
						self.AsmCache[ascii_instruction] = thesebytes
					except Exception as e:
						dbgp("Error using keystone to assemble '%s'" % ascii_instruction, errormode=False)
						dbgp("%s" % str(e), errormode=False)
						dbgp(traceback.format_exc(), errormode=False)
				else:
					dbgp("Keystone not installed, fallback to using pykd")
					objdisasm = pykd.disasm(address)
					dbgp("Instruction '%s' not in cache, assembling: " % ascii_instruction)
					try:
						dbgp("   Running objdisasm.asm('%s')" % ascii_instruction)
						objdisasm.asm(ascii_instruction)
						global disAsmCache
						if address in disAsmCache:
							del disAsmCache[address]
						if address in self.OpcodeCache:
							del self.OpcodeCache[address]

						opc = opcode(address)
						thesebytes = opc.getBytes()
						dbgp("bytes: %s " % thesebytes)
						allbytes += thesebytes
						self.AsmCache[ascii_instruction] = thesebytes
						dbgp("Added opcode for '%s' to cache" % ascii_instruction)

					except Exception as e:
						dbgp("Unable to assemble instruction '%s'" % ascii_instruction, errormode=False)

		# restore origbytes if needed 
		if origbytes != b"":
			putback = "eb 0x%08x " % address
			# In Py2, iterating a bytes/str yields 1-char strings; format expects ints.
			restorebytes = ["%02x" % (b if isinstance(b, int) else ord(b)) for b in origbytes]
			putback += ' '.join(restorebytes)
			pykd.dbgCommand(putback)
			dbgp("putback command: %s" % putback)			

		dbgp("Return value of assemble: %s" % bin2hex(allbytes))
		return allbytes


	def getOpcode(self,address):
		if address in self.OpcodeCache:
			return self.OpcodeCache[address]
		else:
			opcodeobj = opcode(address)
			self.OpcodeCache[address] = opcodeobj
			return opcodeobj

	"""
	strings
	"""

	def readString(self,address):
		dbgp("readString(%s) called" % (PTR_PRINT % address))
		if pykd.isValid(address):
			try:
				result = pykd.loadCStr(address)
				dbgp("readString(%s) loadCStr returned %r" % (PTR_PRINT % address, result))
				return result
			except pykd.MemoryException as e:
				dbgp("readString(%s) loadCStr MemoryException: %s" % (PTR_PRINT % address, str(e)))
				try:
					result = pykd.loadChars(address, 0x100)
					dbgp("readString(%s) loadChars returned %r" % (PTR_PRINT % address, result))
					return result
				except Exception as inner_e:
					dbgp("readString(%s) loadChars exception: %s" % (PTR_PRINT % address, str(inner_e)))
					rawbytes = bytearray()
					nextloc = address
					while pykd.isValid(nextloc):
						chunk = self.readMemory(nextloc, 4)
						dbgp("readString(%s) chunk @ %s -> %s" % (PTR_PRINT % address, PTR_PRINT % nextloc, binascii.hexlify(chunk).decode('ascii') if chunk else "<empty>"))
						if not chunk:
							break
						for thisbyte in iter_byte_values(chunk):
							if thisbyte < 0x20 or thisbyte > 0x7e:
								result = ensure_text(bytes(rawbytes))
								dbgp("readString(%s) terminated on byte 0x%02x, returning %r" % (PTR_PRINT % address, thisbyte, result))
								return result
							rawbytes.append(thisbyte)
						nextloc += len(chunk)
					result = ensure_text(bytes(rawbytes))
					dbgp("readString(%s) exhausted readable memory, returning %r" % (PTR_PRINT % address, result))
					return result
			except Exception as e:
				dbgp("readString(%s) loadCStr general exception: %s" % (PTR_PRINT % address, str(e)))
				rawbytes = bytearray()
				nextloc = address
				while pykd.isValid(nextloc):
					chunk = self.readMemory(nextloc, 4)
					dbgp("readString(%s) chunk @ %s -> %s" % (PTR_PRINT % address, PTR_PRINT % nextloc, binascii.hexlify(chunk).decode('ascii') if chunk else "<empty>"))
					if not chunk:
						break
					for thisbyte in iter_byte_values(chunk):
						if thisbyte < 0x20 or thisbyte > 0x7e:
							result = ensure_text(bytes(rawbytes))
							dbgp("readString(%s) terminated on byte 0x%02x, returning %r" % (PTR_PRINT % address, thisbyte, result))
							return result
						rawbytes.append(thisbyte)
					nextloc += len(chunk)
				result = ensure_text(bytes(rawbytes))
				dbgp("readString(%s) exhausted readable memory, returning %r" % (PTR_PRINT % address, result))
				return result
		dbgp("readString(%s) invalid address" % (PTR_PRINT % address))
		return ""

	"""
	Breakpoints
	"""
	def getHardwareBreakpointCount(self):
		"""Count hardware breakpoints in use by checking DR0-DR3 via DR7 enable bits"""
		count = 0
		try:
			dr7 = int(pykd.reg("dr7"))
			for i in range(4):
				# DR7 local enable bits: bit 0 (DR0), bit 2 (DR1), bit 4 (DR2), bit 6 (DR3)
				if dr7 & (1 << (i * 2)):
					count += 1
		except:
			pass
		return count

	def sanitizeExtraCommand(self, extracmd):
		if extracmd != "":
			# Allow users to pass '|' as a safe separator in !mona -c input.
			# This avoids WinDBG splitting the top-level command line on ';'
			# before mona receives the full payload.
			escaped = extracmd.replace("|", ";")
			# Escape separators so dbgCommand sends the full payload to bp/ba
			# instead of executing commands after the first ';' immediately.
			escaped = escaped.replace(";", "\\;")
			# '#' is the mona placeholder for a literal double quote.
			escaped = escaped.replace("#", '\\"')
			# Preserve literal '\n' sequences for .printf style commands.
			escaped = escaped.replace("\\n", "\\\\n")
			return ('"%s"' % escaped)
		return ""

	def setBreakpoint(self,address,condition="",extracmd=""):
		dbgp("Creating breakpoint at %s" % (PTR_PRINT % address))
		cmd2run = ""
		extracmd = self.sanitizeExtraCommand(extracmd)
		try:
			if condition:
				cmd2run = 'bp 0x%x "%s" %s' % (address, condition, extracmd)
			else:
				cmd2run = 'bp 0x%x %s' % (address, extracmd)
			self.nativeCommand(cmd2run)
		except Exception as e:
			dbgp("Error setting breakpoint: %s " % str(e), errormode=False)
			dbgp("   bp command: %s" % cmd2run, errormode=False)
			return False
		return True

	def deleteBreakpoint(self,address):
		dbgp("Attempting to delete breakpoint at %s" % (PTR_PRINT % address))		
		getallbps = "bl"
		searchaddress = "%s" % (PTR_PRINT_ADDRESSONLY % address).lower()
		allbps = self.nativeCommand(getallbps)
		bplines = allbps.split("\n")
		for line in bplines:
			fieldcnt = 0
			if line.replace(" ","") != "":
				line = line.replace("`","")
				# check if address is in this line
				lineparts = line.split(" ")
				id = ""
				for part in lineparts:
					if part != "":
						fieldcnt += 1
					if fieldcnt == 1:
						id = part
						break
				if id != "":
					if searchaddress in line.lower():
						dbgp("Found it, clear breakpoint id %s" % id)
						rmbp = "bc %s" % id
						self.nativeCommand(rmbp)


	def setMemBreakpoint(self,address,memType,condition="",extracmd=""):

		extracmd = self.sanitizeExtraCommand(extracmd)

		validtype = False
		bpcommand = ""
		addrfmt = "0x%x" % address
		if memType.upper() == "S":
			bpcommand = "ba e 1 %s" % addrfmt
			validtype = True
		if memType.upper() == "R":
			# Smart alignment: size based on address alignment (8 on x64)
			if arch == 64 and address % 8 == 0:
				size = 8
			elif address % 4 == 0:
				size = 4
			elif address % 2 == 0:
				size = 2
			else:
				size = 1
			bpcommand = "ba r %d %s" % (size, addrfmt)
			validtype = True
		if memType.upper() == "W":
			if arch == 64 and address % 8 == 0:
				size = 8
			elif address % 4 == 0:
				size = 4
			elif address % 2 == 0:
				size = 2
			else:
				size = 1
			bpcommand = "ba w %d %s" % (size, addrfmt)
			validtype = True
		if validtype:
			if condition:
				bpcommand = '%s "%s"' % (bpcommand, condition)
			if extracmd:
				bpcommand = '%s %s' % (bpcommand, extracmd)
			output = ""
			try:
				output = pykd.dbgCommand(bpcommand)
			except:
				if memType.upper() == "S":
					bpcommand = "bp %s" % addrfmt
					if condition:
						bpcommand = '%s "%s"' % (bpcommand, condition)
					if extracmd:
						bpcommand = '%s %s' % (bpcommand, extracmd)
					output = pykd.dbgCommand(bpcommand)
				else:
					dbgp("Error setting memory breakpoint with command: %s" % bpcommand, errormode=False)
					dbgp("Output: %s" % output, errormode=False)
					self.log("** Unable to set memory breakpoint. Check alignment,")
					self.log("   and try to run the following command to get more information:")
					self.log("   %s" % bpcommand)

	"""
	Table
	"""

	def createTable(self,title,columns):
		return wtable(title,columns)

	"""
	Symbols
	"""

	def resolveSymbol(self,symbolname):
		resolvecmd = "u %s L1" % symbolname
		try:
			output=self.nativeCommand(resolvecmd)
			outputlines = output.split("\n")
			for line in outputlines:
				lineparts = line.split(" ")
				if len(lineparts) > 1:
					symfound = True
					symaddy = lineparts[0]
					break
			if symfound:
				return symaddy
			else:
				return ""
		except:
			return ""


# other classes

class wtable:

	def __init__(self,title,columns):
		self.title = title
		self.columns = columns
		self.values = []
	
	def add(self,tableindex,values):
		self.values.append(values)
		return None


class wmodule:

	def __init__(self,modname):
		self.key = modname
		self.modname = modname
		self.modpath = None
		self.modbase = None
		self.modsize = None

	# setters
	def setBaseAddress(self,value):
		self.modbase = value

	def setPath(self,value):
		self.modpath = value

	def setSize(self,value):
		self.modsize = value

	# getters
	def __str__(self):
		return self.modname

	def key(self):
		return self.modname

	def getName(self):
		return self.modname
	
	def getBaseAddress(self):
		return self.modbase

	def getPath(self):
		return self.modpath
	
	def getSize(self):
		return self.modsize

	def addressToSymbol(self, address):
		global FuncCache

		if address in FuncCache:
			if FuncCache[address] != "":
				dbgp("Returning symbol from cache. 0x%x = %s" % (address, FuncCache[address]))
				return FuncCache[address]
		else:
			if DEBUG_MODE:
				dbgp("Performing symbol lookup, this may cause symbols to be downloaded")
				pykd.dbgCommand("!sym noisy")

			cmd2run = '.printf "%y", 0x{0:x}'.format(address)

			dbgp("Running %s" % cmd2run)
			output = pykd.dbgCommand(cmd2run)

			if DEBUG_MODE:
				pykd.dbgCommand("!sym quiet")
				
			if not output:
					return ""

			output = output.strip()

			# If WinDBG reports an offset, such as module!func+0x12,
			# then we don't want to return the full symbol name
			if "+" in output:
				return ""

			# Extract everything before the final " (address)"
			# Example:
			#   KERNELBASE!AreFileApisANSI (75a17cc0)
			m = re.match(r'^(.*?)\s+\([0-9A-Fa-f`]+\)$', output)
			if m:
				if not address in FuncCache:
					FuncCache[address] = m.group(1).strip()
				return m.group(1).strip()
		return ""


	def getSymbols(self):
		# enumerate IAT and EAT and put into a symbol object
		dbgp(get_current_function_name())		
		dbgp("Getting symbols for module: %s" % self.modname)		
		ntHeader = getNtHeaders(self.modbase)
		pSize = 4
		if arch == 64:
			pSize = 8
		
		iatlist = self.getIATList(ntHeader,pSize)

		dbgp("iatlist has %d elements" % len(iatlist))

		symbollist = {}
		for iatEntry in iatlist:
			iatEntryAddress = iatEntry
			iatEntryName = iatlist[iatEntry]
			sym = wsymbol("Import", iatEntryAddress, iatEntryName)
			symbollist[iatEntryAddress] = sym 

		eatlist = self.getEATList(ntHeader,pSize)
		dbgp("eatlist has %d elements" % len(eatlist))

		for eatEntry in eatlist:
			eatEntryName = eatEntry
			eatEntryAddress = eatlist[eatEntry]
			sym = wsymbol("Export", eatEntryAddress, eatEntryName)
			symbollist[eatEntryAddress] = sym

		dbgp("returning symbollist, %d elements" % len(symbollist))
		
		return symbollist

	def getIATList(self,ntHeader, pSize):
		# If Import Address Table Directory (DataDirectory[12]) is set this will work.
		# The fallback case of Import Directory (DataDirectory[1]) will produce garbage.
		dbgp(get_current_function_name())
		dbgp("Current module: %s" % self.modname)		
		iatlist = {}
		iatdir = ntHeader.OptionalHeader.DataDirectory[12]
		if iatdir.Size == 0:
			iatdir = ntHeader.OptionalHeader.DataDirectory[1]
		dbgp("iatdir size: %d" % iatdir.Size)
		if iatdir.Size > 0:
			iatAddr = self.modbase + iatdir.VirtualAddress
			dbgp("iatAddr: 0x%x" % iatAddr)
			dbgp("  iat processing range: 0 - %d " % (iatdir.Size // pSize))

			maxnr = iatdir.Size // pSize
			for i in range(0, maxnr):
				try:
					iatEntry = pykd.ptrPtr(iatAddr + i*pSize)
					if iatEntry != None and iatEntry != 0:
						dbgp("Symbol lookup via printf, for 0x%x (%d / %d)" % (iatEntry, i, maxnr))
						symbolName = self.addressToSymbol(iatEntry)
						if symbolName == "":
							dbgp("pykd.findSymbol for 0x%x (%d / %d)" % (iatEntry, i, maxnr))
							symbolName = pykd.findSymbol(iatEntry)
						dbgp("Symbol: %s" % symbolName)
						if "!" in symbolName:
							iatlist[iatAddr + i*pSize] = symbolName
				except Exception as e:
					dbgp("Error while getting IAT: %s" % str(e), errormode=False)
					dbgp(traceback.format_exc(), errormode=False)
					continue
		return iatlist


	def getEATList(self,ntHeader, pSize):
		# http://www.pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
		dbgp(get_current_function_name())
		dbgp("Current module: %s" % self.modname)		
		eatlist = {}
		if ntHeader.OptionalHeader.DataDirectory[0].Size > 0:
			eatAddr = self.modbase + ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
			# eatAddr + 0x18 = IMAGE_EXPORT_DIRECTORY.NumberOfNames(DWORD)
			nr_of_names = pykd.ptrDWord(eatAddr + 0x18)
			# eatAddr + 0x20 = IMAGE_EXPORT_DIRECTORY.AddressOfNames(DWORD)
			rva_of_names = self.modbase + pykd.ptrDWord(eatAddr + 0x20)
			# eatAddr + 0x1c = IMAGE_EXPORT_DIRECTORY.AddressOfFunctions(DWORD)
			address_of_functions = self.modbase + pykd.ptrDWord(eatAddr + 0x1c)
			for i in range (0, nr_of_names):
				# IMAGE_EXPORT_DIRECTORY.AddressOfNames[i](DWORD)
				eatName = pykd.loadCStr(self.modbase + pykd.ptrDWord(rva_of_names + 4 * i))
				# IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[i](DWORD)
				eatAddress = self.modbase + pykd.ptrDWord(address_of_functions + 4*i)
				eatlist[eatName] = eatAddress
				dbgp("Read from OptionalHeader, added to EATList: %s!%s at 0x%08x" % (self.modname, eatName, eatAddress))
		return eatlist
	


class wsymbol():

	def __init__(self,type,address,name):
		self.type = type
		self.address = address
		self.name = name

	def getType(self):
		return self.type

	def getAddress(self):
		return self.address

	def getName(self):
		return self.name


class wpage():
	def __init__(self, begin, size, usage):
		self.begin = begin
		self.size = size
		self.end = self.begin+self.size
		self.protect = None
		self.usage = usage.strip()

	def getSize(self):
		return self.size

	def getUsage(self):
		return self.usage

	def getMemory(self):
		if self.getAccess() > 0x1:
			if isUnreadableMemoryProbeCached(self.begin, fallback_size=self.size):
				dbgp("")
				dbgp("wpage.getMemory: unreadable page cache hit for %s-%s (size 0x%x)" % (
					PTR_PRINT % self.begin,
					PTR_PRINT % self.end,
					self.size
				), errormode=False)
				return None
			try:
				dbgp("")
				dbgp("wpage.getMemory: trying direct read for page %s-%s (size 0x%x, access 0x%x)" % (PTR_PRINT % self.begin, PTR_PRINT % self.end, self.size, self.getAccess()))
				#data =  pykd.loadChars(self.begin,self.size)
				data = bytes(bytearray(pykd.loadBytes(self.begin, self.size)))
				return data
			except Exception as e:
				# pykd.loadBytes() may fail for large reads or when the region contains an unreadable sub-page.
				# Before bailing out, try to reconstruct the region using 0x1000 chunk reads.
				dbgp("wpage.getMemory: direct read failed for page %s-%s: %s" % (PTR_PRINT % self.begin, PTR_PRINT % self.end, str(e)), errormode=False)

				def _parse_db_output_tokens(out, max_tokens=0):
					"""Parse db/db$ output tokens into [0..255] or None (for ??)."""
					tokens = []
					if not out:
						return tokens
					for line in out.splitlines():
						line = line.strip()
						if not line:
							continue
						low = line.lower()
						if "memory access" in low or "error" in low:
							return []

						parts = line.split()
						if len(parts) < 2:
							continue

						# Skip address column (first token), parse byte columns until ASCII column.
						for tok in parts[1:]:
							if tok == "-":
								continue
							if re.match(r"^[0-9a-fA-F]{2}$", tok):
								tokens.append(int(tok, 16))
							elif tok == "??":
								tokens.append(None)
							else:
								break
							if max_tokens > 0 and len(tokens) >= max_tokens:
								return tokens
					return tokens

				def _windbg_db_has_real_bytes(addr, length):
					"""Return True if `db` shows at least one concrete byte; False for all ??; None if inconclusive."""
					if isUnreadableMemoryProbeCached(addr, fallback_size=length):
						dbgp("wpage.getMemory: unreadable db probe cache hit at %s len=0x%x" % (
							PTR_PRINT % addr, length
						), errormode=False)
						return False
					try:
						out = pykd.dbgCommand("db 0x%x L0x%x" % (addr, length))
					except Exception:
						return None
					tokens = _parse_db_output_tokens(out, max_tokens=length)
					if not tokens:
						return None
					# If all visible bytes are ??, there is nothing useful to read.
					if all(t is None for t in tokens):
						markUnreadableMemoryProbeCached(addr, fallback_size=length)
						return False
					return True

				def _windbg_db_read_bytes(addr, length, use_db_dollar=True):
					"""Read memory using WinDBG `db$` (or `db`) output and parse concrete bytes.

					Returns bytes on success, or None on failure/incomplete output.
					"""
					try:
						cmd = "db$ 0x%x L0x%x" % (addr, length) if use_db_dollar else "db 0x%x L0x%x" % (addr, length)
						out = pykd.dbgCommand(cmd)
					except Exception:
						return None
					tokens = _parse_db_output_tokens(out, max_tokens=length)
					if len(tokens) < length:
						return None
					if any(t is None for t in tokens[:length]):
						return None
					return bytes(bytearray(tokens[:length]))

				def _resilient_read_full_region():
					# Read in 0x1000 chunks only.
					# On chunk read failure: probe with `db`.
					# - all ?? => treat as no data, stop trying this page.
					# - has bytes => read that chunk via `db$`.
					page_chunk = 0x1000
					outbuf = bytearray()

					offset = 0
					while offset < self.size:
						remaining = self.size - offset
						this_len = page_chunk if remaining > page_chunk else remaining
						addr = self.begin + offset
						dbgp("wpage.getMemory: trying chunk read at %s len=0x%x (page %s-%s)" %
							 (PTR_PRINT % addr, this_len, PTR_PRINT % self.begin, PTR_PRINT % self.end), errormode=False)
						try:
							chunk = bytes(bytearray(pykd.loadBytes(addr, this_len)))
							if len(chunk) < this_len:
								chunk += b"\x00" * (this_len - len(chunk))
							elif len(chunk) > this_len:
								chunk = chunk[:this_len]
							outbuf.extend(bytearray(chunk))
							offset += this_len
							continue
						except Exception:
							dbgp("wpage.getMemory: chunk read failed at %s len=0x%x; probing with db" %
								 (PTR_PRINT % addr, this_len), errormode=False)

						db_probe = _windbg_db_has_real_bytes(addr, this_len)
						if db_probe is False:
							markUnreadableMemoryProbeCached(self.begin, fallback_size=self.size)
							dbgp("wpage.getMemory: db shows only ?? at %s len=0x%x; giving up page %s-%s" %
								 (PTR_PRINT % addr, this_len, PTR_PRINT % self.begin, PTR_PRINT % self.end), errormode=False)
							return None
						if db_probe is None:
							dbgp("wpage.getMemory: db probe inconclusive at %s len=0x%x; giving up page" %
								 (PTR_PRINT % addr, this_len), errormode=False)
							return None

						dbgp("wpage.getMemory: db shows concrete bytes at %s len=0x%x; reading with db$" %
							 (PTR_PRINT % addr, this_len), errormode=False)
						dbbytes = _windbg_db_read_bytes(addr, this_len, use_db_dollar=True)
						if dbbytes is None:
							# If db$ is not available/parseable, fallback to db parsing as compatibility path.
							dbgp("wpage.getMemory: db$ read failed at %s len=0x%x; trying db parser fallback" %
								 (PTR_PRINT % addr, this_len), errormode=False)
							dbbytes = _windbg_db_read_bytes(addr, this_len, use_db_dollar=False)
						if dbbytes is None:
							dbgp("wpage.getMemory: unable to recover chunk via db$/db at %s len=0x%x; giving up page" %
								 (PTR_PRINT % addr, this_len), errormode=False)
							return None
						if len(dbbytes) < this_len:
							dbbytes += b"\x00" * (this_len - len(dbbytes))
						elif len(dbbytes) > this_len:
							dbbytes = dbbytes[:this_len]
						outbuf.extend(bytearray(dbbytes))
						offset += this_len

					if len(outbuf) < self.size:
						outbuf.extend(bytearray(b"\x00" * (self.size - len(outbuf))))
					elif len(outbuf) > self.size:
						outbuf = outbuf[:self.size]
					dbgp("wpage.getMemory: reconstructed page %s-%s using chunk/db$ path" %
						 (PTR_PRINT % self.begin, PTR_PRINT % self.end), errormode=False)
					return bytes(bytearray(outbuf))

				if "Memory exception at" not in str(e):
					data2 = _resilient_read_full_region()
					if data2 is not None:
						return data2

				dbgp("Error accessing memory: %s" % str(e), errormode=False)
				return None
		else:
			#dbgp("Page at %s has no access, cannot read memory" % (PTR_PRINT % self.begin))
			return None


	def getAccess(self,human=False):
		humanaccess = {
		0x01 : "PAGE_NOACCESS",
		0x02 : "PAGE_READONLY",
		0x04 : "PAGE_READWRITE",
		0x08 : "PAGE_WRITECOPY",
		0x10 : "PAGE_EXECUTE",
		0x20 : "PAGE_EXECUTE_READ",
		0x40 : "PAGE_EXECUTE_READWRITE",
		0x80 : "PAGE_EXECUTE_WRITECOPY"
		}

		modifiers = {
		0x100 : "PAGE_GUARD",
		0x200 : "PAGE_NOCACHE",
		0x400 : "PAGE_WRITECOMBINE"
		}

		modifaccess = {}
		for access in humanaccess:
			newaccess = access
			newacl = humanaccess[access]
			for modif in modifiers:
				newaccess += modif
				newacl = newacl + " " + modifiers[modif]
				modifaccess[newaccess] = newacl

		for modif in modifaccess:
			humanaccess[modif] = modifaccess[modif]

		if self.protect == None:
			try:
				self.protect = pykd.getVaProtect(self.begin)
			except:
				self.protect = 0x1
		if self.protect == 0x0:
			self.protect = 0x1
		if not human:
			return self.protect
		else:
			if self.protect in humanaccess:
				return humanaccess[self.protect]
			else:
				return ""

	def getBegin(self):
		return self.begin

	def getBaseAddress(self):
		return self.begin

	def getSection(self):
		global PageSections
		if self.begin in PageSections:
			return PageSections[self.begin]
		else:
			sectiontoreturn = ""
			imagename = getModuleFromAddress(self.begin)
			if not imagename == None:
				thismod = pykd.module(imagename)
				thismodbase = thismod.begin()
				thismodend = thismod.end()
				if self.begin >= thismodbase and self.begin <= thismodend:
					# find sections and their addresses
					ntHeader = getNtHeaders(thismodbase)
					nrsections = int(ntHeader.FileHeader.NumberOfSections)
					sectionsize = 40
					sizeOptionalHeader = int(ntHeader.FileHeader.SizeOfOptionalHeader)
					try:
						# Python 2
						xrange
					except NameError:
						# Python 3, xrange is now named range
						xrange = range

					for sectioncnt in xrange(nrsections):
						sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
						thissection = rstrip_nulls(pykd.loadChars(sectionstart, 8))
						
						# IMAGE_SECTION_HEADER.SizeOfRawData(DWORD)
						thissectionsize = pykd.ptrDWord(sectionstart + 0x8 + 0x8)
						# IMAGE_SECTION_HEADER.VirtualAddress(DWORD)
						thissectionrva = pykd.ptrDWord(sectionstart + 0x4 + 0x8)
						thissectionstart = thismodbase + thissectionrva
						thissectionend = thissectionstart + thissectionsize
						if (thissectionstart <= self.begin) and (self.begin <= thissectionend):
							sectiontoreturn = thissection
							break
						else:
							PageSections[self.begin]=thissection
					PageSections[self.begin]=sectiontoreturn
					return sectiontoreturn
				PageSections[self.begin]=sectiontoreturn
				return sectiontoreturn
			else:
				return ""


class Function:
	def __init__(self,obj,address):
		self.function_allmodules = {}
		self.address = address
		self.obj = obj

	def getName(self):
		dbgp(get_current_function_name())
		modname = "unknown"
		funcname = "unknown"
		symname = self.addressToSymbol()
		dbgp("Symname: %s" % symname)
		if symname == "":
			# get module this address belongs to
			self.function_allmodules = self.obj.getAllModules()
			for objmod in self.function_allmodules:
				thismod = self.function_allmodules[objmod]
				startaddress = thismod.getBaseAddress()
				size = thismod.getSize()
				endaddress = startaddress + size
				if self.address >= startaddress and self.address <= endaddress:
					modname = thismod.getName().lower()
					syms = thismod.getSymbols()
					for sym in syms:
						if syms[sym].getType().startswith("Export"):
							eatsym = syms[sym]
							if eatsym.getAddress() == self.address:
								funcname = eatsym.getName()
								break
		else:
			dbgp("Splitting module & symbol name %s" % symname)
			if "!" in symname:
				symnameparts = symname.split("!")
				if len(symnameparts) > 1:
					modname = symnameparts[0]
					funcname = symnameparts[1]
			dbgp("Function name: %s" % funcname)
		thename = "%s!%s" % (modname,funcname)
		dbgp("Full name for 0x%x = %s" % (self.address, thename))
		return thename

	def hasAddress(self):
		return False
	
	def addressToSymbol(self):
		global FuncCache

		if self.address in FuncCache:
			if FuncCache[self.address] != "":
				dbgp("Returning symbol from cache. 0x%x = %s" % (self.address, FuncCache[self.address]))
				return FuncCache[self.address]
		else:

			cmd2run = '.printf "%y", 0x{0:x}'.format(self.address)

			dbgp("Running %s" % cmd2run)
			output = pykd.dbgCommand(cmd2run)
			if not output:
					return ""

			output = output.strip()

			# If WinDBG reports an offset, such as module!func+0x12,
			# then we don't want to return the full symbol name
			if "+" in output:
				return ""

			# Extract everything before the final " (address)"
			# Example:
			#   KERNELBASE!AreFileApisANSI (75a17cc0)
			m = re.match(r'^(.*?)\s+\([0-9A-Fa-f`]+\)$', output)
			if m:
				if not self.address in FuncCache:
					FuncCache[self.address] = m.group(1).strip()
				return m.group(1).strip()
		return ""


def cleanDisasmInstruction(instr):
	"""
	Reduce a WinDBG disassembly instruction to a clean, stable form.

	Goals:
	- keep operands
	- remove debugger-only decorations
	- preserve fs:/gs: prefixes
	- drop ds:/es:/ss:/cs: prefixes
	- keep numbers as-is (do not force conversions here)
	- keep output lowercase
	"""
	if instr is None:
		return ""

	instr = ensure_text(instr).strip().lower()
	if instr == "":
		return ""

	# collapse whitespace first
	instr = re.sub(r"\s+", " ", instr)

	# strip WinDBG comments / symbol braces
	# example: "mov eax,dword ptr [eax] {blah}"
	instr = re.sub(r"\s*\{[^}]*\}", "", instr)

	# normalize comma spacing
	instr = re.sub(r"\s*,\s*", ",", instr)

	# remove "offset " keyword but keep the target
	instr = re.sub(r",\s*offset\s+", ",", instr)

	# remove ptr size keywords globally
	instr = re.sub(r"\b(?:byte|word|dword|qword|fword|tbyte|xmmword|ymmword|zmmword)\s+ptr\b", "", instr)

	# normalize spaces again after removing ptr markers
	instr = re.sub(r"\s+", " ", instr).strip()

	# drop segment prefixes except fs:/gs:
	# examples:
	#   es:[edi] -> [edi]
	#   ds:[eax] -> [eax]
	#   fs:[30h] -> fs:[30h]
	#   gs:[60h] -> gs:[60h]
	instr = re.sub(r"\b(?!(?:fs|gs):)(?:cs|ds|es|ss):(?=\[)", "", instr)

	# some string instructions can have two memory operands with segment prefixes
	# remove non-fs/gs prefixes even if spacing is odd
	instr = re.sub(r"\b(?!(?:fs|gs)\b)(?:cs|ds|es|ss):", "", instr)

	# normalize bracket math spacing
	instr = re.sub(r"\[\s*", "[", instr)
	instr = re.sub(r"\s*\]", "]", instr)
	instr = re.sub(r"\s*\+\s*", "+", instr)
	instr = re.sub(r"\s*-\s*", "-", instr)

	# normalize stray spaces after mnemonic
	instr = re.sub(r"\s+", " ", instr).strip()

	# remove spaces after comma for a compact compare-friendly form
	instr = instr.replace(", ", ",")

	return instr


class opcode:

	opsize = 0
	dump = ""

	def __init__(self,address):
		self.address = int(address)
		self.dumpdata = ""
		self.dump = ""
		self.instruction = ""
		self.getDisasm()

	def getBytes(self):
		self.opsize = len(self.dumpdata) // 2
		return hex2bin(self.dumpdata)

	def isJmp(self):
		if self.instruction.lower().startswith("jmp"):
			return True
		return False

	def isCall(self):
		if self.instruction.lower().startswith("call"):
			return True
		return False

	def isPush(self):
		if self.instruction.lower().startswith("push"):
			return True
		return False

	def isPop(self):
		if self.instruction.lower().startswith("pop"):
			return True
		return False

	def isRet(self):
		if self.instruction.lower().startswith("ret"):
			return True
		return False

	def isRep(self):
		if self.instruction.lower().startswith("rep"):
			return True
		return False		

	def getDisasm(self):
		if self.instruction == "":
			disasmdata = ""

			global disAsmCache
			if self.address in disAsmCache:
				disasmdata = disAsmCache[self.address]
			else:
				if arch == 32:
					cmd = "u 0x%08x L 1" % self.address
				else:
					cmd = "u %s L 1" % intToHexWinDbgFormat(self.address)

				disasmlines = pykd.dbgCommand(cmd)
				for thisline in disasmlines.split("\n"):
					thisline = thisline.rstrip()
					if thisline.lower().startswith(intToHexWinDbgFormat(self.address).lower()):
						disasmdata = thisline
						break

			if disasmdata != "":
				disAsmCache[self.address] = disasmdata
				self.parseDisasm(disasmdata)

				# keep dumpdata/opsize from parseDisasm()
				# only reduce the textual instruction to a stable form
				self.instruction = cleanDisasmInstruction(self.instruction)

				# keep RET vs RETN normalization minimal and explicit
				if self.instruction == "ret":
					self.instruction = "retn"

			self.dump = self.instruction

		return self.instruction


	def parseDisasm(self, disasmdata):
		if arch == 32:
			# 0 -> 7 : address
			# 8 : space
			# 9 -> 24 : bytes
			# 25 -> end : instruction
			if len(disasmdata) > 25:
				self.instruction = disasmdata[25:len(disasmdata)]
				self.dumpdata = disasmdata[9:24].replace(" ","")
				self.opsize = len(self.dumpdata) // 2
			address_string = disasmdata[0:8]
			self.address = addrToInt(address_string)
		else:
			splitted = disasmdata.split()
			address_string = splitted[0]
			self.address = addrToInt(address_string)
			instruction = ' '.join(splitted[2:])
			if instruction != '???':
				self.instruction = instruction
				self.dumpdata = splitted[1]
				self.opsize = len(self.dumpdata) // 2

	def getDump(self):
		if self.dumpdata == "":
			self.getDisasm()
		return self.dumpdata

	def getAddress(self):
		return self.address



class _ThreadEntry:
	def __init__(self,address):
		self.address = address

	def getTEB(self):
		# return address of the TEB
		return self.address

	def getId(self):
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
		teb = self.getTEB()
		offset = 0x24
		if arch == 64:
			offset = 0x48
		# _TEB.ClientId(CLIENT_ID).UniqueThread(PVOID)
		tid = pykd.ptrDWord(teb+offset)
		return tid


class wthread(_ThreadEntry):
	pass

class wheap:
	def __init__(self,address):
		self.address = address

	def getChunks(self,address):
		return {}


class LogBpHook:
	def __init__(self):
		return
