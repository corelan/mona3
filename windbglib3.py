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

$Revision: 152 $
$Id: windbglib3.py 152 2026-03-26 18:04:00Z corelanc0d3r $ 
"""

__VERSION__ = '3.0'

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
global cpebaddress
global PEBModList
global FuncCache

arch = 32
cpebaddress = 0

PageSections = {}
ModuleCache = {}
FuncCache = {}
PEBModList = {}
disAsmCache = {}

Registers32BitsOrder = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
Registers64BitsOrder = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
						"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]

if pykd.is64bitSystem():
	arch = 64

TOP_USERLAND = 0x7fffffff if arch == 32 else 0x7FFFFFFFFFFF

# Utility functions

DEBUG_MODE = False

def set_debug_mode(enabled):
    global DEBUG_MODE
    DEBUG_MODE = bool(enabled)

def dbgp(s):
	# print debug information
	try:
		print("[WINDBGLIB DEBUG] %s | %s" % (get_current_datetime(),s))
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
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	osversions = {}
	osversions["5.0"] = "2000"
	osversions["5.1"] = "xp"
	osversions["5.2"] = "2003"
	osversions["6.0"] = "vista"
	osversions["6.1"] = "win7"
	osversions["6.2"] = "win8"
	osversions["6.3"] = "win8.1"
	osversions["10.0"] = "win10"
	peb = getPEBInfo()
	majorversion = int(peb.OSMajorVersion)
	minorversion = int(peb.OSMinorVersion)
	thisversion = str(majorversion)+"." + str(minorversion)
	if thisversion in osversions:
		return osversions[thisversion]
	else:
		return "unknown"

def getArchitecture():
	if DEBUG_MODE:
		dbgp(get_current_function_name())
	if not pykd.is64bitSystem():
		return 32
	else:
		return 64

def getNtHeaders(modulebase):
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	# http://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
	# http://www.nirsoft.net/kernel_struct/vista/IMAGE_NT_HEADERS.html
	if arch == 64:
		ntheaders = "_IMAGE_NT_HEADERS64"
	else:
		ntheaders = "_IMAGE_NT_HEADERS"

	# modulebase + 0x3c = IMAGE_DOS_HEADER.e_lfanew
	nth = None
	try:
		nth = pykd.module("ntdll").typedVar(ntheaders, modulebase + pykd.ptrDWord(modulebase + 0x3c))
	except Exception as e:
		if DEBUG_MODE:
			dbgp("ERROR: %s" % str(e))
	return nth


def clearvars():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	global MemoryPages
	global AsmCache
	global OpcodeCache
	global InstructionCache
	global PageSections
	global ModuleCache
	global cpebaddress	
	MemoryPages = None
	AsmCache = None
	disAsmCache = None
	OpcodeCache = None
	InstructionCache = None
	InstructionCache = None
	PageSections = None
	ModuleCache = None
	cpebaddress = None
	return


def getPEBInfo():
	if DEBUG_MODE:
		dbgp(get_current_function_name())
		dbgp("Current process: %s" % pykd.getCurrentProcess())
	try:
		return pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())
	except:
		currversion = getPyKDVersion()
		print("")
		print(" Oops - It seems that PyKD was unable problem to get the PEB object.")
		print(" This usually means that")
		print("  1. msdiaxxx.dll has not been registered correctly    and/or")
		print("  2. symbols are missing for ntdll.dll")
		print("")
		print(" Possible solutions:")
		print(" -------------------")
		print(" 1. Re-register the VC runtime library:")
		print("    * For PyKd v%s:" % currversion)
		if currversion.startswith("0.2"):
			print("      (Re)Install the x86 VC++ Redistributable Package for Visual Studio 2008")
			print("       (https://www.microsoft.com/en-us/download/details.aspx?id=29)")
			print("      Next, run the following command from an administrator prompt:")
			print("        (x86) regsvr32.exe \"%ProgramFiles%\\Common Files\\microsoft shared\\VC\\msdia90.dll\"\n")
			print("        (x64) regsvr32.exe \"%ProgramFiles(x86)%\\Common Files\\microsoft shared\\VC\\msdia90.dll\"\n")
		else:
			print("      Either install Visual Studio 2013, or get a copy of msdia120.dll and register it manually\n")
			print("      You can find a copy of msdia120.dll inside the pykd.zip file inside the github repository")
			print("      (Use at your own risk!).  Place the file in the correct 'VC' folder and run regsvr32 from an administrative prompt:")
			print("        (x86) regsvr32.exe \"%ProgramFiles%\\Common Files\\microsoft shared\\VC\\msdia120.dll\"\n")
			print("        (x64) regsvr32.exe \"%ProgramFiles(x86)%\\Common Files\\microsoft shared\\VC\\msdia120.dll\"\n")

		print(" 2. Force download of the Symbols for ntdll.dll")
		print("    * Connect to the internet, and verify that the symbol path is configured correctly")
		print("      Assuming that the local symbol path is set to c:\\symbols,"  )
		print("      run the following command from within the windbg application folder")
		print("        symchk /r c:\\windows\\system32\\ntdll.dll /s SRV*c:\\symbols*http://msdl.microsoft.com/download/symbols")
		print("")
		print(" Restart windbg and try again")
		exit(1)

def getPEBAddress():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	global cpebaddress
	peb = getPEBInfo()
	cpebaddress = peb.getAddress()
	return cpebaddress

def getTEBInfo():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	return pykd.typedVar("_TEB", pykd.getImplicitThread())

def getTEBAddress():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	tebinfo = pykd.dbgCommand("!teb")
	if len(tebinfo) > 0:
		teblines = tebinfo.split("\n")
		tebline = teblines[0]
		tebparts = tebline.split(" ")
		if len(tebparts) > 2:
			return hexStrToInt(tebparts[-1])
	# slow
	teb = getTEBInfo()
	return int(teb.Self)

def bin2hex(binbytes):
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	"""
	Converts a binary string to a string of space-separated hexadecimal bytes.
	"""
	return ' '.join('%02x' % b for b in iter_byte_values(binbytes))

def hexptr2bin(hexptr):
	if DEBUG_MODE:
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
	if DEBUG_MODE:
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
	#if DEBUG_MODE:
	#	dbgp(get_current_function_name())

	if arch == 32:
		return "0x%08x" % address
	if arch == 64:
		return "0x%016x" % address

def intToHexWinDbgFormat(address):
	#if DEBUG_MODE:
	#	dbgp(get_current_function_name())

	if arch == 32:
		return "%08x" % address
	if arch == 64:
		formatted_hex = "%016x" % address
		formatted_hex = formatted_hex[:8] + '`' + formatted_hex[8:]
		return formatted_hex

def toHexByte(n):
	if DEBUG_MODE:
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
	if DEBUG_MODE:
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
	if DEBUG_MODE:
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
	if DEBUG_MODE:
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
	if DEBUG_MODE:
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

def _pe_parse_sections(f, nt_off):
	"""
	Parse the PE section table from an already-open file handle.

	Args:
		f:      Open binary file handle, positioned anywhere.
		nt_off: File offset of the PE signature ("PE\\0\\0").

	Returns:
		List of dicts with keys: 'virtual_address', 'virtual_size',
		'raw_ptr', 'raw_size'.
	"""
	f.seek(nt_off + 4)
	file_header = f.read(20)
	num_sections = struct.unpack("<H", file_header[2:4])[0]
	size_opt_hdr = struct.unpack("<H", file_header[16:18])[0]
	sect_table_off = nt_off + 4 + 20 + size_opt_hdr
	f.seek(sect_table_off)
	sections = []
	for _ in range(num_sections):
		sd = f.read(40)
		v_sz, v_addr, raw_sz, raw_ptr = struct.unpack("<IIII", sd[8:24])
		sections.append({
			'virtual_address': v_addr,
			'virtual_size':    v_sz,
			'raw_ptr':         raw_ptr,
			'raw_size':        raw_sz,
		})
	return sections


def _pe_get_resource_dd(f, nt_off):
	"""
	Return the RVA and size of IMAGE_DIRECTORY_ENTRY_RESOURCE (index 2).
	Supports PE32 (magic 0x10b) and PE32+ (magic 0x20b).

	Args:
		f:      Open binary file handle.
		nt_off: File offset of the PE signature.

	Returns:
		Tuple (rva: int, size: int), or (0, 0) if magic is unrecognised.
	"""
	f.seek(nt_off + 4 + 20)
	magic = struct.unpack("<H", f.read(2))[0]
	if magic == 0x10b:
		dd_off = nt_off + 4 + 20 + 96
	elif magic == 0x20b:
		dd_off = nt_off + 4 + 20 + 112
	else:
		return 0, 0
	f.seek(dd_off + 2 * 8)
	return struct.unpack("<II", f.read(8))


def _pe_get_rt_version_data(f, sections, res_rva):
	"""
	Walk the PE resource directory tree and return the raw VS_VERSION_INFO
	bytes for RT_VERSION (type ID 16).

	Args:
		f:        Open binary file handle.
		sections: List of section dicts from _pe_parse_sections.
		res_rva:  RVA of the root resource directory.

	Returns:
		bytes of the VS_VERSION_INFO blob, or None if not found.
	"""
	res_sec = next(
		(s for s in sections
		 if s['virtual_address'] <= res_rva < s['virtual_address'] + s['virtual_size']),
		None
	)
	if res_sec is None:
		return None

	sec_va  = res_sec['virtual_address']
	sec_raw = res_sec['raw_ptr']

	def rva2off(rva):
		return rva - sec_va + sec_raw

	def read_dir_entries(dir_rva):
		f.seek(rva2off(dir_rva))
		hdr = f.read(16)
		num_named, num_id = struct.unpack("<HH", hdr[12:16])
		return [struct.unpack("<II", f.read(8)) for _ in range(num_named + num_id)]

	RT_VERSION = 16
	type_entries = read_dir_entries(res_rva)
	type_off = next(
		(off for id_, off in type_entries
		 if not (id_ & 0x80000000) and id_ == RT_VERSION),
		None
	)
	if type_off is None:
		return None

	name_entries = read_dir_entries(res_rva + (type_off & 0x7FFFFFFF))
	if not name_entries:
		return None
	_, lang_off = name_entries[0]

	lang_entries = read_dir_entries(res_rva + (lang_off & 0x7FFFFFFF))
	if not lang_entries:
		return None
	_, data_entry_off = lang_entries[0]

	f.seek(rva2off(res_rva + data_entry_off))
	data_rva, data_size = struct.unpack("<II", f.read(8))
	f.seek(rva2off(data_rva))
	return f.read(data_size)


class FixedFileInfo(object):
	"""
	Maps to VS_FIXEDFILEINFO as defined in winver.h.
	https://learn.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo

	Attributes:
		dw_signature       -- Must equal 0xFEEF04BD.
		struc_version      -- Tuple (major, minor).
		file_version       -- Tuple (major, minor, build, revision).
		product_version    -- Tuple (major, minor, build, revision).
		dw_file_flags_mask -- Bitmask of valid bits in dw_file_flags.
		dw_file_flags      -- File attribute flags (e.g. VS_FF_DEBUG).
		dw_file_os         -- Target OS (e.g. VOS_NT_WINDOWS32).
		dw_file_type       -- File type (e.g. VFT_DLL).
		dw_file_subtype    -- File subtype (driver/font type, or 0).
		dw_file_date_ms    -- High 32 bits of the 64-bit file timestamp.
		dw_file_date_ls    -- Low  32 bits of the 64-bit file timestamp.
	"""

	SIGNATURE = 0xFEEF04BD

	def __init__(self, data, offset):
		"""
		Parse VS_FIXEDFILEINFO from a bytes buffer at the given offset.

		Args:
			data:   Raw bytes of the VS_VERSION_INFO blob.
			offset: Byte offset within data where VS_FIXEDFILEINFO begins.

		Raises:
			ValueError: If the signature field does not equal 0xFEEF04BD.
		"""
		(self.dw_signature, dw_struc_version,
		 dw_file_version_ms, dw_file_version_ls,
		 dw_product_version_ms, dw_product_version_ls,
		 self.dw_file_flags_mask, self.dw_file_flags,
		 self.dw_file_os, self.dw_file_type, self.dw_file_subtype,
		 self.dw_file_date_ms, self.dw_file_date_ls) = struct.unpack_from("<13I", data, offset)

		if self.dw_signature != self.SIGNATURE:
			raise ValueError("Invalid VS_FIXEDFILEINFO signature: %s" % hex(self.dw_signature))

		self.struc_version   = (dw_struc_version >> 16, dw_struc_version & 0xFFFF)
		self.file_version    = (dw_file_version_ms >> 16,    dw_file_version_ms & 0xFFFF,
		                        dw_file_version_ls >> 16,    dw_file_version_ls & 0xFFFF)
		self.product_version = (dw_product_version_ms >> 16, dw_product_version_ms & 0xFFFF,
		                        dw_product_version_ls >> 16, dw_product_version_ls & 0xFFFF)

	@property
	def file_version_str(self):
		"""File version as a 'major.minor.build.revision' string."""
		return "%d.%d.%d.%d" % self.file_version

	@property
	def product_version_str(self):
		"""Product version as a 'major.minor.build.revision' string."""
		return "%d.%d.%d.%d" % self.product_version

	@property
	def struc_version_str(self):
		"""Structure version as a 'major.minor' string."""
		return "%d.%d" % self.struc_version

	def __repr__(self):
		return ("FixedFileInfo(file_version=%r, product_version=%r, "
		        "file_os=%s, file_type=%s, file_flags=%s)" % (
		        self.file_version_str, self.product_version_str,
		        hex(self.dw_file_os), hex(self.dw_file_type), hex(self.dw_file_flags)))


class StringTable(object):
	"""
	Maps to a StringTable node inside StringFileInfo.

	One StringTable exists per language/codepage combination. The lang_id
	is an 8-character hex string whose upper 4 digits are the Windows LCID
	and lower 4 digits are the code page (e.g. "040904b0" = en-US / UTF-16).

	Attributes:
		lang_id -- 8-character hex string identifying language and code page.
		strings -- Dict mapping string key names to their values.
	"""

	def __init__(self, lang_id, strings):
		"""
		Args:
			lang_id: 8-character hex string (language + code page).
			strings: Dict of {key: value} string resource pairs.
		"""
		self.lang_id = lang_id
		self.strings = strings

	@property
	def language(self):
		"""Upper 16 bits of lang_id as a Windows LCID (int)."""
		return int(self.lang_id[:4], 16)

	@property
	def code_page(self):
		"""Lower 16 bits of lang_id as a code page number (int)."""
		return int(self.lang_id[4:], 16)

	def get(self, key, default=None):
		"""Return the string value for key, or default if not present."""
		return self.strings.get(key, default)

	def __getitem__(self, key):
		"""Return the string value for key, raising KeyError if not present."""
		return self.strings[key]

	def __repr__(self):
		return "StringTable(lang_id=%r, keys=%r)" % (self.lang_id, list(self.strings))


class VSVersionInfo(object):
	"""
	Maps to VS_VERSIONINFO (verrsrc.h).
	https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo

	Attributes:
		w_length       -- Total byte length of the VS_VERSION_INFO structure.
		w_value_length -- Byte length of the VS_FIXEDFILEINFO value.
		w_type         -- 0 = binary value, 1 = text value.
		fixed          -- FixedFileInfo instance (VS_FIXEDFILEINFO).
		string_tables  -- List of StringTable, one per language/codepage.
	"""

	def __init__(self, data):
		"""
		Parse a VS_VERSION_INFO blob from raw bytes.

		Args:
			data: Raw bytes of the VS_VERSION_INFO resource.

		Raises:
			ValueError: If the VS_FIXEDFILEINFO signature is invalid.
		"""
		self._data = data
		self._parse()

	@staticmethod
	def _align4(n):
		"""Round n up to the next 4-byte boundary."""
		return (n + 3) & ~3

	def _read_node_header(self, offset):
		"""
		Read a variable-length node header at the given offset.

		Returns:
			Tuple (w_length, w_value_length, w_type, key, value_start_offset).
		"""
		w_length, w_value_length, w_type = struct.unpack_from("<HHH", self._data, offset)
		pos = offset + 6
		end = pos
		while end + 1 < len(self._data) and self._data[end:end + 2] != b'\x00\x00':
			end += 2
		key = self._data[pos:end].decode('utf-16-le')
		value_start = self._align4(end + 2)
		return w_length, w_value_length, w_type, key, value_start

	def _parse(self):
		"""
		Deserialise the VS_VERSION_INFO tree, populating w_length,
		w_value_length, w_type, fixed, and string_tables.
		"""
		data = self._data
		self.w_length, self.w_value_length, self.w_type, _, pos = self._read_node_header(0)
		self.fixed = FixedFileInfo(data, pos)
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
					self.string_tables.append(StringTable(lang_key, strings))
					st_pos = self._align4(st_pos + st_length)
			pos = self._align4(pos + c_length)

	@classmethod
	def from_file(cls, path):
		"""
		Construct a VSVersionInfo by reading RT_VERSION from a PE file on disk.

		Locates the RT_VERSION resource data via the PE resource directory,
		reads the raw VS_VERSION_INFO bytes, and parses them. Supports both
		PE32 (32-bit) and PE32+ (64-bit) images.

		Args:
			path: Filesystem path to the PE file.

		Returns:
			VSVersionInfo instance.

		Raises:
			ValueError: If the file is not valid, RT_VERSION is absent, or
			            the VS_FIXEDFILEINFO signature is invalid.
		"""
		with open(path, 'rb') as f:
			f.seek(0x3C)
			nt_off = struct.unpack("<I", f.read(4))[0]
			f.seek(nt_off)
			if f.read(4) != b"PE\x00\x00":
				raise ValueError("Not a valid PE file")
			sections = _pe_parse_sections(f, nt_off)
			res_rva, _ = _pe_get_resource_dd(f, nt_off)
			if res_rva == 0:
				raise ValueError("No resource data directory")
			data = _pe_get_rt_version_data(f, sections, res_rva)
			if data is None:
				raise ValueError("RT_VERSION resource not found")
		return cls(data)

	def __repr__(self):
		return "VSVersionInfo(fixed=%r, string_tables=%r)" % (self.fixed, self.string_tables)


def get_module_version(path):
	"""
	Read the FileVersion from a PE file on disk by parsing VS_VERSION_INFO
	directly from the resource section, without relying on pykd.
	Supports both PE32 (32-bit) and PE32+ (64-bit) images.

	Args:
		path: Filesystem path to the PE file.

	Returns:
		Version string in 'major.minor.build.revision' format, or empty
		string if the version resource cannot be found or parsed.
	"""
	try:
		return VSVersionInfo.from_file(path).fixed.file_version_str
	except Exception:
		return ""


def getModulesFromPEB():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	global PEBModList
	peb = getPEBInfo()
	imagenames = []
	# http://www.nirsoft.net/kernel_struct/vista/PEB.html
	# http://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html
	# http://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
	# The usage of _LDR_DATA_TABLE_ENTRY.SizeOfImage is very confusing and appears to actually contain the module base
	offset = 0x20
	if arch == 64:
		offset = 0x40
	moduleLst = pykd.typedVarList(peb.Ldr.deref().InLoadOrderModuleList, "ntdll!_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks.Flink")
	if DEBUG_MODE:
		dbgp("moduleList: %d, PEBModlist: %d" % (len(moduleLst), len(PEBModList)))
	if len(PEBModList) == 0:
		for mod in moduleLst:
			thismod = ensure_text(pykd.loadUnicodeString(mod.BaseDllName))
			if DEBUG_MODE:
				dbgp("Got name for mod.BaseDllName: %s" % thismod)
			modparts = thismod.split("\\")
			modulename = modparts[len(modparts)-1]
			fullpath = thismod
			exename = modulename

			addtolist = True

			moduleparts = modulename.split(".")
			imagename = ""
			if len(moduleparts) == 1:
				imagename = moduleparts[0]
			cnt = 0
			while cnt < len(moduleparts)-1:
				imagename = imagename + moduleparts[cnt] + "."
				cnt += 1
			imagename = imagename.strip(".")

			# no windbg love for +  -  .
			imagename = imagename.replace("+","_")
			imagename = imagename.replace("-","_")
			imagename = imagename.replace(".","_")

			if imagename in imagenames:
				# duplicate name ?  Append _<baseaddress>
				# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
				baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
				imagename = imagename+"_%08x" % baseaddy

			# check if module can be loaded
			try:
				modcheck = pykd.module(imagename)
			except:
				# change to image+baseaddress
				# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
				baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
				imagename = "image%08x" % baseaddy
				try:
					modcheck = pykd.module(imagename)
				except:
					# try with base addy
					try:
						modcheck = pykd.module(baseaddy)
						imagename = modcheck.name()
						#print "Name: %s" % modcheck.name()
						#print "Imagename: %s" % modcheck.image()
					except:
						# try finding it with windbg 'ln'
						cmd2run = "ln 0x%08x" % baseaddy
						output = pykd.dbgCommand(cmd2run)
						if "!__ImageBase" in output:
							outputlines = output.split("\n")
							for l in outputlines:
								if "!__ImageBase" in l:
									lparts = l.split("!__ImageBase")
									leftpart = lparts[0]
									leftparts = leftpart.split(" ")
									imagename = leftparts[len(leftparts)-1]
						try:
							modcheck = pykd.module(imagename)
						except:
							print("")
							print("   *** Error parsing module '%s' ('%s') at 0x%08x ***" % (imagename,modulename,baseaddy))
							print("   *** Please open a github issue ticket at https://github.com/corelan/windbglib ***")
							print("   *** and provide the output of the following 2 windbg commands in the ticket: ***")
							print("         lm")
							print("         !peb")
							print("   *** Thanks")
							print("")
							addtolist = False

			if addtolist:
				imagenames.append(imagename)
				PEBModList[imagename] = [exename, fullpath]
				if DEBUG_MODE:
					dbgp("    Added %s to PEBModList" % imagename)
	
	return moduleLst



def getModuleFromAddress(address):
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	offset = 0x20
	if arch == 64:
		offset = 0x40

	global ModuleCache
	# try fastest way first
	try:
		thismod = pykd.module(address)
		# if that worked, we could add it to the cache if needed
		modbase = thismod.begin()
		modsize = thismod.size()
		modend = modbase + modsize
		modulename = thismod.image()
		ModuleCache[modulename] = [modbase,modsize]
		if (address >= modbase) and (address <= modend):
			return thismod
	except:
		pass


	# maybe cached	
	for modname in ModuleCache:
		modparts = ModuleCache[modname]
		# 0 : base
		# 1 : size
		modbase = modparts[0]
		modsize = modparts[1]
		modend = modbase + modsize
		if (address >= modbase) and (address <= modend):
			#print "0x%08x belongs to %s" % (address,modname)
			return pykd.module(modname)
	# not cached, find it
	moduleLst = getModulesFromPEB()
	for mod in moduleLst:
		thismod = ensure_text(pykd.loadUnicodeString(mod.BaseDllName))
		modparts = thismod.split("\\")
		modulename = modparts[len(modparts)-1].lower()
		moduleparts = modulename.split(".")
		modulename = ""
		if len(moduleparts) == 1:
			modulename = moduleparts[0]
		cnt = 0
		while cnt < len(moduleparts)-1:
			modulename = modulename + moduleparts[cnt] + "."
			cnt += 1
		modulename = modulename.strip(".")
		thismod = ""
		imagename = ""

		try:
			moduleLst = getModulesFromPEB()
			for mod in moduleLst:
				thismod = ensure_text(pykd.loadUnicodeString(mod.BaseDllName))
				modparts = thismod.split("\\")
				thismodname = modparts[len(modparts)-1]
				moduleparts = thismodname.split(".")
				if len(moduleparts) > 1:
					thismodname = ""
					cnt = 0
					while cnt < len(moduleparts)-1:
						thismodname = thismodname + moduleparts[cnt] + "."
						cnt += 1
					thismodname = thismodname.strip(".")					
				if thismodname.lower() == modulename.lower():
					# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
					baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
					baseaddr = "%08x" % baseaddy
					lmcommand = pykd.dbgCommand("lm")
					lmlines = lmcommand.split("\n")
					foundinlm = False
					for lmline in lmlines:
						linepieces = lmline.split(" ")
						if linepieces[0].upper() == baseaddr.upper():
							cnt = 2
							while cnt < len(linepieces) and not foundinlm:
								if linepieces[cnt].strip(" ") != "":
									imagename = linepieces[cnt]
									foundinlm = True
									break
								cnt += 1
					if not foundinlm:
						imagename = "image%s" % baseaddr.lower()
						break
		except:
			pykd.dprintln(traceback.format_exc())

		try:
			modulename = imagename
			thismod = pykd.module(imagename)
			modbase = thismod.begin()
			modsize = thismod.size()
			modend = modbase + modsize
			ModuleCache[modulename] = [modbase,modsize]
			if (address >= modbase) and (address <= modend):
				return thismod
		except:
			thismod = pykd.module(address)

			modbase = thismod.begin()
			modsize = thismod.size()
			modend = modbase + modsize
			modulename = thismod.image()
			ModuleCache[modulename] = [modbase,modsize]
			if (address >= modbase) and (address <= modend):
				return thismod			

	return None

def getImageBaseOnDisk(fullpath):
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	with open(fullpath, "rb") as pe: 
		data = pe.read()
		nt_header_offset = struct.unpack("<I", data[0x3c:0x40])[0]
		optional_header_offset = nt_header_offset + 0x18
		magic = struct.unpack("<H", data[optional_header_offset:optional_header_offset+2])[0]
		if magic == 0x10b:
			#32bit
			imageBase = struct.unpack("<I", data[optional_header_offset+28:optional_header_offset+28+4])[0]
		else:
			# 64bit
			imageBase = struct.unpack("<Q", data[optional_header_offset+24:optional_header_offset+24+8])[0]
	return imageBase



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
		self.OpcodeCache = {}
		self.ModCache = {}
		self.fillAsmCache()
		self.knowledgedb = "windbglib.db"

	def setKBDB(self,filename = "windbglib.db"):
		self.knowledgedb = filename
		return

	def getKBDB(self):
		return self.knowledgedb

	def remoteVirtualAlloc(self, size=0x10000,interactive=False):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		PAGE_EXECUTE_READWRITE = 0x40
		VIRTUAL_MEM = ( 0x1000 | 0x2000 )
		vaddr = self.rVirtualAlloc(0,size,VIRTUAL_MEM,PAGE_EXECUTE_READWRITE)
		return vaddr

	def rVirtualAlloc(self, lpAddress, dwSize, flAllocationType, flProtect):
		if DEBUG_MODE:
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
			return int(vaddr)
		return 0

	def rVirtualProtect(self, lpAddress, dwSize, flNewProtect, lpflOldProtect=0):
		if DEBUG_MODE:
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

		returnval = kernel32.VirtualProtectEx(
			ctypes.c_void_p(hprocess),
			ctypes.c_void_p(lpAddress),
			ctypes.c_size_t(dwSize),
			ctypes.c_ulong(flNewProtect),
			ctypes.byref(oldprotect)
		)

		kernel32.CloseHandle(hprocess)
		return returnval


	def getAddress(self, functionname):
		if DEBUG_MODE:
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

	def getCurrentTEBAddress(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		return getTEBAddress()	

	"""
	AsmCache
	"""

	def fillAsmCache(self):
		if DEBUG_MODE:
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
		# ------------------------------------------------------------
		# JMP reg
		# ------------------------------------------------------------
		self.AsmCache["jmp rax"] = b"\xff\xe0"
		self.AsmCache["jmp rcx"] = b"\xff\xe1"
		self.AsmCache["jmp rdx"] = b"\xff\xe2"
		self.AsmCache["jmp rbx"] = b"\xff\xe3"
		self.AsmCache["jmp rsp"] = b"\xff\xe4"
		self.AsmCache["jmp rbp"] = b"\xff\xe5"
		self.AsmCache["jmp rsi"] = b"\xff\xe6"
		self.AsmCache["jmp rdi"] = b"\xff\xe7"
		self.AsmCache["jmp r8"]  = b"\x41\xff\xe0"
		self.AsmCache["jmp r9"]  = b"\x41\xff\xe1"
		self.AsmCache["jmp r10"] = b"\x41\xff\xe2"
		self.AsmCache["jmp r11"] = b"\x41\xff\xe3"
		self.AsmCache["jmp r12"] = b"\x41\xff\xe4"
		self.AsmCache["jmp r13"] = b"\x41\xff\xe5"
		self.AsmCache["jmp r14"] = b"\x41\xff\xe6"
		self.AsmCache["jmp r15"] = b"\x41\xff\xe7"

		# ------------------------------------------------------------
		# CALL reg
		# ------------------------------------------------------------
		self.AsmCache["call rax"] = b"\xff\xd0"
		self.AsmCache["call rcx"] = b"\xff\xd1"
		self.AsmCache["call rdx"] = b"\xff\xd2"
		self.AsmCache["call rbx"] = b"\xff\xd3"
		self.AsmCache["call rsp"] = b"\xff\xd4"
		self.AsmCache["call rbp"] = b"\xff\xd5"
		self.AsmCache["call rsi"] = b"\xff\xd6"
		self.AsmCache["call rdi"] = b"\xff\xd7"
		self.AsmCache["call r8"]  = b"\x41\xff\xd0"
		self.AsmCache["call r9"]  = b"\x41\xff\xd1"
		self.AsmCache["call r10"] = b"\x41\xff\xd2"
		self.AsmCache["call r11"] = b"\x41\xff\xd3"
		self.AsmCache["call r12"] = b"\x41\xff\xd4"
		self.AsmCache["call r13"] = b"\x41\xff\xd5"
		self.AsmCache["call r14"] = b"\x41\xff\xd6"
		self.AsmCache["call r15"] = b"\x41\xff\xd7"

		# ------------------------------------------------------------
		# JMP [reg]
		# FF /4 with modrm selecting memory operand [reg]
		# Note: [rsp] and [r12] require SIB byte 0x24
		# Note: [rbp] and [r13] with mod=00 do not encode plain [rbp]/[r13],
		#       so use mod=01 with disp8=00 instead.
		# ------------------------------------------------------------
		self.AsmCache["jmp [rax]"] = b"\xff\x20"
		self.AsmCache["jmp [rcx]"] = b"\xff\x21"
		self.AsmCache["jmp [rdx]"] = b"\xff\x22"
		self.AsmCache["jmp [rbx]"] = b"\xff\x23"
		self.AsmCache["jmp [rsp]"] = b"\xff\x24\x24"
		self.AsmCache["jmp [rbp]"] = b"\xff\x65\x00"
		self.AsmCache["jmp [rsi]"] = b"\xff\x26"
		self.AsmCache["jmp [rdi]"] = b"\xff\x27"
		self.AsmCache["jmp [r8]"]  = b"\x41\xff\x20"
		self.AsmCache["jmp [r9]"]  = b"\x41\xff\x21"
		self.AsmCache["jmp [r10]"] = b"\x41\xff\x22"
		self.AsmCache["jmp [r11]"] = b"\x41\xff\x23"
		self.AsmCache["jmp [r12]"] = b"\x41\xff\x24\x24"
		self.AsmCache["jmp [r13]"] = b"\x41\xff\x65\x00"
		self.AsmCache["jmp [r14]"] = b"\x41\xff\x26"
		self.AsmCache["jmp [r15]"] = b"\x41\xff\x27"

		# ------------------------------------------------------------
		# CALL [reg]
		# FF /2 with modrm selecting memory operand [reg]
		# Same encoding caveats as above for rsp/r12 and rbp/r13
		# ------------------------------------------------------------
		self.AsmCache["call [rax]"] = b"\xff\x10"
		self.AsmCache["call [rcx]"] = b"\xff\x11"
		self.AsmCache["call [rdx]"] = b"\xff\x12"
		self.AsmCache["call [rbx]"] = b"\xff\x13"
		self.AsmCache["call [rsp]"] = b"\xff\x14\x24"
		self.AsmCache["call [rbp]"] = b"\xff\x55\x00"
		self.AsmCache["call [rsi]"] = b"\xff\x16"
		self.AsmCache["call [rdi]"] = b"\xff\x17"
		self.AsmCache["call [r8]"]  = b"\x41\xff\x10"
		self.AsmCache["call [r9]"]  = b"\x41\xff\x11"
		self.AsmCache["call [r10]"] = b"\x41\xff\x12"
		self.AsmCache["call [r11]"] = b"\x41\xff\x13"
		self.AsmCache["call [r12]"] = b"\x41\xff\x14\x24"
		self.AsmCache["call [r13]"] = b"\x41\xff\x55\x00"
		self.AsmCache["call [r14]"] = b"\x41\xff\x16"
		self.AsmCache["call [r15]"] = b"\x41\xff\x17"


		# ------------------------------------------------------------
		# PUSH reg (x64)
		# ------------------------------------------------------------
		self.AsmCache["push rax"] = b"\x50"
		self.AsmCache["push rcx"] = b"\x51"
		self.AsmCache["push rdx"] = b"\x52"
		self.AsmCache["push rbx"] = b"\x53"
		self.AsmCache["push rsp"] = b"\x54"
		self.AsmCache["push rbp"] = b"\x55"
		self.AsmCache["push rsi"] = b"\x56"
		self.AsmCache["push rdi"] = b"\x57"
		self.AsmCache["push r8"]  = b"\x41\x50"
		self.AsmCache["push r9"]  = b"\x41\x51"
		self.AsmCache["push r10"] = b"\x41\x52"
		self.AsmCache["push r11"] = b"\x41\x53"
		self.AsmCache["push r12"] = b"\x41\x54"
		self.AsmCache["push r13"] = b"\x41\x55"
		self.AsmCache["push r14"] = b"\x41\x56"
		self.AsmCache["push r15"] = b"\x41\x57"

		# ------------------------------------------------------------
		# POP reg (x64)
		# ------------------------------------------------------------
		self.AsmCache["pop rax"] = b"\x58"
		self.AsmCache["pop rcx"] = b"\x59"
		self.AsmCache["pop rdx"] = b"\x5a"
		self.AsmCache["pop rbx"] = b"\x5b"
		self.AsmCache["pop rsp"] = b"\x5c"
		self.AsmCache["pop rbp"] = b"\x5d"
		self.AsmCache["pop rsi"] = b"\x5e"
		self.AsmCache["pop rdi"] = b"\x5f"
		self.AsmCache["pop r8"]  = b"\x41\x58"
		self.AsmCache["pop r9"]  = b"\x41\x59"
		self.AsmCache["pop r10"] = b"\x41\x5a"
		self.AsmCache["pop r11"] = b"\x41\x5b"
		self.AsmCache["pop r12"] = b"\x41\x5c"
		self.AsmCache["pop r13"] = b"\x41\x5d"
		self.AsmCache["pop r14"] = b"\x41\x5e"
		self.AsmCache["pop r15"] = b"\x41\x5f"

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
		if DEBUG_MODE:
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
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		allk = self.readKnowledgeDB()
		if id in allk:
			return allk[id]
		else:
			return None

	def readKnowledgeDB(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		allk = {}
		try:
			with open(self.knowledgedb,"rb") as fh:
				allk = pickle.load(fh)
		except:
			pass
		return allk

	def listKnowledge(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		allk = self.readKnowledgeDB()
		allid = []
		for thisk in allk:
			allid.append(thisk)
		return allid

	def cleanKnowledge(self):
		if DEBUG_MODE:
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
		if DEBUG_MODE:
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

	def cleanUp(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		self.cleanKnowledge()
		return

	"""
	Placeholders
	"""
	def analysecode(self):
		return

	def isAnalysed(self):
		return True

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
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		return
	
	def log(self, message, highlight=0, address=None, focus=0):
		if not address == None:
			message = intToHex(address) + " | " + message
		showdml = False
		if highlight == 1:
			showdml = True
			message = "<b>" + message + "</b>"
		else:
			if "<b>" in message and "</b>" in message:
				showdml = True
		pykd.dprintln(self.toAsciiOnly(message), showdml)


	def logLines(self, message, highlight=0,address=None, focus=0):
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
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		# http://www.nirsoft.net/kernel_struct/vista/RTL_USER_PROCESS_PARAMETERS.html
		peb = getPEBInfo()
		ProcessParameters = peb.ProcessParameters
		offset = 0x38
		if arch == 64:
			offset = 0x60
		# ProcessParameters + offset = _RTL_USER_PROCESS_PARAMETERS.ImagePathName(_UNICODE_STRING)
		# sImageFile = pykd.loadUnicodeString(ProcessParameters + offset)
		sImageFile = ensure_text(pykd.loadUnicodeString(int(ProcessParameters) + offset))
		sImageFilepieces = sImageFile.split("\\")
		return sImageFilepieces[len(sImageFilepieces)-1]
		
	def getDebuggedPid(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
		teb = getTEBAddress()
		offset = 0x20
		if arch == 64:
			offset = 0x40
		# _TEB.ClientId(CLIENT_ID).UniqueProcess(PVOID)
		pid = pykd.ptrDWord(teb+offset)
		return pid

	
	"""
	OS stuff
	"""
	def getOsRelease(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		peb = getPEBInfo()
		majorversion = int(peb.OSMajorVersion)
		minorversion = int(peb.OSMinorVersion)
		buildversion = int(peb.OSBuildNumber)
		osversion = str(majorversion)+"."+str(minorversion)+"."+str(buildversion)
		return osversion
	
	def getOsVersion(self):
		return getOSVersion()

	def getPyKDVersionNr(self):
		return getPyKDVersion()
		
	"""
	Registers
	"""
	
	def getRegs(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		regs = []
		if arch == 32:
			regs = Registers32BitsOrder[:]
			regs.append("EIP")
		if arch == 64:
			regs = Registers64BitsOrder[:]
			regs.append("RIP")
		reginfo = {}
		for thisreg in regs:
			reginfo[thisreg.upper()] = int(pykd.reg(thisreg.lower()))
		return reginfo
	

	"""
	Commands
	"""
	def nativeCommand(self,cmd2run):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		try:
			if DEBUG_MODE:
				dbgp("nativeCommand: %s" % cmd2run)
			output = pykd.dbgCommand(cmd2run)
			if DEBUG_MODE:
				dbgp("command output: %s" % output)
			if output is None:
				output = ""
			if DEBUG_MODE:
				dbgp("returning '%s'" % output)
			return output
		except:
			#dprintln(traceback.format_exc())
			#dprintln(cmd2run)
			return ""

	"""
	SEH
	"""

	def getSehChain(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())
	
		# http://www.nirsoft.net/kernel_struct/vista/TEB.html
		# http://www.nirsoft.net/kernel_struct/vista/NT_TIB.html
		# http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_REGISTRATION_RECORD.html

		# x64 has no SEH chain
		if arch == 64:
			return []
		sehchain = []
		# get top of chain
		teb = getTEBAddress()
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
		if DEBUG_MODE:
			dbgp(get_current_function_name())
		try:
			data = bytes(bytearray(pykd.loadBytes(location, size)))
			return ensure_bytes(data)
		except:
			return ensure_bytes(b"")

	def readString(self,location):
		if pykd.isValid(location):
			try:
				return pykd.loadCStr(location)
			except pykd.MemoryException:
				return pykd.loadChars(location, 0x100)
			except:
				return ""
		else:
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
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		data = ensure_bytes(data)

		pykd.writeBytes(location, list(bytearray(data)))
		return

	def writeLong(self,location,dword):
		bytesdword = hexptr2bin(dword)
		self.writeMemory(location,bytesdword)
		return


	def getMemoryPages(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		if not self.MemoryPages:
			address_output = pykd.dbgCommand("!address")
			address_output_lines = address_output.splitlines()

			row_regex = re.compile(
				r'^\s*\+?\s*'                 # optional leading "+"
				r'([0-9A-Fa-f`]+)\s+'         # BaseAddress
				r'([0-9A-Fa-f`]+)\s+'         # EndAddress+1
				r'([0-9A-Fa-f`]+)\b'          # RegionSize
			)

			for memory_page_info in address_output_lines:
				memory_page_info = memory_page_info.rstrip()
				m = row_regex.match(memory_page_info)
				if not m:
					continue

				starting_address = int(m.group(1).replace('`', ''), 16)
				size = int(m.group(3).replace('`', ''), 16)

				#if DEBUG_MODE:
				#	dbgp("      OK - Including page: 0x%08x, size 0x%08x" % (starting_address, size))

				page_obj = wpage(starting_address, size)
				self.MemoryPages[starting_address] = page_obj

		return self.MemoryPages


	def getMemoryPages_old(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		if not self.MemoryPages:
			address_output = pykd.dbgCommand('!address -c:".printf\\"%1 %3 \\\\n\\""')
			address_output_lines = address_output.split('\n')
			info_regex = re.compile(r'0x[\da-fA-F]+ 0x[\da-fA-F]+')
			for memory_page_info in address_output_lines:
				memory_page_info = memory_page_info.strip()
				if info_regex.match(memory_page_info):
					info = memory_page_info.split(' ')
					starting_address = int(info[0].replace('`', ''), base=16)
					size = int(info[1].replace('`', ''), base=16)
					page_obj = wpage(starting_address, size)
					self.MemoryPages[starting_address] = page_obj

		if DEBUG_MODE:
			dbgp("--- THIS SHOULD BE HIDDEN ---")
			address_output = pykd.dbgCommand("!address")
			dbgp("--- END THIS SHOULD BE HIDDEN ---")
			address_output_lines = address_output.split('\n')
			for mmm in address_output_lines:
				dbgp(" Line: %s" % mmm)

		return self.MemoryPages


	def getMemoryPageByAddress(self,address):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		if len(self.MemoryPages) == 0:
			# may never get hit
			self.MemoryPages = self.getMemoryPages()
		pagesize = 0
		startaddress = self.getPageContains(address)
		if startaddress in self.MemoryPages:
			return self.MemoryPages[startaddress]
		else:
			page = wpage(startaddress,pagesize)
			return page

	def getMemoryPageByOwner(self,ownerobj):
		return []

	def getPageContains(self,address):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		if len(self.MemoryPages) == 0:
			self.MemoryPages = self.getMemoryPages()
		for pagestart in self.MemoryPages:
			thispage = self.MemoryPages[pagestart]
			pageend = pagestart + thispage.getSize()
			if address >= pagestart and address < pageend:
				return pagestart
		return 0

	def getHeapsAddress(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		allheaps = []
		peb = getPEBInfo()
		offset = 0x88
		if arch == 64:
			offset = 0xe8
		# _PEB.NumberOfHeaps(ULONG)
		nrofheaps = int(pykd.ptrDWord(peb+offset))
		# _PEB.ProcessHeaps(VOID**)
		processheaps = int(peb.ProcessHeaps)
		try:
   			# Python 2
			xrange
		except NameError:
			# Python 3, xrange is now named range
			xrange = range

		for i in xrange(nrofheaps):
			# _PEB.ProcessHeaps[i](VOID*)
			nextheap = pykd.ptrPtr(processheaps + (i*(arch//8)))
			if nextheap == 0x00000000:
				break
			if not nextheap in allheaps:
				allheaps.append(nextheap)
		return allheaps


	def getHeap(self,address):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		return wheap(address)

	def getPEBAddress(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		return getPEBAddress()

	def getAllThreads(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		allthreads = []
		for thisthread in pykd.getProcessThreads():
			allthreads.append(wthread(thisthread))
		return allthreads

	"""
	Modules
	"""
	def getModule(self,modulename):
		if DEBUG_MODE:
			dbgp(get_current_function_name())
			dbgp("------")
			dbgp("Transform '%s' into Module object" % modulename)

		wmod = None
		self.origmodname = modulename
		fullpath = ""
		if len(PEBModList) == 0:
			getModulesFromPEB()
			if DEBUG_MODE:
				dbgp("    Loaded modules from PEB")
		else:
			if DEBUG_MODE:
				dbgp("    Modules were already loaded into PEBModList, continue")
		try:
			thismod = None
			if modulename in PEBModList:
				modentry = PEBModList[modulename]
				if DEBUG_MODE:
					dbgp("    Convert module into pykd module object: %s" % modulename)
				thismod = pykd.module(modulename)
				fullpath = modentry[1]
			else:
				if DEBUG_MODE:
					dbgp("Module %s not found in PEBModList" % modulename)
				# find a good one
				for modentry in PEBModList:
					modrecord = PEBModList[modentry]
					# 0 : file
					# 1 : path
					if DEBUG_MODE:
						dbgp("Modrecord: %s" % modrecord)
					if modulename == modrecord[0]:
						thismod = pykd.module(modentry)
						fullpath = modrecord[1]
						break

			#if thismod == None:
			#	# should never hit, as we have tested if modules can be loaded already
			#	imagename = self.getImageNameForModule(self.origmodname)
			#	thismod = pykd.module(str(imagename))

			if DEBUG_MODE:
				dbgp("    Getting module properties (name, start, end, size, etc)")
			
			thisimagename = thismod.image()
			thismodname = thismod.name()
			thismodbase = thismod.begin()
			thismodsize = thismod.size()
			thismodpath = thismod.image()

			if DEBUG_MODE:
				dbgp("       image: %s" % thisimagename)
				dbgp("       name: %s" % thismodname)
				dbgp("       begin: 0x%08x" % thismodbase)
				dbgp("       size: 0x%08x" % thismodsize)
				dbgp("       path: %s" % thismodpath)				

			try:
				if DEBUG_MODE:
					dbgp("    Trying to get version info")
				thismodversion = get_module_version(fullpath)
				if DEBUG_MODE:
					dbgp("    -> %s" % thismodversion)
			except Exception as e:
				thismodversion = ""
				if DEBUG_MODE:
					dbgp("    Error: %s (might be ok)" % str(e))
				
			if DEBUG_MODE:
				dbgp("    Getting NT Headers for %s. Base: 0x%08x" % (thisimagename, thismodbase))
			ntHeader = getNtHeaders(thismodbase)
			#preferredbase = ntHeader.OptionalHeader.ImageBase
			preferredbase = getImageBaseOnDisk(fullpath)
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			codebase = ntHeader.OptionalHeader.BaseOfCode
			if arch == 64:
				database = 0
			else:
				database = ntHeader.OptionalHeader.BaseOfData
			sizeofcode = ntHeader.OptionalHeader.SizeOfCode

			wmod = wmodule(thismodname)

			wmod.setBaseAddress(thismodbase)
			wmod.setFixupBase(preferredbase)
			wmod.setPath(thismodpath)
			wmod.setSize(thismodsize)
			wmod.setEntry(entrypoint)
			wmod.setCodeBase(codebase)
			wmod.setCodeSize(sizeofcode)
			wmod.setDatabase(database)
			wmod.setVersion(thismodversion)
		except:
			pykd.dprintln("** Error trying to process module %s" % modulename)
			pykd.dprintln(traceback.format_exc())
			wmod = None

		return wmod
		

	def getAllModules(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		if len(self.allmodules) == 0:
			if len(PEBModList) == 0:
				if DEBUG_MODE:
					dbgp("Get modules from PEB")
				getModulesFromPEB()
				if DEBUG_MODE:
					dbgp("Modules in list now: %d" % len(PEBModList))
			for imagename in PEBModList:
				thismodname = PEBModList[imagename][0]
				wmodobject = self.getModule(imagename)
				self.allmodules[thismodname] = wmodobject
		return self.allmodules


	def getImageNameForModule(self,modulename):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		# http://www.nirsoft.net/kernel_struct/vista/PEB.html
		# http://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html
		# http://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
		offset = 0x20
		if arch == 64:
			offset = 0x40
		try:
			imagename = ""
			moduleLst = getModulesFromPEB()
			for mod in moduleLst:
				thismod = ensure_text(pykd.loadUnicodeString(mod.BaseDllName))
				modparts = thismod.split("\\")
				thismodname = modparts[len(modparts)-1]
				moduleparts = thismodname.split(".")
				if thismodname.lower() == modulename.lower():
					# mod.getAddress() + offset = _LDR_DATA_TABLE_ENTRY.SizeOfImage
					baseaddy = int(pykd.ptrPtr(mod.getAddress() + offset))
					baseaddr = "%08x" % baseaddy
					lmcommand = self.nativeCommand("lm")
					lmlines = lmcommand.split("\n")
					foundinlm = False
					for lmline in lmlines:
						linepieces = lmline.split(" ")
						if linepieces[0].upper() == baseaddr.upper():
							cnt = 2
							while cnt < len(linepieces) and not foundinlm:
								if linepieces[cnt].strip(" ") != "":
									imagename = linepieces[cnt]
									foundinlm = True
								cnt += 1
					if not foundinlm:
						imagename = "image%s" % baseaddr.lower()
					return imagename
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
			disasmlist = pykd.dbgCommand(cmd2run)
			disasmLinesTmp = disasmlist.split("\n")
			disasmLines = []
			for line in disasmLinesTmp:
				if line.replace(" ","") != "":
					disasmLines.append(line)
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
			if DEBUG_MODE:
				dbgp("Error disasmForward for 0x%x: %s" % (address, str(e)))
				dbgp(traceback.format_exc())
			return self.getOpcode(address)


	def disasmForwardAddressOnly(self,address,depth):
		# go to correct location, get address of next after current address
		return self.disasmForward(address,depth).getAddress()

	def disasmBackward(self,address,depth):
		while True:
			cmd2run = "ub 0x%08x L%d" % (address,depth)
			if DEBUG_MODE:
				dbgp("cmd2run: %s" % cmd2run)
			try:
				disasmlist = pykd.dbgCommand(cmd2run)
				disasmLinesTmp = disasmlist.split("\n")
				disasmLines = []
				for line in disasmLinesTmp:
					if line.replace(" ","") != "":
						disasmLines.append(line)
				lineindex = len(disasmLines)-depth
				if lineindex > -1:
					asmline = disasmLines[lineindex]
					pointer = asmline[0:8] if arch == 32 else asmline[0:17]
					return self.getOpcode(addrToInt(pointer))
				else:
					return self.getOpcode(address)
			except Exception as e:
				if DEBUG_MODE:
					dbgp("Error disassembling backwards, %s" % str(e))
					dbgp(traceback.format_exc())
					dbgp("Depth: %d" % depth)
				# probably invalid instruction, so fake by returning itself
				# caller should check if address is different than what was provided
				if depth == 1:
					if DEBUG_MODE:
						dbgp("Depth 1, returning opcode at 0x%x" % address)
					return self.getOpcode(address)
			depth -= 1

	def assemble(self,instructions):
		allbytes = b""
		address = pykd.reg("eip") if arch == 32 else pykd.reg("rip")
		if DEBUG_MODE:
			dbgp("instructions: %s" % instructions)
			dbgp("address: 0x%s" % intToHex(address))
			dbgp("pykd.isValid(address): %s" % pykd.isValid(address))
		if not pykd.isValid(address):
			# assemble somewhere else - let's say at the ntdll entrypoint
			thismod = pykd.module("ntdll")
			thismodbase = thismod.begin()
			ntHeader = getNtHeaders(thismodbase)
			entrypoint = ntHeader.OptionalHeader.AddressOfEntryPoint
			address = thismodbase + entrypoint
		allinstructions = instructions.lower().split("\n")
		
		origbytes = bytes(bytearray(pykd.loadBytes(address, 20)))
		if DEBUG_MODE:
			dbgp("allinstructions: %s" % allinstructions)
			dbgp("origbytes: %s" % bin2hex(origbytes))

		cached = True
		for thisinstruction in allinstructions:	
			if DEBUG_MODE:
				dbgp("current instruction : %s" % thisinstruction)
			thisinstruction = thisinstruction.strip(" ").lstrip(" ")
			if thisinstruction.startswith("ret") and not thisinstruction.startswith("retf"):
				thisinstruction = thisinstruction.replace("retn","ret").replace("ret","retn")
			thisinstruction = thisinstruction.replace(" ,",",").replace(", ",",")

			if not thisinstruction in self.AsmCache:
				objdisasm = pykd.disasm(address)
				if DEBUG_MODE:
					dbgp("instruction not in cache, assembling")
				try:
					objdisasm.asm(thisinstruction)
				except Exception as e:
					print(str(e))
					if DEBUG_MODE:
						dbgp("unable to assemble instruction '%s'" % thisinstruction)
						dbgp("error: %s" % str(e))
					return ""
				opc = opcode(address)	
				thesebytes = opc.getBytes()
				if DEBUG_MODE:
					dbgp("bytes: " % thesebytes)
				allbytes += thesebytes
				self.AsmCache[thisinstruction] = thesebytes
				cached = False
			else:
			# return from cache
				if DEBUG_MODE:
					dbgp("return bytes from cache")
					dbgp("cache: %s" % bin2hex(self.AsmCache[thisinstruction]))
				allbytes += self.AsmCache[thisinstruction]
		if not cached:
			putback = "eb 0x%08x " % address
			restorebytes = ["%02x" % b for b in origbytes]
			putback += ' '.join(restorebytes)
			pykd.dbgCommand(putback)
			if DEBUG_MODE:
				dbgp("putback command: %s" % putback)
		if DEBUG_MODE:
			dbgp("returning %s" % bin2hex(allbytes))
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
		return pykd.loadCStr(address)

	"""
	Breakpoints
	"""
	def setBreakpoint(self,address):
		try:
			cmd2run = "bp 0x%08x" % address
			self.nativeCommand(cmd2run)
		except:
			return False
		return True

	def deleteBreakpoint(self,address):
		getallbps = "bl"
		allbps = self.nativeCommand(getallbps)
		bplines = allbps.split("\n")
		for line in bplines:
			fieldcnt = 0
			if line.replace(" ","") != "":
				lineparts = line.split(" ")
				id = ""
				type = ""
				bpaddress = ""
				for part in lineparts:
					if part != "":
						fieldcnt += 1
					if fieldcnt == 1:
						id = part
					if fieldcnt == 2:
						type = part
					if fieldcnt == 3:
						bpaddress = part
						break
				if hexStrToInt(bpaddress) == address and id != "":
					rmbp = "bc %s" % id
					self.nativeCommand(rmbp)

	def setMemBreakpoint(self,address,memType):
		validtype = False
		bpcommand = ""
		if memType.upper() == "S":
			bpcommand = "ba e 1 0x%08x" % address
			validtype = True
		if memType.upper() == "R":
			bpcommand = "ba r 4 0x%08x" % address
			validtype = True
		if memType.upper() == "W":
			bpcommand = "ba w 4 0x%08x" % address
			validtype = True
		if validtype:
			output = ""
			try:
				output = pykd.dbgCommand(bpcommand)
			except:
				if memType.upper() == "S":
					bpcommand = "bp 0x%08x" % address
					output = pykd.dbgCommand(bpcommand)
				else:
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
		self.modend  = None
		self.entrypoint = None
		self.preferredbase = None
		self.codebase = None
		self.sizeofcode = None
		self.database = None
		self.modversion = None

	# setters
	def setBaseAddress(self,value):
		self.modbase = value

	def setFixupBase(self,value):
		self.preferredbase = value

	def setPath(self,value):
		self.modpath = value

	def setSize(self,value):
		self.modsize = value

	def setVersion(self,value):
		self.modversion = value

	def setEntry(self,value):
		self.entrypoint = value

	def setCodeBase(self,value):
		self.codebase = value

	def setCodeSize(self,value):
		self.sizeofcode = value

	def setDatabase(self,value):
		self.database = value

	# getters
	def __str__(self):
		return self.modname

	def key(self):
		return self.modname

	def getName(self):
		return self.modname
	
	def getBaseAddress(self):
		return self.modbase
	
	def getFixupbase(self):
		return self.preferredbase

	def getPath(self):
		return self.modpath
	
	def getSize(self):
		return self.modsize

	def getIssystemdll(self):
		modisos = False
		if "WINDOWS" in self.modpath.upper():
			modisos = True
		else:
			modisos = False
		# exceptions
		if self.modname.lower()=="ntdll":
			modisos = True
		self.issystemdll = modisos
		return self.issystemdll
	
	def getVersion(self):
		return self.modversion
	
	def getEntry(self):
		return self.entrypoint
	
	def getCodebase(self):
		return self.codebase
		
	def getCodesize(self):
		return self.sizeofcode

	def getDatabase(self):
		return self.database

	def addressToSymbol(self, address):
		# use a WinDBG command to force a symbol lookup for an address
		# need double %% to avoid it is seen as format for python.
		global FuncCache

		if address in FuncCache:
			if FuncCache[address] != "":
				if DEBUG_MODE:
					dbgp("Returning symbol from cache. 0x%x = %s" % (address, FuncCache[address]))
				return FuncCache[address]
		else:

			cmd2run = '.printf "%y", 0x{0:x}'.format(address)

			if DEBUG_MODE:
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
				if not address in FuncCache:
					FuncCache[address] = m.group(1).strip()
				return m.group(1).strip()
		return ""


	def getSymbols(self):
		# enumerate IAT and EAT and put into a symbol object
		if DEBUG_MODE:
			dbgp(get_current_function_name())		
			dbgp("Getting symbols for module: %s" % self.modname)		
		ntHeader = getNtHeaders(self.modbase)
		pSize = 4
		if arch == 64:
			pSize = 8
		iatlist = self.getIATList(ntHeader,pSize)
		if DEBUG_MODE:
			dbgp("iatlist has %d elements" % len(iatlist))

		symbollist = {}
		for iatEntry in iatlist:
			iatEntryAddress = iatEntry
			iatEntryName = iatlist[iatEntry]
			sym = wsymbol("Import", iatEntryAddress, iatEntryName)
			symbollist[iatEntryAddress] = sym 

		eatlist = self.getEATList(ntHeader,pSize)
		if DEBUG_MODE:
			dbgp("eatlist has %d elements" % len(eatlist))

		for eatEntry in eatlist:
			eatEntryName = eatEntry
			eatEntryAddress = eatlist[eatEntry]
			sym = wsymbol("Export", eatEntryAddress, eatEntryName)
			symbollist[eatEntryAddress] = sym

		if DEBUG_MODE:
			dbgp("returning symbollist, %d elements" % len(symbollist))
		
		return symbollist

	def getIATList(self,ntHeader, pSize):
		# If Import Address Table Directory (DataDirectory[12]) is set this will work.
		# The fallback case of Import Directory (DataDirectory[1]) will produce garbage.
		if DEBUG_MODE:
			dbgp(get_current_function_name())
			dbgp("Current module: %s" % self.modname)		
		iatlist = {}
		iatdir = ntHeader.OptionalHeader.DataDirectory[12]
		if iatdir.Size == 0:
			iatdir = ntHeader.OptionalHeader.DataDirectory[1]
		if DEBUG_MODE:
			dbgp("iatdir size: %d" % iatdir.Size)
		if iatdir.Size > 0:
			iatAddr = self.modbase + iatdir.VirtualAddress
			if DEBUG_MODE:
				dbgp("iatAddr: 0x%x" % iatAddr)
				dbgp("  iat processing range: 0 - %d " % (iatdir.Size // pSize))

			maxnr = iatdir.Size // pSize
			for i in range(0, maxnr):
				try:
					iatEntry = pykd.ptrPtr(iatAddr + i*pSize)
					if iatEntry != None and iatEntry != 0:
						if DEBUG_MODE:
							dbgp("Symbol lookup via printf, for 0x%x (%d / %d)" % (iatEntry, i, maxnr))
						symbolName = self.addressToSymbol(iatEntry)
						if symbolName == "":
							if DEBUG_MODE:
								dbgp("pykd.findSymbol for 0x%x (%d / %d)" % (iatEntry, i, maxnr))
							symbolName = pykd.findSymbol(iatEntry)
						if DEBUG_MODE:
							dbgp("Symbol: %s" % symbolName)
						if "!" in symbolName:
							iatlist[iatAddr + i*pSize] = symbolName
				except Exception as e:
					if DEBUG_MODE:
						dbgp("Error while getting IAT: %s" % str(e))
						dbgp(traceback.format_exc())
					continue
		return iatlist


	def getEATList(self,ntHeader, pSize):
		# http://www.pinvoke.net/default.aspx/Structures.IMAGE_EXPORT_DIRECTORY
		if DEBUG_MODE:
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
		return eatlist

	def getSectionAddress(self,sectionname):
		ntHeader = getNtHeaders(self.modbase)
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
			# IMAGE_SECTION_HEADER[i]
			sectionstart = (ntHeader.OptionalHeader.getAddress() + sizeOptionalHeader) + (sectioncnt*sectionsize)
			thissection = rstrip_nulls(pykd.loadChars(sectionstart, 8))
			if thissection == sectionname:
				# IMAGE_SECTION_HEADER.SizeOfRawData(DWORD)
				thissectionsize = pykd.ptrDWord(sectionstart + 0x8 + 0x8)
				# IMAGE_SECTION_HEADER.VirtualAddress(DWORD)
				thissectionrva = pykd.ptrDWord(sectionstart + 0x4 + 0x8)
				thissectionstart = self.modbase + thissectionrva
				return thissectionstart
		return 0


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
	def __init__(self,begin,size):
		self.begin = begin
		self.size = size
		self.end = self.begin+self.size
		self.protect = None

	def getSize(self):
		return self.size

	def getMemory(self):
		if self.getAccess() > 0x1:
			try:
				#data =  pykd.loadChars(self.begin,self.size)
				data = bytes(bytearray(pykd.loadBytes(self.begin, self.size)))
				return data
			except Exception as e:
				if DEBUG_MODE:
					dbgp("Error accessing memory: %s" % str(e))
				return None
		else:
			return None


	def getMemoryOld(self):
		if self.getAccess() > 0x1:
			try:
				nrofdwords = self.size // 4
				delta = self.size - (nrofdwords * 4)
				dwords = pykd.loadDWords(self.begin,nrofdwords)
				curpos = self.begin + (nrofdwords * 4)
				remainingbytes = pykd.loadBytes(curpos,delta)
				allbytes = []
				for dword in dwords:
					dwordhex = "%08x" % dword
					allbytes.append(dwordhex[6:8] + dwordhex[4:6] + dwordhex[2:4] + dwordhex[0:2])
				dwords = None
				for byte in remainingbytes:
					allbytes.append("%02x" % bytes)
				data = hex2bin(''.join(allbytes))
				#return hex2bin(''.join(("%02X" % n) for n in loadBytes(self.begin,self.size)))
				return data
			except:
				return None
		else:
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


class LogBpHook():
	def __init__(self):
		return


class Function:
	def __init__(self,obj,address):
		self.function_allmodules = {}
		self.address = address
		self.obj = obj

	def getName(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())
		modname = "unknown"
		funcname = "unknown"
		symname = self.addressToSymbol()
		if DEBUG_MODE:
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
			if DEBUG_MODE:
				dbgp("Splitting module & symbol name")
			if "!" in symname:
				symname.split("!")
				if len(symname) > 1:
					funcname = symname[1]
			if DEBUG_MODE:
				dbgp("Function name: %s" % funcname)
		thename = "%s!%s" % (modname,funcname)
		if DEBUG_MODE:
			dbgp("Full name for 0x%x = %s" % (self.address, thename))
		return thename

	def hasAddress(self):
		return False
	
	def addressToSymbol(self):
		global FuncCache

		if self.address in FuncCache:
			if FuncCache[self.address] != "":
				if DEBUG_MODE:
					dbgp("Returning symbol from cache. 0x%x = %s" % (self.address, FuncCache[self.address]))
				return FuncCache[self.address]
		else:

			cmd2run = '.printf "%y", 0x{0:x}'.format(self.address)

			if DEBUG_MODE:
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


class opcode:

	opsize = 0
	dump = ""

	def __init__(self,address):
		self.address = address
		self.dumpdata = ""
		self.dump = ""
		self.instruction = ""
		self.getDisasm()

	def getBytes(self):
		self.opsize = len(self.dumpdata) // 2
		return hex2bin(self.dumpdata)

	def isJmp(self):
		if self.instruction.upper().startswith("JMP"):
			return True
		return False

	def isCall(self):
		if self.instruction.upper().startswith("CALL"):
			return True
		return False

	def isPush(self):
		if self.instruction.upper().startswith("PUSH"):
			return True
		return False

	def isPop(self):
		if self.instruction.upper().startswith("POP"):
			return True
		return False

	def isRet(self):
		if self.instruction.upper().startswith("RET"):
			return True
		return False

	def isRep(self):
		if self.instruction.upper().startswith("REP"):
			return True
		return False		

	def getDisasm(self):
		if self.instruction == "":
			disasmdata = ""

			global disAsmCache
			if self.address in disAsmCache:
				disasmdata = disAsmCache[self.address]
			else:
				disasmlines = pykd.dbgCommand("u 0x%08x L 1" % self.address)
				for thisline in disasmlines.split("\n"):
					if thisline.lower().startswith(intToHexWinDbgFormat(self.address)):
						disasmdata = thisline
						#if DEBUG_MODE:
						#	dbgp("Disasm at 0x%x: %s" % (self.address, thisline))
						break
			if disasmdata != "":
				disAsmCache[self.address] = disasmdata
				self.parseDisasm(disasmdata)
				self.instruction = self.instruction.replace("   "," ").replace("  "," ")
				# sanitize instruction to make output immlib compatible. Ugly. A bit.
				instructionpieces = self.instruction.split(" ")
				self.instruction = ""
				extrainfo = ""
				for instructionpiece in instructionpieces:
					if ("{" not in instructionpiece and "s:" not in instructionpiece) or ("fs:[" in instructionpiece):
							self.instruction += instructionpiece
							self.instruction += " "
					else:
						extrainfo = instructionpiece.upper()
						break
				self.instruction = self.instruction.strip(" ").upper()
				self.instruction = self.instruction.replace("   "," ").replace("  "," ")
				if "SS:" in extrainfo:
					self.instruction = self.instruction.replace("PTR [","PTR SS:[")
				if "DS:" in extrainfo:
					self.instruction = self.instruction.replace("PTR [","PTR DS:[")
				self.instruction = self.instruction.replace("RET","RETN")	
				self.instruction = self.instruction.replace(",[",",DWORD PTR DS:[")
				if ",OFFSET" in self.instruction:
					# find the value between ()
					instrparts=self.instruction.split("(")
					if len(instrparts) > 1:
						instrparts2 = instrparts[1].split(")")
						offsetval = instrparts2[0].replace(" ","").strip("H")
						if offsetval != "":
							pos = self.instruction.find(",OFFSET")
							self.instruction = self.instruction[0:pos] + "," + offsetval
				if "," in self.instruction and self.instruction.endswith("H"):
					instructionparts = self.instruction.split(",")
					cnt = 0
					self.instruction = ""
					while cnt < len(instructionparts)-1:
						self.instruction = instructionparts[cnt] + ","
						cnt += 1
					self.instruction = self.instruction+ instructionparts[len(instructionparts)-1].strip("H")
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



class wthread:
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

class wheap:
	def __init__(self,address):
		self.address = address

	def getChunks(self,address):
		return {}


class LogBpHook:
	def __init__(self):
		return

