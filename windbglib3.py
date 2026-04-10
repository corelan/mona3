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

$Revision: 300 $
$Id: windbglib3.py 300 2026-03-26 18:04:00Z corelanc0d3r $ 
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
global FuncCache

global currentPID
global currentTEBAddress
global cpebaddress

arch = 32

currentPID = 0
currentTEBAddress = 0
cpebaddress = 0

PageSections = {}
ModuleCache = {}
FuncCache = {}
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
	cpebaddress = 0
	return


def getPEBInfo(peb_addr=None):
	if DEBUG_MODE:
		dbgp(get_current_function_name())
		dbgp("Current process: %s" % pykd.getCurrentProcess())
	if peb_addr is None:
		peb_addr = pykd.getCurrentProcess()
	try:
		return pykd.typedVar("ntdll!_PEB", peb_addr)
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

def getTEBInfo():
	if DEBUG_MODE:
		dbgp(get_current_function_name())
	return pykd.typedVar("_TEB", pykd.getImplicitThread())


def getTEBAddress():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	global currentTEBAddress
	if currentTEBAddress == 0:
		currentTEBAddress = int(pykd.getImplicitThread())
	return currentTEBAddress


def getPEBAddress():
	if DEBUG_MODE:
		dbgp(get_current_function_name())

	global cpebaddress
	if cpebaddress == 0:
		peb = getPEBInfo()
		cpebaddress = peb.getAddress()
	return cpebaddress


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




def getModuleFromAddress(address):
	if DEBUG_MODE:
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
		self.OpcodeCache = {}
		self.ModCache = {}
		self._peb_list = None
		self._teb_addr = None
		self._peb_addr = None
		self._peb_info = None
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
	
	def log(self, message="", highlight=0, address=None, focus=0):
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


	def logLines(self, message="", highlight=0,address=None, focus=0):
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
		peb = self.get_peb_info()
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

		global currentPID

		if currentPID == 0:
			# http://www.nirsoft.net/kernel_struct/vista/TEB.html
			# http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
			teb = self.get_teb_addr()
			offset = 0x20
			if arch == 64:
				offset = 0x40
			# _TEB.ClientId(CLIENT_ID).UniqueProcess(PVOID)
			currentPID = pykd.ptrDWord(teb+offset)

		return currentPID

	
	"""
	OS stuff
	"""
	def getOsRelease(self):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		peb = self.get_peb_info()
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
		#if DEBUG_MODE:
		#	dbgp(get_current_function_name())
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
				pageprotect = m.group(6).strip()
				pageusage = m.group(7).strip()

				#if DEBUG_MODE:
				#	dbgp("      OK - Including page: 0x%08x, size 0x%08x, protect: %s, usage: %s" % (
				#		starting_address, size, pageprotect, pageusage))

				page_obj = wpage(starting_address, size, pageusage)
				self.MemoryPages[starting_address] = page_obj

		return self.MemoryPages



	def getMemoryPageByAddress(self,address):
		#if DEBUG_MODE:
		#	dbgp(get_current_function_name())

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
		#if DEBUG_MODE:
		#	dbgp(get_current_function_name())

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
		peb = self.get_peb_info()
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

	def get_peb_info(self):
		"""
		Return a pykd.typedVar("ntdll!_PEB") using the cached PEB address.
		Result is cached in self._peb_info.
		"""
		if self._peb_info is None:
			self._peb_info = getPEBInfo(self.get_peb_addr())
		return self._peb_info

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
			return struct.unpack(fmt_ptr, bytes(bytearray(self.readMemory(addr, ptr_size))))[0]

		def _wstr(entry, off):
			length  = struct.unpack('<H', bytes(bytearray(self.readMemory(entry + off, 2))))[0]
			buf_ptr = _ptr(entry + off + (8 if arch == 64 else 4))
			if length == 0 or buf_ptr == 0:
				return ""
			raw = bytes(bytearray(self.readMemory(buf_ptr, length)))
			return raw.decode('utf-16-le', errors='replace')

		peb_addr = self.get_peb_addr()
		if peb_addr == 0:
			return
		ldr_addr  = _ptr(peb_addr + (0x18 if arch == 64 else 0x0C))
		list_head = ldr_addr + (0x10 if arch == 64 else 0x0C)

		dll_base_off  = 0x30 if arch == 64 else 0x18
		full_name_off = 0x48 if arch == 64 else 0x24
		base_name_off = 0x58 if arch == 64 else 0x2C

		flink = _ptr(list_head)
		results = []
		while flink != list_head and flink != 0:
			dll_base  = _ptr(flink + dll_base_off)
			full_path = _wstr(flink, full_name_off)
			base_name = _wstr(flink, base_name_off)
			results.append((dll_base, base_name, full_path))
			flink = _ptr(flink)
		self._peb_list = results
		for entry in self._peb_list:
			yield entry

	def getModule(self, modulename, from_memory=False):
		if DEBUG_MODE:
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

			if dll_base == 0:
				if DEBUG_MODE:
					dbgp("Module '%s' not found via PEB walk" % modulename)
				pykd.dprintln("I was not able to find '%s' via PEB walk" % modulename)
				return None

			thismod = pykd.module(dll_base)
			if thismod is None:
				return None

			thisimagename = thismod.image()
			thismodname   = thismod.name()
			thismodbase   = thismod.begin()
			thismodsize   = thismod.size()

			if DEBUG_MODE:
				dbgp("       image: %s" % thisimagename)
				dbgp("       name: %s"  % thismodname)
				dbgp("       begin: 0x%08x" % thismodbase)
				dbgp("       size: 0x%08x"  % thismodsize)
				dbgp("    Building wmodule for %s. Base: 0x%08x" % (thisimagename, thismodbase))

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
		if DEBUG_MODE:
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
					thismod = pykd.module(dll_base)
					if thismod is None:
						continue
					wmod = wmodule(thismod.name())
					wmod.setBaseAddress(thismod.begin())
					wmod.setPath(full_path)
					wmod.setSize(thismod.size())
					self.allmodules[imagename] = wmod
				except:
					continue
		return self.allmodules


	def getImageNameForModule(self, modulename):
		if DEBUG_MODE:
			dbgp(get_current_function_name())

		fname = os.path.splitext(modulename)[0].lower()
		try:
			for dll_base, base_name, _ in self._peb_walk():
				if os.path.splitext(base_name)[0].lower() == fname:
					thismod = pykd.module(dll_base)
					if thismod is not None:
						return thismod.name()
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
					dbgp("bytes: %s " % thesebytes)
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
			# In Py2, iterating a bytes/str yields 1-char strings; format expects ints.
			restorebytes = ["%02x" % (b if isinstance(b, int) else ord(b)) for b in origbytes]
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

	def setBreakpoint(self,address,condition=""):
		try:
			if condition:
				cmd2run = 'bp 0x%x "%s"' % (address, condition)
			else:
				cmd2run = "bp 0x%x" % address
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

	def setMemBreakpoint(self,address,memType,condition=""):
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
			output = ""
			try:
				output = pykd.dbgCommand(bpcommand)
			except:
				if memType.upper() == "S":
					bpcommand = "bp %s" % addrfmt
					if condition:
						bpcommand = '%s "%s"' % (bpcommand, condition)
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
				if DEBUG_MODE:
					dbgp("Returning symbol from cache. 0x%x = %s" % (address, FuncCache[address]))
				return FuncCache[address]
		else:
			if DEBUG_MODE:
				dbgp("Performing symbol lookup, this may cause symbols to be downloaded")
				pykd.dbgCommand("!sym noisy")

			cmd2run = '.printf "%y", 0x{0:x}'.format(address)

			if DEBUG_MODE:
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
				if DEBUG_MODE:
					dbgp("Added to EATList: %s!%s at 0x%08x" % (self.modname, eatName, eatAddress))
		return eatlist
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
				dbgp("Splitting module & symbol name %s" % symname)
			if "!" in symname:
				symnameparts = symname.split("!")
				if len(symnameparts) > 1:
					modname = symnameparts[0]
					funcname = symnameparts[1]
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
				if arch == 32:
					self.instruction = self.instruction.replace(",[",",DWORD PTR DS:[")
				if arch == 64:
					self.instruction = self.instruction.replace(",[",",QWORD PTR DS:[")
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
