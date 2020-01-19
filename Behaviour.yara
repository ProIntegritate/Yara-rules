// Last update: 03:42 2020-01-19
// Author: "@Pro_Integritate"
// Should be used to give you a sorta-idea of what a file does.


import "hash"
import "pe"

rule Windows_Executable{
    strings:
        $pe = "PE"
    condition:
	uint16(0x00) == 0x5a4d and $pe
}

rule Linux_Executable{
    condition:
	uint16(0x00) == 0x457f and uint16(0x02) == 0x464c
}

rule Windows_Executable_Base64{
    strings:
        $string1 = "TVqQ"
	$string2 = "TVpQ"
    condition:
	any of ($string*)
}

rule INFO_Possible_UPX_Compressed{
    strings:
        $upx = "UPX!"
    condition:
	$upx
}

rule INFO_Possible_RichHeader{
    strings:
        $RichHeader = "Rich"
    condition:
	$RichHeader
}

rule INFO_Possible_PDB_Path{
    strings:
        $string1 = ".pdb"
    condition:
	$string1
}

rule MS_Office_Document_Legacy{
    condition:
	uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
	uint16(0x19) == 0x0320
}


// Capabilities

rule Windows_Network_Capability{
    strings:
	$net1 = "WSOCK32.dll" nocase
	$net2 = "WININET.dll" nocase
	$net3 = "IPHLPAPI.DLL" nocase
	$net4 = "ws2_32.dll" nocase
	$net5 = "wsock32.dll" nocase
	$net6 = "wininet.dll" nocase
	$net7 = "winhttp.dll" nocase
	$net8 = "NETAPI32.dll" nocase
	$net9 = "WINHTTP.dll" nocase
    condition:
	any of ($net*)
}

rule Possible_Shell_External_Commands{
    strings:
        $string1 = "Shell" nocase
    condition:
	any of ($string*)
}

rule Possible_Decoding_Base64_Payload{
    strings:
        $string1 = "Convert" nocase
	$string2 = "FromBase64String" nocase
	$string3 = "MSXML2.DOMDocument"
	$string4 = "B64DECODE"
    condition:
	($string1 and $string2) or ($string3 and $string4)
}

rule Possible_URL{
    strings:
        $string1 = "https:"
	$string2 = "http:"
    condition:
	$string1 and $string2
}

rule Possible_UserAgent{
    strings:
        $string1 = "User-Agent"
    condition:
	$string1
}

rule Possible_Payload_Download{
    strings:
        $string1 = "DownloadFile"
        $string2 = "DownloadString"
        $string3 = "DownloadData"
    condition:
	any of ($string*)
}

rule Legacy_Windows_Crypto_Capability{
    strings:
        $string1 = "crypt32.dll" nocase
    condition:
	$string1
}

rule Dotnet_FileWrite_Capability{
    strings:
	$function = "System.IO" nocase // System.IO|0x00|File !
        $string1 = "WriteAllBytes" nocase
        $string2 = "WriteAllLines" nocase
        $string3 = "WriteAllText" nocase
    condition:
	$function and any of ($string*)
}

rule DotNet_Crypto_Capability{
    strings:
        $string1 = "System.Security.Cryptography" nocase
    condition:
	$string1
}

rule DotNet_Sockets_Capability{
    strings:
        $string1 = "System.Net.Sockets" nocase
    condition:
	$string1
}

rule DotNet_File_Decompression_Capability{
    strings:
        $string1 = "System.IO.Compression" nocase
        $string2 = "IO.Compression" nocase 
        $method1 = "Deflate" nocase
        $method2 = "Decompress" nocase
    condition:
	any of ($string*) and any of ($method*)
}

rule Possible_Reading_Keyboard_Input{
    strings:
        $string1 = "GetAsyncKeyState" nocase
	$string2 = "SetWindowsHook" nocase
    condition:
	any of ($string*)
}

rule Possible_HTTP_Binary_transfer{
    strings:
        $string1 = "application/octet-stream" nocase
	$string2 = "application/zip" nocase
    condition:
	any of ($string*)
}

rule Possible_Firewall_Configuration_Change{
    strings:
        $string1 = "iptables" nocase
        $string2 = "netsh advfirewall" nocase
        $string3 = "FirewallAPI" nocase
    condition:
	any of ($string*)
}

rule Unconventional_Build_Tools{
    strings:
        $string1 = "installutil.exe" nocase
        $string2 = "msbuild.exe" nocase
        $string3 = "csc.exe" nocase
        $string4 = "vbc.exe" nocase
        $string5 = "ilasm.exe" nocase
        $string6 = "jsc.exe" nocase
    condition:
	any of ($string*)
}

rule Possible_Recon_WMIC{
    strings:
        $string1 = "wmic.exe" nocase
    condition:
	$string1
}

rule Registry_Query_Infomation{
    strings:
        $open = "RegOpenKey" nocase
        $string1 = "RegQueryValue" nocase
        $string2 = "RegEnumKey" nocase
    condition:
	$open and any of ($string*)
}

rule Registry_Write_Infomation{
    strings:
	$open = "RegOpenKey"
        $string1 = "RegCreateKey" nocase
        $string2 = "RegDeleteKey" nocase
        $string3 = "RegSetValue" nocase
    condition:
	$open and any of ($string*)
}

rule Document_RTF_Possible_Obj_Payload{
    strings:
	$string1 = "rtf" nocase
	$string2 = "objdata" nocase
    condition:
	all of ($string*)
}

rule Possible_GZip_Stream{
    strings:
	$stream1 = {1f 8b 08 08}
	$stream2 = "H4sI" // Base64
    condition:
	any of ($stream*)
}

rule Possible_Zip_Stream{
    strings:
	$stream1 = {50 4b 03 04}
	$stream2 = {55 45 73 44} // Base64
    condition:
	any of ($stream*)
}

rule WARNING_CreateRemoteThread_Found{
    strings:
	$String = "CreateRemoteThread"
    condition:
	$String
}

rule WARNING_ReadProcessMemory_Found{
    strings:
	$String = "ReadProcessMemory"
    condition:
	$String
}

rule WARNING_WriteProcessMemory_Found{
    strings:
	$String = "WriteProcessMemory"
    condition:
	$String
}

rule Possible_SeDebugPrivilege{
    strings:
	$String1 = "AdjustTokenPrivileges"
	$String2 = "SeDebugPrivilege"
    condition:
	all of ($String*)
}

rule Possible_Powershell_Execution_Bypass{
    strings:
	$String1 = "powershell.exe"
	$String2 = "-Exec Bypass"
    condition:
	all of ($String*)
}

rule Windows_Filesystem_Scripting{
    strings:
	$String1 = "Scripting.FileSystemObject"
	$String2 = "Wscript.Shell"
    condition:
	any of ($String*)
}

