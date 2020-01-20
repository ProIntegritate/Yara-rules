// Last update: 07:25 2020-01-20
// Author: "@Pro_Integritate"
// 
// Should be used to give you a sorta-idea of what a file does.
//
// 2020-01-19: Removed the classified "Possible_" since this is stringmatching...
// Everything is "possible" until validated. That is your job.


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
        $string3 = "QqVT" // Reversed
	$string4 = "QpVT" // Reversed
    condition:
	any of ($string*)
}

rule INFO_UPX_Compression{
    strings:
        $upx = "UPX!"
    condition:
	$upx
}

rule INFO_RichHeader{
    strings:
        $RichHeader = "Rich"
    condition:
	$RichHeader
}

rule INFO_PDB_Path{
    strings:
        $string1 = ".pdb" nocase
        $string2 = "bdp." nocase
    condition:
	any of ($string*)
}

rule MS_Office_Document_Legacy{
    condition:
	uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
	uint16(0x19) == 0x0320
}


// Capabilities

rule Networking_Capability{
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
	$net10 = "mswsock.dll" nocase
    condition:
	any of ($net*)
}

rule Shell_External_Commands{
    strings:
	$string1 = "shell32.dll" nocase
	$string2 = "ShellExecute" nocase
	$string3 = "ProcessStartInfo" nocase
        $string4 = "Shell" nocase // Very generic, i know... keep for now

    condition:
	any of ($string*)
}

rule Decoding_Base64_Payload{
    strings:
        $string1 = "Convert" nocase
	$string2 = "FromBase64String" nocase
	$string3 = "MSXML2.DOMDocument" nocase
	$string4 = "B64DECODE" nocase
    condition:
	($string1 and $string2) or ($string3 and $string4)
}

rule URL{
    strings:
        $string1 = "https:" nocase
        $string2 = ":sptth" nocase // reversed
	$string3 = "http:" nocase
	$string4 = ":ptth" nocase // reversed
	$string5 = "ftp:" nocase
	$string6 = ":ptf" nocase // reversed
    condition:
	any of ($string*)
}

rule UserAgent{
    strings:
        $string1 = "User-Agent" nocase
        $string2 = "tnegA-resU" nocase // reversed
    condition:
	any of ($string*)
}

rule Payload_Download{
    strings:
        $string1 = "DownloadFile" nocase
        $string2 = "eliFdaolnwoD" nocase // reversed
        $string3 = "DownloadString" nocase
        $string4 = "gnirtSdaolnwoD" nocase // reversed
        $string5 = "DownloadData" nocase
        $string6 = "ataDdaolnwoD" nocase // reversed
    condition:
	any of ($string*)
}

rule Legacy_Crypto_Capability{
    strings:
        $string1 = "crypt32.dll" nocase
    condition:
	$string1
}

rule Dotnet_FileWrite_Capability{
    strings:
	$function1 = "System.IO" nocase // System.IO|0x00|File !
	$function2 = "OI.metsyS" nocase // reversed
        $string1 = "WriteAllBytes" nocase
        $string2 = "setyBllAetirW" nocase // reversed
        $string3 = "WriteAllLines" nocase
        $string4 = "seniLllAetirW" nocase // reversed
        $string5 = "WriteAllText" nocase
        $string6 = "txeTllAetirW" nocase // reversed
    condition:
	any of ($function*) and any of ($string*)
}

rule Dotnet_FileMove_Capability{
    strings:
        $hex = {53 79 73 74 65 6D 2E 49 4F 00 46 69 6C 65 00 4D 6F 76 65} // System.IO|0x00|File|0x00|Move
	$string1 = "System.IO" nocase // Text for Scripting
	$string2 = "OI.netsyS" nocase // reversed
	$string3 = "File" nocase
	$string4 = "eliF" nocase // reversed
	$string5 = "Move" nocase 
	$string6 = "evoM" nocase // reversed
    condition:
	$hex or
	($string1 and $string3 and $string5) or
	($string2 and $string4 and $string6)
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
        $string2 = "stekcoS.teN.metsyS" nocase // reversed
        $string3 = "System.Net.WebClient" nocase
        $string4 = "tneilCbeW.teN.metsyS" nocase // reversed
    condition:
	any of ($string*)
}

rule DotNet_File_Decompression_Capability{
    strings:
        $string1 = "IO.Compression" nocase 
        $string2 = "noisserpmoC.OI" nocase 
        $method1 = "Deflate" nocase
        $method2 = "etalfeD" nocase // reversed
        $method3 = "Decompress" nocase
        $method4 = "sserpmoceD" nocase // reversed
    condition:
	any of ($string*) and any of ($method*)
}

rule Reading_Keyboard_Input{
    strings:
        $string1 = "GetAsyncKeyState" nocase
	$string2 = "SetWindowsHook" nocase
    condition:
	any of ($string*)
}

rule HTTP_Binary_transfer{
    strings:
        $string1 = "application/octet-stream" nocase
        $string2 = "maerts-tetco/noitacilppa" nocase // reversed
	$string3 = "application/zip" nocase
	$string4 = "piz/noitacilppa" nocase // reversed
    condition:
	any of ($string*)
}

rule Firewall_Configuration_Change{
    strings:
        $string1 = "iptables" nocase
        $string2 = "selbatpi" nocase // reversed
        $string3 = "netsh advfirewall" nocase
        $string4 = "llawerifvda hsten" nocase // reversed
        $string5 = "FirewallAPI" nocase
        $string6 = "IPAllaweriF" nocase // reversed
    condition:
	any of ($string*)
}

rule Unconventional_Build_Tools{ // TODO: Rev
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

rule Recon_WMIC{ // TODO: Rev
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

rule Document_RTF_Obj_Payload{
    strings:
	$string1 = "rtf" nocase
	$string2 = "objdata" nocase
    condition:
	all of ($string*)
}

rule GZip_Stream{
    strings:
	$stream1 = {1f 8b 08 08}
	$stream2 = "H4sI" // Base64
    condition:
	any of ($stream*)
}

rule Zip_Stream{
    strings:
	$stream1 = {50 4b 03 04}
	$stream2 = {55 45 73 44} // Base64
    condition:
	any of ($stream*)
}

rule Creating_Thread_In_Remote_Process{
    strings:
	$String = "CreateRemoteThread" nocase
    condition:
	$String
}

rule Creating_Thread{
    strings:
	$String = "CreateThread" nocase
    condition:
	$String
}

rule Reading_Memory_In_Remote_Process{
    strings:
	$String = "ReadProcessMemory" nocase
    condition:
	$String
}

rule Writing_Memory_In_Remote_Process{
    strings:
	$String = "WriteProcessMemory" nocase
    condition:
	$String
}

rule Calling_Debug_Privileges{
    strings:
	$String1 = "AdjustTokenPrivileges" nocase
	$String2 = "SeDebugPrivilege" nocase
    condition:
	all of ($String*)
}

rule Powershell_Execution_Bypass{ // TODO: Rev
    strings:
	$String1 = "powershell.exe" nocase
	$String2 = "-Exec Bypass" nocase
    condition:
	all of ($String*)
}

rule Filesystem_Scripting{ // TODO: Rev
    strings:
	$String1 = "Scripting.FileSystemObject" nocase
	$String2 = "Wscript.Shell" nocase
    condition:
	any of ($String*)
}

rule Checks_For_Debugger{
    strings:
	$String1 = "IsDebuggerPresent" nocase // Sub process
	$String2 = "CheckRemoteDebuggerPresent" nocase // Paralell process
    condition:
	any of ($String*)
}

rule Registry_HKEY_Hive_Reference{ // TODO: Rev
    strings:
	$String1 = "HKEY_Local_Machine" nocase ascii wide
	$String2 = "HKEY_Current_User" nocase ascii wide
	$String3 = "HKEY_Users" nocase ascii wide
	$String4 = "HKEY_Classes_Root" nocase ascii wide
	$String5 = "HKEY_Current_Config" nocase ascii wide

    condition:
	any of ($String*)
}

rule Autoit_Scripting{
    strings:
	$String1 = "AutoIt"
	$String2 = "FSoftware"
    condition:
	all of ($String*)
}

rule External_Scripting{ // TODO: Rev
    strings:
	$String1 = "psexec.exe" nocase
	$String2 = "psExec64.exe" nocase
	$String3 = "cmd.exe" nocase
	$String4 = "powershell.exe" nocase
    condition:
	any of ($String*)
}

rule System_folder_enumeration{ // TODO: Rev
    strings:
	$String1 = "SystemDirectory" nocase
	$String2 = "Systemroot" nocase
	$String3 = "Windir" nocase
    condition:
	any of ($String*)
}

rule Enumerate_Antivirus_Product{
    strings:
	$String1 = "antivirusproduct" nocase
	$String2 = "tcudorPsurivitna" nocase
    condition:
	any of ($String*)
}

rule String_obfuscation{
    strings:
	$String1 = "StrReverse" nocase
	$String2 = " + " nocase
	$String3 = " & " nocase
    condition:
	any of ($String*)
}

rule Reboot_Persistance{
    strings:
	$String1 = "currentversion" nocase	// Currentversion/Run
	$String2 = "run" nocase
	$String3 = "noisreVtnerruc" nocase
	$String4 = "nur" nocase
	$String5 = "schtasks" nocase		// Schtasks.exe /Create
	$String6 = "create" nocase
	$String7 = "sksathcs" nocase
	$String8 = "etaerc" nocase
    condition:
	($String1 and $String2) or
	($String3 and $String4) or
	($String5 and $String6) or
	($String7 and $String8)
}

rule Registry_Commandline{ // TODO: Rev
    strings:
        $string1 = "Reg.exe" nocase
    condition:
	$string1
}

