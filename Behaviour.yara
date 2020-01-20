// Last update: 18:34 2020-01-20
// Author: "@Pro_Integritate"
// 
// Should be used to give you a sorta-idea of what a file does.
//
// Disclaimer: This is just a triage script and does not tell
// you with 100% certainty that something is going on.
// Everything need to be validated - and that is your job.

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
    condition:
	any of ($string*)
}

rule MS_Office_Document_Legacy{
    condition:
	uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
	uint16(0x19) == 0x0320
}


// ---- Capabilities ----

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
	$string4 = "Scripting.FileSystemObject" nocase
	$string5 = "Shell.Application" nocase
        $string6 = "Shell" nocase // Very generic, i know... keep for now

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
    condition:
	any of ($string*)
}

rule DotNet_Webclient_Capability{
    strings:
        $string1 = "System.Net.WebClient" nocase
        $string2 = "tneilCbeW.teN.metsyS" nocase // reversed
    condition:
	any of ($string*)
}

rule DotNet_DNS_Capability{
    strings:
        $string1 = "System.Net" nocase
        $string2 = "teN.metsyS" nocase // reversed
	$string3 = "Dns" nocase
	$string4 = "snD" nocase // reversed
    condition:
	($string1 and $string3) or
	($string2 and $string4)
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

rule Unconventional_Build_Tools{
    strings:
        $string1 = "installutil.exe" nocase
        $string2 = "exe.litullatsni" nocase
        $string3 = "msbuild.exe" nocase
        $string4 = "exe.dliubsm" nocase
        $string5 = "csc.exe" nocase
        $string6 = "exe.csc" nocase
        $string7 = "vbc.exe" nocase
        $string8 = "exe.cbv" nocase
        $string9 = "ilasm.exe" nocase
        $string10 = "exe.msali" nocase
        $string11 = "jsc.exe" nocase
        $string12 = "exe.csj" nocase
    condition:
	any of ($string*)
}

rule Recon_WMIC{
    strings:
        $string1 = "wmic.exe" nocase
        $string2 = "exe.cimw" nocase
    condition:
	any of ($string*)
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

rule RAR_Stream{
    strings:
	$stream1 = {52 61 72 21}
	$stream2 = {52 45 7E 5E}
	$stream3 = {55 6d 46 79} // Base64
	$stream4 = {55 6b 56 2b} // Base64
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

rule Powershell_Execution_Bypass{
    strings:
	$String1 = "powershell.exe" nocase
	$String2 = "exe.llehsrewop" nocase // reverse
	$String3 = "-Exec Bypass" nocase
	$String4 = "ssapyB cexE-" nocase // reverse
    condition:
	($String1 and $String3) or
	($String2 and $String4)
}

rule Filesystem_Scripting{
    strings:
	$String1 = "Scripting.FileSystemObject" nocase
	$String2 = "tcejbOmetsySeliF.gnitpircS" nocase
	$String3 = "Wscript.Shell" nocase
	$String4 = "llehS.tpircsW" nocase
    condition:
	($String1 and $String3) or
	($String2 and $String4)
}

rule Checks_For_Debugger{
    strings:
	$String1 = "IsDebuggerPresent" nocase // Sub process
	$String2 = "CheckRemoteDebuggerPresent" nocase // Paralell process
    condition:
	any of ($String*)
}

rule Registry_HKEY_Hive_Reference{
    strings:
	$String1 = "HKEY_Local_Machine" nocase ascii wide
	$String2 = "enihcaM_lacoL_YEKH" nocase ascii wide // reverse
	$String3 = "HKEY_Current_User" nocase ascii wide
	$String4 = "resU_tnerruC_YEKH" nocase ascii wide // reverse
	$String5 = "HKEY_Users" nocase ascii wide
	$String6 = "sresU_YEKH" nocase ascii wide // reverse
	$String7 = "HKEY_Classes_Root" nocase ascii wide
	$String8 = "tooR_sessalC_YEKH" nocase ascii wide // reverse
	$String9 = "HKEY_Current_Config" nocase ascii wide
	$String10 = "gifnoC_tnerruC_YEKH" nocase ascii wide // reverse

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

rule External_Scripting{
    strings:
	$String1 = "psexec.exe" nocase
	$String2 = "psExec64.exe" nocase
	$String3 = "cmd.exe" nocase
	$String4 = "powershell.exe" nocase
    condition:
	any of ($String*)
}

rule System_folder_enumeration{
    strings:
	$String1 = "SystemDirectory" nocase
	$String2 = "yrotceriDmetsyS" nocase // reverse
	$String3 = "Systemroot" nocase
	$String4 = "toormetsyS" nocase // reverse
	$String5 = "Windir" nocase
	$String6 = "ridniW" nocase // reverse
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
	$string1 = "StrReverse" nocase
	$string2 = {22 20 26 20 22} 	// " & "
	$string3 = {22 26 22}  	 	//  "&"
	$string4 = {22 20 2B 20 22} 	// " + "
	$string5 = {22 2B 22}  	 	//  "+"
    condition:
	any of ($string*)
}

rule Registry_Commandline{
    strings:
        $string1 = "Reg.exe" nocase
        $string2 = "exe.geR" nocase // reverse
    condition:
	any of ($string*)
}

rule Accessing_Or_Creating_Services{
    strings:
        $string1 = "OpenService" nocase
        $string2 = "CreateService" nocase
    condition:
	any of ($string*)
}

rule Terminate_process_capability{
    strings:
        $string1 = "TerminateProcess" nocase
    condition:
	$string1
}

rule Reboot_Persistance{
    strings:
	$String1 = "currentversion" nocase	// Currentversion/Run
	$String2 = "run" nocase			// Note: some FP's with this.
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
