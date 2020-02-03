// Last update: 19:04 2020-02-03
// Author: "@Pro_Integritate"
// 
// Should be used to give you a sorta-idea of a files capabilities.
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

rule Scripting_Function_or_Subroutine{
    strings:
	$string1 = "function " nocase
	$string2 = "sub " nocase
    condition:
	any of ($string*)
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
	(uint16(0x00) == 0x5a4d or
	(uint16(0x00) == 0x457f and uint16(0x02) == 0x464c)) and
	$upx
}

rule INFO_RichHeader{
    strings:
        $RichHeader = "Rich"
    condition:
	uint16(0x00) == 0x5a4d and $RichHeader
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

rule Network_Access{
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
	$string6 = "WScript.Shell" nocase
	$string7 = "CreateProcess" nocase
    condition:
	any of ($string*)
}

rule Decoding_Base64_Payload{
    strings:
        $string1 = "Convert" nocase
	$string2 = "FromBase64" nocase
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

rule Sets_specific_HTTP_Useragent{
    strings:
	$string1 = "SetRequestHeader" nocase
	$string2 = "User-Agent:" nocase
    condition:
	all of ($string*)
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

rule Access_Cryptograpic_Libraries{
    strings:
        $string1 = "crypt32.dll" nocase
        $string2 = "Security.Cryptography" nocase // -"System."
	$string3 = "yhpargotpyrC.ytiruceS" nocase
        $string4 = "bcrypt.dll" nocase
    condition:
	any of ($string*)
}

rule Dotnet_FileWrite{
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

rule Dotnet_FileMove{
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

rule DotNet_Sockets{
    strings:
        $string1 = "Net.Sockets" nocase // -"System."
        $string2 = "stekcoS.teN" nocase // reversed // -"System."
    condition:
	any of ($string*)
}

rule DotNet_Webclient{
    strings:
        $string1 = "Net.WebClient" nocase // -"System."
        $string2 = "tneilCbeW.teN" nocase // reversed // -"System."
    condition:
	any of ($string*)
}

rule DotNet_DNS{
    strings:
        $string1 = "System.Net" nocase
        $string2 = "teN.metsyS" nocase // reversed
	$string3 = "Dns" nocase
	$string4 = "snD" nocase // reversed
	$string5 = "Net.Dns" // Scripts
    condition:
	($string1 and $string3) or
	($string2 and $string4) or
	$string5
}

rule DotNet_File_Decompression{
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
	$dotnetstring1 = "Win32.Registry" nocase
	$dotnetstring2 = "GetValue" nocase
    condition:
	$open and any of ($string*) or all of ($dotnetstring*)
}

rule Registry_Write_Infomation{
    strings:
	$open = "RegOpenKey"
        $string1 = "RegCreateKey" nocase
        $string2 = "RegDeleteKey" nocase
        $string3 = "RegSetValue" nocase
	$dotnetstring1 = "Win32.Registry" nocase
	$dotnetstring2 = "SetValue" nocase
    condition:
	$open and any of ($string*) or all of ($dotnetstring*)
}

rule Document_RTF_Obj_Payload{
    strings:
	$string1 = "rtf" nocase
	$string2 = "objdata" nocase
    condition:
	all of ($string*)
}

rule GZip_Stream{ // Position independend, not Magic bytes specifically
    strings:
	$stream1 = {1f 8b 08 08}
	$stream2 = "H4sI" // Base64
    condition:
	any of ($stream*)
}

rule Zip_Stream{ // Position independend, not Magic bytes specifically
    strings:
	$stream1 = {50 4b 03 04}
	$stream2 = {55 45 73 44} // Base64
    condition:
	any of ($stream*)
}

rule RAR_Stream{ // Position independend, not Magic bytes specifically
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

rule Terminate_Thread{
    strings:
	$String = "TerminateThread" nocase
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
	$String3 = "KdDebuggerEnabled" nocase // Kernel call
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
	// + HKLM, HKCU, HKCR, HKCC
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
	$string1 = "SystemDirectory" nocase
	$string2 = "yrotceriDmetsyS" nocase // reverse
	$string3 = "Systemroot" nocase
	$string4 = "toormetsyS" nocase // reverse
	$string5 = "Windir" nocase
	$string6 = "ridniW" nocase // reverse
	$string7 = "GetSystemWindowsDirectory" nocase
	$string8 = "GetWindowsDirectory" nocase
	$string9 = "GetSystemDirectory" nocase
    condition:
	any of ($string*)
}

rule String_obfuscation{
    strings:
	$string1 = "StrReverse" nocase
	$string2 = {22 20 26 20 22} 	// " & "
	$string3 = {22 26 22}  	 	//  "&"
	$string4 = {22 20 2B 20 22} 	// " + "
	$string5 = {22 2B 22}  	 	//  "+"
	$string6 = "decode" nocase
	$string7 = "replace" nocase
	$string8 = "unescape" nocase
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

rule Deletes_Services{
    strings:
	$string1 = "DeleteService" nocase
	$string2 = "ecivreSeteleD" nocase
    condition:
	any of ($string*)
}

rule Terminate_process{
    strings:
        $string1 = "TerminateProcess" nocase
    condition:
	$string1
}

rule Reboot_Persistance{
    strings:
	$String1 = "currentversion" nocase	// Currentversion/Run
	$String2 = "run" nocase			// Note: some FP's with this.
	$String3 = "noisreVtnerruc" nocase	// Reversed
	$String4 = "nur" nocase
	$String5 = "schtasks" nocase		// Schtasks.exe /Create
	$String6 = "create" nocase
	$String7 = "sksathcs" nocase		// Reversed
	$String8 = "etaerc" nocase
    condition:
	($String1 and $String2) or
	($String3 and $String4) or
	($String5 and $String6) or
	($String7 and $String8)
}

rule LOLBins{
    strings:
	$string1 = "wscript.exe" nocase
	$string2 = "exe.tpircsw" nocase		// Reversed
	$string3 = "cscript.exe" nocase
	$string4 = "exe.tpircsc" nocase		// Reversed
	$string5 = "bitsadmin.exe" nocase
	$string6 = "exe.nimdastib" nocase	// Reversed

	// Already here:
	// "installutil.exe" nocase
	// "msbuild.exe" nocase
	// "csc.exe" nocase
	// "vbc.exe" nocase
	// "ilasm.exe" nocase
	// "jsc.exe" nocase
	// "certutil.exe" nocase
    condition:
	any of ($string*)
}

rule WMI_Query_Moniker_LDAP{
    strings:
	$string1 = "winmgmts:" nocase
	$string2 = ":stmgmniw" nocase
	$string3 = "LDAP" nocase
	$string4 = "PADL" nocase
    condition:
	($string1 or $string2) and ($string3 or $string4)
}

rule Reflective_loader{
    strings:
	$string1 = "EntryPoint.Invoke" nocase
	$string2 = "System.Reflection" nocase
	$string3 = "Reflection.Assembly" nocase
    condition:
	$string1 and ($string2 or $string3)
}

rule Starting_Code_From_Payload{
    strings:
	$string1 = ".Invoke" nocase
	$string2 = "System.Runtime" nocase
	$string3 = "Runtime.InteropServices" nocase
    condition:
	$string1 and ($string2 or $string3)
}

rule Requires_Admin_Privileges{
    strings:
	$string1 = "<?xml" nocase
	$string2 = "requestedPrivileges" nocase
	$string3 = "requireAdministrator" nocase
    condition:
	all of ($string*)
}

rule Access_Service_Control_Manager{
    strings:
	$string1 = "OpenSCManagerA" nocase
    condition:
	$string1
}

rule WMI_Enumerates_Antivirus{
    strings:
	$string1 = "winmgmts:" nocase
	$string2 = ":stmgmniw" nocase
	$string3 = "securitycenter" nocase
	$string4 = "retnecytiruces" nocase
	$string5 = "AntiVirusProduct" nocase
	$string6 = "tcudorPsuriVitnA" nocase
    condition:
	($string1 or $string2) and ($string3 or $string4) and ($string5 or $string6)
}

rule WMI_Enumerates_Disk_properties{
    strings:
	$string1 = "winmgmts:" nocase
	$string2 = ":stmgmniw" nocase
	$string3 = "win32_logicaldisk" nocase
	$string4 = "ksidlacigol_23niw" nocase
    condition:
	($string1 or $string2) and ($string3 or $string4)
}

rule WMI_Enumerates_OperatingSystem{
    strings:
	$string1 = "winmgmts:" nocase
	$string2 = ":stmgmniw" nocase
	$string3 = "Win32_OperatingSystem" nocase
	$string4 = "metsySgnitarepO_23niW" nocase
    condition:
	($string1 or $string2) and ($string3 or $string4)
}

rule Enumerate_Processes{
    strings:
	$string1 = "OpenProcess" nocase
	$string2 = "CreateToolhelp32Snapshot" nocase
	$string3 = "Process32First" nocase
	$string4 = "Process32Next" nocase
    condition:
	all of ($string*)
}

rule Enumerate_Threads{
    strings:
	$string1 = "OpenProcess" nocase
	$string2 = "CreateToolhelp32Snapshot" nocase
	$string3 = "Thread32First" nocase
	$string4 = "Thread32Next" nocase
    condition:
	all of ($string*)
}

rule Suspends_running_Threads{
    strings:
	$string1 = "SuspendThread" nocase
    condition:
	all of ($string*)
}

rule Resumes_suspended_Threads{
    strings:
	$string1 = "ResumeThread" nocase
    condition:
	all of ($string*)
}

rule Enumerates_Active_Window{
    strings:
	$string1 = "GetActiveWindow" nocase
	$string2 = "GetForegroundWindow" nocase
    condition:
	any of ($string*)
}

rule Enumerates_Drive_Serial_Numbers{
    strings:
	$string1 = "volumeserialnumber" nocase
    condition:
	$string1
}

rule Enumerates_Available_Drives{
    strings:
	$string1 = "GetLogicalDrives" nocase
    condition:
	$string1
}

rule Enumerate_files{
    strings:
	$string1 = "FindFirstFile"
	$string2 = "FindNextFile"
    condition:
	all of ($string*)
}

rule Creates_Folders{
    strings:
	$string1 = "CreateDirectory"
    condition:
	$string1
}

rule Deletes_Folders{
    strings:
	$string1 = "RemoveDirectory"
    condition:
	$string1
}

rule Create_Files{
    strings:
	$string1 = "CreateFile"
    condition:
	$string1
}

rule Copy_Files{
    strings:
	$string1 = "CopyFile"
    condition:
	$string1
}

rule Move_Files{
    strings:
	$string1 = "MoveFile"
    condition:
	$string1
}

rule Delete_Files{
    strings:
	$string1 = "DeleteFile"
    condition:
	$string1
}

rule Enumerate_filesystem_info{
    strings:
	$string1 = "GetVolumeInformation"
    condition:
	$string1
}

rule Enumerate_SystemInfo{
    strings:
	$string1 = "GetSystemInfo" // x86
	$string2 = "GetNativeSystemInfo" // x64
    condition:
	any of ($string*)
}

rule Enumerate_loaded_modules{
    strings:
	$string1 = "GetWindowModuleFileNameA"
	$string2 = "GetModuleFileName"
    condition:
	any of ($string*)
}

rule Search_for_Specific_Program_Window{
    strings:
	$string1 = "FindWindow"
    condition:
	$string1
}

rule Enumerate_Programs_windows{
    strings:
	$string1 = "EnumWindows"
    condition:
	$string1
}
