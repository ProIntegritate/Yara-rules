// Last update: 18:33 2020-12-30
// Author: "@Pro_Integritate"
// Tested with: Yara 4.0.2
// 
// Should be used to give you a sorta-idea of a files capabilities.
//
// Disclaimer: This is just a triage script and does not tell you with
// certainty that something is good or bad - it's not reverse engineering.
// Everything you see need to be validated - and that is your job.

rule INFO_Windows_Executable{
	strings:
		$pe = "PE"
	condition:
	uint16(0x00) == 0x5a4d and $pe
}

rule INFO_Linux_Executable{
	condition:
	uint16(0x00) == 0x457f and uint16(0x02) == 0x464c
}

rule INFO_Scripting_Function_or_Subroutine{
	strings:
	$string1 = "function " nocase ascii wide
	$string2 = "sub " nocase ascii wide
	condition:
	any of ($string*)
}

rule Windows_Executable_Base64{
	strings:
		$string1 = "TVqQ" ascii wide
		$string2 = "TVpQ" ascii wide
		$string3 = "QqVT" ascii wide // Reversed
		$string4 = "QpVT" ascii wide // Reversed
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
		$string1 = ".pdb" nocase ascii wide
		$string2 = ":\\" ascii wide
	condition:
		all of ($string*)
}

rule INFO_Build_System_path{
	strings:
		$string1 = "C:\\Users\\" nocase ascii wide
	condition:
		$string1
}

rule INFO_MS_Office_Document_Legacy{
	condition:
		uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
		(uint16(0x19) == 0x0320 or uint16(0x19) == 0x0300)
}


// ---- Capabilities ----

rule Network_Access{
	strings:
		$net1 = "WSOCK32.dll" nocase ascii wide
		$net2 = "WININET.dll" nocase ascii wide
		$net3 = "IPHLPAPI.DLL" nocase ascii wide
		$net4 = "ws2_32.dll" nocase ascii wide
		$net5 = "wsock32.dll" nocase ascii wide
		$net6 = "wininet.dll" nocase ascii wide
		$net7 = "NETAPI32.dll" nocase ascii wide
		$net8 = "mswsock.dll" nocase ascii wide
		$net9 = "WSAStartup" nocase ascii wide
	condition:
		any of ($net*)
}

rule Shell_External_Commands{
	strings:
		$string1 = "shell32.dll" nocase ascii wide
		$string2 = "ShellExecute" nocase ascii wide
		$string3 = "ProcessStartInfo" nocase ascii wide
		$string4 = "Scripting.FileSystemObject" nocase ascii wide
		$string5 = "Shell.Application" nocase ascii wide
		$string6 = "WScript.Shell" nocase ascii wide
		$string7 = "CreateProcess" nocase ascii wide
		$string8 = "WinExec" nocase ascii wide
	condition:
		any of ($string*)
}

rule Decoding_Base64_Payload{
	strings:
		$string1 = "Convert" nocase ascii wide
		$string2 = "FromBase64" nocase ascii wide
		$string3 = "MSXML2.DOMDocument" nocase ascii wide
		$string4 = "B64DECODE" nocase ascii wide
		$string5 = "Base64ToString" nocase ascii wide
		$string6 = "base64_decode" nocase ascii wide
		$string7 = "B64D" nocase ascii wide
		$string8 = "base64ToStream" nocase ascii wide
		$string9 = "base64" nocase ascii wide
		$string10 = "Cryptography" nocase ascii wide
		$string11 = "FromBase64Transform" nocase ascii wide
		$string12 = "2933BF90-7B36-11D2-B20E-00C04F983E60" nocase ascii wide
	condition:
		($string1 and $string2) or
		($string3 and ($string4 or $string9)) or
		$string5 or $string6 or $string7 or $string8 or
		($string10 and $string11) or
		($string7 and $string12)
}

rule URL{
	strings:
		$string1 = "https:" nocase ascii wide
		$string2 = ":sptth" nocase ascii wide // reversed
		$string3 = "http:" nocase ascii wide
		$string4 = ":ptth" nocase ascii wide // reversed
		$string5 = "ftp:" nocase ascii wide
		$string6 = ":ptf" nocase ascii wide // reversed
	condition:
		any of ($string*)
}

rule UserAgent{
	strings:
		$string1 = "User-Agent" nocase ascii wide
		$string2 = "tnegA-resU" nocase ascii wide // reversed
		$common1 = "(Windows " nocase ascii wide
		$common2 = "WOW64;" nocase ascii wide
	condition:
		any of ($string*) or ($common1 and $common2)
}

rule Sets_specific_HTTP_Useragent{
	strings:
		$string1 = "SetRequestHeader" nocase ascii wide
		$string2 = "User-Agent" nocase ascii wide
	condition:
		all of ($string*)
}

rule Payload_Download{
	strings:
		$string1 = "DownloadFile" nocase ascii wide
		$string2 = "eliFdaolnwoD" nocase ascii wide // reversed
		$string3 = "DownloadString" nocase ascii wide
		$string4 = "gnirtSdaolnwoD" nocase ascii wide // reversed
		$string5 = "DownloadData" nocase ascii wide
		$string6 = "ataDdaolnwoD" nocase ascii wide // reversed
		$msxml1 = "Msxml2.XMLHttp" nocase ascii wide
		$msxml2 = ".open" nocase ascii wide
		$msxml3 = ".send" nocase ascii wide
	condition:
		any of ($string*) or all of ($msxml*)
}

rule Access_Cryptograpic_Libraries{
	strings:
		$string1 = "crypt32.dll" nocase ascii wide
		$string2 = "Security.Cryptography" nocase ascii wide
		$string3 = "yhpargotpyrC.ytiruceS" nocase ascii wide
		$string4 = "bcrypt.dll" nocase ascii wide
	condition:
		any of ($string*)
}

rule Dotnet_FileWrite{
	strings:
		$function1 = "System.IO" nocase ascii wide // System.IO|0x00|File !
		$function2 = "OI.metsyS" nocase ascii wide // reversed
		$string1 = "WriteAllBytes" nocase ascii wide
		$string2 = "setyBllAetirW" nocase ascii wide // reversed
		$string3 = "WriteAllLines" nocase ascii wide
		$string4 = "seniLllAetirW" nocase ascii wide // reversed
		$string5 = "WriteAllText" nocase ascii wide
		$string6 = "txeTllAetirW" nocase ascii wide // reversed
	condition:
		any of ($function*) and any of ($string*)
}

rule Dotnet_FileMove{
	strings:
		$hex = {53 79 73 74 65 6D 2E 49 4F 00 46 69 6C 65 00 4D 6F 76 65} // System.IO|0x00|File|0x00|Move
		$string1 = "System.IO" nocase ascii wide // Text for Scripting
		$string2 = "OI.netsyS" nocase ascii wide // reversed
		$string3 = "File" nocase ascii wide
		$string4 = "eliF" nocase ascii wide // reversed
		$string5 = "Move" nocase ascii wide 
		$string6 = "evoM" nocase ascii wide // reversed
	condition:
		$hex or
		($string1 and $string3 and $string5) or
		($string2 and $string4 and $string6)
}

rule DotNet_Sockets{
	strings:
		$string1 = "Net.Sockets" nocase ascii wide // -"System." nocase ascii wide
		$string2 = "stekcoS.teN" nocase ascii wide // reversed // -"System." nocase ascii wide
	condition:
		any of ($string*)
}

rule DotNet_Webclient{
	strings:
		$string1 = "Net.WebClient" nocase ascii wide // -"System."
		$string2 = "tneilCbeW.teN" nocase ascii wide // reversed // -"System."
		$string3 = "Net.Webrequest" nocase ascii wide // -"System."
		$string4 = "tseuqerbeW.teN" nocase ascii wide // -"System."
	condition:
		any of ($string*)
}

rule Legacy_WebQuery{
	strings:
		$string1 = "winhttp.dll" nocase ascii wide
		$string2 = "WinHttpOpen" nocase ascii wide
		$string3 = "createobject" nocase ascii wide
		$string4 = "msxml2.xmlhttp" nocase ascii wide
		$string5 = "urlmon.dll" nocase ascii wide
		$string6 = "URLDownloadToFile" nocase ascii wide
	condition:
		($string1 and $string2) or
		($string3 and $string4) or
		($string5 and $string6)
}

rule DotNet_DNS{
	strings:
		$string1 = "Net.dns" nocase ascii wide
		$string2 = "snD.teN" nocase ascii wide // reversed
	condition:
		any of ($string*)
}

rule Legacy_DNS{
	strings:
		$string1 = "DnsQuery" nocase ascii wide
		$string2 = "DNSAPI.dll" nocase ascii wide
	condition:
		$string1 and $string2
}

rule DotNet_File_Decompression{
	strings:
		$string1 = "IO.Compression" nocase ascii wide
		$string2 = "noisserpmoC.OI" nocase ascii wide
		$method1 = "Deflate" nocase ascii wide 
		$method2 = "etalfeD" nocase ascii wide// reversed
		$method3 = "Decompress" nocase ascii wide 
		$method4 = "sserpmoceD" nocase ascii wide // reversed
	condition:
		any of ($string*) and any of ($method*)
}

rule Reading_Keyboard_Input{
	strings:
		$string1 = "GetAsyncKeyState" nocase ascii wide 
		$string2 = "SetWindowsHook" nocase ascii wide 
	condition:
		any of ($string*)
}

rule HTTP_Binary_transfer{
	strings:
		$string1 = "application/octet-stream" nocase ascii wide 
		$string2 = "maerts-tetco/noitacilppa" nocase ascii wide  // reversed
		$string3 = "application/zip" nocase ascii wide 
		$string4 = "piz/noitacilppa" nocase ascii wide  // reversed
	condition:
		any of ($string*)
}

rule Firewall_Configuration_Change{
	strings:
		$string1 = "iptables" nocase ascii wide 
		$string2 = "selbatpi" nocase ascii wide  // reversed
		$string3 = "netsh advfirewall" nocase ascii wide 
		$string4 = "llawerifvda hsten" nocase ascii wide  // reversed
		$string5 = "FirewallAPI" nocase ascii wide 
		$string6 = "IPAllaweriF" nocase ascii wide  // reversed
		$string7 = "netsh firewall" nocase ascii wide 
		$string8 = "llawerif hsten" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Unconventional_Build_Tools{
	strings:
		$string1 = "installutil.exe" nocase ascii wide 
		$string2 = "exe.litullatsni" nocase ascii wide 
		$string3 = "msbuild.exe" nocase ascii wide 
		$string4 = "exe.dliubsm" nocase ascii wide 
		$string5 = "csc.exe" nocase ascii wide 
		$string6 = "exe.csc" nocase ascii wide 
		$string7 = "vbc.exe" nocase ascii wide 
		$string8 = "exe.cbv" nocase ascii wide 
		$string9 = "ilasm.exe" nocase ascii wide 
		$string10 = "exe.msali" nocase ascii wide 
		$string11 = "jsc.exe" nocase ascii wide 
		$string12 = "exe.csj" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Recon_WMIC{
	strings:
		$string1 = "wmic.exe" nocase ascii wide 
		$string2 = "exe.cimw" nocase ascii wide 
		$string3 = "winmgmts:" nocase ascii wide 
		$string4 = "Select " nocase ascii wide 
	condition:
		$string1 or $string2 or ($string3 and $string4)
}

rule Generic_Recon_Indicator{
	strings:
		$string1 = "GetOEMCP" nocase ascii wide 
		$string2 = "GetTimeZoneInformation" nocase ascii wide 
		$string3 = "EnumSystemLocales" nocase ascii wide 
		$string4 = "systeminfo" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Registry_Query_Information{
	strings:
		$open = "RegOpenKey" nocase ascii wide 
		$string1 = "RegQueryValue" nocase ascii wide 
		$string2 = "RegEnumKey" nocase ascii wide 
		$string3 = "RegQueryMultipleValues" nocase ascii wide 
		$dotnetstring1 = "Win32.Registry" nocase ascii wide 
		$dotnetstring2 = "GetValue" nocase ascii wide 
		$api1 = "GetValueFromRegistry" nocase ascii wide 
		$api2 = "ZwQueryValueKey"
	condition:
		($open and any of ($string*)) or all of ($dotnetstring*) or any of ($api*)
}

rule Registry_Write_Information{
	strings:
		$open = "RegOpenKey"
		$string1 = "RegCreateKey" nocase ascii wide 
		$string2 = "RegDeleteKey" nocase ascii wide 
		$string3 = "RegSetValue" nocase ascii wide 
		$dotnetstring1 = "Win32.Registry" nocase ascii wide 
		$dotnetstring2 = "SetValue" nocase ascii wide 
		$api1 = "ZwSetValueKey"
	condition:
		($open and any of ($string*)) or all of ($dotnetstring*) or $api1
}

rule Registry_Delete_Information{
	strings:
		$api1 = "DeleteValueFromRegistry"
		$api2 = "RegDeleteKey"
		$api3 = "RegistryKey.DeleteSubKey"
	condition:
		any of ($api*)
}

rule Document_RTF_Obj_Payload{
	strings:
		$string1 = "{\\r" nocase ascii wide 
		$string2 = "objdata" nocase ascii wide 
		$string3 = "objemb" nocase ascii wide 
	condition:
		$string1 and ($string2 or $string3)
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
		$String = "CreateRemoteThread" nocase ascii wide 
	condition:
		$String
}

rule Creating_Thread{
	strings:
		$String = "CreateThread" nocase ascii wide 
	condition:
		$String
}

rule Terminate_Thread{
	strings:
		$String = "TerminateThread" nocase ascii wide 
	condition:
		$String
}

rule Reading_Memory_In_Remote_Process{
	strings:
		$String = "ReadProcessMemory" nocase ascii wide 
	condition:
		$String
}

rule Writing_Memory_In_Remote_Process{
	strings:
		$String = "WriteProcessMemory" nocase ascii wide 
	condition:
		$String
}

rule Calling_Debug_Privileges{
	strings:
		$String1 = "AdjustTokenPrivileges" nocase ascii wide 
		$String2 = "SeDebugPrivilege" nocase ascii wide 
	condition:
		all of ($String*)
}

rule Powershell_Execution_Bypass{
	strings:
		$String1 = "powershell.exe" nocase ascii wide 
		$String2 = "exe.llehsrewop" nocase ascii wide  // reverse
		$String3 = "-Exec Bypass" nocase ascii wide 
		$String4 = "ssapyB cexE-" nocase ascii wide  // reverse
	condition:
		($String1 and $String3) or
		($String2 and $String4)
}

rule Powershell_EncodedCommand_Usage{
	strings:
		$String1 = "powershell" nocase ascii wide 
		$String2 = " -EncodedCommand " nocase ascii wide 
		$String3 = " -e " nocase ascii wide 
	condition:
		$String1 and ($String2 or $String3)
}

rule Powershell_Registry_Key_Access{
	strings:
		$String1 = "Policies\\Microsoft\\Windows\\PowerShell" nocase ascii wide
	condition:
		$String1
}

rule Filesystem_Scripting{
	strings:
		$String1 = "Scripting.FileSystemObject" nocase ascii wide 
		$String2 = "tcejbOmetsySeliF.gnitpircS" nocase ascii wide 
		$String3 = "Wscript.Shell" nocase ascii wide 
		$String4 = "llehS.tpircsW" nocase ascii wide 
	condition:
		($String1 and $String3) or
		($String2 and $String4)
}

rule Checks_For_Debugger{
	strings:
		$String1 = "IsDebuggerPresent" nocase ascii wide  // Sub process
		$String2 = "CheckRemoteDebuggerPresent" nocase ascii wide  // Paralell process
		$String3 = "KdDebuggerEnabled" nocase ascii wide  // Kernel call
		$String4 = "NtQueryInformationProcess" nocase ascii wide  // Ring3 debugger (ProcessDebugPort)
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
		$String11 = "HKLM" nocase ascii wide
		$String12 = "MLKH" nocase ascii wide
		$String13 = "HKCU" nocase ascii wide
		$String14 = "UCKH" nocase ascii wide
		$String15 = "HKCR" nocase ascii wide
		$String16 = "RCKH" nocase ascii wide
		$String17 = "HKCC" nocase ascii wide
		$String18 = "CCKH" nocase ascii wide
	condition:
	any of ($String*)
}

rule Autoit_Scripting{
	strings:
		$String1 = "FSoftware" nocase ascii wide
		$String2 = "AutoIt v3" nocase ascii wide
		$String3 = "AutoIt3Execute" nocase ascii wide
		$String4 = "Software\\AutoIt" nocase ascii wide
		$String5 = "third-party compiled AutoIt script" nocase ascii wide
		$String6 = "AutoIt script files (*.au3, *.a3x)" nocase ascii wide
		$String7 = "AutoIt has detected the stack has become corrupt" nocase ascii wide
		$String8 = "AutoIt supports the __stdcall" nocase ascii wide
		$String9 = "reserved for AutoIt internal use" nocase ascii wide

	condition:
		3 of ($String*)
}

rule External_Scripting{
	strings:
		$String1 = "psexec.exe" nocase ascii wide 
		$String2 = "psExec64.exe" nocase ascii wide 
		$String3 = "cmd.exe" nocase ascii wide 
		$String4 = "powershell.exe" nocase ascii wide 
	condition:
		any of ($String*)
}

rule System_folder_enumeration{
	strings:
		$string1 = "SystemDirectory" nocase ascii wide 
		$string2 = "yrotceriDmetsyS" nocase ascii wide  // reverse
		$string3 = "Systemroot" nocase ascii wide 
		$string4 = "toormetsyS" nocase ascii wide  // reverse
		$string5 = "Windir" nocase ascii wide 
		$string6 = "ridniW" nocase ascii wide  // reverse
		$string7 = "GetSystemWindowsDirectory" nocase ascii wide 
		$string8 = "GetWindowsDirectory" nocase ascii wide 
		$string9 = "GetSystemDirectory" nocase ascii wide 
	condition:
		any of ($string*)
}

rule String_obfuscation{
	strings:
		$string1 = "StrReverse" nocase ascii wide 
		$string2 = {22 20 26 20 22}	 // " & "
		$string3 = {22 26 22}		   //  "&"
		$string4 = {22 20 2B 20 22}	 // " + "
		$string5 = {22 2B 22}		   //  "+"
		$string6 = "decode" nocase ascii wide 
		$string7 = "replace" nocase ascii wide 
		$string8 = "unescape" nocase ascii wide 
		$string9 = "[alias((" nocase ascii wide 
		$string10 = "[alias ((" nocase ascii wide 
		$string11 = "$FuncVars[(" nocase ascii wide 
		$string12 = "$FuncVars [(" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Registry_Commandline{
	strings:
		$string1 = "Reg.exe" nocase ascii wide 
		$string2 = "exe.geR" nocase ascii wide  // reverse
	condition:
		any of ($string*)
}

rule Accessing_Starting_Or_Creating_Services{
	strings:
		$string1 = "OpenService" nocase ascii wide 
		$string2 = "CreateService" nocase ascii wide 
		$string3 = "StartService" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Deletes_Services{
	strings:
		$string1 = "DeleteService" nocase ascii wide 
		$string2 = "ecivreSeteleD" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Terminate_process{
	strings:
		$string1 = "TerminateProcess" nocase ascii wide 
		$string2= "Win32_Process" nocase ascii wide 
		$string3 = ".Terminate" nocase ascii wide 
	condition:
		$string1 or ($string2 and $string3)
}

rule Reboot_Persistance{
	strings:
		$String1 = "currentversion\\run" nocase ascii wide // Currentversion\Run, can be scripted (ascii) or compiled (Wide)
		$String2 = "nur\\noisreVtnerruc" nocase ascii // Reversed
		$String3 = "schtasks" nocase ascii wide		 // Schtasks.exe /Create
		$String4 = "create" nocase ascii wide 
		$String5 = "change" nocase ascii wide 
		$String6 = "sksathcs" nocase ascii wide		 // Reversed
		$String7 = "etaerc" nocase ascii wide 
	condition:
		($String1 or $String2) or
		($String3 and ($String4 or $String5) ) or
		($String6 and $String7)
}

rule LOLBins{
	strings:
		$string1 = "wscript.exe" nocase ascii wide 
		$string2 = "exe.tpircsw" nocase ascii wide		 // Reversed
		$string3 = "cscript.exe" nocase ascii wide 
		$string4 = "exe.tpircsc" nocase ascii wide		 // Reversed
		$string5 = "bitsadmin.exe" nocase ascii wide 
		$string6 = "exe.nimdastib" nocase ascii wide		 // Reversed

		// Already here:
		// "installutil.exe" nocase ascii wide 
		// "msbuild.exe" nocase ascii wide 
		// "csc.exe" nocase ascii wide 
		// "vbc.exe" nocase ascii wide 
		// "ilasm.exe" nocase ascii wide 
		// "jsc.exe" nocase ascii wide 
		// "certutil.exe" nocase ascii wide 
	condition:
		any of ($string*)
}

rule WMI_Query_Moniker_LDAP{
	strings:
		$string1 = "winmgmts:" nocase ascii wide 
		$string2 = ":stmgmniw" nocase ascii wide 
		$string3 = "LDAP" nocase ascii wide 
		$string4 = "PADL" nocase ascii wide 
	condition:
		($string1 or $string2) and ($string3 or $string4)
}

rule Reflective_loader{
	strings:
		$string1 = "EntryPoint.Invoke" nocase ascii wide 
		$string2 = "System.Reflection" nocase ascii wide 
		$string3 = "Reflection.Assembly" nocase ascii wide 
		$string4 = "::Load" nocase ascii wide 
		$string5 = ".Invoke" nocase ascii wide 
		$string6 = "Runtime.InteropServices.Marshal"
		$string7 = "::CreateThread"
	condition:
		$string1 and ($string2 or $string3) or
		($string3 and $string4 and $string5) or
		$string6 and ($string7 or $string5)
}

rule Starting_Code_From_Payload{
	strings:
		$string1 = ".Invoke" nocase ascii wide 
		$string2 = "System.Runtime" nocase ascii wide 
		$string3 = "Runtime.InteropServices" nocase ascii wide 
	condition:
		$string1 and ($string2 or $string3)
}

rule Requires_Admin_Privileges{
	strings:
		$string1 = "<?xml" nocase ascii wide 
		$string2 = "requestedPrivileges" nocase ascii wide 
		$string3 = "requireAdministrator" nocase ascii wide 
	condition:
		all of ($string*)
}

rule Access_Service_Control_Manager{
	strings:
		$string1 = "OpenSCManagerA" nocase ascii wide 
	condition:
		$string1
}

rule WMI_Enumerates_Antivirus{
	strings:
		$string1 = "winmgmts:" nocase ascii wide 
		$string2 = ":stmgmniw" nocase ascii wide 
		$string3 = "securitycenter" nocase ascii wide 
		$string4 = "retnecytiruces" nocase ascii wide 
		$string5 = "AntiVirusProduct" nocase ascii wide 
		$string6 = "tcudorPsuriVitnA" nocase ascii wide 
	condition:
		($string1 or $string2) and ($string3 or $string4) and ($string5 or $string6)
}

rule WMI_Enumerates_Disk_properties{
	strings:
		$string1 = "winmgmts:" nocase ascii wide 
		$string2 = ":stmgmniw" nocase ascii wide 
		$string3 = "win32_logicaldisk" nocase ascii wide 
		$string4 = "ksidlacigol_23niw" nocase ascii wide 
	condition:
		($string1 or $string2) and ($string3 or $string4)
}

rule WMI_Enumerates_OperatingSystem{
	strings:
		$string1 = "winmgmts:" nocase ascii wide 
		$string2 = ":stmgmniw" nocase ascii wide 
		$string3 = "Win32_OperatingSystem" nocase ascii wide 
		$string4 = "metsySgnitarepO_23niW" nocase ascii wide 
	condition:
		($string1 or $string2) and ($string3 or $string4)
}

rule Enumerate_Processes{
	strings:
		$string1 = "OpenProcess" nocase ascii wide 
		$string2 = "CreateToolhelp32Snapshot" nocase ascii wide 
		$string3 = "Process32First" nocase ascii wide 
		$string4 = "Process32Next" nocase ascii wide 
		$dotnetstring1 = "Process" nocase ascii wide
		$dotnetstring2 = ".GetProcessesByName" nocase ascii wide
	condition:
		all of ($string*) or all of ($dotnetstring*)
}

rule Enumerate_Threads{
	strings:
		$string1 = "OpenProcess" nocase ascii wide 
		$string2 = "CreateToolhelp32Snapshot" nocase ascii wide 
		$string3 = "Thread32First" nocase ascii wide 
		$string4 = "Thread32Next" nocase ascii wide 
	condition:
		all of ($string*)
}

rule Suspends_running_Threads{
	strings:
		$string1 = "SuspendThread" nocase ascii wide 
	condition:
		all of ($string*)
}

rule Resumes_suspended_Threads{
	strings:
		$string1 = "ResumeThread" nocase ascii wide 
	condition:
		all of ($string*)
}

rule Enumerates_Active_Window{
	strings:
		$string1 = "GetActiveWindow" nocase ascii wide 
		$string2 = "GetForegroundWindow" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Enumerates_Drive_Serial_Numbers{
	strings:
		$string1 = "volumeserialnumber" nocase ascii wide 
	condition:
		$string1
}

rule Enumerates_Available_Drives{
	strings:
		$string1 = "GetLogicalDrives" nocase ascii wide 
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
		$string2 = ".DeleteFolder" nocase ascii wide
	condition:
		any of ($string*)
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
		$string2 = "Kill" nocase ascii wide
		$string3 = ".DeleteFile" nocase ascii wide
	condition:
	any of ($string*)
}

rule Read_Files{
	strings:
		$string1 = "ReadFile"
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

rule Execute_Dynamic_Script_Code{
	strings:
		$string1 = "eval " nocase ascii wide		 //java
		$string2 = "eval(" nocase ascii wide
		$string3 = "Invoke-Expression"  ascii wide	 //powershell
		$string4 = " iex" nocase ascii wide
		$string5 = "iex " nocase ascii wide 
		$string6 = "iex(" nocase ascii wide
		$string7 = "|iex" nocase ascii wide
		$string8 = "fromCharCode" nocase ascii wide
		$string9 = "execute " nocase ascii wide 	//vbscript
		$string10 = "execute(" nocase ascii wide
		$string11 = " etucexe" nocase ascii wide
		$string12 = "(etucexe" nocase ascii wide
	condition:
		any of ($string*)
}

rule INFO_Console_application{
	strings:
		$string1 = "GetCommandLine" nocase ascii wide 
	condition:
		$string1
}

rule Retrieves_environment_strings{
	strings:
		$string1 = "GetEnvironmentStrings" nocase ascii wide 
		$string2 = "environ(" nocase ascii wide 
		$string3 = "environ " nocase ascii wide 
		$string4 = "$env:" nocase ascii wide 
	condition:
		any of ($string*)
}

rule INFO_VisualBasic6_Runtime{
	strings:
		$string1 = "MSVBVM60.DLL" nocase ascii wide 
		$string2 = "VB6.OLB" nocase ascii wide 
		$string3 = "VBA6.DLL" nocase ascii wide 
		$string4 = "__vba" nocase ascii wide 
		$string5 = ".vbp"
	condition:
		2 of ($string*)
}

rule Unpack_GZipStream{
	strings:
		$string1 = "GZipStream" nocase ascii wide  
		$string2 = "decompress" nocase ascii wide  
		$string3 = "deflate" nocase ascii wide  
	condition:
		$string1 and ($string2 or $string3)
}

rule HTTP_POST_Information{
	strings:
		$string1 = "HttpMethod(" nocase ascii wide  
		$string2 = "HttpMethod " nocase ascii wide  
		$string3 = "POST" nocase ascii wide  
	condition:
		($string1 or $string2) and $string3
}

rule Delete_VolumeShadowCopy{
	strings:
		$string1 = "vssadmin" nocase ascii wide 
		$string2 = "delete shadow" nocase ascii wide 
		$string3 = "nimdassv" nocase ascii wide 
		$string4 = "wodahs eteled" nocase ascii wide 
	condition:
		($string1 and $string2) or ($string3 and $string4)
}

rule SessionCookie{
	strings:
		$string1 = "Headers" nocase ascii wide 
		$string2 = "Cookie" nocase ascii wide 
		$string3 = "session" nocase ascii wide 
	condition:
		2 of ($string*)
}

rule IP_Address{
	strings:
		$rxip = /[0-9a-zA-Z]{1,3}\.[0-9a-zA-Z]{1,3}\.[0-9a-zA-Z]{1,3}\.[0-9a-zA-Z]{1,3}/
	condition:
		$rxip // Version strings can trigger FPs.
}

rule Modify_Shell_Startup{
	strings:
		$reg1 = "shell\\open\\command" nocase ascii wide
	condition:
		$reg1
}

rule Access_Powershell_Library{
	strings:
		$string1 = "System.Management.Automation.dll" nocase ascii wide
	condition:
		$string1
}

rule AMSI_Bypass{
	strings:
		$string1 = "Management.Automation.PSTypeName" nocase ascii wide 
		$string2 = "emaNepyTSP.noitamotuA.tnemeganaM" nocase ascii wide  //Rev
		$string3 = "Bypass.AMSI" nocase ascii wide 
		$string4 = "ISMA.ssapyB" nocase ascii wide  //Rev
	condition:
		all of ($string*)
}

rule DLLImport{
	strings:
		$string1 = "DllImport" nocase ascii wide 
		$string2 = ".dll" nocase ascii wide 
	condition:
		all of ($string*)
}

rule ByteArray{
	strings:
		$string1 = "Byte[]" nocase ascii wide 
	condition:
		all of ($string*)
}

rule Use_of_Credentials{
	strings:
		$string1 = "Password =" nocase ascii wide 
		$string2 = "Password=" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Word_Scripting_Document_open{
	strings:
		$string1 = "Document_open" nocase ascii wide 
	condition:
		uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
		(uint16(0x19) == 0x0320 or uint16(0x19) == 0x0300) and
		$string1
}

rule Word_Embedded_Object{
	strings:
		$string1 = "Embedded Object" nocase ascii wide 
	condition:
		uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
		(uint16(0x19) == 0x0320 or uint16(0x19) == 0x0300) and
		$string1
}

rule Base64_Payload{
	strings:
		$rxbs1 = /[0-9a-zA-Z+\/]{12}\=/
		$rxbs2 = /[0-9a-zA-Z+\/]{12}\=\=/
		$rxbs3 = /\=[0-9a-zA-Z+\/]{12}/		// reversed
		$rxbs4 = /\=\=[0-9a-zA-Z+\/]{12}/		// reversed
	condition:
		any of ($rxbs*) 
}

rule External_IP_Lookup{
	strings:
		$ipext1 = "api.ip.sb" nocase ascii wide 
		$ipext2 = "api.ipify.org" nocase ascii wide 
		$ipext3 = "checkip.amazonaws.com" nocase ascii wide 
		$ipext4 = "icanhazip.com" nocase ascii wide 
		$ipext5 = "ident.me" nocase ascii wide 
		$ipext6 = "ip1.dynupdate.no-ip.com" nocase ascii wide 
		$ipext7 = "xip.aws.noip.net" nocase ascii wide 
	condition:
		any of ($ipext*)
}

rule VM_Detection{
	strings:
		$vm1 = "Win32_Processor" nocase ascii wide
		$vm2 = ".NumberOfCores" nocase ascii wide
		$vm3 = "Win32_ComputerSystem" nocase ascii wide
		$vm4 = ".TotalPhysicalMemory" nocase ascii wide
		$vm5 = "Win32_LogicalDisk" nocase ascii wide
		$vm6 = ".Size" nocase ascii wide
		$vm7 = "isProcessorFeaturePresent" nocase ascii wide
		$vm8 = "win32_TemperatureProbe" nocase ascii wide
		$vm9 = "status" nocase ascii wide
	 condition:
		($vm1 and $vm2) or ($vm3 and $vm4) or ($vm5 and $vm6) or $vm7 or ($vm8 and $vm9)
}

rule lolbin_bitsadmin_download{
	strings:
		$badl = "bitsadmin" nocase ascii wide
		$bad2 = "/download " nocase ascii wide
	 condition:
		all of ($bad*)
}

rule Creates_ActiveXObject{
	strings:
		$aao = "new ActiveXObject" nocase ascii wide
	 condition:
		$aao
}

rule INFO_GCC_Runtime{
	strings:
		$string1 = "GCC:" nocase ascii wide 
		$string2 = "GNU C" nocase ascii wide 
	condition:
		any of ($string*)
}

rule Socket_Listener{
	strings:
		$string1 = "websocket" nocase ascii wide	// Java
		$string2 = ".server" nocase ascii wide 
		$string3 = ".createServer" nocase ascii wide 
		$string4 = ".listen" nocase ascii wide 

		$string5 = "net.sockets" nocase ascii wide	 // Dotnet
		$string6 = "tcplistener" nocase ascii wide 
		$string7 = ".start" nocase ascii wide 

	condition:
		($string1 and $string2 and $string3 and $string4) or 
		($string5 and $string6 and $string7)
}

rule Tunneling{
	strings:
		$string1 = "ngrok.io" nocase
		$string2 = "portmap.io" nocase
		$string3 = "beameio.net" nocase
		$string4 = "tmate.io" nocase
		$string5 = "pktriot.net" nocase
		$string6 = "loclx.io" nocase
	condition:
		any of ($string*)
}

rule Hex_Payload{
	strings:    // Less specific now
		$hexpayload1 = /[0-9a-fA-F]{1,2}.[0-9a-fA-F]{1,2}.[0-9a-fA-F]{1,2}.[0-9a-fA-F]{1,2}.[0-9a-fA-F]{1,2}.[0-9a-fA-F]{1,2}/
		$hexpayload2 = /[0-9a-fA-F]{1,2}..[0-9a-fA-F]{1,2}..[0-9a-fA-F]{1,2}..[0-9a-fA-F]{1,2}..[0-9a-fA-F]{1,2}..[0-9a-fA-F]{1,2}/
		$hexpayload3 = /[0-9a-fA-F]{1,2}...[0-9a-fA-F]{1,2}...[0-9a-fA-F]{1,2}...[0-9a-fA-F]{1,2}...[0-9a-fA-F]{1,2}...[0-9a-fA-F]{1,2}/
		$hexpayload4 = /[0-9a-fA-F]{1,2}....[0-9a-fA-F]{1,2}....[0-9a-fA-F]{1,2}....[0-9a-fA-F]{1,2}....[0-9a-fA-F]{1,2}....[0-9a-fA-F]{1,2}/
	condition:
		any of ($hexpayload*) 
}

rule Process_Sleep{
	strings:
		$sleep1 = "WScript.Sleep" nocase ascii wide
	condition:
		any of ($sleep*) 
}

rule Process_Redirect_Output{ // Often use by web/revshells
	strings:
		$redirect1 = "Diagnostics.Process" nocase ascii wide
		$redirect2 = "StartInfo.RedirectStandardOutput" nocase ascii wide
	condition:
		any of ($redirect*)
}

rule EFS_Encryption{
	strings:
		$efs1 = "encryption"  nocase ascii wide
		$efs2 = ".EncryptFile"  nocase ascii wide
		$efs3 = ".DecryptFile"  nocase ascii wide
	condition:
		$efs1 and ($efs2 or $efs3)
}

rule Dotnet_Code_Injection{
	strings:
		$inj1 = "InjectionMethod" nocase ascii wide
		$inj2 = ".Create" nocase ascii wide
	condition:
		all of ($inj*)
}

rule Deletes_ScheduleTask{
	strings:
		$scht1 = "schtasks" nocase ascii wide
		$scht2 = "/delete" nocase ascii wide
	condition:
		all of ($scht*)
}

rule Modifies_Windows_Defender{
	strings:
		$gen1 = "Windows Defender" nocase ascii wide
		$gen2 = "Real-Time Protection" nocase ascii wide
		$wd1 = "DisableAntiSpyware" nocase ascii wide
		$wd2 = "DisableBehaviorMonitoring" nocase ascii wide
		$wd3 = "DisableOnAccessProtection" nocase ascii wide
		$wd4 = "DisableScanOnRealtimeEnable" nocase ascii wide
	condition:
		all of ($gen*) and
		any of ($wd*)
}

rule Modifies_Windows_SecurityCenter{
	strings:
		$gen1 = "Microsoft" nocase ascii wide
		$gen2 = "Security Center" nocase ascii wide
		$wsc1 = "AntiVirusOverride" nocase ascii wide
		$wsc2 = "UpdateOverride" nocase ascii wide
		$wsc3 = "FirewallOverride" nocase ascii wide
		$wsc4 = "AntiVirusDisableNotify" nocase ascii wide
		$wsc5 = "UpdateDisableNotify" nocase ascii wide
		$wsc6 = "AutoUpdateDisableNotify" nocase ascii wide
		$wsc7 = "FirewallDisableNotify" nocase ascii wide
	condition:
		all of ($gen*) and
		any of ($wsc*)
}

rule Disable_SystemRestore{
	strings:
		$hklm = "HKLM" nocase ascii wide
		$sres1 = "SystemRestore" nocase ascii wide
		$sres2 = "DisableSR" nocase ascii wide
	condition:
		$hklm and all of ($sres*)
}

rule Check_Admin_Membership{
	strings:
		$cham1 = "WindowsPrincipal" nocase ascii wide
		$cham2 = ".WindowsIdentity" nocase ascii wide
		$cham3 = "GetCurrent" nocase ascii wide
		$cham4 = ".IsInRole" nocase ascii wide
		$cham5 = "Administrator" nocase ascii wide
	condition:
		all of ($cham*)
}

rule VB_EnableEventMonitor{
	strings:
		$hklm = "HKLM" nocase ascii wide
		$VBMon = "VBA\\Monitors" nocase ascii wide
	condition:
		$hklm and $VBMon
}

rule INFO_Cab_Containing_Executable{
	strings:
		$exe1 = ".exe" nocase ascii wide
		$exe2 = ".dll" nocase ascii wide
	condition:
	any of ($exe*) and uint16(0x00) == 0x534d and uint16(0x02) == 0x4643
}

rule VB_Array{
	strings:    
		$VBArray1 = "Array("
		$VBArray2 = "Array ("
	condition:
		any of ($VBArray*) 
}

rule Decimal_Payload{
	strings:    
		$Decpayload = /[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3}/
	condition:
		$Decpayload
}

rule Macro_Execute_script{
	strings:    
		$macro1 = "Auto_Open" nocase ascii wide
		$macro2 = "AutoOpen" nocase ascii wide
		$macro3 = "Workbook_Open" nocase ascii wide
		$macro4 = "Auto_Close" nocase ascii wide
	condition:
		any of ($macro*)
}

rule Wevtutil_Clear_Logs{
	strings:    
		$command1 = "wevtutil" nocase ascii wide
		$command2 = " cl " nocase ascii wide
	condition:
		$command1 and $command2
}

rule CoinMiner{
	strings:    
		$miner1 = "Usage: xmrig" nocase ascii wide
		$miner2 = "xmrig.com" nocase ascii wide
		$miner3 = "xmrig-proxy" nocase ascii wide
		$miner4 = "xmrig-cuda.dll" nocase ascii wide
		$miner5 = "XMRig 5.0.0" nocase ascii wide
		$minerparam1 = "--coin=" nocase ascii wide
		$minerparam2 = "--url=" nocase ascii wide
		$minerparam3 = "--user=" nocase ascii wide
	condition:
		any of ($miner*) or all of ($minerparam*)
}

rule UAC_Bypass_Schtasks{
	strings:    
		$reg1 = "HKCU" nocase ascii wide
		$reg2 = "Environment" nocase ascii wide
		$schtask1 = "schtasks" nocase ascii wide
		$schtask2 = "/run" nocase ascii wide
		$schtask3 = "/tn" nocase ascii wide
		$schtask4 = "DiskCleanup" nocase ascii wide
		$schtask5 = "SilentCleanup" nocase ascii wide
	condition:
		all of ($reg*) and all of ($schtask*)
}

rule INFO_GoLang{
	strings:    
		$golang1 = "runtime.go" nocase ascii wide
		$golang2 = "ddgs/vendor/golang.org/" nocase ascii wide
		$golang3 = "encoding/gob." nocase ascii wide
	condition:
		any of ($golang*)
}
