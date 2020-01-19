// Last updated: 08:00 2020-01-19

import "hash"
import "pe"

rule Sodinokibi_Payload{

    meta:
        description = "Sodinokibi/REvil signature (payload)"
        reference = "URLHaus links + Downloads (i.e. AAR)"
        author = "@Pro_Integritate"
        maltype = "Ransomware"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "b25cffe5d8f5190aa58ab8fad74e8066" or
	 hash.md5(pe.rich_signature.clear_data) == "7d5f2a8d9c84d114b7886faa24a587e2" or
	 hash.md5(pe.rich_signature.clear_data) == "6655569d2eaaec3117f6be2d997788b8" or
	 hash.md5(pe.rich_signature.clear_data) == "73975984302e5a2a9cf0b580d2064fbf" or
	 hash.md5(pe.rich_signature.clear_data) == "01ac0f0babb057155523bb86fb1ff0a1" or
	 hash.md5(pe.rich_signature.clear_data) == "21ba709282442aaf42d874166711d4fc" or
	 hash.md5(pe.rich_signature.clear_data) == "58981d802dffcfc4dba8bd8577bf4c57" or
	 hash.md5(pe.rich_signature.clear_data) == "9985b043d95ba30a4fbdb57f54d29acc")

}

rule Sodinokibi_Loader{

    meta:
        description = "Sodinokibi/REvil signature (Loader)"
        author = "@Pro_Integritate"
        maltype = "Ransomware"

    strings:
        $string1 = "function Invoke-" nocase
        $string2 = "$ForceASLR" nocase
        $string3 = "$DoNotZeroMZ" nocase
        $string4 = "$RemoteScriptBlock" nocase
        $string5 = "$TypeBuilder" nocase
        $string6 = "$Win32Constants" nocase
        $string7 = "$OpenProcess" nocase
        $string8 = "$WaitForSingleObject" nocase
        $string9 = "$WriteProcessMemory" nocase
        $string10 = "$ReadProcessMemory" nocase
        $string11 = "$CreateRemoteThread" nocase
        $string12 = "$OpenThreadToken" nocase
        $string13 = "$AdjustTokenPrivileges" nocase
        $string14 = "$LookupPrivilegeValue" nocase
        $string15 = "$ImpersonateSelf" nocase
        $string16 = "-SignedIntAsUnsigned" nocase
        $string17 = "Get-Win32Types" nocase
        $string18 = "Get-Win32Functions" nocase
        $string19 = "Write-BytesToMemory" nocase
        $string20 = "Get-ProcAddress" nocase
        $string21 = "Enable-SeDebugPrivilege" nocase
        $string22 = "Get-ImageNtHeaders" nocase
        $string23 = "Get-PEBasicInfo" nocase
        $string24 = "Get-PEDetailedInfo" nocase
        $string25 = "Import-DllInRemoteProcess" nocase
        $string26 = "Get-RemoteProcAddress" nocase
        $string27 = "Update-MemoryAddresses" nocase
        $string28 = "Import-DllImports" nocase
        $string29 = "Get-VirtualProtectValue" nocase
        $string30 = "Update-MemoryProtectionFlags" nocase
        $string31 = "Update-ExeFunctions" nocase
        $string32 = "Copy-ArrayOfMemAddresses" nocase
        $string33 = "Get-MemoryProcAddress" nocase
        $string34 = "Invoke-MemoryLoadLibrary" nocase
        $string35 = "Invoke-MemoryFreeLibrary" nocase
        $string36 = "$PEBytes32" nocase
        $string37 = "TVqQAA"
        $string38 = "FromBase64String" nocase

    condition:
	30 of ($string*)

}

