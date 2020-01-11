import "hash"
import "pe"

rule Sodinokibi_Payload{

    meta:
        description = "Sodinokibi/REvil signature (payload)"
        author = "@Pro_Integritate"
        date = "2020-01-11"
        maltype = "Ransomware"

    strings:
        $string1 = "expand 32-byte"
        $string2 = "expand 16-byte"

    condition:
	all of ($string*) and 
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "b25cffe5d8f5190aa58ab8fad74e8066") // 2020-01-11 (8 samples)

}

rule Sodinokibi_Loader{

    meta:
        description = "Sodinokibi/REvil signature (Loader)"
        author = "@Pro_Integritate"
        date = "2020-01-11"
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
        $string37 = "TVqQAA" nocase
        $string38 = "FromBase64String" nocase

    condition:
	35 of ($string*) // 2020-01-11 (11 samples)

}

