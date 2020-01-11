import "hash"
import "pe"

rule Sodinokibi{

    meta:
        description = "Sodinokibi/REvil signature (payload)."
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

