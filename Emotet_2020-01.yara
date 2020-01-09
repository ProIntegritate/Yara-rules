import "hash"
import "pe"

rule Emotet_RichHash_2020_01{

    meta:
        description = "Emotet Richhash signatures found in 2020-01"
        reference = "URLHaus links"
        author = "@Pro_Integritate"
        date = "2020-01-09"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "83b61676889c62f5d5814b1c116653e7")

}

