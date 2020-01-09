import "hash"
import "pe"

rule Trickbot_RichHash_2020_01{

    meta:
        description = "Trickbot Richhash signature found in 2020-01"
        reference = "URLHaus links"
        author = "@Pro_Integritate"
        date = "2020-01-09"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "39e7e4a426dc855e00db64450b76813b" or
	hash.md5(pe.rich_signature.clear_data) == "c3640cf13baf9e781aa01038c09f9052" or
	hash.md5(pe.rich_signature.clear_data) == "cba790c0bfcb514df5ac49f47b49c34a")

}

