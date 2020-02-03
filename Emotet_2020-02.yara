// Last updated: 00:11 2020-02-04

import "hash"
import "pe"

rule Emotet_RichHash{

    meta:
        description = "Emotet Richhash signatures"
        reference = "URLHaus links + Downloads (i.e. AAR)"
        author = "@Pro_Integritate"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "724b0220debdbd79f13fab8ae6667a5e" or
	 hash.md5(pe.rich_signature.clear_data) == "c1239871d6a25322ea5ec63c74027889" or
	 hash.md5(pe.rich_signature.clear_data) == "0b5e5f6432a440becf9d5b437a125bbd")

}
