// Last updated: 06:44 2020-02-05

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
	 hash.md5(pe.rich_signature.clear_data) == "0b5e5f6432a440becf9d5b437a125bbd" or
	 hash.md5(pe.rich_signature.clear_data) == "07dc1b4943727e33559d2b96fa09bf43" or
	 hash.md5(pe.rich_signature.clear_data) == "0e8e6b6894b84246b3fdd253453d31d3" or
	 hash.md5(pe.rich_signature.clear_data) == "0e8e6b6894b84246b3fdd253453d31d3" or
	 hash.md5(pe.rich_signature.clear_data) == "352045ff6d21cd3869d0c6b67e50171a")

}
