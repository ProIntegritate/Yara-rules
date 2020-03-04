// Last updated: 21:10 2020-03-04

import "hash"
import "pe"

rule Trickbot_RichHash{

    meta:
        description = "Trickbot Richhash signatures"
        reference = "URLHaus links + Downloads (i.e. AAR)"
        author = "@Pro_Integritate"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "40f953563375f6f9b56ce685e0ee6645" or
	 hash.md5(pe.rich_signature.clear_data) == "8ded9ffadcbd5c9096cab2071ef6a140" or
	 hash.md5(pe.rich_signature.clear_data) == "17bade4db423a23b80df9a4c51f1244d" or
	 hash.md5(pe.rich_signature.clear_data) == "af603350ce3e118b8581d93b3e42f079" or
	 hash.md5(pe.rich_signature.clear_data) == "fa0f2e139d62600e631f5fd0de6718ae")

}
