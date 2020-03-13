// Last updated: 00:47 2020-03-14

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
	 hash.md5(pe.rich_signature.clear_data) == "fa0f2e139d62600e631f5fd0de6718ae" or
	 hash.md5(pe.rich_signature.clear_data) == "11e0de6e0cd83bb803e2bfcd57528672" or
	 hash.md5(pe.rich_signature.clear_data) == "91b4183776fb64b507688811a0be5a6d" or
	 hash.md5(pe.rich_signature.clear_data) == "2fbd7de6b05238079d30baf97499de21" or
	 hash.md5(pe.rich_signature.clear_data) == "6e3568ca8d3139d08e40a4be36215c72" or
	 hash.md5(pe.rich_signature.clear_data) == "7a7922866dd08ab458834b51bdea934b" or
	 hash.md5(pe.rich_signature.clear_data) == "7cdefb74f5d6addf09c6d8630afd1b39" or
	 hash.md5(pe.rich_signature.clear_data) == "ac09095d65563fcc8d567224aacd5762" or
	 hash.md5(pe.rich_signature.clear_data) == "bfb1a7e93a3f4656032c3cf91e18c5f1" or
	 hash.md5(pe.rich_signature.clear_data) == "fa21c51d08f8d7d67229a72a54d8d0ab")

}
