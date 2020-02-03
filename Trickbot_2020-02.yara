// Last updated: 23:37 2020-02-03

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
	(hash.md5(pe.rich_signature.clear_data) == "36aaac199ca6fecbae7a3f23465ac94f" or
	 hash.md5(pe.rich_signature.clear_data) == "6dda137aa0a398d95dab414a830f9909")
}
