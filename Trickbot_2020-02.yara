// Last updated: 22:05 2020-02-21

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
	 hash.md5(pe.rich_signature.clear_data) == "6dda137aa0a398d95dab414a830f9909" or
	 hash.md5(pe.rich_signature.clear_data) == "5d810f3871b7c9c8d31a78fa5cfce75b" or
	 hash.md5(pe.rich_signature.clear_data) == "2d36bf96937908664876130a7c413402" or
	 hash.md5(pe.rich_signature.clear_data) == "3c0bcaa1107014004832e1c2e8a0b3b7" or
	 hash.md5(pe.rich_signature.clear_data) == "11b822876c1109874a99ddf5ff5a2b2a" or
	 hash.md5(pe.rich_signature.clear_data) == "1f33510119007be8d934ca87c327c5f3" or
	 hash.md5(pe.rich_signature.clear_data) == "70a444412d36b4317ca688f5ff8a01cd" or
	 hash.md5(pe.rich_signature.clear_data) == "80ff7bf8aab1092aeb8489fba20c534d" or
	 hash.md5(pe.rich_signature.clear_data) == "a68ed8e0118ecd34896c33fbe535746c" or
	 hash.md5(pe.rich_signature.clear_data) == "b80edbf466bfd1ad11e64786dba88beb" or
	 hash.md5(pe.rich_signature.clear_data) == "b81c0a1f71165d072bbe75aed0d94e13" or
	 hash.md5(pe.rich_signature.clear_data) == "d2138e441020e523b7d3be5e7e9f2adc" or
	 hash.md5(pe.rich_signature.clear_data) == "e2bdf4068e689b6ecfee1b9e1198869e" or
	 hash.md5(pe.rich_signature.clear_data) == "e3b235722e8bc47ff44aae8c422f84b1" or
	 hash.md5(pe.rich_signature.clear_data) == "e56c38c168569277016ef992331baf7e" or
	 hash.md5(pe.rich_signature.clear_data) == "f029f4f124951add69ecea9e0334698f" or
	 hash.md5(pe.rich_signature.clear_data) == "feb87b5702fc9faa302a94fd88f3a733" or
	 hash.md5(pe.rich_signature.clear_data) == "e17567aee7121ccae7486292dbde0ac4" or
	 hash.md5(pe.rich_signature.clear_data) == "68c74a84f88cc052bb72f4cdac4ec73e" or
	 hash.md5(pe.rich_signature.clear_data) == "e3f39d5cf25718801d348bd70ff5012b" or
	 hash.md5(pe.rich_signature.clear_data) == "5f0a020374addb5efde02d7a92b1a191")
}
