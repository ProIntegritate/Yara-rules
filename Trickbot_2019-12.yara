import "hash"
import "pe"

rule Trickbot_RichHash{

    meta:
        description = "Trickbot Richhash signature."
        author = "@Pro_Integritate"
        date = "2019-12 to 2020-01"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "f7080950e540bfd3f31602d51a61c230" or
	 hash.md5(pe.rich_signature.clear_data) == "4de464f6047ee0ac6488dff938afe077" or
	 hash.md5(pe.rich_signature.clear_data) == "2eed36844da934ee87a90696e32b00c9")

}
