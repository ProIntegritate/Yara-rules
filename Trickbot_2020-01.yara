import "hash"
import "pe"

rule Trickbot_RichHash_2020_01{

    meta:
        description = "Trickbot Richhash signature found in 2020-01"
        reference = "URLHaus links"
        author = "@Pro_Integritate"
        date = "2020-01-10"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "39e7e4a426dc855e00db64450b76813b" or
	 hash.md5(pe.rich_signature.clear_data) == "01b20073b8364d2121226fc579aac0c7" or
	 hash.md5(pe.rich_signature.clear_data) == "14edc3e5131fdcf3472f9d0fb54d55cd" or
	 hash.md5(pe.rich_signature.clear_data) == "19161c2bbb817fe02b5b11df15749292" or
	 hash.md5(pe.rich_signature.clear_data) == "1f33510119007be8d934ca87c327c5f3" or
	 hash.md5(pe.rich_signature.clear_data) == "4de464f6047ee0ac6488dff938afe077" or
	 hash.md5(pe.rich_signature.clear_data) == "5f62d61c76dacfaafc1e1cfb8261245f" or
	 hash.md5(pe.rich_signature.clear_data) == "c3640cf13baf9e781aa01038c09f9052" or
	 hash.md5(pe.rich_signature.clear_data) == "cba790c0bfcb514df5ac49f47b49c34a")

}
