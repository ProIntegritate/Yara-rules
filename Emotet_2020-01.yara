import "hash"
import "pe"

rule Emotet_RichHash_2020_01{

    meta:
        description = "Emotet Richhash signatures found in 2020-01"
        reference = "URLHaus links"
        author = "@Pro_Integritate"
        date = "2020-01-10"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "07c4932d1fee8a2d2105a514129a5c9c" or
	 hash.md5(pe.rich_signature.clear_data) == "029723f6bbf930981b63397071df0217" or
	 hash.md5(pe.rich_signature.clear_data) == "19790190eacf226586729fe9133f6296" or
	 hash.md5(pe.rich_signature.clear_data) == "304dc0fecbaa34e3705acade381886dc" or
	 hash.md5(pe.rich_signature.clear_data) == "44baaea5f978a0d5d20aa43856d2f87f" or
	 hash.md5(pe.rich_signature.clear_data) == "4cf469ab2227902bbd5942a05876ab91" or
	 hash.md5(pe.rich_signature.clear_data) == "536133a24ee18066cf53b6c1fa6ffc08" or
	 hash.md5(pe.rich_signature.clear_data) == "59f6b8b2e0dca75d42c6144c56a29c9d" or
	 hash.md5(pe.rich_signature.clear_data) == "83b61676889c62f5d5814b1c116653e7" or
	 hash.md5(pe.rich_signature.clear_data) == "bf4055335a51f3fa635444d3d838b439" or
	 hash.md5(pe.rich_signature.clear_data) == "cc66fe8671208ee9cb7a62f5524df910" or
	 hash.md5(pe.rich_signature.clear_data) == "db29f940bfa4b5d0e4e8ed57e158c90c" or
	 hash.md5(pe.rich_signature.clear_data) == "e509d6c1334839bb4014a4dae788fb89" or
	 hash.md5(pe.rich_signature.clear_data) == "eb785e618d99684f278df42ffaefab04" or
	 hash.md5(pe.rich_signature.clear_data) == "f475be015099be2ea9bf3cc159f5dc99")

}
