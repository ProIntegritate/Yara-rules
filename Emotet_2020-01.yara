// Last updated: 00:55 2020-01-18

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
	 hash.md5(pe.rich_signature.clear_data) == "f475be015099be2ea9bf3cc159f5dc99" or
	 hash.md5(pe.rich_signature.clear_data) == "91b4d1d1ffc542b4a8c0e78b3b1798df" or
	 hash.md5(pe.rich_signature.clear_data) == "04493e34d9ca943a968b8a849953d298" or
	 hash.md5(pe.rich_signature.clear_data) == "2f59279dc43165b64e02ccc5a80c1594" or
	 hash.md5(pe.rich_signature.clear_data) == "b2d4ca17618d0a548ead1e7212be9e28" or
	 hash.md5(pe.rich_signature.clear_data) == "3b563ac2144b030de0c73cce32185744" or
	 hash.md5(pe.rich_signature.clear_data) == "6e9c07fae9c1c627b0338e35318617d3" or
	 hash.md5(pe.rich_signature.clear_data) == "df3da9a4af60ea815452a46dc02aca8f" or
	 hash.md5(pe.rich_signature.clear_data) == "e30041a40082476e29a01a997512abeb" or
	 hash.md5(pe.rich_signature.clear_data) == "20b86e2e5c27f605c05f1e9e5d5a34b9" or
	 hash.md5(pe.rich_signature.clear_data) == "279eed9e8ff9d93495b3956cdbcf320f" or
	 hash.md5(pe.rich_signature.clear_data) == "3e7e9bc419fd963c02767421f7d5605f" or
	 hash.md5(pe.rich_signature.clear_data) == "9ec047671e6e58feec21aee100ce0960" or
	 hash.md5(pe.rich_signature.clear_data) == "a03093196d178f13242b74ab12c57b36" or
	 hash.md5(pe.rich_signature.clear_data) == "13fb66c37cefb03b667fed85ce8053db" or
	 hash.md5(pe.rich_signature.clear_data) == "3c7b16f90bfa042c8260da0b12b31f73" or
	 hash.md5(pe.rich_signature.clear_data) == "502cb4f51b5ede001d01ed82374577b2" or
	 hash.md5(pe.rich_signature.clear_data) == "b7531720c720edcbbc555192e2144662")

}
