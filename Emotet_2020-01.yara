// Last updated: 09:16 2020-01-24

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
	 hash.md5(pe.rich_signature.clear_data) == "b7531720c720edcbbc555192e2144662" or
	 hash.md5(pe.rich_signature.clear_data) == "06847e309eb1aa446b4a3d4f45bda001" or
	 hash.md5(pe.rich_signature.clear_data) == "43cd1f34e61bc6a8a34468c0550b2866" or
	 hash.md5(pe.rich_signature.clear_data) == "a04b6ed332ece70eb49e12d3b0e9d90f" or
	 hash.md5(pe.rich_signature.clear_data) == "dda1c67517404ff2a26719872babe17c" or
	 hash.md5(pe.rich_signature.clear_data) == "f2d490bdffe8d32931666b496c74f8a7" or
	 hash.md5(pe.rich_signature.clear_data) == "a8a85782731ec6e41475d34a8e005120" or
	 hash.md5(pe.rich_signature.clear_data) == "979ce79e0791972c0741071a7501b37e" or
	 hash.md5(pe.rich_signature.clear_data) == "ad2982790d12b46e74e8fcab091a56ea" or
	 hash.md5(pe.rich_signature.clear_data) == "b3d9f6adbc1e304db91625582cfbf6df" or
	 hash.md5(pe.rich_signature.clear_data) == "55668867803b5833d84d7e7223342b81" or
	 hash.md5(pe.rich_signature.clear_data) == "5d2986ac26e330150523f660b6003664" or
	 hash.md5(pe.rich_signature.clear_data) == "b0c405fcb5f9399c7ce7cd488503b81a" or
	 hash.md5(pe.rich_signature.clear_data) == "790d2f7d44f0d4db26b6d1436df5753e" or
	 hash.md5(pe.rich_signature.clear_data) == "b77be9e153e00337d06c106f9925804c" or
	 hash.md5(pe.rich_signature.clear_data) == "4203f9c5b249b4cb83acee35697ab64d" or
	 hash.md5(pe.rich_signature.clear_data) == "1c698935218931ece17864f217b1d372" or
	 hash.md5(pe.rich_signature.clear_data) == "337e35a396cbfc2da091c5b881301e07" or
	 hash.md5(pe.rich_signature.clear_data) == "1613490e11d70129ec07bd3aaef9c86a" or
	 hash.md5(pe.rich_signature.clear_data) == "e89bd0c9cfdb0e3f46cfece2915277b4")

}
