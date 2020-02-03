import "hash"
import "pe"

rule Emotet_RichHash_2019_12{

    meta:
        description = "Emotet Richhash signatures to 2019-12-31"
        reference = "771 Emotet Samples with Richheader present from URLHaus links"
        author = "@Pro_Integritate"
        date = "2020-01-09"
        maltype = "Bot/Stealer/Trojan"

    condition:
	uint16(0x00) == 0x5a4d and
	(hash.md5(pe.rich_signature.clear_data) == "07803d77b7af75ca38d574f923fbd28b" or
	 hash.md5(pe.rich_signature.clear_data) == "0ce23de0970400615c0b01afad3209b3" or
	 hash.md5(pe.rich_signature.clear_data) == "177d568a1599e9acc5b57e3b38eaf5f1" or
	 hash.md5(pe.rich_signature.clear_data) == "1f905fa6acda0e5ae1f5978f1cef4dfa" or
	 hash.md5(pe.rich_signature.clear_data) == "2411f7e4255da51927e126989811c7d8" or
	 hash.md5(pe.rich_signature.clear_data) == "25232c149e67af26ba6190ad867f64f1" or
	 hash.md5(pe.rich_signature.clear_data) == "25cae87232d2de300e2a4b6d2469af26" or
	 hash.md5(pe.rich_signature.clear_data) == "26e0a5722940a4673b951a907acdd89b" or
	 hash.md5(pe.rich_signature.clear_data) == "32f1dda1a31e18be1d1fc8f02ae7917e" or
	 hash.md5(pe.rich_signature.clear_data) == "45653c7d55e18c3029181dee02f2a06f" or
	 hash.md5(pe.rich_signature.clear_data) == "474d32bbaa7181c8e1bdeadf3ffd08c7" or
	 hash.md5(pe.rich_signature.clear_data) == "481e2db95b60210589ecebc061ef89ef" or
	 hash.md5(pe.rich_signature.clear_data) == "4cf469ab2227902bbd5942a05876ab91" or
	 hash.md5(pe.rich_signature.clear_data) == "4fa0ce09061043985be3ee9d06dbdf43" or
	 hash.md5(pe.rich_signature.clear_data) == "551464d0452df273e390cf6f10599a92" or
	 hash.md5(pe.rich_signature.clear_data) == "59ad6cc38ab8f6efc5da5ede5bb84051" or
	 hash.md5(pe.rich_signature.clear_data) == "5b2ae56f518c408ef7971dba19e0d23e" or
	 hash.md5(pe.rich_signature.clear_data) == "5d7024fcde5d6d705da04f29eef4cae0" or
	 hash.md5(pe.rich_signature.clear_data) == "67ebb36bbdaecab1de2e75e5c321c85f" or
	 hash.md5(pe.rich_signature.clear_data) == "68352bb52ebc3374e98283b4be3f6b9e" or
	 hash.md5(pe.rich_signature.clear_data) == "6bf169c0ca8c35f81c862e3d043e53b0" or
	 hash.md5(pe.rich_signature.clear_data) == "6c648adfa708e238fdf3516309f15649" or
	 hash.md5(pe.rich_signature.clear_data) == "7a8c4ba2535280d77cd13de9f70de32b" or
	 hash.md5(pe.rich_signature.clear_data) == "7b35108d4fef7edf492f30d4126983f0" or
	 hash.md5(pe.rich_signature.clear_data) == "976ae8323e48269b43b356144b46fff8" or
	 hash.md5(pe.rich_signature.clear_data) == "a51a808388d37fcf4676ba4d236fc994" or
	 hash.md5(pe.rich_signature.clear_data) == "bef0d5a2d4f9223bc2a82701d30089f6" or
	 hash.md5(pe.rich_signature.clear_data) == "c4b2704f6cae147148c60523c9b69f4a" or
	 hash.md5(pe.rich_signature.clear_data) == "c91d9564adf59927ffcec94abcd2b172" or
	 hash.md5(pe.rich_signature.clear_data) == "cd817774651f728e564fba6325351f9d" or
	 hash.md5(pe.rich_signature.clear_data) == "ce1e49edaa50ec2c22007c2b86cff187" or
	 hash.md5(pe.rich_signature.clear_data) == "cefba9cb700f316052e770a8b75ab5d2" or
	 hash.md5(pe.rich_signature.clear_data) == "d8acf4ff6cfc4fdcfd1ab59136e02ec6" or
	 hash.md5(pe.rich_signature.clear_data) == "d93b644fdff426e098ac93d07ab82b4c" or
	 hash.md5(pe.rich_signature.clear_data) == "dda70bd627382701ac7515a0398c0b82" or
	 hash.md5(pe.rich_signature.clear_data) == "ddee47b737c419d80a78f5af51d506e9" or
	 hash.md5(pe.rich_signature.clear_data) == "ded205e9f427ba31749305f5727f7876" or
	 hash.md5(pe.rich_signature.clear_data) == "e2407af20808646e916407bab6ef9519" or
	 hash.md5(pe.rich_signature.clear_data) == "e390c54e6a988051c1326335f1542861" or
	 hash.md5(pe.rich_signature.clear_data) == "e4a82fbefd1985e58ff97ae92983d856" or
	 hash.md5(pe.rich_signature.clear_data) == "e509d6c1334839bb4014a4dae788fb89" or
	 hash.md5(pe.rich_signature.clear_data) == "e769127db366453e1f56e5e33a42df90" or
	 hash.md5(pe.rich_signature.clear_data) == "f147c0beea551a85deb532e58d0ce615" or
	 hash.md5(pe.rich_signature.clear_data) == "f3c277c8f9147445dd2dacf074325d71" or
	 hash.md5(pe.rich_signature.clear_data) == "f5a0bb848bcd63dd57178b6255c8315d" or
	 hash.md5(pe.rich_signature.clear_data) == "fccb16be9b55c6856dd5f43f572549b9" or
	 hash.md5(pe.rich_signature.clear_data) == "fd7f29676c9501563a5c4715145de956" or
	 hash.md5(pe.rich_signature.clear_data) == "ff0fa679b9d301b9fb8fefddccc82757")

}

