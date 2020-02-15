// FileID.Yara, last updated: 00:32 2020-02-16

import "hash"
import "pe"

rule Windows_Executable{
    strings:
        $upx = "UPX!" nocase
    condition:
	(uint16(0x00) == 0x5a4d or
	uint16(0x0050) == 0x5a4d) and
	not $upx
}

rule Windows_Executable_UPX{
    strings:
        $upx = "UPX!" nocase
    condition:
	uint16(0x00) == 0x5a4d and
	$upx
}

rule Linux_Executable{
    strings:
        $upx = "UPX!" nocase
    condition:
	uint16(0x00) == 0x457f and uint16(0x02) == 0x464c and
	not $upx
}

rule Linux_Executable_UPX{
    strings:
        $upx = "UPX!" nocase
    condition:
	uint16(0x00) == 0x457f and uint16(0x02) == 0x464c and
	$upx
}

rule Linux_Executable_Base64{
    condition:
	uint16(0x00) == 0x3066 and uint16(0x02) == 0x4d56
}

rule Windows_Executable_Base64{
    condition:
	uint16(0x00) == 0x5654 and uint16(0x02) == 0x5171
}

rule Windows_Executable_Base64_variant{
    condition:
	uint16(0x00) == 0x5654 and uint16(0x02) == 0x5170
}

rule Windows_Executable_Compressed{
    condition:
	uint16(0x00) == 0x7bed and uint16(0x02) == 0x740b
}

rule Windows_Executable_Compressed_Base64{
    condition:
	uint16(0x00) == 0x5837 and uint16(0x02) == 0x4c73
}

rule Windows_Executable_Hex{
    condition:
	uint16(0x00) == 0x6434 and uint16(0x02) == 0x6135
}

rule Windows_Executable_Hex_separated{
    condition:
	(uint16(0x00) == 0x6434 and uint16(0x03) == 0x6135) or
	(uint16(0x00) == 0x6434 and uint16(0x04) == 0x6135) or
	(uint16(0x00) == 0x6434 and uint16(0x05) == 0x6135)
}

rule Compressed_7Zip{
    condition:
	uint16(0x00) == 0x7a37 and uint16(0x02) == 0xafbc
}

rule Compressed_7Zip_Base64{
    condition:
	uint16(0x00) == 0x334e and uint16(0x02) == 0x3871
}

rule Compressed_Bvx2{
    condition:
	uint16(0x00) == 0x7662 and uint16(0x02) == 0x3278
}

rule Compressed_Bvx2_Base64{
    condition:
	uint16(0x00) == 0x6e59 and uint16(0x02) == 0x345a
}

rule Compressed_Bzip2{
    condition:
	uint16(0x00) == 0x5a42 and uint16(0x02) == 0x3968
}

rule Compressed_Bzip2_Base64{
    condition:
	uint16(0x00) == 0x6c51 and uint16(0x02) == 0x6f70
}

rule Chrome{
    condition:
	uint16(0x00) == 0x7243 and uint16(0x02) == 0x3432
}

rule Chrome_Base64{
    condition:
	uint16(0x00) == 0x3351 and uint16(0x02) == 0x7949
}

rule MS_Office_Document_Legacy{
    condition:
	uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
	(uint16(0x19) == 0x0320 or uint16(0x19) == 0x0300)
}

rule MS_MSI_package{
    condition:
	uint16(0x00) == 0xcfd0 and uint16(0x02) == 0xe011 and
	uint16(0x19) == 0x0420
}

rule Adobe_Flash{
    condition:
	uint16(0x00) == 0x5743 and uint16(0x02) == 0x4653
}

rule Adobe_Flash_V2{
    condition:
	uint16(0x00) == 0x5746 and uint16(0x02) == 0x4653
}

rule Adobe_Flash_Base64{
    condition:
	uint16(0x00) == 0x3151 and uint16(0x02) == 0x5464
}

rule Adobe_Flash_V2_Base64{
    condition:
	uint16(0x00) == 0x6c52 and uint16(0x02) == 0x5464
}

rule Image_GIF{
    condition:
	uint16(0x00) == 0x4947 and uint16(0x02) == 0x3846
}

rule Image_GIF_Base64{
    condition:
	uint16(0x00) == 0x3052 and uint16(0x02) == 0x476c
}

rule Compressed_GZip{
    condition:
	uint16(0x00) == 0x8b1f and uint16(0x02) == 0x0808
}

rule Compressed_GZip_Base64{
    condition:
	uint16(0x00) == 0x3448 and uint16(0x02) == 0x4973
}

rule Image_JPEG{
    condition:
	uint16(0x00) == 0xd8ff and uint16(0x02) == 0xe0ff
}

rule Image_JPEG_Base64{
    condition:
	uint16(0x00) == 0x392f and uint16(0x02) == 0x2f6a
}

rule Compressed_LZip{
    condition:
	uint16(0x00) == 0x5a4c and uint16(0x02) == 0x5049
}

rule Compressed_LZip_Base64{
    condition:
	uint16(0x00) == 0x4654 and uint16(0x02) == 0x4a70
}

rule Compressed_MS_CAB{
    condition:
	uint16(0x00) == 0x534d and uint16(0x02) == 0x4643
}

rule Compressed_MS_CAB_Base64{
    condition:
	uint16(0x00) == 0x5654 and uint16(0x02) == 0x444e
}


rule Compressed_ZIP_Office_Apk_Jar_War{
    condition:
	uint16(0x00) == 0x4b50 and uint16(0x02) == 0x0403
}

rule Compressed_ZIP_Office_Apk_Jar_War_Base64{
    condition:
	uint16(0x00) == 0x4555 and uint16(0x02) == 0x4473
}

rule MacOS_32Bit_executable{
    condition:
	uint16(0x00) == 0xface and uint16(0x02) == 0xfeed
}

rule MacOS_32Bit_executable_reverse_byte_order{
    condition:
	uint16(0x00) == 0xedfe and uint16(0x02) == 0xcefa
}

rule MacOS_64Bit_executable{
    condition:
	uint16(0x00) == 0xfacf and uint16(0x02) == 0xfeed
}

rule MacOS_64Bit_executable_reverse_byte_order{
    condition:
	uint16(0x00) == 0xedfe and uint16(0x02) == 0xcffa
}

rule MacOS_DMG{
    condition:
	uint16(0x00) == 0xda78 and uint16(0x02) == 0x6063
}

rule MacOS_PKG{
    condition:
	uint16(0x00) == 0x6178 and uint16(0x02) == 0x2172
}

rule PCAP{
    condition:
	uint16(0x00) == 0xc3d4 and uint16(0x02) == 0xa1b2
}

rule PCAPNG{
    condition:
	uint16(0x00) == 0x0d0a and uint16(0x02) == 0x0a0d
}

rule Document_PDF_Base64{
    condition:
	uint16(0x00) == 0x564a and uint16(0x02) == 0x4542
}

rule Document_PDF{
    condition:
	uint16(0x00) == 0x5025 and uint16(0x02) == 0x4644
}

rule Image_PNG_Base64{
    condition:
	uint16(0x00) == 0x5669 and uint16(0x02) == 0x4f42
}

rule Image_PNG{
    condition:
	uint16(0x00) == 0x5089 and uint16(0x02) == 0x474e
}

rule Compressed_RAR_Base64{
    condition:
	uint16(0x00) == 0x6d55 and uint16(0x02) == 0x7946
}

rule Compressed_RAR_Old_Base64{
    condition:
	uint16(0x00) == 0x6b55 and uint16(0x02) == 0x2b56
}

rule Compressed_RAR{
    condition:
	uint16(0x00) == 0x6152 and uint16(0x02) == 0x2172
}
  
rule Compressed_RAR_Old{
    condition:
	uint16(0x00) == 0x4552 and uint16(0x02) == 0x5E7E
}

rule RPM_Base64{
    condition:
	uint16(0x00) == 0x6137 and uint16(0x02) == 0x7576
}

rule RPM{
    condition:
	uint16(0x00) == 0xabed and uint16(0x02) == 0xdbee
}

rule Document_RTF{
    condition:
	uint16(0x00) == 0x5c7b and uint16(0x02) == 0x7472
}

rule Disk_VMDK{
    condition:
	uint16(0x00) == 0x444b and uint16(0x02) == 0x464d
}

rule Disk_VMDK_Base64{
    condition:
	uint16(0x00) == 0x3053 and uint16(0x02) == 0x4e52
}

rule Compressed_XAR_base64{
    condition:
	uint16(0x00) == 0x4765 and uint16(0x02) == 0x7946
}

rule Compressed_XAR{
    condition:
	uint16(0x00) == 0x6178 and uint16(0x02) == 0x2172
}

rule Compressed_XZ_base64{
    condition:
	uint16(0x00) == 0x542f and uint16(0x02) == 0x3664
}

rule Compressed_XZ{
    condition:
	uint16(0x00) == 0x37fd and uint16(0x02) == 0x587a
}

rule Batch_Script{
    strings:
	$string1 = "@echo off"
	$string2 = "echo "
	$string3 = "type "
	$string4 = "start "
    condition:
	any of ($string*)
}

rule Bash_Script{
    strings:
	$string = "#!/bin/bash"
    condition:
	$string
}

rule PEM_Certificate{
    strings:
	$string1 = "-----BEGIN CERTIFICATE-----"
	$string2 = "-----END CERTIFICATE-----"
    condition:
	all of ($string*)
}
