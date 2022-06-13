// Last updated: 2022-06-08 15:36
//
// Detects:
// 	118 families of PHP webshells + Obfuscator + Compressed + Encoded
// 	 52 families of ASP webshells
// 	 15 families of JSP webshells (Latest: confluence JSP webshell)
//	  5 families of CFM webshells + Encoded pages

rule PHP_Webshell{
        meta:
                description = "Generic PHP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "70e3f4cd-32f1-4e29-bd25-b4dd784214ef"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
                $generic1 = "?php" nocase ascii wide

                $phpwebshell1 = "shell_exec" nocase ascii wide
                $phpwebshell2 = "exec" nocase ascii wide
                $phpwebshell3 = "system" nocase ascii wide
                $phpwebshell4 = "passthru" nocase ascii wide
                $phpwebshell5 = "popen" nocase ascii wide
                $phpwebshell6 = "proc_open" nocase ascii wide
                $phpwebshell7 = "@opendir" nocase ascii wide
                $phpwebshell8 = "eval" nocase ascii wide
                $phpwebshell9 = "curl_exec" nocase ascii wide

                $form1 = "<form" nocase ascii wide
                $form2 = "<input" nocase ascii wide
                $form3 = "escapeshellarg" nocase ascii wide
                $form4 = "/usr/bin/" nocase ascii wide
                $form5 = "POST" nocase ascii wide
                $form6 = "fgets(STDIN" nocase ascii wide
                $form7 = "base64_decode" nocase ascii wide
		$form8 = "urldecode" nocase ascii wide

        condition:
		not (uint16(0x00) == 0x5a4d) and
                $generic1 and any of ($phpwebshell*) and any of ($form*)
}

rule PHP_Obfuscator{
        meta:
                description = "PHP Obfuscator, used sometimes by PHP webshells"
                author = "@Pro_Integritate"
                maltype = "Webshell/Encoder"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "4e5ff008-0870-42e1-96c3-80354f152bde"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
		$php1 = "<?php" nocase ascii wide
		$php2 = "Obfuscator" nocase ascii wide
		$php3 = "www.fopo.com.ar" nocase ascii wide
		$php4 = "goto" nocase ascii wide
		$php5 = "system" nocase ascii wide
		$php6 = "echo" nocase ascii wide
		$php7 = "\"\\"
        condition:
		not (uint16(0x00) == 0x5a4d) and
		3 of ($php*)
}
rule PHP_Compressed_Encoded_Payload{
        meta:
                description = "Compressed or Encoded PHP payload"
                author = "@Pro_Integritate"
                maltype = "Webshell/Encoder"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "6876854b-c11f-46d0-b446-718787791eb0"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
        strings:
		$php = "<?php"
		$decomp1 = "UncompressFile"
		$decomp2 = "gzuncompress"
		$decomp3 = "gzopen"
		$decomp4 = "gzdecode"
		$decomp5 = "eval(" // These two nullify the decompression, for encoded payloads only
		$decomp6 = "eval ("

		$decode = "base64" // "base64_decode"
		$eval = "eval"
        condition:
		not (uint16(0x00) == 0x5a4d) and
		$php and any of ($decomp*) and $decode and $eval
}

rule PHP_Emotet_Webshell{
        meta:
                description = "Emotet SAP Webshell as payload in Wordpress"
                author = "@Pro_Integritate"
                maltype = "Webshell/Botnet"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "2b48bf59-de67-46cc-abde-4cae246f5a98"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
		$php = "<?php"
		$content1 = "$wp_kses_data"
		$content2 = "'O7ZDrQwa6UbFoqf"
        condition:
		not (uint16(0x00) == 0x5a4d) and
		$php and all of ($content*)
}

rule ASP_Webshell{

	meta:
                description = "Generic ASP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "ecb1d2c2-8587-41b2-bc91-3cab0dd5feae"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

	strings:
		$php = "<?php" nocase ascii wide

		$asp1 = "<%@ import" nocase ascii wide
		$asp2 = "<asp:" nocase ascii wide
		$asp3 = "CmdAsp.asp" nocase ascii wide // specific signature
		$asp4 = "WScript.Shell" nocase ascii wide
		$asp5 = "Scripting.FileSystemObject" nocase ascii wide

		$exec1 = "shell" nocase ascii wide
		$exec2 = "execute" nocase ascii wide
		$exec3 = "command" nocase ascii wide
		$exec4 = "cmd" nocase ascii wide
		$exec5 = ".Exec" nocase ascii wide

		$generic1 = "process" nocase ascii wide
		$generic2 = "redirectStandard" nocase ascii wide
		$generic3 = "<FORM" nocase ascii wide
		$generic4 = "POST" nocase ascii wide
		$generic5 = "<input" nocase ascii wide
		$generic6 = "StdOut" nocase ascii wide
		$generic7 = ".stdout.read" nocase ascii wide
		//TODO: $generic7 = "Request.QueryString" nocase ascii wide

        condition:
		not (uint16(0x00) == 0x5a4d) and
		not $php and
                any of ($asp*) and
		any of ($exec*) and
		( ($generic1 or $generic2) or
		  ($generic3 and ($generic4 or $generic5)) or $generic6 or $generic7) 

}

rule JSP_Webshell{
        meta:
                description = "Generic JSP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "62f173f9-6e29-430b-980a-aafddcab0afc"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
		$php = "<?php" nocase ascii wide

                $java1 = "jsp" nocase ascii wide
                $java2 = "java" nocase ascii wide
		$java3 = "<%@page" nocase ascii wide

		$io1 = "<FORM" nocase ascii wide
		$io2 = "<INPUT" nocase ascii wide
		$io3 = "Encoding" nocase ascii wide
		$io4 = "POST" nocase ascii wide

		$exec1 = "Process" nocase ascii wide
		$exec2 = "command" nocase ascii wide
		$exec3 = "Exec" nocase ascii wide
		$exec4 = "ClassLoader" nocase ascii wide

		$console1 = "Stream" nocase ascii wide
		$console2 = "BASE64Decoder" nocase ascii wide

        condition:
		not (uint16(0x00) == 0x5a4d) and
		not $php and
		( any of ($java*) ) and
		( ($io1 and $io2) or ($io3) or ($io4) ) and
		any of ($exec*) and
		any of ($console*)
}


rule CFM_Encoded_file{
        meta:
                description = "Cold Fusion Encoded signature"
                author = "@Pro_Integritate"
                maltype = "Encoded Colf Fusion page"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "a422a898-7d6d-4ea2-9518-a0234f08e250"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
                $php = "?php" nocase ascii wide

		$sign = "Allaire Cold Fusion Template"

        condition:
		not (uint16(0x00) == 0x5a4d) and
		not $php and
		$sign
}

rule CFM_Webshell{
        meta:
                description = "Generic CFM Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"
		date = "2022-06-08"
		yarahub_reference_md5 = "ea4bfb665e54953275f8120844b2a819" // Viper webshell as sample
		yarahub_uuid = "14561b6b-8677-4363-b84e-248b58db3df6"
		yarahub_license = "CC BY 4.0"
		yarahub_reference_link = "https://github.com/ProIntegritate/Yara-rules/blob/master/Webshell.yara"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

        strings:
                $php = "?php" nocase ascii wide

		$header1 = "<html" nocase ascii wide
		$header2 = "<cfparam" nocase ascii wide

		$input1 = "<form" nocase ascii wide
		$input2 = "post" nocase ascii wide

		$cfcommand1 = "<cffile"
		$cfcommand2 = "<cfexecute"
		$cfcommand3 = "<cfdirectory"
		$cfcommand4 = "<cfscript"

		$cfcommand5 = "coldfusion.server.ServiceFactory"
		$cfcommand6 = "getDatasourceService"
		$cfcommand7 = ".getDatasources"

		$output = "<cfoutput"
        condition:
		not (uint16(0x00) == 0x5a4d) and
		not $php and
		($header1 or $header2) and
		all of ($input*) and
		($cfcommand1 or $cfcommand2 or $cfcommand3 or $cfcommand4 or
		($cfcommand5 and $cfcommand6 and $cfcommand7)) and
		$output
}
