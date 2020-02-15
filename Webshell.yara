// Last updated: 14:23 2020-02-15

rule PHP_Webshell{
        meta:
                description = "Generic PHP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

        strings:
                $generic1 = "?php" nocase

                $phpwebshell1 = "shell_exec" nocase ascii wide
                $phpwebshell2 = "exec" nocase ascii wide
                $phpwebshell3 = "system" nocase ascii wide
                $phpwebshell4 = "passthru" nocase ascii wide
                $phpwebshell5 = "popen" nocase ascii wide
                $phpwebshell6 = "proc_open" nocase ascii wide

		$form1 = "<form" nocase ascii wide
		$form2 = "<input" nocase ascii wide

        condition:
                $generic1 and 2 of ($phpwebshell*) and all of ($form*)
}

rule ASP_Webshell{

	meta:
                description = "Generic ASP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

	strings:
		$asp1 = "<%@ import" nocase ascii wide
		$asp2 = "<asp:" nocase ascii wide
		$asp3 = "CmdAsp.asp" nocase ascii wide // specific signature
		// $asp4 = "import"
		// $asp5 = "runat="

		$exec1 = "shell" nocase ascii wide
		$exec2 = "execute" nocase ascii wide
		$exec3 = "command" nocase ascii wide
		$exec4 = "cmd"  nocase ascii wide

		$generic1 = "process" nocase ascii wide
		$generic2 = "redirectStandard" nocase ascii wide
		$generic3 = "<FORM" nocase ascii wide
		$generic4 = "POST" nocase ascii wide

		//$io1 = "file" nocase
		//$io2 = "directory" nocase
		//$io3 = "folder" nocase
		//$io4 = "bucket" nocase

        condition:
                any of ($asp*) and
		any of ($exec*) and
		( ($generic1 or $generic2) or
		  ($generic3 and $generic4) ) //and
		//any of ($io*)

}


rule JSP_Webshell{
        meta:
                description = "Generic JSP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

        strings:
                $java1 = "jsp" nocase ascii wide
                $java2 = "java" nocase ascii wide

		$exclude1 = "javascript" nocase ascii wide

		$htmlform1 = "<FORM" nocase ascii wide
		$htmlform2 = "<INPUT" nocase ascii wide

		$exec1 = "Process" nocase ascii wide
		$exec2 = "command" nocase ascii wide
		$exec3 = "Exec" nocase ascii wide

		$console1 = "Stream" nocase ascii wide

        condition:
		( any of ($java*) and not $exclude1 ) and
		all of ($htmlform*) and
		any of ($exec*) and $console1
}
