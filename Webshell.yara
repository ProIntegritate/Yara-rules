// Last updated: 14:44 2020-01-17

rule PHP_Webshell{
        meta:
                description = "Generic PHP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

        strings:
                $generic1 = "?php"
                $generic2 = "eval"
                $phpwebshell1 = "shell_exec" nocase

                $phpwebshell2 = "exec" nocase
                $phpwebshell3 = "system" nocase
                $phpwebshell4 = "passthru" nocase

        condition:
                ($generic1 and $generic2) and 2 of ($phpwebshell*)
}

rule ASP_Webshell{

	meta:
                description = "Generic ASP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

	strings:
		$asp1 = "<%@ import" nocase
		$asp2 = "<asp:" nocase
		$asp3 = "runat=" nocase

		$exec1 = "shell" nocase
		$exec2 = "execute" nocase
		$exec3 = "command" nocase

		$generic1 = "process" nocase
		$generic2 = "redirectStandard" nocase

		$io1 = "file"
		$io2 = "directory"
		$io3 = "folder"
		$io4 = "bucket"

        condition:
                all of ($asp*) and any of ($exec*) and any of ($generic*) and any of ($io*)

}
