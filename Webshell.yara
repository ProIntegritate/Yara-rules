// Last updated: 14:47 2020-01-17

rule PHP_Webshell{
        meta:
                description = "Generic PHP Webshell signature"
                author = "@Pro_Integritate"
                maltype = "Webshell"

        strings:
                $generic1 = "?php" nocase
                $generic2 = "eval" nocase
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

		$io1 = "file" nocase
		$io2 = "directory" nocase
		$io3 = "folder" nocase
		$io4 = "bucket" nocase

        condition:
                all of ($asp*) and any of ($exec*) and any of ($generic*) and any of ($io*)

}
