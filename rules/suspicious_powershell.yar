rule Suspicious_PowerShell_Patterns : windows powershell execution
{
    meta:
        id = "YS-0001"
        description = "Detects PowerShell combined with suspicious execution patterns"
        author = "dornelasdev"
        created = "2026-08-29"
        modified = "2026-09-24"
        license = "MIT"
        category = "behavior"
        severity = "medium"
        confidence = "medium"
        scope = "file"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        false_positives = "Administrative scripts using hidden, downloaded, or encoded PowerShell commands"

    strings:
        $powershell = "powershell" nocase ascii wide
        $hidden_window = "-WindowStyle Hidden" nocase ascii wide
        $download_string = "DownloadString" nocase ascii wide
        $encoded_command = "-EncodedCommand" nocase ascii wide

    condition:
        filesize < 5MB and
        $powershell and
        1 of ($hidden_window, $download_string, $encoded_command)
}
