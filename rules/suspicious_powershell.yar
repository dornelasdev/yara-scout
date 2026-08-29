rule Suspicious_PowerShell_Patterns : demo powershell
{
    meta:
        description = "Detects PowerShell combined with suspicious execution patterns"
        author = "YARA Scout"
        severity = "medium"
        purpose = "demonstration"

    strings:
        $powershell = "powershell" nocase ascii wide
        $hidden = "-WindowStyle Hidden" nocase ascii wide
        $download = "DownloadString" nocase ascii wide
        $encoded = "-EncodedCommand" nocase ascii wide

    condition:
        $powershell and 1 of ($hidden, $download, $encoded)
}
