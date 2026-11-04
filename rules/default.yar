rule isitsafe_powershell_download
{
    meta:
        severity = "high"
        description = "PowerShell download or in-memory execution behavior"
    strings:
        $download1 = "Invoke-WebRequest" nocase ascii wide
        $download2 = "DownloadString" nocase ascii wide
        $execute1 = "Invoke-Expression" nocase ascii wide
        $execute2 = "FromBase64String" nocase ascii wide
    condition:
        any of them
}

rule isitsafe_remote_access_indicator
{
    meta:
        severity = "high"
        description = "Potential remote shell or tunnelling behavior"
    strings:
        $a = "reverse shell" nocase ascii wide
        $b = "TcpClient" nocase ascii wide
        $c = "New-Object Net.Sockets.TCPClient" nocase ascii wide
        $d = "RemoteAccess" nocase ascii wide
    condition:
        any of them
}

rule isitsafe_bundler_persistence
{
    meta:
        severity = "medium"
        description = "Silent startup or persistence behavior commonly used by bundles"
    strings:
        $a = "CurrentVersion\\Run" nocase ascii wide
        $b = "schtasks" nocase ascii wide
        $c = "New-Service" nocase ascii wide
    condition:
        any of them
}
