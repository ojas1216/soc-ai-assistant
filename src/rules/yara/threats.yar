/*
    SOC AI Assistant Pro — YARA Threat Rules
    15 production-grade rules covering common malware families and TTPs.
*/

rule Mimikatz_Indicators {
    meta:
        description = "Detects Mimikatz credential dumping tool references"
        severity    = "CRITICAL"
        mitre       = "T1003.001"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::dcsync" nocase
        $s4 = "wce.exe" nocase
        $s5 = "fgdump" nocase
        $s6 = "sekurlsa" nocase
    condition:
        any of them
}

rule PowerShell_Obfuscated {
    meta:
        description = "Detects obfuscated PowerShell commands"
        severity    = "HIGH"
        mitre       = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $enc4 = "IEX(" nocase
        $enc5 = "Invoke-Expression" nocase
        $amsi1 = "amsi" nocase
        $amsi2 = "bypass" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "WebClient" nocase
    condition:
        (any of ($enc*)) or (all of ($amsi*)) or (2 of ($dl*))
}

rule Reverse_Shell_Indicators {
    meta:
        description = "Detects reverse shell payloads and C2 callbacks"
        severity    = "CRITICAL"
        mitre       = "T1059.004"
    strings:
        $rs1 = "bash -i >& /dev/tcp/" nocase
        $rs2 = "bash -c 'bash -i" nocase
        $rs3 = "nc -e /bin/bash" nocase
        $rs4 = "nc -e /bin/sh" nocase
        $rs5 = "reverse_tcp" nocase
        $rs6 = "reverse_https" nocase
        $rs7 = "meterpreter" nocase
        $rs8 = "0>&1" nocase
        $rs9 = "python -c 'import socket" nocase
    condition:
        any of them
}

rule Ransomware_Behaviour {
    meta:
        description = "Detects ransomware-related commands and strings"
        severity    = "CRITICAL"
        mitre       = "T1486"
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "wmic shadowcopy delete" nocase
        $vss3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $vss4 = "wbadmin delete catalog" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".enc"
        $msg1 = "your files have been encrypted" nocase
        $msg2 = "pay the ransom" nocase
        $msg3 = "decrypt your files" nocase
    condition:
        (any of ($vss*)) or (2 of ($msg*))
}

rule Credential_Dumping {
    meta:
        description = "Detects credential dumping techniques"
        severity    = "CRITICAL"
        mitre       = "T1003"
    strings:
        $s1 = "procdump" nocase
        $s2 = "comsvcs.dll" nocase
        $s3 = "MiniDump" nocase
        $s4 = "lsass.dmp" nocase
        $s5 = "/proc/1/mem" nocase
        $s6 = "hashdump" nocase
        $s7 = "secretsdump" nocase
        $s8 = "crackmapexec" nocase
        $s9 = "ntds.dit" nocase
    condition:
        any of them
}

rule LOLBins_Abuse {
    meta:
        description = "Detects Living-Off-The-Land Binary abuse"
        severity    = "HIGH"
        mitre       = "T1218"
    strings:
        $lol1 = "certutil -decode" nocase
        $lol2 = "certutil -urlcache" nocase
        $lol3 = "bitsadmin /transfer" nocase
        $lol4 = "mshta http" nocase
        $lol5 = "regsvr32 /s /u /i:http" nocase
        $lol6 = "rundll32 javascript:" nocase
        $lol7 = "wscript //e:jscript" nocase
        $lol8 = "cmstp /s /ns" nocase
        $lol9 = "installutil /logfile=" nocase
    condition:
        any of them
}

rule C2_Cobalt_Strike {
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity    = "CRITICAL"
        mitre       = "T1071.001"
    strings:
        $cs1 = "beacon." nocase
        $cs2 = "cobalt strike" nocase
        $cs3 = "checksum8" nocase
        $cs4 = "sleep(" nocase
        $cs5 = "cobaltstrike" nocase
        $cs6 = "BEACON_" nocase
        $pipe = "\\\\.\\pipe\\msagent_" nocase
    condition:
        2 of them
}

rule DNS_Tunneling {
    meta:
        description = "Detects DNS tunneling tools and patterns"
        severity    = "HIGH"
        mitre       = "T1071.004"
    strings:
        $t1 = "iodine" nocase
        $t2 = "dnscat" nocase
        $t3 = "dns2tcp" nocase
        $t4 = "dnscapy" nocase
        $pattern = /[a-z0-9]{40,}\.[a-z]{2,6}/
    condition:
        any of ($t*) or $pattern
}

rule Lateral_Movement {
    meta:
        description = "Detects lateral movement techniques"
        severity    = "HIGH"
        mitre       = "T1021"
    strings:
        $s1 = "pass-the-hash" nocase
        $s2 = "pass-the-ticket" nocase
        $s3 = "wmiexec" nocase
        $s4 = "psexec" nocase
        $s5 = "smbexec" nocase
        $s6 = "impacket" nocase
        $s7 = "dcom" nocase
        $s8 = "winrm" nocase
        $s9 = "evil-winrm" nocase
    condition:
        any of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Detects common persistence techniques"
        severity    = "MEDIUM"
        mitre       = "T1547"
    strings:
        $reg1 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $schtask = "schtasks /create" nocase
        $service = "sc create" nocase
        $startup = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $cron = "crontab -e" nocase
        $rc = "/etc/rc.local" nocase
        $systemd = "systemctl enable" nocase
    condition:
        any of them
}

rule Data_Exfiltration {
    meta:
        description = "Detects data exfiltration patterns"
        severity    = "HIGH"
        mitre       = "T1048"
    strings:
        $s1 = "exfiltrat" nocase
        $s2 = "POST /exfil" nocase
        $s3 = "curl -X POST" nocase
        $s4 = "wget --post-data" nocase
        $s5 = "tar -czf" nocase
        $ftp1 = "ftp.put" nocase
        $ftp2 = "ncftpput" nocase
        $s3_upload = "aws s3 cp" nocase
    condition:
        2 of them
}

rule Web_Shell {
    meta:
        description = "Detects web shell indicators"
        severity    = "CRITICAL"
        mitre       = "T1505.003"
    strings:
        $php1 = "eval(base64_decode(" nocase
        $php2 = "system($_GET" nocase
        $php3 = "passthru($_POST" nocase
        $php4 = "shell_exec($_REQUEST" nocase
        $asp1 = "Response.Write(CreateObject" nocase
        $jsp1 = "Runtime.getRuntime().exec(" nocase
        $cmd1 = "cmd.exe /c" nocase
    condition:
        any of them
}

rule SQL_Injection {
    meta:
        description = "Detects SQL injection attempts"
        severity    = "HIGH"
        mitre       = "T1190"
    strings:
        $s1 = "' OR '1'='1" nocase
        $s2 = "UNION SELECT" nocase
        $s3 = "DROP TABLE" nocase
        $s4 = "1=1--" nocase
        $s5 = "' OR 1=1" nocase
        $s6 = "xp_cmdshell" nocase
        $s7 = "information_schema" nocase
        $s8 = "LOAD_FILE(" nocase
    condition:
        any of them
}

rule Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        severity    = "HIGH"
        mitre       = "T1068"
    strings:
        $s1 = "sudo su" nocase
        $s2 = "chmod +s" nocase
        $s3 = "setuid" nocase
        $s4 = "token impersonation" nocase
        $s5 = "getsystem" nocase
        $s6 = "bypassuac" nocase
        $s7 = "eventvwr.exe" nocase
        $s8 = "fodhelper" nocase
    condition:
        any of them
}

rule Network_Reconnaissance {
    meta:
        description = "Detects network reconnaissance tools"
        severity    = "LOW"
        mitre       = "T1046"
    strings:
        $s1 = "nmap" nocase
        $s2 = "masscan" nocase
        $s3 = "zmap" nocase
        $s4 = "unicornscan" nocase
        $s5 = "-sV" nocase
        $s6 = "-sS" nocase
        $s7 = "netdiscover" nocase
        $s8 = "shodan" nocase
    condition:
        any of them
}
