rule Medium_Obfuscated_Script
{
    meta:
        description = "Medium level: Detects encoded or obfuscated commands"
        author = "CyberShield"
        level = "medium"

    strings:
        // Base64 PowerShell abuse
        $ps1 = "powershell.exe -enc" nocase
        $ps2 = "FromBase64String" nocase

        // VBS malicious commands
        $vb1 = "CreateObject(\"WScript.Shell\")" nocase
        $vb2 = "Execute(\""

        // Suspicious hex patterns (common shellcode)
        $hex1 = { 90 90 90 90 }     // NOP sled
        $hex2 = { E8 ?? ?? ?? ?? } // CALL instruction
        
    condition:
        any of them
}
