rule Hard_Ransomware_Family_Signature
{
    meta:
        description = "Hard level: Detects ransomware-like binary patterns"
        author = "CyberShield"
        level = "hard"

    strings:
        // File extension ransom notes
        $note1 = "README_TO_DECRYPT.txt"
        $note2 = "HOW_TO_RECOVER_FILES.html"
        $note3 = "YOUR_FILES_ARE_ENCRYPTED"

        // Ransomware API usage (simulated patterns)
        $api1 = "CryptEncrypt"
        $api2 = "CryptAcquireContext"
        $api3 = "VirtualAlloc"
        $api4 = "WriteFile"

        // XOR-based encryptor sequence (typical in malware)
        $xor_pattern = { 31 C0 31 DB 31 C9 31 D2 } 

    condition:
        any of ($note*, $api*, $xor_pattern)
}
