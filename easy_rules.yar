rule Easy_Suspicious_Keywords
{
    meta:
        description = "Easy level: Detects common suspicious keywords"
        author = "CyberShield"
        level = "easy"

    strings:
        $a = "malware"
        $b = "virus"
        $c = "trojan"
        $d = "hacktool"
        $e = "keylogger"
        $f = "backdoor"
        $g = "payload"
        $h = "MALWARE_TEST"
        $i = "EASY_TRIGGER"

    condition:
        any of ($a, $b, $c, $d, $e, $f, $g, $h, $i)
}
