rule MaliciousUsernames{

	meta:
		date = ""
		author = "Potatech"
		description = "list of username from malware"

    strings:
        $u = "buhimojipoye31" ascii
        $u2 = "Vitali Kremez" wide ascii

    condition:
    	uint16(0) == 0x5A4D and any of ($u*)
}
