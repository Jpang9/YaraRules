rule SignsOfPersistance{

	meta:
		date = ""
		author = "Potatech"
		description = "Persistance"

    strings:
    	$p1 = "CurrentVersion\\Run" wide ascii


    condition:
    	uint16(0) == 0x5A4D and any of ($p*)
}
