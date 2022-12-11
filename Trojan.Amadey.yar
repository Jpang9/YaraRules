rule AmadeyNov2022{

	meta:
		date = "11/12/2022"
		author = "Potatech"
		description = "Amadey Detection"
		Hash1 = "e91bb1f7c2b2ffd094d3915f1fffbfe929efd49e1d732b51d60e8a378a8a066b"
		Hash2 = "f6a9c1724adebd1e1bc54cb2b2e6cc49b8a6f11910a3b6acdfc6c5531a1d742b"
		Hash3 = "2092f476fcb07e4c663a4c72d4ff6aa992c32d33e65552c267d18780d681e321"
		Hash4 = "2f356283c209400c6385a24450f266b59477e035e9389c8d1af4843cd1ad2374"

    strings:
    	$s1 = "RycGBA2.exe" wide ascii
    	$s2 = "Visovexejeluze" ascii fullword
    	$s3 = "ellocnak.xml" wide ascii
    	$s4 = /R60[0-9]{2}/ wide ascii
    	$s5 = "FamItrfc.Exe" wide ascii
		$Translate1 = "bDizuka yabevuxogew" wide ascii 
    	$Translate2 = "conferencia" wide ascii
    	$Translate3 = "mucizugihokevim" wide ascii
    	$Translate4 = "xapogalejiyixu" wide ascii


    condition:
    	uint16(0) == 0x5A4D and any of ($s*) or
    	uint16(0) == 0x5A4D and any of ($Translate*) 
}
