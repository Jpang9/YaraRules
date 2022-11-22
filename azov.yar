rule azov_DropperType{

	meta:
		date = "21/Nov/2022"
		author = "Potatech"
		description = "Azov Detection"
		sha256 = "7ac05b69d57813d3c18362bf3565aaf4705953802dc7c79e4c7bc7fb3b9a1095"

    strings:
    	$s1 = "RUXIMIH" fullword wide
    	$s2 = "[OneSettings]" ascii fullword
    	$s3 = "Washington1" ascii fullword
    	$s4 = "Redmond1" ascii fullword
    	$s5 = "ruxim" ascii
    	$s6 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide


    condition:
    	uint16(0) == 0x5A4D and 4 of them

}