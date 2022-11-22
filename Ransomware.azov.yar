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

rule azov_Dropped{

	meta:
		date = "2022-11-21"
		author = "Potatech"
		description = "Azov Detection"
		yarahub_reference_md5 = "914bcab4e777c2b32b7563edf0b6a7aa"
		yarahub_uuid = "b00cdd3b-1adb-454e-9626-19d75f9d6b93"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:AMBER"
		yarahub_rule_sharing_tlp = "TLP:AMBER"


    strings:
    	$s1 = "RunOnceEntries" wide ascii
    	$s2 = "REBOOTPROMPT=" wide ascii
    	$s3 = "REBOOT=" wide ascii
    	$s4 = "ServerMain" wide ascii
    	$s5 = "msiexec.pdb" ascii
    	$s6 = "(CA)" wide ascii

    condition:
    	uint16(0) == 0x5A4D and 5 of them
}