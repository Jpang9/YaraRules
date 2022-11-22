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