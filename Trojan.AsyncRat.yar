rule AsyncRatDec2022{

	meta:
		date = "03/12/2022"
		author = "Potatech"
		description = "AsyncRat"
		sha256 = "53542563788e98bdc1a23102c0cdf82a08e0cfc955f23f38be064811efc2a1a0"

    strings:
    	$s1 = "BSJB" wide ascii
    	$s2 = "V4.0.30319" wide ascii
    	$s3 = "#Strings" wide ascii
    	$s4 = "#GUID" wide ascii
    	$s5 = "#Blob" wide ascii
    	$u1 = "get_IsConnected" wide ascii
    	$u2 = "set_IsConnected" wide ascii
    	$u3 = "IDisposable" wide ascii
    	$u4 = "ComplilationRelaxationsAttribute" wide ascii
    	$name = "InternalName" fullword ascii
    	$name2 = "OriginalFileName" fullword ascii
    	$name3 = "FileDescription" fullword ascii
    	$n1 = "Stub.exe" fullword ascii
    	$n2 = "Macafi.exe" fullword ascii
    	$n3 = "Client.exe" fullword ascii
    	$n4 = "moscow2.exe" fullword ascii
    	$version1 = "1.0.0.0" fullword ascii
    	$version2 = "3.0.3.0" fullword ascii


    condition:
    	uint16(0) == 0x5A4D and 2 of ($s*) and any of ($u*) and filesize < 150KB or
    	uint16(0) == 0x5A4D and any of ($n*) and any of ($version*) and 2 of ($name*)
}