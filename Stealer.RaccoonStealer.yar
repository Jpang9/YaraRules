rule RaccoonStealerOct2022{

	meta:
		date = "28/10/2022"
		author = "Potatech"
		description = "Raccon Stealer Detection"
		yarahub_reference_md5 = "80b0745106a9a4ed3c18264ba1887bff"
		yarahub_license = "CC0 1.0"
      	yarahub_rule_matching_tlp = "TLP:WHITE"
      	yarahub_rule_sharing_tlp = "TLP:GREEN"
      	yarahub_UUID = "703ba12d-2b17-4abf-ad1f-ff90a2733411"

	strings:
		$ = "edinayarossiya"
		$ = "Bcrypt.dll"
		$ = "bkoJoy0="
		$ = "fVQMox8c"
		$ = "wallet.dat"
		$ = "ffcookies.txt"

	condition:
		uint16(0) == 0x5A4D and 4 of them
}
