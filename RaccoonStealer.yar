
rule Raccon_Stealer_sample	{

	meta:
		last_updated = "2022-10-28"
		author = "Potatech"
		description = "Raccon Stealer Detection"
		md5hash = "80b0745106a9a4ed3c18264ba1887bff"

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
