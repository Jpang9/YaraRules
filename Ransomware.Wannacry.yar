rule Wannacry_sample	{

	meta:
		Date = "2022-10-24"
		author = "Potatech"
		description = "WannaCry Detection"
		md5hash = "db349b97c37d22f5ea1d1841e3c89eb4 "

	strings:
		$ = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea"
		$ = "WINDOWS"
		$ = "tasksche.exe"

	condition:
		uint16(0) == 0x5A4D and all of them
			 
}
