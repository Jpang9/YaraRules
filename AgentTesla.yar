import "pe"


rule Agent_Tesla_Sample	{

	meta:
		last_updated = "2022-11-04"
		author = "Potatech"
		description = "Agent_Tesla Detection"
		md5hash = "2b294b3499d1cce794badffc959b7618 "

	strings:
		$ = "mscorlib"
		$ = "Po160118"
		$ = "xws.exe"
		$ = "4System.Web.Services.Protocols.SoapHttpClientProtocol"
		$ = "XorObject"

	condition:
		uint16(0) == 0x5A4D and 4 of them
}

rule Agent_tesla_Dropped_Binary	{

	meta:
		last_updated = "2022-11-04"
		author = "Potatech"
		description = "Dumped Binary of Agent Tesla"
		md5hash = "aa5e9af3f263b96805f14058605f21e9"

	strings:
		$ = /(\W[a-zA-Z0-9]{3}.exe\W)/
		$ = "mscoree.dll"
		$ = "ConsoleApp1"
		$ = "m_ThreadStaticValue"
		$ = "OriginalFilename"
		$ = "Users\\Admin\\Desktop"

	condition:
		uint16(0) == 0x5A4D and 4 of them
}
