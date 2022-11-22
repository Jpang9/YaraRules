

rule RedLiner_Decryption	{

	meta:
		last_updated = "2022-11-13"
		author = "Potatotech"
		Description = "RedLiner Decryption Thread"
		sha256sum = "a486e074ab9751f2873e017237fe22ed98dad4214e5d76feec8424fa5166eae5"

	strings:
		$decryptionthread = {B8 ?? ?? ?? ?? 8B CE F7 E6 8B C6 2B C2 D1 E8 03 C2 C1 E8 ?? 6B C0 ?? 2B C8 C1 E9 ?? 8A 81 ?? ?? ?? ?? 8A C8 C0 E1 ?? 2A C8 02 C9 30 8E ?? ?? ?? ?? 46 81 FE ?? ?? ?? ?? 72 C4} 

	condition:
		uint16(0) == 0x5A4D any of them
}


