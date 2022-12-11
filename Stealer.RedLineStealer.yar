rule RedLineStealerNov2022{
	
	meta:
		last_updated = "13/11/2022"
		author = "Potatotech"
		Description = "RedLine_Stealer Generic Detection"
		Hash1 = "29956baef7de02eb8eaeb36c6b82eb778e1ff8d19bdd5ce1a08228563dac025e"
		Hash2 = "4b2eabeff9e3537b167db6f06678f657b99430c590563d2a6c30160f05859d45"
		Hash3 = "94b7f4efeb2e325b65c2ada70c884cb6d1537960131f67aa8cfee9126eb69c9f"
		Hash4 = "8b9c6b974b3aa5d4eeaa4cfa62ac27213b7276c2c20d7a22683e27cd2364c14b"
		Hash5 = "c251403b9a2931b733ab581cde3c347e6eaf39e44e195c23c0314bb9f0692ac4"
		Hash6 = "f81541db6e4764fde4afb114a625d8f73f3c920c727dfba1f3562d607bb3b500"

	strings:
		$s1 = ".pdb"
		$s2 = "pogusamumugelohimojimoj"
		$s3 = "wallet"
		$s4 = "discord"
		$s5 = "net.tcp://"

	condition:
		uint16(0) == 0x5a4d and 2 of them
 }