package com.example.demo.ntlm;


public class NtlmServiceAccount {

	private final String accountName;
	private final String computerName;
	private final String password;
	
	public NtlmServiceAccount(String computerName, String password) {
		if (computerName != null) {
			this.computerName = computerName;
			this.accountName = computerName + "$";
		} else {
			this.computerName = null;
			this.accountName = null;
		}
		this.password = password;
	}

	public String getAccountName() {
		return accountName;
	}

	public String getComputerName() {
		return computerName;
	}

	public String getPassword() {
		return password;
	}

}