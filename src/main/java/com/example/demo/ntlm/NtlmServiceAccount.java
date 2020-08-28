package com.example.demo.ntlm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NtlmServiceAccount {

	private static Logger log = LoggerFactory.getLogger(NtlmServiceAccount.class);
	
	public NtlmServiceAccount(String domain, String computerName, String password) {
        setDomain(domain);
		setComputerName(computerName);
		setPassword(password);
	}

	public String getAccountName() {
		return _accountName;
	}

	public String getComputerName() {
		return _computerName;
	}

	public String getPassword() {
		return _password;
	}

	public void setComputerName(String computerName) {
        _computerName = computerName;
        _accountName = _computerName != null ? _computerName + "$" : _computerName;

        log.info("--> domain: " + _domain);
		log.info("--> accountName: " + _accountName);
		log.info("--> computerName: " + _computerName);
	}

	public void setPassword(String password) {
		_password = password;
	}

    public String getDomain() {
        return _domain;
    }

    public void setDomain(String domain) {
        this._domain = domain;
    }

    public String getAccount() {
        return getAccountName() + '@' + getDomain();
    }

    private String _domain;
	private String _accountName;
	private String _computerName;
	private String _password;

}