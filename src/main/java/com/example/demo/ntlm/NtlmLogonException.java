package com.example.demo.ntlm;


public class NtlmLogonException extends RuntimeException {

	public NtlmLogonException() {
		super();
	}

	public NtlmLogonException(String msg) {
		super(msg);
	}

	public NtlmLogonException(String msg, Throwable cause) {
		super(msg, cause);
	}

	public NtlmLogonException(Throwable cause) {
		super(cause);
	}

}