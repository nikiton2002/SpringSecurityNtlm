package com.example.demo.web.resource.auth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class NtlmAuthToken extends UsernamePasswordAuthenticationToken {

    // Для прошедших аутентификацию
    public NtlmAuthToken(Object principal, Object credentials) {
        super(principal, credentials, null);
    }

    public NtlmAuthToken(Object principal, Object credentials, String domain, String workstation, byte[] ntResponse, byte[] lmResponse) {
        super(principal, credentials);
        setDetails(new Details(domain, workstation, ntResponse, lmResponse));
    }

    public String getDomain() {
        return ((Details) getDetails()).getDomain();
    }

    public String getWorkstation() {
        return ((Details) getDetails()).getWorkstation();
    }

    public byte[] getNtResponse() {
        return ((Details) getDetails()).getNtResponse();
    }

    public byte[] getLmResponse() {
        return ((Details) getDetails()).getLmResponse();
    }

    public static class Details {
        private final String domain;
        private final String workstation;
        private final byte[] ntResponse;
        private final byte[] lmResponse;

        public Details(String domain, String workstation, byte[] ntResponse, byte[] lmResponse) {
            this.domain = domain;
            this.workstation = workstation;
            this.ntResponse = ntResponse;
            this.lmResponse = lmResponse;
        }

        public String getDomain() {
            return domain;
        }

        public String getWorkstation() {
            return workstation;
        }

        public byte[] getNtResponse() {
            return ntResponse;
        }

        public byte[] getLmResponse() {
            return lmResponse;
        }
    }

}
