package com.example.demo.web.resource.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;


public class NtlmAuthToken extends AbstractAuthenticationToken {

    private String domain;
    private String userName;
    private String workstation;
    private final byte[] material;
    private final byte[] serverChallenge;

    public NtlmAuthToken(byte[] material, byte[] serverChallenge) {
        super(null);
        this.material = material;
        this.serverChallenge = serverChallenge;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getWorkstation() {
        return workstation;
    }

    public void setWorkstation(String workstation) {
        this.workstation = workstation;
    }

    public byte[] getServerChallenge() {
        return serverChallenge;
    }

    public byte[] getMaterial() {
        return material;
    }
}
