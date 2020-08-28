package com.example.demo.web.resource.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class NtlmAuthenticationConverter implements AuthenticationConverter {

    private static final String AUTH_HEADER_NAME = "Authorization";
    private static final String NTLM_HEADER_BEGIN = "NTLM ";
    private static final String NTLM_CHALLENGE = "NtlmHttpChal";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String authHeader = request.getHeader(AUTH_HEADER_NAME);
        if (authHeader != null && (authHeader.startsWith(NTLM_HEADER_BEGIN))) {
            byte[] material = java.util.Base64.getDecoder().decode(authHeader.substring(5));
            HttpSession session = request.getSession(false);
            byte[] serverChallenge = (byte[]) session.getAttribute(NTLM_CHALLENGE);
            return new NtlmAuthToken(material, serverChallenge);
        }
        return null;
    }

}
