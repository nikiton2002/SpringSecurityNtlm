package com.example.demo.web.resource.auth;

import jcifs.ntlmssp.Type3Message;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class NtlmAuthenticationConverter implements AuthenticationConverter {

    private static final String AUTH_HEADER_NAME = "Authorization";
    private static final String NTLM_HEADER_BEGIN = "NTLM ";
    private static final String NTLM_CHALLENGE = "NtlmHttpChal";

    private static final int NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000;

    @Override
    public Authentication convert(HttpServletRequest request) {

        String authHeader = request.getHeader(AUTH_HEADER_NAME);
        if (authHeader != null && (authHeader.startsWith(NTLM_HEADER_BEGIN))) {

            byte[] material = Base64.getDecoder().decode(authHeader.substring(5));
            HttpSession session = request.getSession(false);
            byte[] serverChallenge = (byte[]) session.getAttribute(NTLM_CHALLENGE);

            Type3Message type3Message;
            try {
                type3Message = new Type3Message(material);
            } catch (IOException e) {
                throw new InternalAuthenticationServiceException(e.getMessage());
            }

            if (type3Message.getFlag(NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) &&
                    (type3Message.getNTResponse().length == 24)) {

                MessageDigest messageDigest;
                try {
                    messageDigest = MessageDigest.getInstance("MD5");
                } catch (NoSuchAlgorithmException e) {
                    throw new InternalAuthenticationServiceException(e.getMessage());
                }

                byte[] bytes = new byte[16];
                System.arraycopy(serverChallenge, 0, bytes, 0, 8);
                System.arraycopy(type3Message.getLMResponse(), 0, bytes, 8, 8);

                messageDigest.update(bytes);

                serverChallenge = messageDigest.digest();
            }

            return new NtlmAuthToken(
                    type3Message.getUser(),
                    serverChallenge,
                    type3Message.getDomain(),
                    type3Message.getWorkstation(),
                    type3Message.getNTResponse(),
                    type3Message.getLMResponse());
        }
        return null;
    }

}
