package com.example.demo.web.resource.auth;

import com.example.demo.ntlm.ArrayUtil;
import com.example.demo.ntlm.StringPool;
import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.util.Encdec;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Properties;

public class NtlmAuthenticationProcessingFilter extends AuthenticationFilter {

    // Session attributes
    private static final String NTLM_CHALLENGE = "NtlmHttpChal";
    private static final String USER_ACCOUNT = "AuthenticatedUser";
    // NTLM flags
    private static final int NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000;
    // JCIFS settings
    private final static String JCIFS_HTTP_DOMAIN_CONTROLLER = "jcifs.http.domainController";
    private final static String JCIFS_ENCODING = "jcifs.encoding";
    private final static String JCIFS_NETBIOS_HOSTNAME = "jcifs.netbios.hostname";
    private final static String JCIFS_SMB_CLIENT_DOMAIN = "jcifs.smb.client.domain";
    private final static String JCIFS_SMB_CLIENT_RESPONSE_TIME = "jcifs.smb.client.responseTimeout";
    private final static String JCIFS_SMB_CLIENT_USERNAME = "jcifs.smb.client.username";
    private final static String JCIFS_SMB_CLIENT_PASSWORD = "jcifs.smb.client.password";
    private final static String NTLM_AUTH_NEGOTIATE_FLAGS = "ntlm.auth.negotiate.flags";
    private final static String JCIFS_HTTP_DOMAIN_CONTROLLER_NAME = "jcifs.http.domainControllerName";

    private final SecureRandom secureRandom;

    private final CIFSContext jcifsContext;

    public NtlmAuthenticationProcessingFilter(AuthenticationManager authenticationManager, AuthenticationConverter authenticationConverter) throws CIFSException {
        super(authenticationManager, authenticationConverter);
        secureRandom = new SecureRandom();

        Properties jcifsProperties = new Properties();
        jcifsProperties.setProperty("jcifs.smb.client.soTimeout", "1800000");
        jcifsProperties.setProperty("jcifs.netbios.cachePolicy", "1200");
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER, "192.168.9.15");
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER_NAME, "tsk-dc02.ois.ru");
        jcifsProperties.setProperty(JCIFS_ENCODING, "Cp1251");
        jcifsProperties.setProperty(JCIFS_NETBIOS_HOSTNAME, "");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_DOMAIN, "OIS");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_RESPONSE_TIME, "3000");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_USERNAME, "USOI-RSN");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_PASSWORD, "FNTvZ35cQH");
        jcifsProperties.setProperty(NTLM_AUTH_NEGOTIATE_FLAGS, "WIN2008");

        jcifsContext = new BaseContext(new PropertyConfiguration(jcifsProperties));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (!getRequestMatcher().matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        String msg = request.getHeader("Authorization");
        if (msg != null && (msg.startsWith("NTLM "))) {
            byte[] src = java.util.Base64.getDecoder().decode(msg.substring(5));
            if (src[8] == 1) {
                // Create server challenge
//                log.debug("Starting ntlm authentication");
                byte[] serverChallenge = new byte[8];
                secureRandom.nextBytes(serverChallenge);

                byte[] challengeMessage;
                try {
//                    log.debug("Creating server challenge");
                    challengeMessage = negotiate(src, serverChallenge);
                    HttpSession session = request.getSession(true);
                    session.setAttribute(NTLM_CHALLENGE, serverChallenge);
//                    log.debug("Server challenge created");
                } catch (Throwable e) {
                    safeRemoveChallengeAttribute(request.getSession(false));
//                    log.error(getAuthType() + ": Server challenge creation failed: " + e.getMessage());
//                    throw new AuthException(e);
                    throw new RuntimeException(e);
                }
                String authorization = new String(java.util.Base64.getEncoder().encode(challengeMessage));
//                log.debug("Sending server challenge to client");
                sendWwwAuthenticateResponse(response, authorization);
//                log.debug("Server challenge sent to client");
            } else {

                HttpSession session = request.getSession(false);
                byte[] serverChallenge = (byte[]) safeGetAttribute(session, NTLM_CHALLENGE);
//            log.debug("Got server challenge result from client");
                if (serverChallenge == null) {
//                log.debug("Server challenge result from client is null");
                    // Start NTLM login
                    sendWwwAuthenticateResponse(response);
                }
                try {
                    Authentication authenticationResult = attemptAuthentication(request);
                    if (authenticationResult == null) {
                        return;
                    }
                    successfulAuthentication(request, response, chain, authenticationResult);
                } catch (AuthenticationException e) {
                    unsuccessfulAuthentication(e);
                }
            }
        } else {
            HttpSession session = request.getSession(false);
            if (safeGetAttribute(session, USER_ACCOUNT) == null) {
                sendWwwAuthenticateResponse(response);
            }
        }
    }

    private void unsuccessfulAuthentication(AuthenticationException failed) {
        SecurityContextHolder.clearContext();
        throw failed;
//        getFailureHandler().onAuthenticationFailure(request, response, failed);
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                          Authentication authentication) throws IOException, ServletException {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        safeRemoveChallengeAttribute(request.getSession(false));
        chain.doFilter(request, response);
//        getSuccessHandler().onAuthenticationSuccess(request, response, chain, authentication);
    }

    private Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException, ServletException {
        Authentication authentication = getAuthenticationConverter().convert(request);
        if (authentication == null) {
            return null;
        }
        AuthenticationManager authenticationManager = getAuthenticationManagerResolver().resolve(request);
        Authentication authenticationResult = authenticationManager.authenticate(authentication);
        if (authenticationResult == null) {
            throw new ServletException("AuthenticationManager should not return null Authentication object.");
        }
        return authenticationResult;
    }

    private byte[] negotiate(byte[] material, byte[] serverChallenge) throws IOException {
        Type1Message type1Message = new Type1Message(material);
        Type2Message type2Message = new Type2Message(jcifsContext, type1Message.getFlags(), serverChallenge, jcifsContext.getConfig().getDefaultDomain());
        if (type2Message.getFlag(NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY)) {
            type2Message.setFlag(NtlmFlags.NTLMSSP_NEGOTIATE_LM_KEY, false);
            type2Message.setFlag(NtlmFlags.NTLMSSP_NEGOTIATE_TARGET_INFO, true);
            type2Message.setTargetInformation(getTargetInformation());
        }
        return type2Message.toByteArray();
    }

    private byte[] getAVPairBytes(int avId, String value) {

        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_16LE);
        byte[] avPairBytes = new byte[4 + valueBytes.length];

        Encdec.enc_uint16le((short) avId, avPairBytes, 0);
        Encdec.enc_uint16le((short) valueBytes.length, avPairBytes, 2);

        System.arraycopy(valueBytes, 0, avPairBytes, 4, valueBytes.length);

        return avPairBytes;
    }

    private byte[] getTargetInformation() {

        byte[] computerName = getAVPairBytes(
                1, jcifsContext.getConfig().getDefaultUsername());
        byte[] domainName = getAVPairBytes(2, jcifsContext.getConfig().getDefaultDomain());

        byte[] targetInformation = ArrayUtil.append(computerName, domainName);

        byte[] eol = getAVPairBytes(0, StringPool.BLANK);

        targetInformation = ArrayUtil.append(targetInformation, eol);

        return targetInformation;
    }

    private void safeRemoveChallengeAttribute(HttpSession session) {
        if (session != null) {
            session.removeAttribute(NTLM_CHALLENGE);
        }
    }

    private Object safeGetAttribute(HttpSession session, String name) {
        return session != null ? session.getAttribute(name) : null;
    }

    private void sendWwwAuthenticateResponse(HttpServletResponse response) throws IOException {
        sendWwwAuthenticateResponse(response, null);
    }

    private void sendWwwAuthenticateResponse(HttpServletResponse response, String authMsg) throws IOException {
        response.setContentLength(0);
        response.setHeader("WWW-Authenticate", "NTLM" + (!StringUtils.isEmpty(authMsg) ? " " + authMsg : ""));
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.flushBuffer();
    }

}
