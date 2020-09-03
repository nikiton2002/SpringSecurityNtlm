package com.example.demo.web.resource.auth;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.ntlmssp.NtlmFlags;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.av.AvPair;
import jcifs.ntlmssp.av.AvPairs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

public class NtlmAuthenticationProcessingFilter extends AuthenticationFilter {

    private static final Logger log = LoggerFactory.getLogger(NtlmAuthenticationProcessingFilter.class);

    // Session attributes
    private static final String AUTH_HEADER_NAME = "Authorization";
    private static final String NTLM_HEADER_BEGIN = "NTLM ";
    private static final String NTLM_CHALLENGE = "NtlmHttpChal";
    private static final String USER_ACCOUNT = "AuthenticatedUser";
    private static final int NTLM_MESSAGE_TYPE_BYTE = 8;
    // NTLM flags
    private static final int NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000;
    // JCIFS
    // Custom
    private final static String JCIFS_HTTP_DOMAIN_CONTROLLER = "jcifs.http.domainController";
    private final static String JCIFS_HTTP_DOMAIN_CONTROLLER_NAME = "jcifs.http.domainControllerName";
    // Original
    private final static String JCIFS_ENCODING = "jcifs.encoding";
    private final static String JCIFS_NETBIOS_HOSTNAME = "jcifs.netbios.hostname";
    private final static String JCIFS_SMB_CLIENT_DOMAIN = "jcifs.smb.client.domain";
    private final static String JCIFS_SMB_CLIENT_USERNAME = "jcifs.smb.client.username";
    private final static String JCIFS_SMB_CLIENT_PASSWORD = "jcifs.smb.client.password";
    private final static String JCIFS_SMB_CLIENT_RESPONSE_TIME = "jcifs.smb.client.responseTimeout";

    private final CIFSContext jcifsContext;

    public NtlmAuthenticationProcessingFilter(AuthenticationManager authenticationManager, AuthenticationConverter authenticationConverter) throws CIFSException {
        super(authenticationManager, authenticationConverter);

        Properties jcifsProperties = new Properties();
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_DOMAIN, "OIS");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_USERNAME, "USOI-RSN");
        jcifsProperties.setProperty("jcifs.smb.client.soTimeout", "1800000");
        jcifsProperties.setProperty("jcifs.netbios.cachePolicy", "1200");
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER, "192.168.9.15");
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER_NAME, "tsk-dc02.ois.ru");
        jcifsProperties.setProperty(JCIFS_ENCODING, "Cp1251");
        jcifsProperties.setProperty(JCIFS_NETBIOS_HOSTNAME, "");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_RESPONSE_TIME, "3000");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_PASSWORD, "FNTvZ35cQH");

        jcifsContext = new BaseContext(new PropertyConfiguration(jcifsProperties));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (!getRequestMatcher().matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        String msg = request.getHeader(AUTH_HEADER_NAME);
        if (msg != null && (msg.startsWith(NTLM_HEADER_BEGIN))) {
            byte[] src = Base64.getDecoder().decode(msg.substring(5));
            if (src[NTLM_MESSAGE_TYPE_BYTE] == 1) {
                log.debug("Starting ntlm authentication");

                byte[] serverChallenge = new byte[8];
                jcifsContext.getConfig().getRandom().nextBytes(serverChallenge);

                byte[] challengeMessage;
                try {
                    log.debug("Creating server challenge");

                    challengeMessage = negotiate(src, serverChallenge);
                    HttpSession session = request.getSession(true);
                    session.setAttribute(NTLM_CHALLENGE, serverChallenge);

                    log.debug("Server challenge created");
                } catch (Throwable e) {
                    log.error("NTLM : Server challenge creation failed: " + e.getMessage());

                    safeRemoveChallengeAttribute(request.getSession(false));
                    throw new AuthException(e);
                }
                log.debug("Sending server challenge to client");

                String authorization = new String(Base64.getEncoder().encode(challengeMessage));
                sendWwwAuthenticateResponse(response, authorization);

                log.debug("Server challenge sent to client");
            } else if (src[NTLM_MESSAGE_TYPE_BYTE] == 3) {
                log.debug("Got server challenge result from client");

                HttpSession session = request.getSession(false);
                byte[] serverChallenge = (byte[]) safeGetAttribute(session, NTLM_CHALLENGE);
                if (serverChallenge == null) {
                    log.debug("Server challenge result from client is null");
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

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
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

    private byte[] getTargetInformation() {
        AvPair computerName = new AvPair(1, jcifsContext.getConfig().getDefaultUsername().getBytes(StandardCharsets.UTF_16LE));
        AvPair domainName = new AvPair(2, jcifsContext.getConfig().getDefaultDomain().getBytes(StandardCharsets.UTF_16LE));
        return AvPairs.encode(Arrays.asList(computerName, domainName));
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
