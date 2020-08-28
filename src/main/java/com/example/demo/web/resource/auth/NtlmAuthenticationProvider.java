package com.example.demo.web.resource.auth;

import com.example.demo.ntlm.*;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.dcerpc.DcerpcBinding;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.ntlmssp.Type3Message;
import jcifs.smb.SmbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class NtlmAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(NtlmAuthenticationProvider.class);

    private final List<String> domainControllers;
    private final List<String> domainControllerNames;
    private final NtlmServiceAccount ntlmServiceAccount;

    private static final int NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000;

    // JCIFS
    public final static String JCIFS_HTTP_DOMAIN_CONTROLLER = "jcifs.http.domainController";
    private final static String JCIFS_ENCODING = "jcifs.encoding";
    private final static String JCIFS_NETBIOS_HOSTNAME = "jcifs.netbios.hostname";
    public final static String JCIFS_SMB_CLIENT_DOMAIN = "jcifs.smb.client.domain";
    private final static String JCIFS_SMB_CLIENT_RESPONSE_TIME = "jcifs.smb.client.responseTimeout";
    public final static String JCIFS_SMB_CLIENT_USERNAME = "jcifs.smb.client.username";
    public final static String JCIFS_SMB_CLIENT_PASSWORD = "jcifs.smb.client.password";
    public final static String NTLM_AUTH_NEGOTIATE_FLAGS = "ntlm.auth.negotiate.flags";
    public final static String JCIFS_HTTP_DOMAIN_CONTROLLER_NAME = "jcifs.http.domainControllerName";

    Properties jcifsProperties;

    static {
        DcerpcBinding.addInterface(
                "netlogon", "12345678-1234-abcd-ef00-01234567cffb:1.0");
    }

    public NtlmAuthenticationProvider() {

        jcifsProperties = new Properties();
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

        String defaultDomain = jcifsProperties.getProperty(JCIFS_SMB_CLIENT_DOMAIN);
        String domainController = jcifsProperties.getProperty(JCIFS_HTTP_DOMAIN_CONTROLLER);
        List<String> domainControllers;
        if (domainController == null) {
            domainControllers = new ArrayList<>();
            domainControllers.add(defaultDomain);
        } else {
            domainControllers = new ArrayList<>(Arrays.asList(domainController.split(";")));
            domainControllers.forEach((String e) -> domainControllers.set(domainControllers.indexOf(e), e.trim()));
        }

        String domains = jcifsProperties.getProperty(JCIFS_HTTP_DOMAIN_CONTROLLER_NAME);
        List<String> domainControllerNames;
        if (domains == null) {
            domainControllerNames = new ArrayList<>();
        } else {
            domainControllerNames = new ArrayList<>(Arrays.asList(domains.split(";")));
            domainControllerNames.forEach((String e) -> domainControllerNames.set(domainControllerNames.indexOf(e), e.trim()));
        }

        String account = jcifsProperties.getProperty(JCIFS_SMB_CLIENT_USERNAME);
        String password = jcifsProperties.getProperty(JCIFS_SMB_CLIENT_PASSWORD);

        this.domainControllers = domainControllers;
        this.domainControllerNames = domainControllerNames;
        ntlmServiceAccount = new NtlmServiceAccount(defaultDomain, account, password);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        NtlmAuthToken token = (NtlmAuthToken) authentication;

        Type3Message type3Message;
        byte[] serverChallenge = token.getServerChallenge();
        try {
            type3Message = new Type3Message(token.getMaterial());
        } catch (IOException e) {
            throw new InternalAuthenticationServiceException(e.getMessage());
        }

        if (type3Message.getFlag(
                NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY) &&
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

        String domain = type3Message.getDomain();
        String userName = type3Message.getUser();
        String workstation = type3Message.getWorkstation();
        byte[] ntResponse = type3Message.getNTResponse();
        byte[] lmResponse = type3Message.getLMResponse();

        NetlogonConnection netlogonConnection = new NetlogonConnection();

        log.debug("Sending challenge data and result from client to domain controller");
        for (String domainController : domainControllers) {
            for (String domainControllerName : domainControllerNames) {
                try {
                    log.debug("Trying to connect to \"" + domainController + "\"(" + domainControllerName + ")");
                    netlogonConnection.connect(
                            domainController,
                            domainControllerName,
                            ntlmServiceAccount,
                            new BaseContext(new PropertyConfiguration(jcifsProperties)));

                    NetlogonAuthenticator netlogonAuthenticator =
                            netlogonConnection.computeNetlogonAuthenticator();

                    log.debug("Connected to \"" + domainController + "\"(" + domainControllerName + ")");
                    NetlogonIdentityInfo netlogonIdentityInfo =
                            new NetlogonIdentityInfo(
                                    domain, 0x00000820, 0, 0, userName, workstation);

                    NetlogonNetworkInfo netlogonNetworkInfo = new NetlogonNetworkInfo(
                            netlogonIdentityInfo, serverChallenge, ntResponse, lmResponse);

                    log.debug("Sending to domain server data: " +
                            "domain: " + "\"" + domain + "\", " +
                            "userName: " + "\"" + userName + "\", " +
                            "workstation: " + "\"" + workstation + "\"");
                    NetrLogonSamLogon netrLogonSamLogon = new NetrLogonSamLogon(
                            domainControllerName, ntlmServiceAccount.getComputerName(),
                            netlogonAuthenticator, new NetlogonAuthenticator(), 2,
                            netlogonNetworkInfo, 2, new NetlogonValidationSamInfo(), 0);

                    DcerpcHandle dcerpcHandle = netlogonConnection.getDcerpcHandle();

                    dcerpcHandle.sendrecv(netrLogonSamLogon);

                    if (netrLogonSamLogon.getStatus() == 0) {
                        log.debug("Auth successful (" +
                                "domain: " + "\"" + domain + "\", " +
                                "userName: " + "\"" + userName + "\", " +
                                "workstation: " + "\"" + workstation + "\", " +
                                "domainController: " + "\"" + domainController + "\", " +
                                "domainControllerName: " + "\"" + domainControllerName + "\")");

                        token.setDomain(domain);
                        token.setUserName(userName);
                        token.setAuthenticated(true);
                        return token;
                    }

                    SmbException smbe = new SmbException(netrLogonSamLogon.getStatus(), false);
                    throw new BadCredentialsException(smbe.getMessage());
                } catch (NoSuchAlgorithmException | IOException e) {
                    throw new AuthenticationServiceException(e.getMessage());
                } catch (NtlmLogonException e) {
                    //если данные признаны сервером некорректными, то пробуем вкинуть их на другие
                    throw new BadCredentialsException(e.getMessage());
                } finally {
                    try {
                        netlogonConnection.disconnect();
                    } catch (Exception e) {
                        log.error("Unable to disconnect Netlogon connection", e);
                    }
                }
            }
        }
        /*
        //если зашли сюда, значит косячат ip и/или доменное имя контроллера
        String message;
        if (_lastErrorType.equals(IOException.class.getName())) {
            message = "Unable to authenticate due to communication failure with server";
        } else if (_lastErrorType.equals(SmbException.class.getName())) {
            message = "Unable to authenticate user: " + _lastError.getMessage();
        } else if (_lastErrorType.equals(NoSuchAlgorithmException.class.getName())) {
            message = "Unable to authenticate due to invalid encryption algorithm";
        } else {
            message = "Session key negotiation failed";
        }
        throw new NtlmLogonException(message, _lastError);
        */
        throw new BadCredentialsException("OLLOLO!");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return NtlmAuthToken.class.isAssignableFrom(authentication);
    }

}
