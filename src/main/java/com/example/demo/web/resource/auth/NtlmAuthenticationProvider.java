package com.example.demo.web.resource.auth;

import com.example.demo.ntlm.*;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.dcerpc.DcerpcBinding;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.smb.SmbException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

public class NtlmAuthenticationProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(NtlmAuthenticationProvider.class);

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

    Properties jcifsProperties = new Properties();

    static {
        DcerpcBinding.addInterface(
                "netlogon", "12345678-1234-abcd-ef00-01234567cffb:1.0");
    }

    public NtlmAuthenticationProvider() {
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER, "192.168.9.15");
        jcifsProperties.setProperty(JCIFS_HTTP_DOMAIN_CONTROLLER_NAME, "tsk-dc02.ois.ru");

        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_DOMAIN, "OIS");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_USERNAME, "USOI-RSN");
        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_PASSWORD, "FNTvZ35cQH");

        jcifsProperties.setProperty(JCIFS_SMB_CLIENT_RESPONSE_TIME, "3000");
        jcifsProperties.setProperty("jcifs.smb.client.soTimeout", "1800000");
        jcifsProperties.setProperty("jcifs.netbios.cachePolicy", "1200");
        jcifsProperties.setProperty(JCIFS_ENCODING, "Cp1251");
        jcifsProperties.setProperty(JCIFS_NETBIOS_HOSTNAME, "");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        NtlmAuthToken token = (NtlmAuthToken) authentication;
        String domain = token.getDomain();
        String userName = (String) token.getPrincipal();
        String workstation = token.getWorkstation();

        NetlogonConnection netlogonConnection = new NetlogonConnection();
        NtlmServiceAccount ntlmServiceAccount = createServiceAccount();

        log.debug("Sending challenge data and result from client to domain controller");

        List<String> domainControllers = getDomainControllers();
        List<String> domainControllerNames = getDomainControllerNames();
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

                    NetlogonIdentityInfo netlogonIdentityInfo = new NetlogonIdentityInfo(
                                    domain,
                                    0x00000820,
                                    0,
                                    0,
                                    userName,
                                    workstation);

                    NetlogonNetworkInfo netlogonNetworkInfo = new NetlogonNetworkInfo(
                            netlogonIdentityInfo,
                            (byte[]) token.getCredentials(),
                            token.getNtResponse(),
                            token.getLmResponse());

                    log.debug("Sending to domain server data: " +
                            "domain: " + "\"" + domain + "\", " +
                            "userName: " + "\"" + userName + "\", " +
                            "workstation: " + "\"" + workstation + "\"");

                    NetrLogonSamLogon netrLogonSamLogon = new NetrLogonSamLogon(
                            domainControllerName,
                            ntlmServiceAccount.getComputerName(),
                            netlogonAuthenticator,
                            new NetlogonAuthenticator(),
                            2,
                            netlogonNetworkInfo,
                            2,
                            new NetlogonValidationSamInfo(),
                            0);

                    DcerpcHandle dcerpcHandle = netlogonConnection.getDcerpcHandle();

                    dcerpcHandle.sendrecv(netrLogonSamLogon);

                    if (netrLogonSamLogon.getStatus() == 0) {
                        log.debug("Auth successful (" +
                                "domain: " + "\"" + domain + "\", " +
                                "userName: " + "\"" + userName + "\", " +
                                "workstation: " + "\"" + workstation + "\", " +
                                "domainController: " + "\"" + domainController + "\", " +
                                "domainControllerName: " + "\"" + domainControllerName + "\")");

                        return new NtlmAuthToken(token.getPrincipal(), token.getCredentials());
                    }

                    SmbException smbe = new SmbException(netrLogonSamLogon.getStatus(), false);
                    throw new BadCredentialsException(smbe.getMessage());

                } catch (NoSuchAlgorithmException | IOException | ShortBufferException e) {
                    throw new AuthenticationServiceException(e.getMessage());
                } catch (NtlmLogonException e) {
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
        throw new AuthenticationServiceException("Domain controllers info not defined!");
    }

    private List<String> getDomainControllers() {
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
        return domainControllers;
    }

    private List<String> getDomainControllerNames() {
        String names = jcifsProperties.getProperty(JCIFS_HTTP_DOMAIN_CONTROLLER_NAME);
        List<String> domainControllerNames;
        if (names == null) {
            domainControllerNames = new ArrayList<>();
        } else {
            domainControllerNames = new ArrayList<>(Arrays.asList(names.split(";")));
            domainControllerNames.forEach((String e) -> domainControllerNames.set(domainControllerNames.indexOf(e), e.trim()));
        }
        return domainControllerNames;
    }

    private NtlmServiceAccount createServiceAccount() {
        return new NtlmServiceAccount(
                jcifsProperties.getProperty(JCIFS_SMB_CLIENT_USERNAME),
                jcifsProperties.getProperty(JCIFS_SMB_CLIENT_PASSWORD));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return NtlmAuthToken.class.isAssignableFrom(authentication);
    }

}
