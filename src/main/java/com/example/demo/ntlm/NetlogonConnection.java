package com.example.demo.ntlm;

import com.example.demo.ntlm.oldutil.DES;
import com.example.demo.ntlm.oldutil.HMACT64;
import com.example.demo.ntlm.oldutil.MD4;
import jcifs.CIFSContext;
import jcifs.dcerpc.DcerpcHandle;
import jcifs.util.Encdec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class NetlogonConnection {

    private static final String NTLM_AUTH_NEGOTIATE_WIN2003 = "0x600FFFFF";
    private static final String NTLM_AUTH_NEGOTIATE_WIN2008 = "0x6013C600";
	private static final String NTLM_AUTH_NEGOTIATE_FLAGS = "WIN2008";

	public NetlogonConnection() {
        if (_negotiateFlags == 0) {
            String negotiateFlags = NTLM_AUTH_NEGOTIATE_FLAGS;

            if (!negotiateFlags.startsWith("0x")) {
                if (negotiateFlags.equalsIgnoreCase("WIN2008")) {
                    negotiateFlags = NTLM_AUTH_NEGOTIATE_WIN2008;
                } else {
                    negotiateFlags = NTLM_AUTH_NEGOTIATE_WIN2003;
                }
            }

            _negotiateFlags = Long.valueOf(negotiateFlags.substring(2), 16).intValue();

        }
	}

	public NetlogonAuthenticator computeNetlogonAuthenticator() {
		int timestamp = (int)System.currentTimeMillis();

		int input = Encdec.dec_uint32le(_clientCredential, 0) + timestamp;

		Encdec.enc_uint32le(input, _clientCredential, 0);

		byte[] credential = computeNetlogonCredential(
			_clientCredential, _sessionKey);

		return new NetlogonAuthenticator(credential, timestamp);
	}

	public void connect(String domainController,
						String domainControllerName,
						NtlmServiceAccount ntlmServiceAccount,
						CIFSContext context)
		throws IOException, NoSuchAlgorithmException, NtlmLogonException {

//		NtlmPasswordAuthentication ntlmPasswordAuthentication =
//			new NtlmPasswordAuthentication(
//				null, ntlmServiceAccount.getAccount(),
//				ntlmServiceAccount.getPassword());

		String endpoint = "ncacn_np:" + domainController + "[\\PIPE\\NETLOGON]";

		DcerpcHandle dcerpcHandle = DcerpcHandle.getHandle(
			endpoint, context);

		setDcerpcHandle(dcerpcHandle);

		dcerpcHandle.bind();

		byte[] clientChallenge = new byte[8];

		BigEndianCodec.putLong(clientChallenge, 0, SecureRandomUtil.nextLong());

		NetrServerReqChallenge netrServerReqChallenge =
			new NetrServerReqChallenge(
				domainControllerName, ntlmServiceAccount.getComputerName(),
				clientChallenge, new byte[8]);

		dcerpcHandle.sendrecv(netrServerReqChallenge);

		MD4 md4 = new MD4();

		md4.update(ntlmServiceAccount.getPassword().getBytes(StandardCharsets.UTF_16LE));

		byte[] sessionKey = computeSessionKey(
			md4.digest(), clientChallenge,
			netrServerReqChallenge.getServerChallenge());

		byte[] clientCredential = computeNetlogonCredential(
			clientChallenge, sessionKey);

		NetrServerAuthenticate3 netrServerAuthenticate3 =
			new NetrServerAuthenticate3(
				domainControllerName, ntlmServiceAccount.getAccountName(), 2,
				ntlmServiceAccount.getComputerName(), clientCredential,
				new byte[8], _negotiateFlags);

		dcerpcHandle.sendrecv(netrServerAuthenticate3);

		byte[] serverCredential = computeNetlogonCredential(
			netrServerReqChallenge.getServerChallenge(), sessionKey);

		if (!Arrays.equals(
				serverCredential,
				netrServerAuthenticate3.getServerCredential())) {

			throw new NtlmLogonException("Session key negotiation failed");
		}

		_clientCredential = clientCredential;
		_sessionKey = sessionKey;
	}

	public void disconnect() throws IOException {
		if (_dcerpcHandle != null) {
			_dcerpcHandle.close();
		}
	}

	public byte[] getClientCredential() {
		return _clientCredential;
	}

	public DcerpcHandle getDcerpcHandle() {
		return _dcerpcHandle;
	}

	public byte[] getSessionKey() {
		return _sessionKey;
	}

	public void setDcerpcHandle(DcerpcHandle dcerpcHandle) {
		_dcerpcHandle = dcerpcHandle;
	}

	protected byte[] computeNetlogonCredential(
		byte[] input, byte[] sessionKey) {

		byte[] k1 = new byte[7];
		byte[] k2 = new byte[7];

		System.arraycopy(sessionKey, 0, k1, 0, 7);
		System.arraycopy(sessionKey, 7, k2, 0, 7);

		DES k3 = new DES(k1);
		DES k4 = new DES(k2);

		byte[] output1 = new byte[8];
		byte[] output2 = new byte[8];

		k3.encrypt(input, output1);
		k4.encrypt(output1, output2);

		return output2;
	}

	protected byte[] computeSessionKey(
			byte[] sharedSecret, byte[] clientChallenge, byte[] serverChallenge)
		throws NoSuchAlgorithmException {

		MessageDigest messageDigest = MessageDigest.getInstance("MD5");

		byte[] zeroes = {0, 0, 0, 0};

		messageDigest.update(zeroes, 0, 4);
		messageDigest.update(clientChallenge, 0, 8);
		messageDigest.update(serverChallenge, 0, 8);

		HMACT64 hmact64 = new HMACT64(sharedSecret);

		hmact64.update(messageDigest.digest());

		return hmact64.digest();
	}

	private static int _negotiateFlags;

	private byte[] _clientCredential;
	private DcerpcHandle _dcerpcHandle;
	private byte[] _sessionKey;

}