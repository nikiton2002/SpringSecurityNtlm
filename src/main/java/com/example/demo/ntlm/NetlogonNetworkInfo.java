package com.example.demo.ntlm;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrObject;

public class NetlogonNetworkInfo extends NdrObject {

	public NetlogonNetworkInfo(
		NetlogonIdentityInfo netlogonIdentityInfo, byte[] lmChallenge,
		byte[] ntChallengeResponse, byte[] lmChallengeResponse) {

		_netlogonIdentityInfo = netlogonIdentityInfo;
		_lmChallenge = lmChallenge;
		_ntChallengeResponse = ntChallengeResponse;
		_lmChallengeResponse = lmChallengeResponse;
	}

	@Override
	public void decode(NdrBuffer ndrBuffer) {
	}

	@Override
	public void encode(NdrBuffer ndrBuffer) {
		ndrBuffer.align(4);

		_netlogonIdentityInfo.encode(ndrBuffer);

		int lmChallengeIndex = ndrBuffer.index;

		ndrBuffer.advance(8);

		ndrBuffer.enc_ndr_short((short)_ntChallengeResponse.length);
		ndrBuffer.enc_ndr_short((short)_ntChallengeResponse.length);
		ndrBuffer.enc_ndr_referent(_ntChallengeResponse, 1);

		ndrBuffer.enc_ndr_short((short)_lmChallengeResponse.length);
		ndrBuffer.enc_ndr_short((short)_lmChallengeResponse.length);
		ndrBuffer.enc_ndr_referent(_lmChallengeResponse, 1);

		_netlogonIdentityInfo.encodeLogonDomainName(ndrBuffer);
		_netlogonIdentityInfo.encodeUserName(ndrBuffer);
		_netlogonIdentityInfo.encodeWorkStationName(ndrBuffer);

		ndrBuffer = ndrBuffer.derive(lmChallengeIndex);

		for (int i = 0; i < 8; i++) {
			ndrBuffer.enc_ndr_small(_lmChallenge[i]);
		}

		encodeChallengeResponse(ndrBuffer, _ntChallengeResponse);
		encodeChallengeResponse(ndrBuffer, _lmChallengeResponse);
	}

	protected void encodeChallengeResponse(
		NdrBuffer ndrBuffer, byte[] challenge) {

		ndrBuffer = ndrBuffer.deferred;

		ndrBuffer.enc_ndr_long(challenge.length);
		ndrBuffer.enc_ndr_long(0);
		ndrBuffer.enc_ndr_long(challenge.length);

		int index = ndrBuffer.index;

		ndrBuffer.advance(challenge.length);

		ndrBuffer = ndrBuffer.derive(index);

		for (int i = 0; i < challenge.length; i++) {
			ndrBuffer.enc_ndr_small(challenge[i]);
		}
	}

	private byte[] _lmChallenge;
	private byte[] _lmChallengeResponse;
	private NetlogonIdentityInfo _netlogonIdentityInfo;
	private byte[] _ntChallengeResponse;

}