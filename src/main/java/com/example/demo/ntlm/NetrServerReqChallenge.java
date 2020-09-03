package com.example.demo.ntlm;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;

public class NetrServerReqChallenge extends DcerpcMessage {

	private final byte[] _clientChallenge;
	private final String _computerName;
	private final String _primaryName;
	private final byte[] _serverChallenge;

    public NetrServerReqChallenge(String primaryName,
                                  String computerName,
                                  byte[] clientChallenge,
                                  byte[] serverChallenge) {

        _primaryName = primaryName;
        _computerName = computerName;
        _clientChallenge = clientChallenge;
        _serverChallenge = serverChallenge;

        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }

    @Override
    public void decode_out(NdrBuffer ndrBuffer) {
        int index = ndrBuffer.index;

        ndrBuffer.advance(8);

        ndrBuffer = ndrBuffer.derive(index);

        for (int i = 0; i < 8; i++) {
            _serverChallenge[i] = (byte) ndrBuffer.dec_ndr_small();
        }
        // status (int)
        ndrBuffer.dec_ndr_long();
    }

    @Override
    public void encode_in(NdrBuffer ndrBuffer) {
        ndrBuffer.enc_ndr_referent(_primaryName, 1);
        ndrBuffer.enc_ndr_string(_primaryName);
        ndrBuffer.enc_ndr_string(_computerName);

        int index = ndrBuffer.index;

        ndrBuffer.advance(8);

        ndrBuffer = ndrBuffer.derive(index);

        for (int i = 0; i < 8; i++) {
            ndrBuffer.enc_ndr_small(_clientChallenge[i]);
        }
    }

    @Override
    public int getOpnum() {
        return 4;
    }

    public byte[] getServerChallenge() {
        return _serverChallenge;
    }

}