package com.example.demo.ntlm;

import jcifs.dcerpc.DcerpcMessage;
import jcifs.dcerpc.ndr.NdrBuffer;

public class NetrServerAuthenticate3 extends DcerpcMessage {

	private final String _accountName;
    private final byte[] _clientCredential;
	private final String _computerName;
	private int _negotiateFlags;
	private final String _primaryName;
	private final short _secureChannelType;
	private final byte[] _serverCredential;

    public NetrServerAuthenticate3(String primaryName,
                                   String accountName,
                                   int secureChannelType,
                                   String computerName,
                                   byte[] clientCredential,
                                   byte[] serverCredential,
                                   int negotiateFlags) {
        _primaryName = primaryName;
        _accountName = accountName;
        _secureChannelType = (short) secureChannelType;
        _computerName = computerName;
        _clientCredential = clientCredential;
        _serverCredential = serverCredential;
        _negotiateFlags = negotiateFlags;

        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }

    @Override
    public void decode_out(NdrBuffer ndrBuffer) {
        int index = ndrBuffer.index;

        ndrBuffer.advance(8);

        ndrBuffer = ndrBuffer.derive(index);

        for (int i = 0; i < 8; i++) {
            _serverCredential[i] = (byte) ndrBuffer.dec_ndr_small();
        }

        _negotiateFlags = ndrBuffer.dec_ndr_long();
        // accountRid (int)
        ndrBuffer.dec_ndr_long();
        // status (int)
        ndrBuffer.dec_ndr_long();
    }

    @Override
    public void encode_in(NdrBuffer ndrBuffer) {
        ndrBuffer.enc_ndr_referent(_primaryName, 1);
        ndrBuffer.enc_ndr_string(_primaryName);
        ndrBuffer.enc_ndr_string(_accountName);
        ndrBuffer.enc_ndr_short(_secureChannelType);
        ndrBuffer.enc_ndr_string(_computerName);

        int index = ndrBuffer.index;

        ndrBuffer.advance(8);

        NdrBuffer derivedNrdBuffer = ndrBuffer.derive(index);

        for (int i = 0; i < 8; i++) {
            derivedNrdBuffer.enc_ndr_small(_clientCredential[i]);
        }

        ndrBuffer.enc_ndr_long(_negotiateFlags);
    }

    @Override
    public int getOpnum() {
        return 26;
    }

    public byte[] getServerCredential() {
        return _serverCredential;
    }

}