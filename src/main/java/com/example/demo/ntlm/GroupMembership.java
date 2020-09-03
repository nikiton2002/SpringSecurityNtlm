package com.example.demo.ntlm;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrObject;

public class GroupMembership extends NdrObject {

	private int _attributes;
	private int _relativeId;

	@Override
	public void decode(NdrBuffer ndrBuffer) {
		ndrBuffer.align(4);
		_relativeId = ndrBuffer.dec_ndr_long();
		_attributes = ndrBuffer.dec_ndr_long();
	}

	@Override
	public void encode(NdrBuffer ndrBuffer) {
		ndrBuffer.align(4);
		ndrBuffer.enc_ndr_long(_relativeId);
		ndrBuffer.enc_ndr_long(_attributes);
	}

}