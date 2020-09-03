package com.example.demo.ntlm;

import jcifs.dcerpc.ndr.NdrBuffer;
import jcifs.dcerpc.ndr.NdrException;
import jcifs.dcerpc.ndr.NdrObject;
import jcifs.dcerpc.rpc;

public class NetlogonValidationSamInfo extends NdrObject {

	private final rpc.unicode_string _effectiveName;
	private final rpc.unicode_string _fullName;
	private final rpc.unicode_string _homeDirectory;
	private final rpc.unicode_string _homeDirectoryDrive;

	private final rpc.sid_t _logonDomain;
	private final rpc.unicode_string _logonDomainName;
	private final rpc.unicode_string _logonScript;
	private final rpc.unicode_string _logonServer;

	private final rpc.unicode_string _profilePath;

    public NetlogonValidationSamInfo() {
        _effectiveName = new rpc.unicode_string();
        _fullName = new rpc.unicode_string();
        _logonScript = new rpc.unicode_string();
        _profilePath = new rpc.unicode_string();
        _homeDirectory = new rpc.unicode_string();
        _homeDirectoryDrive = new rpc.unicode_string();
        _logonServer = new rpc.unicode_string();
        _logonDomainName = new rpc.unicode_string();
        _logonDomain = new rpc.sid_t();
    }

    @Override
    public void decode(NdrBuffer ndrBuffer) throws NdrException {
        // logonTime (long)
        ndrBuffer.dec_ndr_hyper();
        // logoffTime (long)
        ndrBuffer.dec_ndr_hyper();
        // kickoffTime (long)
        ndrBuffer.dec_ndr_hyper();
        // passwordLastSet (long)
        ndrBuffer.dec_ndr_hyper();
        // passwordCanChange (long)
        ndrBuffer.dec_ndr_hyper();
        // passwordMustChange (long)
        ndrBuffer.dec_ndr_hyper();

        _effectiveName.length = (short) ndrBuffer.dec_ndr_short();
        _effectiveName.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int effectiveNamePtr = ndrBuffer.dec_ndr_long();

        _fullName.length = (short) ndrBuffer.dec_ndr_short();
        _fullName.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int fullNamePtr = ndrBuffer.dec_ndr_long();

        _logonScript.length = (short) ndrBuffer.dec_ndr_short();
        _logonScript.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int logonScriptPtr = ndrBuffer.dec_ndr_long();

        _profilePath.length = (short) ndrBuffer.dec_ndr_short();
        _profilePath.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int profilePathPtr = ndrBuffer.dec_ndr_long();

        _homeDirectory.length = (short) ndrBuffer.dec_ndr_short();
        _homeDirectory.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int homeDirectoryPtr = ndrBuffer.dec_ndr_long();

        _homeDirectoryDrive.length = (short) ndrBuffer.dec_ndr_short();
        _homeDirectoryDrive.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int homeDirectoryDrivePtr = ndrBuffer.dec_ndr_long();

        // logonCount (short)
        ndrBuffer.dec_ndr_short();
        // badPasswordCount (short)
        ndrBuffer.dec_ndr_short();
		// userId (int)
        ndrBuffer.dec_ndr_long();
        // primaryGroupId (int)
        ndrBuffer.dec_ndr_long();

        int _groupCount = ndrBuffer.dec_ndr_long();

        int groupIdsPtr = ndrBuffer.dec_ndr_long();
		// userFlags (int)
        ndrBuffer.dec_ndr_long();

        int userSessionKeyI = ndrBuffer.index;

        ndrBuffer.advance(16);

        _logonServer.length = (short) ndrBuffer.dec_ndr_short();
        _logonServer.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int logonServerPtr = ndrBuffer.dec_ndr_long();

        _logonDomainName.length = (short) ndrBuffer.dec_ndr_short();
        _logonDomainName.maximum_length = (short) ndrBuffer.dec_ndr_short();

        int logonDomainNamePtr = ndrBuffer.dec_ndr_long();

        int logonDomainPtr = ndrBuffer.dec_ndr_long();

        ndrBuffer.advance(40);

        if (effectiveNamePtr > 0) {
            decodeUnicodeString(ndrBuffer, _effectiveName);
        }

        if (fullNamePtr > 0) {
            decodeUnicodeString(ndrBuffer, _fullName);
        }

        if (logonScriptPtr > 0) {
            decodeUnicodeString(ndrBuffer, _logonScript);
        }

        if (profilePathPtr > 0) {
            decodeUnicodeString(ndrBuffer, _profilePath);
        }

        if (homeDirectoryPtr > 0) {
            decodeUnicodeString(ndrBuffer, _homeDirectory);
        }

        if (homeDirectoryDrivePtr > 0) {
            decodeUnicodeString(ndrBuffer, _homeDirectoryDrive);
        }

        if (groupIdsPtr > 0) {
            GroupMembership[] _groupIds = new GroupMembership[_groupCount];

            ndrBuffer = ndrBuffer.deferred;

            int groupIdsS = ndrBuffer.dec_ndr_long();
            int groupIdsI = ndrBuffer.index;

            ndrBuffer.advance(8 * groupIdsS);

            ndrBuffer = ndrBuffer.derive(groupIdsI);

            for (int i = 0; i < groupIdsS; i++) {
                if (_groupIds[i] == null) {
                    _groupIds[i] = new GroupMembership();
                }

                _groupIds[i].decode(ndrBuffer);
            }
        }

        ndrBuffer = ndrBuffer.derive(userSessionKeyI);

        // userSessionKey (byte[16])
        for (int i = 0; i < 16; i++) {
            ndrBuffer.dec_ndr_small();
        }

        if (logonServerPtr > 0) {
            decodeUnicodeString(ndrBuffer, _logonServer);
        }

        if (logonDomainNamePtr > 0) {
            decodeUnicodeString(ndrBuffer, _logonDomainName);
        }

        if (logonDomainPtr > 0) {
            ndrBuffer = ndrBuffer.deferred;

            _logonDomain.decode(ndrBuffer);
        }
    }

    @Override
    public void encode(NdrBuffer ndrBuffer) {
    }

    protected void decodeUnicodeString(
            NdrBuffer ndrBuffer, rpc.unicode_string string) {

        ndrBuffer = ndrBuffer.deferred;

        int bufferS = ndrBuffer.dec_ndr_long();

        ndrBuffer.dec_ndr_long();

        int bufferL = ndrBuffer.dec_ndr_long();
        int bufferI = ndrBuffer.index;

        ndrBuffer.advance(2 * bufferL);

        if (string.buffer == null) {
            string.buffer = new short[bufferS];
        }

        ndrBuffer = ndrBuffer.derive(bufferI);

        for (int i = 0; i < bufferL; i++) {
            string.buffer[i] = (short) ndrBuffer.dec_ndr_short();
        }
    }

}