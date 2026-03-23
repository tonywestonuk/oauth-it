package com.oauth_it.model;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;

public class StoredCredential {
    public final ByteArray credentialId;
    public final ByteArray userHandle;     // userId bytes (UTF-8)
    public final ByteArray publicKeyCose;
    public final long signCount;
    public final String username;

    public StoredCredential(ByteArray credentialId, ByteArray userHandle,
                            ByteArray publicKeyCose, long signCount, String username) {
        this.credentialId = credentialId;
        this.userHandle = userHandle;
        this.publicKeyCose = publicKeyCose;
        this.signCount = signCount;
        this.username = username;
    }

    /** Format: credentialId(b64url):userHandle(b64url):publicKeyCose(b64url):signCount:username */
    public String toLine() {
        return credentialId.getBase64Url()
                + ":" + userHandle.getBase64Url()
                + ":" + publicKeyCose.getBase64Url()
                + ":" + signCount
                + ":" + username;
    }

    public static StoredCredential fromLine(String line) {
        String[] p = line.split(":", 5);
        try {
            return new StoredCredential(
                    ByteArray.fromBase64Url(p[0]),
                    ByteArray.fromBase64Url(p[1]),
                    ByteArray.fromBase64Url(p[2]),
                    Long.parseLong(p[3]),
                    p[4]);
        } catch (Base64UrlException e) {
            throw new RuntimeException("Invalid credential line: " + line, e);
        }
    }
}
