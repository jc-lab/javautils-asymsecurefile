package kr.jclab.javautils.asymsecurefile.internal;

import java.io.InputStream;
import java.security.Provider;

public class InputStreamOptions {
    private final InputStream inputStream;
    private final Provider securityProvider;
    private SignatureHeader signatureHeader = null;
    private boolean excludeHeader = false;
    private byte[] authKey = null;

    public InputStreamOptions(InputStream inputStream, Provider securityProvider) {
        this.inputStream = inputStream;
        this.securityProvider = securityProvider;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public Provider getSecurityProvider() {
        return securityProvider;
    }

    public SignatureHeader getSignatureHeader() {
        return signatureHeader;
    }

    public void setSignatureHeader(SignatureHeader signatureHeader) {
        this.signatureHeader = signatureHeader;
    }

    public boolean isExcludeHeader() {
        return excludeHeader;
    }

    public void setExcludeHeader(boolean excludeHeader) {
        this.excludeHeader = excludeHeader;
    }

    public byte[] getAuthKey() {
        return authKey;
    }

    public void setAuthKey(byte[] authKey) {
        this.authKey = authKey;
    }
}
