package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.*;

import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;

public class OutputStreamOptions {
    private final AsymSecureFileVersion version;
    private final OperationType operationType;
    private final OutputStream outputStream;
    private final boolean excludeHeader;
    private final Provider securityProvider;
    private byte[] authKey;

    private AsymmetricKeyObject asymKey = null;
    private PrivateKey localPrivateKey = null;
    private AsymAlgorithmOld asymAlgorithm = null;
    private DataAlgorithm dataAlgorithm = DataAlgorithm.AES256_GCM;

    private String tsaLocation = null;
    private int timestampingTimeout = 3000;

    public OutputStreamOptions(AsymSecureFileVersion version, OperationType operationType, OutputStream outputStream, boolean excludeHeader, Provider securityProvider, byte[] authKey, String tsaLocation) {
        this.version = version;
        this.operationType = operationType;
        this.outputStream = outputStream;
        this.excludeHeader = excludeHeader;
        this.securityProvider = securityProvider;
        this.authKey = authKey;
        this.tsaLocation = tsaLocation;
    }

    public static AsymmetricKeyObject convertToAsymmetricKeyObject(Key key, Provider securityProvider) throws NotSupportAlgorithmException {
        if (key == null) {
            return null;
        }
        return AsymmetricKeyObject.fromKey(key, securityProvider);
    }

    public void setAuthKey(byte[] authKey) {
        if(this.authKey != null) {
            throw new IllegalStateException("The authkey can only be set once");
        }
        this.authKey = authKey;
    }

    public void setAsymKey(Key asymKey) throws NotSupportAlgorithmException {
        if(this.asymKey != null) {
            throw new IllegalStateException("The asymKey can only be set once");
        }
        this.asymKey = convertToAsymmetricKeyObject(asymKey, this.securityProvider);
    }

    public void setLocalPrivateKey(PrivateKey localPrivateKey) {
        if(this.localPrivateKey != null) {
            throw new IllegalStateException("The localPrivateKey can only be set once");
        }
        this.localPrivateKey = localPrivateKey;
    }

    public void setAsymAlgorithm(AsymAlgorithmOld asymAlgorithm) {
        this.asymAlgorithm = asymAlgorithm;
    }

    public void setDataAlgorithm(DataAlgorithm dataAlgorithm) {
        if(this.dataAlgorithm != null) {
            throw new IllegalStateException("The dataAlgorithm can only be set once");
        }
        this.dataAlgorithm = dataAlgorithm;
    }

    public void enableTimestamping(String tsaLocation) {
        this.tsaLocation = tsaLocation;
    }

    public void setTimestampingTimeout(int milliseconds) {
        this.timestampingTimeout = milliseconds;
    }

    public AsymSecureFileVersion getVersion() {
        return this.version;
    }

    public OperationType getOperationType() {
        return this.operationType;
    }

    public OutputStream getOutputStream() {
        return this.outputStream;
    }

    public boolean isExcludeHeader() {
        return this.excludeHeader;
    }

    public Provider getSecurityProvider() {
        return this.securityProvider;
    }

    public byte[] getAuthKey() {
        return this.authKey;
    }

    public AsymmetricKeyObject getAsymKey() {
        return this.asymKey;
    }

    public PrivateKey getLocalPrivateKey() {
        return this.localPrivateKey;
    }

    public AsymAlgorithmOld getAsymAlgorithm() {
        return this.asymAlgorithm;
    }

    public DataAlgorithm getDataAlgorithm() {
        return this.dataAlgorithm;
    }

    public boolean isEnabledTimestamping() {
        return this.tsaLocation != null;
    }

    public String getTsaLocation() {
        return this.tsaLocation;
    }

    public int getTimestampingTimeout() {
        return timestampingTimeout;
    }
}
