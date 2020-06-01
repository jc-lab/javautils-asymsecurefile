/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import kr.jclab.javautils.asymsecurefile.internal.OutputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.OutputStreamOptions;
import kr.jclab.javautils.asymsecurefile.internal.VersionRouter;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;

public class AsymSecureFileOutputStream extends OutputStream {
    private final OutputStreamOptions options;
    private final OutputStreamDelegate delegate;

    private boolean inited = false;
    private boolean finished = false;

    private static Provider orDefaultProvider(Provider provider) {
        if(provider == null) {
            return BCProviderSingletone.getProvider();
        }
        return provider;
    }

    private AsymSecureFileOutputStream(OutputStreamOptions options) {
        try {
            this.options = options;
            this.delegate = VersionRouter
                    .findWriterDelegate(options.getVersion())
                    .getDeclaredConstructor(OutputStreamOptions.class)
                    .newInstance(options);
            this.checkAndInit(false);
        } catch (IOException | InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            // Never occur
            throw new RuntimeException(e);
        }
    }

    public AsymSecureFileOutputStream(AsymSecureFileVersion version, OperationType operationType, OutputStream outputStream, Provider securityProvider) throws NotSupportVersionException {
        this(new OutputStreamOptions(
                version, operationType, outputStream, false, orDefaultProvider(securityProvider), null, null
        ));
    }

    public AsymSecureFileOutputStream(OperationType operationType, OutputStream outputStream, Provider securityProvider) {
        this(new OutputStreamOptions(
                AsymSecureFileVersion.LATEST, operationType, outputStream, false, orDefaultProvider(securityProvider), null, null
        ));
    }

    @SuppressWarnings("unused")
    public AsymSecureFileOutputStream(OperationType operationType, OutputStream outputStream) {
        this(operationType, outputStream, BCProviderSingletone.getProvider());
    }

    /**
     * Set local private key for PUBLIC_ENCRYPT.
     * Must be set before setAsymKey.
     */
    public void setLocalPrivateKey(PrivateKey privateKey) throws IOException {
        if(this.delegate.getOperationType() != OperationType.PUBLIC_ENCRYPT) {
            throw new IOException("The local private key is only used in PUBLIC_ENCRYPT.");
        }
        this.options.setLocalPrivateKey(privateKey);
    }

    /**
     * Set asymmetric key with auto algorithm detection
     *
     * @param keyPair keyPair
     */
    public void setAsymKey(@NotNull KeyPair keyPair) throws IOException {
        if(this.delegate.getOperationType() == OperationType.SIGN) {
            this.options.setAsymKey(keyPair.getPrivate());
        }else if(this.delegate.getOperationType() == OperationType.PUBLIC_ENCRYPT) {
            this.options.setAsymKey(keyPair.getPublic());
        }
        this.options.setAsymAlgorithm(null);
        checkAndInit(false);
    }

    /**
     * Set asymmetric key without auto algorithm detection
     *
     * @param keyPair keyPair
     * @param asymAlgorithm asymAlgorithm
     * @throws IOException
     * @deprecated use jasf version 4 and setAsymKey instead of AsymAlgorithm.
     */
    public void setAsymKey(@NotNull KeyPair keyPair, AsymAlgorithmOld asymAlgorithm) throws IOException {
        if(this.delegate.getOperationType() == OperationType.SIGN) {
            this.options.setAsymKey(keyPair.getPrivate());
        }else if(this.delegate.getOperationType() == OperationType.PUBLIC_ENCRYPT) {
            this.options.setAsymKey(keyPair.getPublic());
        }
        this.options.setAsymAlgorithm(asymAlgorithm);
        checkAndInit(false);
    }

    /**
     * Set asymmetric key with auto algorithm detection
     *
     * @param key key
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull Key key) throws IOException {
        this.options.setAsymKey(key);
        this.options.setAsymAlgorithm(null);
        checkAndInit(false);
    }

    /**
     * Set asymmetric key without auto algorithm detection
     *
     * @param key key
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull Key key, AsymAlgorithmOld asymAlgorithm) throws IOException {
        this.options.setAsymKey(key);
        this.options.setAsymAlgorithm(asymAlgorithm);
        checkAndInit(false);
    }

    @SuppressWarnings("unused")
    public void setDataAlgorithm(DataAlgorithm dataAlgorithm) throws IOException {
        this.options.setDataAlgorithm(dataAlgorithm);
        checkAndInit(false);
    }

    @SuppressWarnings("unused")
    public void setAuthKey(byte[] authKey) throws IOException {
        this.options.setAuthKey(authKey);
        checkAndInit(false);
    }

    public void enableTimestamping(boolean enabled, String tsaLocation) {
        if(enabled) {
            this.options.enableTimestamping(tsaLocation);
        }else{
            this.options.enableTimestamping(null);
        }
    }

    @Override
    public void write(byte[] cbuf, int off, int len) throws IOException {
        checkAndInit(true);
        this.delegate.write(cbuf, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        checkAndInit(true);
        byte[] d = new byte[] { (byte)b };
        this.delegate.write(d, 0, 1);
    }

    @Override
    public void flush() throws IOException {
        this.options.getOutputStream().flush();
    }

    @SuppressWarnings("unused")
    public void finish() throws IOException {
        if(!this.finished) {
            this.delegate.finish();
            this.finished = true;
        }
    }

    @Override
    public void close() throws IOException {
        if(!this.finished) {
            this.delegate.finish();
            this.finished = true;
        }
        this.options.getOutputStream().close();
    }

    public void setUserChunk(UserChunk userChunk) throws IOException {
        this.delegate.setUserChunk(userChunk);
    }

    @SuppressWarnings("unused")
    private void checkAndInit(boolean force) throws IOException {
        if(this.inited)
            return ;
        if(this.options.getAsymKey() != null && this.options.getDataAlgorithm() != null && this.options.getAuthKey() != null) {
            this.delegate.init();
            this.inited = true;
        }else if(force) {
            if(this.options.getAsymKey() == null) {
                throw new IOException("Empty asymKey");
            }
            if(this.options.getDataAlgorithm() == null) {
                throw new IOException("Empty dataAlgorithm");
            }
            if(this.options.getAuthKey() == null) {
                throw new IOException("Empty authKey");
            }
        }
    }

    public static Builder sign(OutputStream outputStream) {
        return new Builder(AsymSecureFileVersion.JASF_4_1, OperationType.SIGN, outputStream);
    }

    public static Builder publicEncrypt(OutputStream outputStream) {
        return new Builder(AsymSecureFileVersion.JASF_4_1, OperationType.PUBLIC_ENCRYPT, outputStream);
    }

    public static Builder jasf4Sign(OutputStream outputStream) {
        return new Builder(AsymSecureFileVersion.JASF_4_1, OperationType.SIGN, outputStream);
    }

    public static Builder jasf4PublicEncrypt(OutputStream outputStream) {
        return new Builder(AsymSecureFileVersion.JASF_4_1, OperationType.PUBLIC_ENCRYPT, outputStream);
    }

    public static class Builder {
        final AsymSecureFileVersion version;
        final OperationType operationType;
        final OutputStream outputStream;
        Provider securityProvider = null;
        boolean excludeHeader = false;
        byte[] authKey = null;
        String tsaLocation = null;
        Key asymKey = null;
        KeyPair keyPair = null;

        public Builder(AsymSecureFileVersion version, OperationType operationType, OutputStream outputStream) {
            this.version = version;
            this.operationType = operationType;
            this.outputStream = outputStream;
        }

        public Builder securityProvider(Provider securityProvider) {
            this.securityProvider = securityProvider;
            return this;
        }

        public Builder excludeHeader(boolean excludeHeader) {
            this.excludeHeader = excludeHeader;
            return this;
        }

        public Builder authKey(byte[] authKey) {
            this.authKey = authKey;
            return this;
        }

        public Builder authKey(String authKey) {
            this.authKey = authKey.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public Builder asymKey(Key key) {
            this.asymKey = key;
            return this;
        }

        public Builder asymKey(KeyPair keyPair) {
            this.keyPair = keyPair;
            return this;
        }

        public Builder enableTimestamping(String tsaLocation) {
            this.tsaLocation = tsaLocation;
            return this;
        }

        public AsymSecureFileOutputStream build() throws NotSupportAlgorithmException {
            OutputStreamOptions options = new OutputStreamOptions(
                    (this.version == null) ?
                            AsymSecureFileVersion.LATEST : this.version,
                    this.operationType,
                    this.outputStream,
                    this.excludeHeader,
                    (this.securityProvider == null) ?
                            BCProviderSingletone.getProvider() : this.securityProvider,
                    this.authKey,
                    this.tsaLocation
            );
            if (this.keyPair != null) {
                options.setAsymKey(this.keyPair);
            }else{
                options.setAsymKey(this.asymKey);
            }
            return new AsymSecureFileOutputStream(options);
        }
    }
}
