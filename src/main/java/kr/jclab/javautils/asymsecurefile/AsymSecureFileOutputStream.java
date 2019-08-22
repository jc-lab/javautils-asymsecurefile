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
import kr.jclab.javautils.asymsecurefile.internal.VersionRouter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;

public class AsymSecureFileOutputStream extends OutputStream {
    private final OutputStream outputStream;
    private final OutputStreamDelegate delegate;

    private boolean inited = false;
    private boolean finished = false;

    private transient Key asymKey = null;
    private transient PrivateKey localPrivateKey = null;
    private AsymAlgorithm asymAlgorithm = null;
    private byte[] authKey = null;
    private DataAlgorithm dataAlgorithm = DataAlgorithm.AES256_GCM;

    public AsymSecureFileOutputStream(OperationType operationType, OutputStream outputStream, Provider securityProvider) {
        this.outputStream = outputStream;
        if(securityProvider == null)
            securityProvider = BCProviderSingletone.getProvider();
        try {
            this.delegate = VersionRouter.getWriterDelegate().getDeclaredConstructor(OperationType.class, OutputStream.class, Provider.class).newInstance(operationType, outputStream, securityProvider);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            // Never occur
            throw new RuntimeException(e);
        }
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
        this.localPrivateKey = privateKey;
    }

    /**
     * Set asymmetric key with auto algorithm detection
     *
     * @param keyPair keyPair
     */
    public void setAsymKey(@NotNull KeyPair keyPair) throws IOException {
        if(this.delegate.getOperationType() == OperationType.SIGN) {
            this.asymKey = keyPair.getPrivate();
        }else if(this.delegate.getOperationType() == OperationType.PUBLIC_ENCRYPT) {
            this.asymKey = keyPair.getPublic();
        }
        this.asymAlgorithm = null;
        checkAndInit(false);
    }

    /**
     * Set asymmetric key without auto algorithm detection
     *
     * @param keyPair keyPair
     * @param asymAlgorithm asymAlgorithm
     * @throws IOException
     */
    public void setAsymKey(@NotNull KeyPair keyPair, AsymAlgorithm asymAlgorithm) throws IOException {
        if(this.delegate.getOperationType() == OperationType.SIGN) {
            this.asymKey = keyPair.getPrivate();
        }else if(this.delegate.getOperationType() == OperationType.PUBLIC_ENCRYPT) {
            this.asymKey = keyPair.getPublic();
        }
        this.asymAlgorithm = asymAlgorithm;
        checkAndInit(false);
    }

    /**
     * Set asymmetric key with auto algorithm detection
     *
     * @param key key
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull Key key) throws IOException {
        this.asymKey = key;
        this.asymAlgorithm = null;
        checkAndInit(false);
    }

    /**
     * Set asymmetric key without auto algorithm detection
     *
     * @param key key
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull Key key, AsymAlgorithm asymAlgorithm) throws IOException {
        this.asymKey = key;
        this.asymAlgorithm = asymAlgorithm;
        checkAndInit(false);
    }

    @SuppressWarnings("unused")
    public void setDataAlgorithm(DataAlgorithm dataAlgorithm) throws IOException {
        this.dataAlgorithm = dataAlgorithm;
        checkAndInit(false);
    }

    @SuppressWarnings("unused")
    public void setAuthKey(byte[] authKey) throws IOException {
        this.authKey = authKey;
        checkAndInit(false);
    }

    public void enableTimestamping(boolean enabled, String tsaLocation) {
        if(enabled) {
            this.delegate.enableTimestamping(tsaLocation);
        }else{
            this.delegate.enableTimestamping(null);
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
        outputStream.flush();
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
        outputStream.close();
    }

    public void setUserChunk(UserChunk userChunk) throws IOException {
        this.delegate.setUserChunk(userChunk);
    }

    @SuppressWarnings("unused")
    private void checkAndInit(boolean force) throws IOException {
        if(this.inited)
            return ;
        if(this.asymKey != null && this.dataAlgorithm != null && this.authKey != null) {
            this.delegate.init(this.asymKey, this.asymAlgorithm, this.dataAlgorithm, this.authKey, this.localPrivateKey);
            this.asymKey = null;
            this.authKey = null;
            this.localPrivateKey = null;
            this.inited = true;
        }else if(force) {
            if(this.asymKey == null) {
                throw new IOException("Empty asymKey");
            }
            if(this.dataAlgorithm == null) {
                throw new IOException("Empty dataAlgorithm");
            }
            if(this.authKey == null) {
                throw new IOException("Empty authKey");
            }
        }
    }
}
