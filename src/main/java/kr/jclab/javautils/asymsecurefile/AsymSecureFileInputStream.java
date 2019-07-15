/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile;

import kr.jclab.javautils.asymsecurefile.internal.InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.SignatureHeader;
import kr.jclab.javautils.asymsecurefile.internal.VersionRouter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.security.KeyPair;
import java.security.Provider;

public class AsymSecureFileInputStream extends InputStream {
    private final InputStream inputStream;
    private final Provider securityProvider;
    private InputStreamDelegate delegate = null;

    private final SignatureHeader signatureHeader = new SignatureHeader();
    private boolean signatureHeaderReady = false;

    public AsymSecureFileInputStream(InputStream inputStream, Provider securityProvider) {
        this.inputStream = inputStream;
        if(securityProvider == null)
            securityProvider = new BouncyCastleProvider();
        this.securityProvider = securityProvider;
    }

    @SuppressWarnings("unused")
    public AsymSecureFileInputStream(InputStream inputStream) {
        this(inputStream, new BouncyCastleProvider());
    }

    /**
     * Read header
     *
     * @return The following return values can occur:
     *         0 : Header reading is complete. The data is ready to be read.
     *         1 : Need more header reads.
     *
     * @throws IOException If an I/O error occurs
     */
    public int headerRead() throws IOException {
        if(!this.signatureHeaderReady) {
            if (this.inputStream.available() >= SignatureHeader.SIGNATURE_SIZE) {
                this.signatureHeader.read(this.inputStream);
                try {
                    this.delegate = VersionRouter.findReaderDelegate(this.signatureHeader.getVersion()).getDeclaredConstructor(new Class[] {InputStream.class, Provider.class, SignatureHeader.class}).newInstance(this.inputStream, this.securityProvider, this.signatureHeader);
                } catch (InstantiationException | IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
                    // Never occur
                    throw new RuntimeException(e);
                }
                this.signatureHeaderReady = true;
            }
        }
        if(this.signatureHeaderReady) {
            return this.delegate.headerRead();
        }
        return 1;
    }

    /**
     * Set authKey
     *
     * @param authKey authKey
     */
    @SuppressWarnings("unused")
    public void setAuthKey(@NotNull byte[] authKey) {
        this.delegate.setAuthKey(authKey);
    }

    /**
     * Set asymmetric key
     *
     * @param key asymKey
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull Key key) {
        this.delegate.setAsymKey(key);
    }

    /**
     * Set asymmetric key
     *
     * @param keyPair asymKeyPair
     */
    @SuppressWarnings("unused")
    public void setAsymKey(@NotNull KeyPair keyPair) {
        this.delegate.setAsymKey(keyPair);
    }

    /**
     * Reads characters into a portion of an array
     *
     * @param cbuf Destination buffer
     * @param off  Offset at which to start storing characters
     * @param len  Maximum number of characters to read
     *
     * @return The number of characters read, or -1 if the end of the
     *         stream has been reached
     *
     * @throws IOException If an I/O error occurs
     */
    @Override
    public int read(byte[] cbuf, int off, int len) throws IOException {
        if(!this.delegate.isDataReadable()) {
            throw new IOException("Not readable yet");
        }
        return this.delegate.read(cbuf, off, len);
    }

    @Override
    public int read(byte[] b) throws IOException {
        if(!this.delegate.isDataReadable()) {
            throw new IOException("Not readable yet");
        }
        return this.delegate.read(b, 0, b.length);
    }

    @Override
    public int read() throws IOException {
        if(!this.delegate.isDataReadable()) {
            throw new IOException("Not readable yet");
        }
        byte[] d = new byte[1];
        int rc = this.delegate.read(d, 0, 1);
        if(rc < 0)
            return rc;
        return d[0];
    }

    @Override
    public void close() throws IOException {
        this.inputStream.close();
    }
}
