/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.signedsecurefile;

import kr.jclab.javautils.asymsecurefile.UserChunk;
import kr.jclab.javautils.asymsecurefile.ValidateFailedException;
import kr.jclab.javautils.asymsecurefile.internal.InputStreamDelegate;
import kr.jclab.javautils.asymsecurefile.internal.SignatureHeader;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class SignedSecureFileInputStreamDelegate extends InputStreamDelegate {
    private transient Key asymmetricKey = null;
    private transient String secretKey = null;

    private SignedSecureFileInputStream realInputStream = null;

    public SignedSecureFileInputStreamDelegate(InputStream inputStream, Provider securityProvider, SignatureHeader signatureHeader) {
        super(inputStream, securityProvider, signatureHeader);
    }

    @Override
    public void setAsymKey(Key key) {
        this.asymmetricKey = key;
    }

    @Override
    public void setAsymKey(KeyPair keyPair) {
        this.asymmetricKey = keyPair.getPublic();
    }

    @Override
    public void setAuthKey(byte[] authKey) {
        try {
            this.secretKey = new String(authKey, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private void start() throws IOException {
        if(this.realInputStream != null)
            return ;

        if(!(this.asymmetricKey instanceof PublicKey)) {
            throw new RuntimeException("Need public key");
        }
        if(this.secretKey == null) {
            this.secretKey = "";
        }
        try {
            this.realInputStream = new SignedSecureFileInputStream(this.inputStream, this.asymmetricKey, this.secretKey, this.signatureHeader);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IOException(e);
        } catch (IntegrityException e) {
            throw new ValidateFailedException(e);
        }
    }

    @Override
    public int headerRead() throws IOException {
        if(this.asymmetricKey != null && this.secretKey != null) {
            start();
        }
        return 0;
    }

    @Override
    public UserChunk getUserChunk(short code) {
        return null;
    }

    @Override
    public boolean isDataReadable() {
        return true;
    }

    @Override
    public int available() throws IOException {
        return this.realInputStream.available();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        start();
        return this.realInputStream.read(b, off, len);
    }

    @Override
    public void validate() throws IOException {
        if(this.realInputStream == null) {
            throw new ValidateFailedException("");
        }
    }
}
