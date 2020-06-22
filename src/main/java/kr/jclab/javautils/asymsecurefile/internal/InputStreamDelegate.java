/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.UserChunk;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.Provider;
import java.util.Enumeration;

public abstract class InputStreamDelegate {
    protected final InputStreamOptions options;

    public InputStreamDelegate(InputStreamOptions options) {
        this.options = options;
    }

    public abstract void setAsymKey(Key key);
    public abstract void setAsymKey(KeyPair keyPair);
    public abstract void setAuthKey(byte[] authKey) throws IOException;

    /**
     * headerRead
     *
     * @return
     *  1: continous
     *  0: done
     * @throws IOException error
     */
    public abstract int headerRead() throws IOException;
    public abstract int available() throws IOException;
    public abstract int read(byte[] buffer, int offset, int size) throws IOException;
    public abstract Enumeration<UserChunk> userChunks() throws IOException;
    public abstract UserChunk getUserChunk(short code) throws IOException;
    public abstract boolean isDataReadable();

    public abstract void validate() throws IOException;
    public abstract TimeStampToken getTimestampToken() throws IOException, TSPException;
}
