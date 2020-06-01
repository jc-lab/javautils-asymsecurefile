/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.OperationType;
import kr.jclab.javautils.asymsecurefile.UserChunk;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;

public abstract class OutputStreamDelegate {
    protected OutputStreamOptions options;
    protected final OperationType operationType;
    private final OutputStream realOutputStream;
    protected final OutputStream outputStream;
    protected final Provider securityProvider;
    private long writtenBytes = 0;

    public OutputStreamDelegate(OutputStreamOptions options) {
        this.options = options;
        this.operationType = options.getOperationType();
        this.securityProvider = options.getSecurityProvider();
        this.realOutputStream = options.getOutputStream();
        this.outputStream = new OutputStream() {
            public long getWrittenBytes() {
                return writtenBytes;
            }

            @Override
            public void write(int b) throws IOException {
                realOutputStream.write(b);
                writtenBytes += 1;
            }

            @Override
            public void write(byte b[]) throws IOException {
                realOutputStream.write(b);
                writtenBytes += b.length;
            }
            @Override
            public void write(byte b[], int off, int len) throws IOException {
                realOutputStream.write(b, off, len);
                writtenBytes += len;
            }
            @Override
            public void flush() throws IOException {
                realOutputStream.flush();
            }
            @Override
            public void close() throws IOException {
                realOutputStream.close();
            }
        };
    }

    public long getWrittenBytes() {
        return this.writtenBytes;
    }

    public final OperationType getOperationType() {
        return this.operationType;
    }

    public abstract void init() throws IOException;

    public abstract void write(byte[] buffer, int off, int size) throws IOException;
    public abstract void finish() throws IOException;
    public abstract void setUserChunk(UserChunk chunk) throws IOException;
}
