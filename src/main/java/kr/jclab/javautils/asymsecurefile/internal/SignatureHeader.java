/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal;

import kr.jclab.javautils.asymsecurefile.InvalidFileException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class SignatureHeader {
    public static final byte[] SIGNATURE = {(byte)0x0a, (byte)0x9b, (byte)0xd8, (byte)0x13, (byte)0x97, (byte)0x1f, (byte)0x93, (byte)0xe8, (byte)0x6b, (byte)0x7e, (byte)0xdf, (byte)0x05, (byte)0x70, (byte)0x54, (byte)0x02};
    public static final int SIGNATURE_SIZE = SIGNATURE.length + 1;

    private byte[] signature = new byte[SIGNATURE.length];
    private byte   version = 0;

    public SignatureHeader() {

    }

    /**
     * Should inputStream.available() &gt; {@link #SIGNATURE_SIZE}
     * @param inputStream
     */
    public void read(InputStream inputStream) throws IOException {
        byte[] buffer;
        buffer = new byte[SIGNATURE_SIZE];
        inputStream.read(buffer);
        this.signature = Arrays.copyOf(buffer, SIGNATURE.length);
        this.version = buffer[15];

        if(!Arrays.equals(this.signature, SIGNATURE))
            throw new InvalidFileException("Invalid file signature");
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte getVersion() {
        return version;
    }
}
