/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.signedsecurefile;

import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import kr.jclab.javautils.asymsecurefile.internal.SignatureHeader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public final class SignedSecureFileInputStream extends InputStream {
    private final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    private SignatureHeader signatureHeader = null;

    private InputStream m_stream = null;
    private ByteBuffer m_dataBuffer = null;

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & (byte)0xFF;
            if(stringBuilder.length() > 0)
                stringBuilder.append(" ");
            stringBuilder.append(hexArray[(v >>> 4) & 0xf]);
            stringBuilder.append(hexArray[v & 0xf]);
        }
        return stringBuilder.toString();
    }
    public SignedSecureFileInputStream(@NotNull InputStream inputStream, @NotNull Key asymmetricKey, String secretKey, SignatureHeader signatureHeader) throws IOException, NoSuchAlgorithmException, InvalidKeyException, IntegrityException {
        Cipher dataCipher;
        SecretKey dataKey;
        Header header = new Header(BCProviderSingletone.getProvider());
        header.readHeader(inputStream, asymmetricKey, signatureHeader);
        m_stream = inputStream;

        try {
            byte[] bytesDataKey;
            byte[] dataBuffer;
            int readLen;
            byte[] bytesHmac;
            byte[] decbuf;
            SecretKeySpec signingKey = new SecretKeySpec(secretKey.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            bytesDataKey = mac.doFinal(header.secureHeader.key);
            dataKey = new SecretKeySpec(bytesDataKey, header.dataCipherAlgorithm.getAlgoName().split("/")[0]);
            dataCipher = Cipher.getInstance(header.dataCipherAlgorithm.getAlgoName());
            dataCipher.init(Cipher.DECRYPT_MODE, dataKey, new IvParameterSpec(Header.DATA_IV));

            mac.reset();
            m_dataBuffer = ByteBuffer.allocate(header.secureHeader.datasize);
            dataBuffer = new byte[1024];
            while((readLen = m_stream.read(dataBuffer)) > 0) {
                if((readLen % 16) > 0) {
                    throw new InvalidFileException("file broken");
                }
                decbuf = dataCipher.update(dataBuffer, 0, readLen);
                mac.update(decbuf);
                m_dataBuffer.put(decbuf);
            }
            decbuf = dataCipher.doFinal();
            mac.update(decbuf);
            m_dataBuffer.put(decbuf);
            m_dataBuffer.position(0);

            bytesHmac = mac.doFinal();
            if(!header.secureHeader.equalsHmac(bytesHmac)) {
                throw new InvalidKeyException();
            }
        } catch (BadPaddingException e) {
            throw new InvalidKeyException();
        } catch (java.security.InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e) {
            throw new IOException("Invalid internal error");
        } catch (InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        int readlen;
        int remaining = m_dataBuffer.remaining();
        if(remaining <= 0)
            return -1;
        readlen = Math.min(remaining, b.length);
        m_dataBuffer.get(b, 0, readlen);
        return readlen;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int readlen;
        int remaining = m_dataBuffer.remaining();
        if(remaining <= 0)
            return -1;
        readlen = Math.min(remaining, len);
        m_dataBuffer.get(b, off, readlen);
        return readlen;
    }

    @Override
    public long skip(long n) throws IOException {
        int remaining = m_dataBuffer.remaining();
        long skiplen = (n > remaining) ? remaining : n;
        long count = skiplen;
        while((count--) > 0)
            m_dataBuffer.get();
        return skiplen;
    }

    @Override
    public int available() throws IOException {
        return m_dataBuffer.remaining();
    }

    @Override
    public void close() throws IOException {
        if(m_stream != null) {
            m_stream.close();
            m_stream = null;
        }
    }

    @Override
    public synchronized void mark(int readlimit) {
    }

    @Override
    public synchronized void reset() throws IOException {
        m_dataBuffer.reset();
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public int read() throws IOException {
        return m_dataBuffer.get();
    }
}
