/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.util.Enumeration;

public class Asn1EncryptedChunk extends Asn1AbstractChunk<ASN1OctetString> {
    public static final Asn1AbstractChunkDataFactory<ASN1OctetString> FACTORY = ASN1OctetString::getInstance;

    private static Asn1ChunkFlags convertFlags(Asn1ChunkFlags input) {
        Asn1ChunkFlags flags = new Asn1ChunkFlags(input.getValue());
        flags.encryptWithAuthKey(true);
        return flags;
    }

    protected Asn1EncryptedChunk(int chunkId, Asn1ChunkFlags flags, byte[] data) {
        super(FACTORY, chunkId, flags, new DEROctetString(data));
    }

    protected Asn1EncryptedChunk(int chunkId, Asn1ChunkFlags flags, ASN1OctetString data) {
        super(FACTORY, chunkId, flags, data);
    }

    public Asn1EncryptedChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public byte[] getBytesData() {
        return this.data.getOctets();
    }

    public static Asn1EncryptedChunk encryptChunk(Asn1ObjectChunkBase chunk, Cipher cipher) throws IOException, BadPaddingException, IllegalBlockSizeException {
        return new Asn1EncryptedChunk(
                chunk.getRawId(),
                chunk.getFlags(),
                cipher.doFinal(chunk.dataToASN1Primitive().getEncoded())
        );
    }

    public static Asn1EncryptedChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1EncryptedChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1EncryptedChunk)
        {
            return (Asn1EncryptedChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1EncryptedChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
