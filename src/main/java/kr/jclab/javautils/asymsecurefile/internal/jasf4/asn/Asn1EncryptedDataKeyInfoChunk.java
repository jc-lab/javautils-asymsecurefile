/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.util.Enumeration;

public class Asn1EncryptedDataKeyInfoChunk extends Asn1AbstractChunk<ASN1OctetString> {
    public static final ChunkId CHUNK_ID = ChunkId.EncryptedDataKeyInfo;
    public static final Asn1AbstractChunkDataFactory<ASN1OctetString> FACTORY = ASN1OctetString::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1EncryptedDataKeyInfoChunk.class, Asn1EncryptedDataKeyInfoChunk::new);
    }

    public Asn1EncryptedDataKeyInfoChunk(byte[] data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), new DEROctetString(data));
    }

    public Asn1EncryptedDataKeyInfoChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1EncryptedDataKeyInfoChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1EncryptedDataKeyInfoChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1EncryptedDataKeyInfoChunk)
        {
            return (Asn1EncryptedDataKeyInfoChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1EncryptedDataKeyInfoChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }

    public byte[] getBytesData() {
        return this.data.getOctets();
    }
}
