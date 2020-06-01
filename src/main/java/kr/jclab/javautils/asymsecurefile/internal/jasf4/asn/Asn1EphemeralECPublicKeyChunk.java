/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.util.Enumeration;

public class Asn1EphemeralECPublicKeyChunk extends Asn1AbstractChunk<SubjectPublicKeyInfo> {
    public static final ChunkId CHUNK_ID = ChunkId.EphemeralECPublicKey;
    public static final Asn1AbstractChunkDataFactory<SubjectPublicKeyInfo> FACTORY = SubjectPublicKeyInfo::getInstance;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1EphemeralECPublicKeyChunk.class, Asn1EphemeralECPublicKeyChunk::new);
    }

    public Asn1EphemeralECPublicKeyChunk(SubjectPublicKeyInfo data) {
        super(FACTORY, CHUNK_ID, new Asn1ChunkFlags(), data);
    }

    public Asn1EphemeralECPublicKeyChunk(Enumeration e) {
        super(FACTORY, e);
    }

    public static Asn1EphemeralECPublicKeyChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1EphemeralECPublicKeyChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1EphemeralECPublicKeyChunk)
        {
            return (Asn1EphemeralECPublicKeyChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1EphemeralECPublicKeyChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }
}
