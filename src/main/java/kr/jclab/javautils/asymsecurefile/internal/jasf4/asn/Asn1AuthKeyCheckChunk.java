/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;

import java.util.Enumeration;

public class Asn1AuthKeyCheckChunk extends Asn1ObjectChunkBase {
    public static final ChunkId CHUNK_ID = ChunkId.AuthKeyCheckData;

    private final PBKDF2Params params;
    private final byte[] key;

    @ChunkInitializer
    public static void init() {
        ChunkResolver.addChunkClass(CHUNK_ID, Asn1AuthKeyCheckChunk.class, Asn1AuthKeyCheckChunk::new);
    }

    public static Asn1AuthKeyCheckChunk getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static Asn1AuthKeyCheckChunk getInstance(
            Object obj)
    {
        if (obj instanceof Asn1AuthKeyCheckChunk)
        {
            return (Asn1AuthKeyCheckChunk)obj;
        }

        if (obj != null)
        {
            return new Asn1AuthKeyCheckChunk(ASN1Sequence.getInstance(obj).getObjects());
        }

        return null;
    }

    public Asn1AuthKeyCheckChunk(Asn1ChunkFlags flags, PBKDF2Params params, byte[] key) {
        super(CHUNK_ID, flags);
        this.params = params;
        this.key = key;
    }

    public Asn1AuthKeyCheckChunk(PBKDF2Params params, byte[] key) {
        this(new Asn1ChunkFlags(), params, key);
    }

    private Asn1AuthKeyCheckChunk(Enumeration e)
    {
        super(e);
        ASN1Sequence sequence = ASN1Sequence.getInstance(e.nextElement());
        this.params = PBKDF2Params.getInstance(sequence.getObjectAt(0));
        this.key = ASN1OctetString.getInstance(sequence.getObjectAt(1)).getOctets();
    }

    @Override
    public ASN1Object dataToASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.params);
        v.add(new DEROctetString(this.key));
        return new DERSequence(v);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        appendAsString(sb, 0);
        return sb.toString();
    }

    public void appendAsString(StringBuilder sb, int indentLevel) {

        sb.append("{");
        sb.append("\n");
        for (int i = 0; i < indentLevel + 1; i++) {
            sb.append("\t");
        }

        if (params != null) {
            sb.append(",\n");
            for (int i = 0; i < indentLevel + 1; i++) {
                sb.append("\t");
            }
            sb.append("params: ").append(params);
        }

        sb.append(",\n");
        for (int i = 0; i < indentLevel + 1; i++) {
            sb.append("\t");
        }
        if (key != null) {
            sb.append("key: ").append(key);
        }
        else {
            sb.append("key: <empty-required-field>");
        }

        sb.append("\n");
        for (int i = 0; i < indentLevel; i++) {
            sb.append("\t");
        }
        sb.append("}");
    }

    public PBKDF2Params getParams() {
        return params;
    }

    public byte[] getKey() {
        return key;
    }
}

