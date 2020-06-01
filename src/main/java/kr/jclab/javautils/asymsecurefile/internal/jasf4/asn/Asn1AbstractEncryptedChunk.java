/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import kr.jclab.javautils.asymsecurefile.internal.jasf4.ChunkResolver;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

public class Asn1AbstractEncryptedChunk<T extends Asn1ObjectChunkBase> extends Asn1EncryptedChunk {
    private final ChunkResolver.IGetInstanceType<T> getInstanceFunction;

    public Asn1AbstractEncryptedChunk(ChunkResolver.IGetInstanceType<T> getInstanceFunction, int chunkId, Asn1ChunkFlags flags, ASN1OctetString data) {
        super(chunkId, flags, data);
        this.getInstanceFunction = getInstanceFunction;
    }

    public T decrypt(Cipher cipher) throws IOException {
        CipherInputStream cipherInputStream = new CipherInputStream(this.data.getOctetStream(), cipher);
        ASN1InputStream asn1InputStream = new ASN1InputStream(cipherInputStream);
        ArrayList<Object> list = new ArrayList<>(3);
        list.add(new ASN1Integer(this.getRawId()));
        list.add(new ASN1Integer(this.getFlags().getValue()));
        list.add(asn1InputStream.readObject());
        return getInstanceFunction.getInstance(Collections.enumeration(list));
    }
}
