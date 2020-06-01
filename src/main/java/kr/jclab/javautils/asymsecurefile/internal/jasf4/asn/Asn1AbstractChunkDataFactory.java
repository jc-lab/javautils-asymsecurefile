/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import org.bouncycastle.asn1.ASN1Object;

@FunctionalInterface
public interface Asn1AbstractChunkDataFactory<T extends ASN1Object> {
    T convert(Object o);
}
