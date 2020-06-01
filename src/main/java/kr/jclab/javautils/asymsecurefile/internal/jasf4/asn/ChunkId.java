/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4.asn;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum ChunkId {
    DefaultHeader(0x01),
    AuthKeyCheckData(0x02),
    AsymAlgorithmIdentifier(0x21),
    DataCryptoAlgorithmParameterSpec(0x31),
    DataMacAlgorithm(0x32),
    EphemeralECPublicKey(0x33),
    DataKeyInfo(0x34),
    EncryptedDataKeyInfo(0x35),
    DHCheckData(0x39),
    Data(0x70),
    MacOfEncryptedData(0x72),
    Fingerprint(0x76),
    SignedFingerprint(0x77),
    Timestamp(0x79),
    CustomBegin(0x80);

    private final int value;

    ChunkId(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    private static Map<Integer, ChunkId> MAP;
    static {
        MAP = Collections.unmodifiableMap(new HashMap<Integer, ChunkId>() {{
            for (ChunkId item : ChunkId.values()) {
                put(item.value, item);
            }
        }});
    }

    public static ChunkId fromValue(int value) {
        return MAP.get(value);
    }
}
