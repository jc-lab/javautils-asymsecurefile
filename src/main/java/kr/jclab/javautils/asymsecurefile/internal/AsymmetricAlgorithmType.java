package kr.jclab.javautils.asymsecurefile.internal;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum AsymmetricAlgorithmType {
    rsa(0x01),
    ec(0x02),

    dsa(0x11),
    edwards(0x12),

    dh(0x21),
    x448(0x22),
    x25519(0x23);

    private static Map<Integer, AsymmetricAlgorithmType> MAP;
    static {
        MAP = Collections.unmodifiableMap(new HashMap<Integer, AsymmetricAlgorithmType>() {{
            for(AsymmetricAlgorithmType item : AsymmetricAlgorithmType.values()) {
                put(item.getValue(), item);
            }
        }});
    }

    private final int value;
    AsymmetricAlgorithmType(int value) {
        this.value = value;
    }
    public int getValue() {
        return this.value;
    }

    public static AsymmetricAlgorithmType fromValue(int value) {
        return MAP.get(value);
    }
}

