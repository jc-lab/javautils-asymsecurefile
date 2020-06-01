/*
 * AsymSecureFile
 * https://ablog.jc-lab.net/186
 *
 *  This software may be modified and distributed under the terms
 *  of the Apache License 2.0.  See the LICENSE file for details.
 */

package kr.jclab.javautils.asymsecurefile.internal.jasf4;

import kr.jclab.javautils.asymsecurefile.internal.BCProviderSingletone;
import kr.jclab.javautils.asymsecurefile.internal.jasf4.asn.Asn1AuthKeyCheckChunk;
import kr.jclab.javautils.asymsecurefile.internal.utils.HashAlgorithms;
import kr.jclab.javautils.asymsecurefile.internal.utils.HkdfUtils;
import kr.jclab.javautils.asymsecurefile.internal.utils.Pbkdf2Utils;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

public class Jasf4AuthKeyUtils {
    public static class DerivedKeys {
        public final byte[] encryptKey;
        public final byte[] macKey;

        public DerivedKeys(byte[] encryptKey, byte[] macKey) {
            this.encryptKey = encryptKey;
            this.macKey = macKey;
        }
    }

    public static DerivedKeys deriveKeys(byte[] authKey) {
        byte[] authKeyDerivationPool = HkdfUtils.generateKey(
                HashAlgorithms.findByOid(NISTObjectIdentifiers.id_sha256.getId()),
                authKey,
                64,
                null);
        return new DerivedKeys(
                Arrays.copyOfRange(authKeyDerivationPool, 0, 32),
                Arrays.copyOfRange(authKeyDerivationPool, 32, 64)
        );
    }

    public static Asn1AuthKeyCheckChunk makeAuthKeyCheck(byte[] key) {
        Provider provider = BCProviderSingletone.getProvider();
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        PBKDF2Params params = new PBKDF2Params(
                salt,
                4000,
                32,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE)
        );
        byte[] generated = Pbkdf2Utils.generateKey(
                params,
                key,
                provider);
        return new Asn1AuthKeyCheckChunk(params, generated);
    }

    public static boolean checkAuthKeyChunk(Asn1AuthKeyCheckChunk chunk, byte[] authKey) {
        Provider provider = BCProviderSingletone.getProvider();
        int keyLength = (chunk.getParams().getKeyLength() != null) ? chunk.getParams().getKeyLength().intValue() : chunk.getKey().length;
        if (keyLength > 4096)
            return false;
        PBKDF2Params params = new PBKDF2Params(
                chunk.getParams().getSalt(),
                chunk.getParams().getIterationCount().intValue(),
                keyLength,
                chunk.getParams().getPrf()
        );
        byte[] generated = Pbkdf2Utils.generateKey(
                params,
                authKey,
                provider);
        return Arrays.equals(generated, chunk.getKey());
    }

}
