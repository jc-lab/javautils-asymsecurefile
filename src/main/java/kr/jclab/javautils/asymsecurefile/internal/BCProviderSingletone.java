package kr.jclab.javautils.asymsecurefile.internal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BCProviderSingletone {
    private static final class LazyHolder {
        private static final BouncyCastleProvider INSTANCE = new BouncyCastleProvider();
    }

    public static BouncyCastleProvider getProvider() {
        return LazyHolder.INSTANCE;
    }
}
