package kr.jclab.javautils.asymsecurefile;

public enum AsymSecureFileVersion {
    V1(1, 0),
    V2(2, 0),
    JASF_3(3, 0),
    JASF_4_1(4, 1),

    LATEST(JASF_4_1);

    private final int version;
    private final int subVersion;
    AsymSecureFileVersion(int version, int subVersion) {
        this.version = version;
        this.subVersion = subVersion;
    }
    AsymSecureFileVersion(AsymSecureFileVersion o) {
        this.version = o.version;
        this.subVersion = o.subVersion;
    }
    public int getVersion() {
        return version;
    }
    public int getSubVersion() {
        return this.subVersion;
    }
}
