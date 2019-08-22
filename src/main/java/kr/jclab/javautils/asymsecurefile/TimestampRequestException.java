package kr.jclab.javautils.asymsecurefile;

import java.io.IOException;

public class TimestampRequestException extends IOException {
    public TimestampRequestException() {
        super();
    }

    public TimestampRequestException(String s) {
        super(s);
    }

    public TimestampRequestException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public TimestampRequestException(Throwable throwable) {
        super(throwable);
    }
}
