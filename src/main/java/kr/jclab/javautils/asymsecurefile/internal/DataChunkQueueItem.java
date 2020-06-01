package kr.jclab.javautils.asymsecurefile.internal;

public class DataChunkQueueItem {
    private final byte[] buffer;
    private int readPosition = 0;
    private int size = 0;

    public DataChunkQueueItem(byte[] buffer, int size) {
        this.size = size;
        this.buffer = buffer;
    }

    public DataChunkQueueItem(byte[] buffer) {
        this.size = buffer.length;
        this.buffer = buffer;
    }

    public byte[] getBuffer() {
        return this.buffer;
    }

    public int readPosition() {
        return this.readPosition;
    }

    public int readRemaining() {
        return this.size - this.readPosition;
    }

    public void incReadPosition(int size) {
        this.readPosition += size;
    }

    public int getSize() {
        return this.size;
    }
}
