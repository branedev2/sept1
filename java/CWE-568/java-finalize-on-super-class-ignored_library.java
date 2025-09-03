import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.imageio.stream.FileImageInputStream;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import redis.clients.jedis.Jedis;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import java.util.Properties;

// Security Issue: Failing to call super.finalize() in a finalize() method override can lead to resource leaks
// and memory corruption, as the parent class's cleanup code is not executed.

// True Positive Examples (Vulnerable/Insecure Code)

class bad_case_1 extends FileInputStream {
    private boolean closed = false;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_1(String name) throws IOException {
        super(name);
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (!closed) {
            closed = true;
            close(); // Only closes this resource, but not parent's resources
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_2 extends Socket {
    private HttpClient httpClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_2() throws IOException {
        super();
        this.httpClient = HttpClients.createDefault();
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (httpClient != null) {
            // Close HTTP client resources but forget parent socket resources
            System.out.println("Closing HTTP client resources");
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_3 extends RandomAccessFile {
    private FileChannel channel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_3(String name, String mode) throws IOException {
        super(name, mode);
        this.channel = getChannel();
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (channel != null && channel.isOpen()) {
            channel.close();
        }
        // Missing super.finalize() call which would close the underlying file
    }
}
// {/fact}

class bad_case_4 extends Connection {
    private MongoClient mongoClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_4() {
        this.mongoClient = new MongoClient();
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (mongoClient != null) {
            mongoClient.close();
        }
        // Missing super.finalize() call
    }
    
    // Required overrides for abstract Connection class
    @Override public java.sql.Statement createStatement() throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql) throws SQLException { return null; }
    @Override public String nativeSQL(String sql) throws SQLException { return null; }
    @Override public void setAutoCommit(boolean autoCommit) throws SQLException {}
    @Override public boolean getAutoCommit() throws SQLException { return false; }
    @Override public void commit() throws SQLException {}
    @Override public void rollback() throws SQLException {}
    @Override public void close() throws SQLException {}
    @Override public boolean isClosed() throws SQLException { return false; }
    @Override public java.sql.DatabaseMetaData getMetaData() throws SQLException { return null; }
    @Override public void setReadOnly(boolean readOnly) throws SQLException {}
    @Override public boolean isReadOnly() throws SQLException { return false; }
    @Override public void setCatalog(String catalog) throws SQLException {}
    @Override public String getCatalog() throws SQLException { return null; }
    @Override public void setTransactionIsolation(int level) throws SQLException {}
    @Override public int getTransactionIsolation() throws SQLException { return 0; }
    @Override public java.sql.SQLWarning getWarnings() throws SQLException { return null; }
    @Override public void clearWarnings() throws SQLException {}
    @Override public java.sql.Statement createStatement(int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.util.Map<String, Class<?>> getTypeMap() throws SQLException { return null; }
    @Override public void setTypeMap(java.util.Map<String, Class<?>> map) throws SQLException {}
    @Override public void setHoldability(int holdability) throws SQLException {}
    @Override public int getHoldability() throws SQLException { return 0; }
    @Override public java.sql.Savepoint setSavepoint() throws SQLException { return null; }
    @Override public java.sql.Savepoint setSavepoint(String name) throws SQLException { return null; }
    @Override public void rollback(java.sql.Savepoint savepoint) throws SQLException {}
    @Override public void releaseSavepoint(java.sql.Savepoint savepoint) throws SQLException {}
    @Override public java.sql.Statement createStatement(int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int autoGeneratedKeys) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int[] columnIndexes) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, String[] columnNames) throws SQLException { return null; }
    @Override public java.sql.Clob createClob() throws SQLException { return null; }
    @Override public java.sql.Blob createBlob() throws SQLException { return null; }
    @Override public java.sql.NClob createNClob() throws SQLException { return null; }
    @Override public java.sql.SQLXML createSQLXML() throws SQLException { return null; }
    @Override public boolean isValid(int timeout) throws SQLException { return false; }
    @Override public void setClientInfo(String name, String value) throws java.sql.SQLClientInfoException {}
    @Override public void setClientInfo(Properties properties) throws java.sql.SQLClientInfoException {}
    @Override public String getClientInfo(String name) throws SQLException { return null; }
    @Override public Properties getClientInfo() throws SQLException { return null; }
    @Override public java.sql.Array createArrayOf(String typeName, Object[] elements) throws SQLException { return null; }
    @Override public java.sql.Struct createStruct(String typeName, Object[] attributes) throws SQLException { return null; }
    @Override public void setSchema(String schema) throws SQLException {}
    @Override public String getSchema() throws SQLException { return null; }
    @Override public void abort(java.util.concurrent.Executor executor) throws SQLException {}
    @Override public void setNetworkTimeout(java.util.concurrent.Executor executor, int milliseconds) throws SQLException {}
    @Override public int getNetworkTimeout() throws SQLException { return 0; }
    @Override public <T> T unwrap(Class<T> iface) throws SQLException { return null; }
    @Override public boolean isWrapperFor(Class<?> iface) throws SQLException { return false; }
}
// {/fact}

class bad_case_5 extends FileOutputStream {
    private AmazonS3 s3Client;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_5(String name) throws IOException {
        super(name);
        this.s3Client = AmazonS3ClientBuilder.standard().build();
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        // Clean up S3 client but forget parent resources
        if (s3Client != null) {
            System.out.println("Cleaning up S3 client");
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_6 extends FileDescriptor {
    private Jedis redisClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_6() {
        this.redisClient = new Jedis("localhost");
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (redisClient != null) {
            redisClient.close();
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_7 extends FileImageInputStream {
    private Producer<String, String> kafkaProducer;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_7(java.io.File file) throws IOException {
        super(file);
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        this.kafkaProducer = new KafkaProducer<>(props);
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (kafkaProducer != null) {
            kafkaProducer.close();
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_8 extends AudioInputStream {
    private Channel rabbitMQChannel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_8(AudioInputStream stream) {
        super(stream, stream.getFormat(), stream.getFrameLength());
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            com.rabbitmq.client.Connection connection = factory.newConnection();
            this.rabbitMQChannel = connection.createChannel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (rabbitMQChannel != null && rabbitMQChannel.isOpen()) {
            rabbitMQChannel.close();
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_9 extends Clip {
    private Logger logger;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_9() {
        this.logger = LogManager.getLogger(bad_case_9.class);
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        logger.info("Finalizing clip resource");
        // Missing super.finalize() call
    }
    
    // Required overrides for abstract Clip class
    @Override public void open(AudioInputStream stream) throws IOException {}
    @Override public void loop(int count) {}
    @Override public void setFramePosition(int frames) {}
    @Override public void setMicrosecondPosition(long microseconds) {}
    @Override public void setLoopPoints(int start, int end) {}
    @Override public void flush() {}
    @Override public void drain() {}
    @Override public void close() {}
    @Override public boolean isRunning() { return false; }
    @Override public boolean isActive() { return false; }
    @Override public void start() {}
    @Override public void stop() {}
    @Override public int getFramePosition() { return 0; }
    @Override public long getMicrosecondPosition() { return 0; }
    @Override public long getMicrosecondLength() { return 0; }
    @Override public int getFrameLength() { return 0; }
    @Override public javax.sound.sampled.Line.Info getLineInfo() { return null; }
    @Override public void open() throws java.lang.Exception {}
    @Override public void addLineListener(javax.sound.sampled.LineListener listener) {}
    @Override public void removeLineListener(javax.sound.sampled.LineListener listener) {}
    @Override public javax.sound.sampled.Control[] getControls() { return null; }
    @Override public boolean isControlSupported(javax.sound.sampled.Control.Type control) { return false; }
    @Override public javax.sound.sampled.Control getControl(javax.sound.sampled.Control.Type control) { return null; }
    @Override public javax.sound.sampled.FloatControl getFloatControl(javax.sound.sampled.FloatControl.Type type) { return null; }
    @Override public javax.sound.sampled.BooleanControl getBooleanControl(javax.sound.sampled.BooleanControl.Type type) { return null; }
    @Override public javax.sound.sampled.EnumControl getEnumControl(javax.sound.sampled.EnumControl.Type type) { return null; }
    @Override public javax.sound.sampled.CompoundControl getCompoundControl(javax.sound.sampled.CompoundControl.Type type) { return null; }
}
// {/fact}

class bad_case_10 extends BufferedReader {
    private Cipher cipher;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_10(java.io.Reader in) {
        super(in);
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            this.cipher = Cipher.getInstance("AES");
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        // Clean up cipher resources but forget parent resources
        if (cipher != null) {
            System.out.println("Cleaning up cipher resources");
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_11 extends Thread {
    private Lock lock;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_11() {
        this.lock = new ReentrantLock();
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (lock != null && lock.tryLock()) {
            try {
                System.out.println("Releasing lock in finalizer");
            } finally {
                lock.unlock();
            }
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_12 extends ByteBuffer {
    private FileChannel fileChannel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    private bad_case_12(ByteBuffer buffer) {
        super(buffer.capacity(), buffer.limit(), buffer.position(), buffer.mark(), buffer.order());
        try {
            this.fileChannel = new RandomAccessFile("temp.dat", "rw").getChannel();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static bad_case_12 allocate(int capacity) {
        return new bad_case_12(ByteBuffer.allocate(capacity));
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (fileChannel != null && fileChannel.isOpen()) {
            fileChannel.close();
        }
        // Missing super.finalize() call
    }
    
    // Required overrides for abstract ByteBuffer class
    @Override public ByteBuffer slice() { return null; }
    @Override public ByteBuffer duplicate() { return null; }
    @Override public ByteBuffer asReadOnlyBuffer() { return null; }
    @Override public byte get() { return 0; }
    @Override public ByteBuffer put(byte b) { return null; }
    @Override public byte get(int index) { return 0; }
    @Override public ByteBuffer put(int index, byte b) { return null; }
    @Override public ByteBuffer compact() { return null; }
    @Override public boolean isDirect() { return false; }
    @Override public char getChar() { return 0; }
    @Override public ByteBuffer putChar(char value) { return null; }
    @Override public char getChar(int index) { return 0; }
    @Override public ByteBuffer putChar(int index, char value) { return null; }
    @Override public short getShort() { return 0; }
    @Override public ByteBuffer putShort(short value) { return null; }
    @Override public short getShort(int index) { return 0; }
    @Override public ByteBuffer putShort(int index, short value) { return null; }
    @Override public int getInt() { return 0; }
    @Override public ByteBuffer putInt(int value) { return null; }
    @Override public int getInt(int index) { return 0; }
    @Override public ByteBuffer putInt(int index, int value) { return null; }
    @Override public long getLong() { return 0; }
    @Override public ByteBuffer putLong(long value) { return null; }
    @Override public long getLong(int index) { return 0; }
    @Override public ByteBuffer putLong(int index, long value) { return null; }
    @Override public float getFloat() { return 0; }
    @Override public ByteBuffer putFloat(float value) { return null; }
    @Override public float getFloat(int index) { return 0; }
    @Override public ByteBuffer putFloat(int index, float value) { return null; }
    @Override public double getDouble() { return 0; }
    @Override public ByteBuffer putDouble(double value) { return null; }
    @Override public double getDouble(int index) { return 0; }
    @Override public ByteBuffer putDouble(int index, double value) { return null; }
}
// {/fact}

class bad_case_13 extends java.io.ObjectInputStream {
    private java.util.zip.ZipFile zipFile;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_13(java.io.InputStream in) throws IOException {
        super(in);
        this.zipFile = new java.util.zip.ZipFile("data.zip");
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (zipFile != null) {
            zipFile.close();
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_14 extends java.util.Timer {
    private java.util.concurrent.ExecutorService executorService;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_14() {
        super();
        this.executorService = java.util.concurrent.Executors.newFixedThreadPool(5);
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        // Missing super.finalize() call
    }
}
// {/fact}

class bad_case_15 extends java.awt.Graphics {
    private java.awt.image.BufferedImage bufferedImage;
    
// {fact rule=finalize-on-super-class@v1.0 defects=1}
    public bad_case_15() {
        this.bufferedImage = new java.awt.image.BufferedImage(100, 100, java.awt.image.BufferedImage.TYPE_INT_RGB);
    }
    
    // ruleid: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        if (bufferedImage != null) {
            bufferedImage.flush();
        }
        // Missing super.finalize() call
    }
    
    // Required overrides for abstract Graphics class
    @Override public java.awt.Graphics create() { return null; }
    @Override public void translate(int x, int y) {}
    @Override public java.awt.Color getColor() { return null; }
    @Override public void setColor(java.awt.Color c) {}
    @Override public void setPaintMode() {}
    @Override public void setXORMode(java.awt.Color c1) {}
    @Override public java.awt.Font getFont() { return null; }
    @Override public void setFont(java.awt.Font font) {}
    @Override public java.awt.FontMetrics getFontMetrics(java.awt.Font f) { return null; }
    @Override public java.awt.Rectangle getClipBounds() { return null; }
    @Override public void clipRect(int x, int y, int width, int height) {}
    @Override public void setClip(int x, int y, int width, int height) {}
    @Override public java.awt.Shape getClip() { return null; }
    @Override public void setClip(java.awt.Shape clip) {}
    @Override public void copyArea(int x, int y, int width, int height, int dx, int dy) {}
    @Override public void drawLine(int x1, int y1, int x2, int y2) {}
    @Override public void fillRect(int x, int y, int width, int height) {}
    @Override public void clearRect(int x, int y, int width, int height) {}
    @Override public void drawRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {}
    @Override public void fillRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {}
    @Override public void drawOval(int x, int y, int width, int height) {}
    @Override public void fillOval(int x, int y, int width, int height) {}
    @Override public void drawArc(int x, int y, int width, int height, int startAngle, int arcAngle) {}
    @Override public void fillArc(int x, int y, int width, int height, int startAngle, int arcAngle) {}
    @Override public void drawPolyline(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void drawPolygon(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void fillPolygon(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void drawString(String str, int x, int y) {}
    @Override public void drawString(java.text.AttributedCharacterIterator iterator, int x, int y) {}
    @Override public boolean drawImage(java.awt.Image img, int x, int y, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, int width, int height, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, int width, int height, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1, int sx2, int sy2, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1, int sx2, int sy2, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public void dispose() {}
}
// {/fact}

// True Negative Examples (Safe/Secure Code)

class good_case_1 extends FileInputStream {
    private boolean closed = false;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_1(String name) throws IOException {
        super(name);
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (!closed) {
                closed = true;
                close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_2 extends Socket {
    private HttpClient httpClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_2() throws IOException {
        super();
        this.httpClient = HttpClients.createDefault();
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (httpClient != null) {
                System.out.println("Closing HTTP client resources");
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_3 extends RandomAccessFile {
    private FileChannel channel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_3(String name, String mode) throws IOException {
        super(name, mode);
        this.channel = getChannel();
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (channel != null && channel.isOpen()) {
                channel.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_4 extends Connection {
    private MongoClient mongoClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_4() {
        this.mongoClient = new MongoClient();
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (mongoClient != null) {
                mongoClient.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
    
    // Required overrides for abstract Connection class
    @Override public java.sql.Statement createStatement() throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql) throws SQLException { return null; }
    @Override public String nativeSQL(String sql) throws SQLException { return null; }
    @Override public void setAutoCommit(boolean autoCommit) throws SQLException {}
    @Override public boolean getAutoCommit() throws SQLException { return false; }
    @Override public void commit() throws SQLException {}
    @Override public void rollback() throws SQLException {}
    @Override public void close() throws SQLException {}
    @Override public boolean isClosed() throws SQLException { return false; }
    @Override public java.sql.DatabaseMetaData getMetaData() throws SQLException { return null; }
    @Override public void setReadOnly(boolean readOnly) throws SQLException {}
    @Override public boolean isReadOnly() throws SQLException { return false; }
    @Override public void setCatalog(String catalog) throws SQLException {}
    @Override public String getCatalog() throws SQLException { return null; }
    @Override public void setTransactionIsolation(int level) throws SQLException {}
    @Override public int getTransactionIsolation() throws SQLException { return 0; }
    @Override public java.sql.SQLWarning getWarnings() throws SQLException { return null; }
    @Override public void clearWarnings() throws SQLException {}
    @Override public java.sql.Statement createStatement(int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency) throws SQLException { return null; }
    @Override public java.util.Map<String, Class<?>> getTypeMap() throws SQLException { return null; }
    @Override public void setTypeMap(java.util.Map<String, Class<?>> map) throws SQLException {}
    @Override public void setHoldability(int holdability) throws SQLException {}
    @Override public int getHoldability() throws SQLException { return 0; }
    @Override public java.sql.Savepoint setSavepoint() throws SQLException { return null; }
    @Override public java.sql.Savepoint setSavepoint(String name) throws SQLException { return null; }
    @Override public void rollback(java.sql.Savepoint savepoint) throws SQLException {}
    @Override public void releaseSavepoint(java.sql.Savepoint savepoint) throws SQLException {}
    @Override public java.sql.Statement createStatement(int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.CallableStatement prepareCall(String sql, int resultSetType, int resultSetConcurrency, int resultSetHoldability) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int autoGeneratedKeys) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, int[] columnIndexes) throws SQLException { return null; }
    @Override public java.sql.PreparedStatement prepareStatement(String sql, String[] columnNames) throws SQLException { return null; }
    @Override public java.sql.Clob createClob() throws SQLException { return null; }
    @Override public java.sql.Blob createBlob() throws SQLException { return null; }
    @Override public java.sql.NClob createNClob() throws SQLException { return null; }
    @Override public java.sql.SQLXML createSQLXML() throws SQLException { return null; }
    @Override public boolean isValid(int timeout) throws SQLException { return false; }
    @Override public void setClientInfo(String name, String value) throws java.sql.SQLClientInfoException {}
    @Override public void setClientInfo(Properties properties) throws java.sql.SQLClientInfoException {}
    @Override public String getClientInfo(String name) throws SQLException { return null; }
    @Override public Properties getClientInfo() throws SQLException { return null; }
    @Override public java.sql.Array createArrayOf(String typeName, Object[] elements) throws SQLException { return null; }
    @Override public java.sql.Struct createStruct(String typeName, Object[] attributes) throws SQLException { return null; }
    @Override public void setSchema(String schema) throws SQLException {}
    @Override public String getSchema() throws SQLException { return null; }
    @Override public void abort(java.util.concurrent.Executor executor) throws SQLException {}
    @Override public void setNetworkTimeout(java.util.concurrent.Executor executor, int milliseconds) throws SQLException {}
    @Override public int getNetworkTimeout() throws SQLException { return 0; }
    @Override public <T> T unwrap(Class<T> iface) throws SQLException { return null; }
    @Override public boolean isWrapperFor(Class<?> iface) throws SQLException { return false; }
}
// {/fact}

class good_case_5 extends FileOutputStream {
    private AmazonS3 s3Client;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_5(String name) throws IOException {
        super(name);
        this.s3Client = AmazonS3ClientBuilder.standard().build();
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (s3Client != null) {
                System.out.println("Cleaning up S3 client");
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_6 extends FileDescriptor {
    private Jedis redisClient;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_6() {
        this.redisClient = new Jedis("localhost");
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (redisClient != null) {
                redisClient.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_7 extends FileImageInputStream {
    private Producer<String, String> kafkaProducer;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_7(java.io.File file) throws IOException {
        super(file);
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        this.kafkaProducer = new KafkaProducer<>(props);
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (kafkaProducer != null) {
                kafkaProducer.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_8 extends AudioInputStream {
    private Channel rabbitMQChannel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_8(AudioInputStream stream) {
        super(stream, stream.getFormat(), stream.getFrameLength());
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            com.rabbitmq.client.Connection connection = factory.newConnection();
            this.rabbitMQChannel = connection.createChannel();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (rabbitMQChannel != null && rabbitMQChannel.isOpen()) {
                rabbitMQChannel.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_9 extends Clip {
    private Logger logger;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_9() {
        this.logger = LogManager.getLogger(good_case_9.class);
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            logger.info("Finalizing clip resource");
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
    
    // Required overrides for abstract Clip class
    @Override public void open(AudioInputStream stream) throws IOException {}
    @Override public void loop(int count) {}
    @Override public void setFramePosition(int frames) {}
    @Override public void setMicrosecondPosition(long microseconds) {}
    @Override public void setLoopPoints(int start, int end) {}
    @Override public void flush() {}
    @Override public void drain() {}
    @Override public void close() {}
    @Override public boolean isRunning() { return false; }
    @Override public boolean isActive() { return false; }
    @Override public void start() {}
    @Override public void stop() {}
    @Override public int getFramePosition() { return 0; }
    @Override public long getMicrosecondPosition() { return 0; }
    @Override public long getMicrosecondLength() { return 0; }
    @Override public int getFrameLength() { return 0; }
    @Override public javax.sound.sampled.Line.Info getLineInfo() { return null; }
    @Override public void open() throws java.lang.Exception {}
    @Override public void addLineListener(javax.sound.sampled.LineListener listener) {}
    @Override public void removeLineListener(javax.sound.sampled.LineListener listener) {}
    @Override public javax.sound.sampled.Control[] getControls() { return null; }
    @Override public boolean isControlSupported(javax.sound.sampled.Control.Type control) { return false; }
    @Override public javax.sound.sampled.Control getControl(javax.sound.sampled.Control.Type control) { return null; }
    @Override public javax.sound.sampled.FloatControl getFloatControl(javax.sound.sampled.FloatControl.Type type) { return null; }
    @Override public javax.sound.sampled.BooleanControl getBooleanControl(javax.sound.sampled.BooleanControl.Type type) { return null; }
    @Override public javax.sound.sampled.EnumControl getEnumControl(javax.sound.sampled.EnumControl.Type type) { return null; }
    @Override public javax.sound.sampled.CompoundControl getCompoundControl(javax.sound.sampled.CompoundControl.Type type) { return null; }
}
// {/fact}

class good_case_10 extends BufferedReader {
    private Cipher cipher;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_10(java.io.Reader in) {
        super(in);
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();
            this.cipher = Cipher.getInstance("AES");
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (cipher != null) {
                System.out.println("Cleaning up cipher resources");
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_11 extends Thread {
    private Lock lock;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_11() {
        this.lock = new ReentrantLock();
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (lock != null && lock.tryLock()) {
                try {
                    System.out.println("Releasing lock in finalizer");
                } finally {
                    lock.unlock();
                }
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_12 extends ByteBuffer {
    private FileChannel fileChannel;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    private good_case_12(ByteBuffer buffer) {
        super(buffer.capacity(), buffer.limit(), buffer.position(), buffer.mark(), buffer.order());
        try {
            this.fileChannel = new RandomAccessFile("temp.dat", "rw").getChannel();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static good_case_12 allocate(int capacity) {
        return new good_case_12(ByteBuffer.allocate(capacity));
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (fileChannel != null && fileChannel.isOpen()) {
                fileChannel.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
    
    // Required overrides for abstract ByteBuffer class
    @Override public ByteBuffer slice() { return null; }
    @Override public ByteBuffer duplicate() { return null; }
    @Override public ByteBuffer asReadOnlyBuffer() { return null; }
    @Override public byte get() { return 0; }
    @Override public ByteBuffer put(byte b) { return null; }
    @Override public byte get(int index) { return 0; }
    @Override public ByteBuffer put(int index, byte b) { return null; }
    @Override public ByteBuffer compact() { return null; }
    @Override public boolean isDirect() { return false; }
    @Override public char getChar() { return 0; }
    @Override public ByteBuffer putChar(char value) { return null; }
    @Override public char getChar(int index) { return 0; }
    @Override public ByteBuffer putChar(int index, char value) { return null; }
    @Override public short getShort() { return 0; }
    @Override public ByteBuffer putShort(short value) { return null; }
    @Override public short getShort(int index) { return 0; }
    @Override public ByteBuffer putShort(int index, short value) { return null; }
    @Override public int getInt() { return 0; }
    @Override public ByteBuffer putInt(int value) { return null; }
    @Override public int getInt(int index) { return 0; }
    @Override public ByteBuffer putInt(int index, int value) { return null; }
    @Override public long getLong() { return 0; }
    @Override public ByteBuffer putLong(long value) { return null; }
    @Override public long getLong(int index) { return 0; }
    @Override public ByteBuffer putLong(int index, long value) { return null; }
    @Override public float getFloat() { return 0; }
    @Override public ByteBuffer putFloat(float value) { return null; }
    @Override public float getFloat(int index) { return 0; }
    @Override public ByteBuffer putFloat(int index, float value) { return null; }
    @Override public double getDouble() { return 0; }
    @Override public ByteBuffer putDouble(double value) { return null; }
    @Override public double getDouble(int index) { return 0; }
    @Override public ByteBuffer putDouble(int index, double value) { return null; }
}
// {/fact}

class good_case_13 extends java.io.ObjectInputStream {
    private java.util.zip.ZipFile zipFile;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_13(java.io.InputStream in) throws IOException {
        super(in);
        this.zipFile = new java.util.zip.ZipFile("data.zip");
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (zipFile != null) {
                zipFile.close();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_14 extends java.util.Timer {
    private java.util.concurrent.ExecutorService executorService;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_14() {
        super();
        this.executorService = java.util.concurrent.Executors.newFixedThreadPool(5);
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (executorService != null && !executorService.isShutdown()) {
                executorService.shutdown();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
}
// {/fact}

class good_case_15 extends java.awt.Graphics {
    private java.awt.image.BufferedImage bufferedImage;
    
// {fact rule=finalize-on-super-class@v1.0 defects=0}
    public good_case_15() {
        this.bufferedImage = new java.awt.image.BufferedImage(100, 100, java.awt.image.BufferedImage.TYPE_INT_RGB);
    }
    
    // ok: java-finalize-on-super-class-ignored
    protected void finalize() throws Throwable {
        try {
            if (bufferedImage != null) {
                bufferedImage.flush();
            }
        } finally {
            super.finalize(); // Properly call parent's finalize
        }
    }
    
    // Required overrides for abstract Graphics class
    @Override public java.awt.Graphics create() { return null; }
    @Override public void translate(int x, int y) {}
    @Override public java.awt.Color getColor() { return null; }
    @Override public void setColor(java.awt.Color c) {}
    @Override public void setPaintMode() {}
    @Override public void setXORMode(java.awt.Color c1) {}
    @Override public java.awt.Font getFont() { return null; }
    @Override public void setFont(java.awt.Font font) {}
    @Override public java.awt.FontMetrics getFontMetrics(java.awt.Font f) { return null; }
    @Override public java.awt.Rectangle getClipBounds() { return null; }
    @Override public void clipRect(int x, int y, int width, int height) {}
    @Override public void setClip(int x, int y, int width, int height) {}
    @Override public java.awt.Shape getClip() { return null; }
    @Override public void setClip(java.awt.Shape clip) {}
    @Override public void copyArea(int x, int y, int width, int height, int dx, int dy) {}
    @Override public void drawLine(int x1, int y1, int x2, int y2) {}
    @Override public void fillRect(int x, int y, int width, int height) {}
    @Override public void clearRect(int x, int y, int width, int height) {}
    @Override public void drawRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {}
    @Override public void fillRoundRect(int x, int y, int width, int height, int arcWidth, int arcHeight) {}
    @Override public void drawOval(int x, int y, int width, int height) {}
    @Override public void fillOval(int x, int y, int width, int height) {}
    @Override public void drawArc(int x, int y, int width, int height, int startAngle, int arcAngle) {}
    @Override public void fillArc(int x, int y, int width, int height, int startAngle, int arcAngle) {}
    @Override public void drawPolyline(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void drawPolygon(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void fillPolygon(int[] xPoints, int[] yPoints, int nPoints) {}
    @Override public void drawString(String str, int x, int y) {}
    @Override public void drawString(java.text.AttributedCharacterIterator iterator, int x, int y) {}
    @Override public boolean drawImage(java.awt.Image img, int x, int y, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, int width, int height, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int x, int y, int width, int height, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1, int sx2, int sy2, java.awt.image.ImageObserver observer) { return false; }
    @Override public boolean drawImage(java.awt.Image img, int dx1, int dy1, int dx2, int dy2, int sx1, int sy1, int sx2, int sy2, java.awt.Color bgcolor, java.awt.image.ImageObserver observer) { return false; }
    @Override public void dispose() {}
}
// {/fact}