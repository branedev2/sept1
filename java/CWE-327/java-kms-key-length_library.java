import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.CreateKeyRequest;
import com.amazonaws.services.kms.model.KeySpec;
import com.amazonaws.services.kms.model.CustomerMasterKeySpec;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKeyVersionTemplate;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.cloud.kms.v1.CryptoKeyName;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.CreateEcKeyOptions;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.HttpResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.apache.commons.codec.binary.Base64;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.client.WebClient;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;

// Security Issue: Insufficient key length in cryptographic operations

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    // AWS KMS with insufficient key length based on user input
    String keySpec = request.getParameter("keySpec");
    AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
    CreateKeyRequest createKeyRequest = new CreateKeyRequest();
    
    // ruleid: java-kms-key-length
    createKeyRequest.withKeySpec("RSA_1024"); // Insufficient key length for RSA
    
    kmsClient.createKey(createKeyRequest);
}

public void bad_case_2(HttpServletRequest request) {
    // Google Cloud KMS with insufficient key length
    try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
        String parent = request.getParameter("keyRingName");
        String keyId = request.getParameter("keyId");
        
        CryptoKey key = CryptoKey.newBuilder()
            .setPurpose(CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN)
            .setVersionTemplate(
                CryptoKeyVersionTemplate.newBuilder()
                    // ruleid: java-kms-key-length
                    .setCryptoKeyVersionAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256)
                    .setProtectionLevel(ProtectionLevel.HSM)
                    .build())
            .build();
        
        client.createCryptoKey(parent, keyId, key);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3(HttpServletRequest request) {
    // Azure Key Vault with insufficient key length
    String endpoint = request.getParameter("endpoint");
    KeyClient keyClient = new KeyClientBuilder()
        .vaultUrl(endpoint)
        .buildClient();
    
    // ruleid: java-kms-key-length
    CreateRsaKeyOptions rsaKeyOptions = new CreateRsaKeyOptions("RSAKey")
        .setKeySize(1024) // Insufficient key size for RSA
        .setExpiresOn(null);
    
    keyClient.createRsaKey(rsaKeyOptions);
}

public void bad_case_4() {
    try {
        // Java KeyPairGenerator with insufficient key length
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        
        // Get key size from HTTP request
        URL url = new URL("http://example.com/keysize");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        // ruleid: java-kms-key-length
        keyGen.initialize(1024); // Insufficient key size for RSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5(HttpServletRequest request) {
    try {
        // BouncyCastle with insufficient key length
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        // ruleid: java-kms-key-length
        keyGen.initialize(1024, new SecureRandom()); // Insufficient key size for RSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_6(HttpServletRequest request) {
    try {
        // Java KeyGenerator with insufficient key length for AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        // ruleid: java-kms-key-length
        keyGen.init(64); // Insufficient key size for AES
        
        SecretKey secretKey = keyGen.generateKey();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    try {
        // OkHttp client to fetch key size and use insufficient key length
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("http://example.com/keysize")
            .build();
        
        Response response = client.newCall(request).execute();
        int keySize = Integer.parseInt(response.body().string().trim());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        // ruleid: java-kms-key-length
        keyGen.init(56); // Insufficient key size for DES
        
        SecretKey secretKey = keyGen.generateKey();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8(HttpServletRequest request) {
    try {
        // AWS KMS v2 SDK with insufficient key length
        String keySpec = request.getParameter("keySpec");
        KmsClient kmsClient = KmsClient.builder().build();
        
        // ruleid: java-kms-key-length
        software.amazon.awssdk.services.kms.model.CreateKeyRequest createKeyRequest = 
            software.amazon.awssdk.services.kms.model.CreateKeyRequest.builder()
                .keySpec("RSA_1024") // Insufficient key length for RSA
                .build();
        
        CreateKeyResponse response = kmsClient.createKey(createKeyRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    try {
        // Apache HttpClient to fetch key size and use insufficient key length for EC
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("http://example.com/curve");
        HttpResponse response = httpClient.execute(httpGet);
        String curve = new java.util.Scanner(response.getEntity().getContent()).useDelimiter("\\A").next();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ruleid: java-kms-key-length
        keyGen.initialize(new ECGenParameterSpec("secp160r1")); // Insufficient curve for EC
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        // Azure Key Vault with insufficient EC curve
        String endpoint = request.getParameter("endpoint");
        KeyClient keyClient = new KeyClientBuilder()
            .vaultUrl(endpoint)
            .buildClient();
        
        // ruleid: java-kms-key-length
        CreateEcKeyOptions ecKeyOptions = new CreateEcKeyOptions("ECKey")
            .setCurveName(KeyCurveName.P_256K) // P-256K is considered less secure than other curves
            .setExpiresOn(null);
        
        keyClient.createEcKey(ecKeyOptions);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // Vertx web client to fetch key size and use insufficient key length
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    client.get(8080, "localhost", "/keysize")
        .send(ar -> {
            if (ar.succeeded()) {
                int keySize = Integer.parseInt(ar.result().bodyAsString());
                try {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    // ruleid: java-kms-key-length
                    keyGen.init(64); // Insufficient key size for AES
                    
                    SecretKey secretKey = keyGen.generateKey();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
}

public void bad_case_12(HttpServletRequest request) {
    try {
        // RSA key generation with insufficient modulus size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        
        // ruleid: java-kms-key-length
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4);
        keyGen.initialize(spec);
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    try {
        // Apache Commons Crypto with insufficient key length
        URL url = new URL("http://example.com/keysize");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        Properties properties = new Properties();
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties);
        
        // ruleid: java-kms-key-length
        byte[] key = new byte[8]; // 64-bit key, insufficient for modern encryption
        random.nextBytes(key);
        
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        String transform = "AES/CBC/PKCS5Padding";
        CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher(transform, properties);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    try {
        // Netty HTTP server handling key generation with insufficient length
        NioEventLoopGroup bossGroup = new NioEventLoopGroup();
        NioEventLoopGroup workerGroup = new NioEventLoopGroup();
        
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) throws Exception {
                    ch.pipeline().addLast(new HttpServerCodec());
                    ch.pipeline().addLast(new HttpObjectAggregator(65536));
                    ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                            if (msg instanceof HttpRequest) {
                                // Process request and generate keys
                                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                                // ruleid: java-kms-key-length
                                keyGen.init(64); // Insufficient key size for AES
                                
                                SecretKey secretKey = keyGen.generateKey();
                            }
                        }
                    });
                }
            });
        
        bootstrap.bind(8080).sync();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    try {
        // Java built-in HTTP client with insufficient DSA key length
        String keySizeUrl = request.getParameter("keySizeUrl");
        URL url = new URL(keySizeUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ruleid: java-kms-key-length
        keyGen.initialize(512); // Insufficient key size for DSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // AWS KMS with sufficient key length
    String keySpec = request.getParameter("keySpec");
    AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
    CreateKeyRequest createKeyRequest = new CreateKeyRequest();
    
    // ok: java-kms-key-length
    createKeyRequest.withKeySpec("RSA_4096"); // Sufficient key length for RSA
    
    kmsClient.createKey(createKeyRequest);
}

public void good_case_2(HttpServletRequest request) {
    // Google Cloud KMS with sufficient key length
    try (KeyManagementServiceClient client = KeyManagementServiceClient.create()) {
        String parent = request.getParameter("keyRingName");
        String keyId = request.getParameter("keyId");
        
        CryptoKey key = CryptoKey.newBuilder()
            .setPurpose(CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN)
            .setVersionTemplate(
                CryptoKeyVersionTemplate.newBuilder()
                    // ok: java-kms-key-length
                    .setCryptoKeyVersionAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512)
                    .setProtectionLevel(ProtectionLevel.HSM)
                    .build())
            .build();
        
        client.createCryptoKey(parent, keyId, key);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3(HttpServletRequest request) {
    // Azure Key Vault with sufficient key length
    String endpoint = request.getParameter("endpoint");
    KeyClient keyClient = new KeyClientBuilder()
        .vaultUrl(endpoint)
        .buildClient();
    
    // ok: java-kms-key-length
    CreateRsaKeyOptions rsaKeyOptions = new CreateRsaKeyOptions("RSAKey")
        .setKeySize(4096) // Sufficient key size for RSA
        .setExpiresOn(null);
    
    keyClient.createRsaKey(rsaKeyOptions);
}

public void good_case_4() {
    try {
        // Java KeyPairGenerator with sufficient key length
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        
        // Get key size from HTTP request
        URL url = new URL("http://example.com/keysize");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        // ok: java-kms-key-length
        keyGen.initialize(3072); // Sufficient key size for RSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    try {
        // BouncyCastle with sufficient key length
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        // ok: java-kms-key-length
        keyGen.initialize(4096, new SecureRandom()); // Sufficient key size for RSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_6(HttpServletRequest request) {
    try {
        // Java KeyGenerator with sufficient key length for AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        // ok: java-kms-key-length
        keyGen.init(256); // Sufficient key size for AES
        
        SecretKey secretKey = keyGen.generateKey();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        // OkHttp client to fetch key size and use sufficient key length
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("http://example.com/keysize")
            .build();
        
        Response response = client.newCall(request).execute();
        int keySize = Integer.parseInt(response.body().string().trim());
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // ok: java-kms-key-length
        keyGen.init(256); // Sufficient key size for AES
        
        SecretKey secretKey = keyGen.generateKey();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    try {
        // AWS KMS v2 SDK with sufficient key length
        String keySpec = request.getParameter("keySpec");
        KmsClient kmsClient = KmsClient.builder().build();
        
        // ok: java-kms-key-length
        software.amazon.awssdk.services.kms.model.CreateKeyRequest createKeyRequest = 
            software.amazon.awssdk.services.kms.model.CreateKeyRequest.builder()
                .keySpec("RSA_4096") // Sufficient key length for RSA
                .build();
        
        CreateKeyResponse response = kmsClient.createKey(createKeyRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    try {
        // Apache HttpClient to fetch key size and use sufficient key length for EC
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet("http://example.com/curve");
        HttpResponse response = httpClient.execute(httpGet);
        String curve = new java.util.Scanner(response.getEntity().getContent()).useDelimiter("\\A").next();
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ok: java-kms-key-length
        keyGen.initialize(new ECGenParameterSpec("secp521r1")); // Sufficient curve for EC
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        // Azure Key Vault with sufficient EC curve
        String endpoint = request.getParameter("endpoint");
        KeyClient keyClient = new KeyClientBuilder()
            .vaultUrl(endpoint)
            .buildClient();
        
        // ok: java-kms-key-length
        CreateEcKeyOptions ecKeyOptions = new CreateEcKeyOptions("ECKey")
            .setCurveName(KeyCurveName.P_521) // P-521 is considered more secure
            .setExpiresOn(null);
        
        keyClient.createEcKey(ecKeyOptions);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    // Vertx web client to fetch key size and use sufficient key length
    Vertx vertx = Vertx.vertx();
    WebClient client = WebClient.create(vertx);
    
    client.get(8080, "localhost", "/keysize")
        .send(ar -> {
            if (ar.succeeded()) {
                int keySize = Integer.parseInt(ar.result().bodyAsString());
                try {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    // ok: java-kms-key-length
                    keyGen.init(256); // Sufficient key size for AES
                    
                    SecretKey secretKey = keyGen.generateKey();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
}

public void good_case_12(HttpServletRequest request) {
    try {
        // RSA key generation with sufficient modulus size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        int keySize = Integer.parseInt(request.getParameter("keySize"));
        
        // ok: java-kms-key-length
        RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4);
        keyGen.initialize(spec);
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13() {
    try {
        // Apache Commons Crypto with sufficient key length
        URL url = new URL("http://example.com/keysize");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        Properties properties = new Properties();
        CryptoRandom random = CryptoRandomFactory.getCryptoRandom(properties);
        
        // ok: java-kms-key-length
        byte[] key = new byte[32]; // 256-bit key, sufficient for modern encryption
        random.nextBytes(key);
        
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        
        String transform = "AES/CBC/PKCS5Padding";
        CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher(transform, properties);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14() {
    try {
        // Netty HTTP server handling key generation with sufficient length
        NioEventLoopGroup bossGroup = new NioEventLoopGroup();
        NioEventLoopGroup workerGroup = new NioEventLoopGroup();
        
        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
            .channel(NioServerSocketChannel.class)
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel ch) throws Exception {
                    ch.pipeline().addLast(new HttpServerCodec());
                    ch.pipeline().addLast(new HttpObjectAggregator(65536));
                    ch.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                            if (msg instanceof HttpRequest) {
                                // Process request and generate keys
                                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                                // ok: java-kms-key-length
                                keyGen.init(256); // Sufficient key size for AES
                                
                                SecretKey secretKey = keyGen.generateKey();
                            }
                        }
                    });
                }
            });
        
        bootstrap.bind(8080).sync();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    try {
        // Java built-in HTTP client with sufficient DSA key length
        String keySizeUrl = request.getParameter("keySizeUrl");
        URL url = new URL(keySizeUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        int keySize = Integer.parseInt(new java.util.Scanner(conn.getInputStream()).useDelimiter("\\A").next());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ok: java-kms-key-length
        keyGen.initialize(3072); // Sufficient key size for DSA
        
        KeyPair keyPair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}