import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.jose4j.keys.RsaKeyUtil;
import io.jsonwebtoken.security.Keys;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import spark.Request;
import spark.Response;
import spark.Spark;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.server.RatpackServer;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.JsonKeysetWriter;
import org.conscrypt.OpenSSLProvider;

// Security Issue: Improper use of cryptographic key pair generators with weak algorithms, insufficient key sizes, 
// or insecure configurations, which can lead to compromised encryption.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    try {
        String keySize = request.getParameter("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt); // Vulnerable: User-controlled key size without validation
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_2() {
    try {
        // Using a weak key size for RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512); // Vulnerable: 512-bit RSA keys are considered insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_3() {
    try {
        // Using DSA with weak parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512); // Vulnerable: 512-bit DSA keys are insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    try {
        // Using a weak algorithm (DH with small key)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(512); // Vulnerable: 512-bit DH keys are insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    try {
        // Using BouncyCastle provider with weak key size
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(112); // Vulnerable: 112-bit ECDSA keys are insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void bad_case_6(@RequestParam String algorithm) {
    try {
        // Using user-controlled algorithm without validation
        // ruleid: java-crypto-key-pair-generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm); // Vulnerable: User-controlled algorithm
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    try {
        // Using Nimbus JOSE JWT library with weak key
        // ruleid: java-crypto-key-pair-generator
        RSAKey jwk = new RSAKeyGenerator(512) // Vulnerable: 512-bit RSA key for JWT
            .keyID("123")
            .generate();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    try {
        // Using jose4j library with weak key
        RsaKeyUtil keyUtil = new RsaKeyUtil();
        // ruleid: java-crypto-key-pair-generator
        KeyPair keyPair = keyUtil.generateKeyPair(512); // Vulnerable: 512-bit RSA key
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    try {
        // Using JJWT library with weak key
        // ruleid: java-crypto-key-pair-generator
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256); // Vulnerable: Default may not be strong enough for some contexts
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10(HttpServletRequest request) {
    try {
        // Using Azure Key Vault with weak key
        KeyClient keyClient = new KeyClientBuilder().buildClient();
        String keySize = request.getParameter("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // ruleid: java-crypto-key-pair-generator
        CreateRsaKeyOptions options = new CreateRsaKeyOptions("key-name")
            .setKeySize(keySizeInt); // Vulnerable: User-controlled key size without validation
        keyClient.createRsaKey(options);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    try {
        // Using Conscrypt OpenSSL provider with weak key
        Security.insertProviderAt(new OpenSSLProvider(), 1);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "Conscrypt");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(768); // Vulnerable: 768-bit RSA keys are insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12(RoutingContext ctx) {
    try {
        // Using Vert.x with weak key
        String keySize = ctx.request().getParam("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt); // Vulnerable: User-controlled key size without validation
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13(spark.Request request) {
    try {
        // Using Spark framework with weak key
        String keySize = request.queryParams("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(112); // Vulnerable: 112-bit EC keys are insecure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14(Http.Request request) {
    try {
        // Using Play framework with weak key
        String keySize = request.getQueryString("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt); // Vulnerable: User-controlled key size without validation
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(Context ctx) {
    try {
        // Using Ratpack with weak key
        String keySize = ctx.getRequest().getQueryParams().get("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ruleid: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt); // Vulnerable: User-controlled key size without validation
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    try {
        String keySize = request.getParameter("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // Validate key size before using it
        if (keySizeInt < 2048) {
            keySizeInt = 2048; // Enforce minimum secure key size
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt);
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_2() {
    try {
        // Using a secure key size for RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048); // Secure: 2048-bit RSA keys are currently considered secure
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_3() {
    try {
        // Using DSA with secure parameters
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048); // Secure: 2048-bit DSA keys
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4() {
    try {
        // Using a secure algorithm with appropriate key size
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048); // Secure: 2048-bit DH keys
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5() {
    try {
        // Using BouncyCastle provider with secure key size
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(256); // Secure: 256-bit ECDSA keys
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

@RestController
public void good_case_6(@RequestParam String algorithm) {
    try {
        // Validate algorithm before using it
        String safeAlgorithm;
        if ("RSA".equals(algorithm) || "EC".equals(algorithm)) {
            safeAlgorithm = algorithm;
        } else {
            safeAlgorithm = "RSA"; // Default to a secure algorithm
        }
        
        // ok: java-crypto-key-pair-generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(safeAlgorithm);
        keyGen.initialize(2048); // Secure key size
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7() {
    try {
        // Using Nimbus JOSE JWT library with secure key
        // ok: java-crypto-key-pair-generator
        RSAKey jwk = new RSAKeyGenerator(2048) // Secure: 2048-bit RSA key for JWT
            .keyID("123")
            .generate();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8() {
    try {
        // Using jose4j library with secure key
        RsaKeyUtil keyUtil = new RsaKeyUtil();
        // ok: java-crypto-key-pair-generator
        KeyPair keyPair = keyUtil.generateKeyPair(2048); // Secure: 2048-bit RSA key
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9() {
    try {
        // Using JJWT library with explicitly secure key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        // Use the key pair with JJWT
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    try {
        // Using Azure Key Vault with secure key
        KeyClient keyClient = new KeyClientBuilder().buildClient();
        String keySize = request.getParameter("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // Validate key size
        if (keySizeInt < 2048) {
            keySizeInt = 2048; // Enforce minimum secure key size
        }
        
        // ok: java-crypto-key-pair-generator
        CreateRsaKeyOptions options = new CreateRsaKeyOptions("key-name")
            .setKeySize(keySizeInt);
        keyClient.createRsaKey(options);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11() {
    try {
        // Using Conscrypt OpenSSL provider with secure key
        Security.insertProviderAt(new OpenSSLProvider(), 1);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "Conscrypt");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(2048); // Secure: 2048-bit RSA keys
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(RoutingContext ctx) {
    try {
        // Using Vert.x with secure key
        String keySize = ctx.request().getParam("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // Validate key size
        if (keySizeInt < 2048) {
            keySizeInt = 2048; // Enforce minimum secure key size
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt);
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(spark.Request request) {
    try {
        // Using Spark framework with secure key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(256); // Secure: 256-bit EC keys
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(Http.Request request) {
    try {
        // Using Play framework with secure key
        String keySize = request.getQueryString("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // Validate key size
        if (keySizeInt < 2048) {
            keySizeInt = 2048; // Enforce minimum secure key size
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt);
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(Context ctx) {
    try {
        // Using Ratpack with secure key
        String keySize = ctx.getRequest().getQueryParams().get("keysize");
        int keySizeInt = Integer.parseInt(keySize);
        
        // Validate key size
        if (keySizeInt < 2048) {
            keySizeInt = 2048; // Enforce minimum secure key size
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        // ok: java-crypto-key-pair-generator
        keyGen.initialize(keySizeInt);
        KeyPair pair = keyGen.generateKeyPair();
    } catch (Exception e) {
        e.printStackTrace();
    }
}