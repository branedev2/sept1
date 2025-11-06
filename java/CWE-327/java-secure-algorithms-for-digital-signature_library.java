import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import io.jsonwebtoken.*;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.Utils;
import com.google.crypto.tink.*;
import com.google.crypto.tink.signature.*;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.google.api.client.util.SecurityUtils;
import com.google.api.client.auth.oauth2.Credential;
import org.conscrypt.Conscrypt;
import org.conscrypt.OpenSSLProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.ssl.PKCS8Key;
import org.apache.commons.ssl.TrustMaterial;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.SignatureVerificationProvider;

// Security Issue: Improper use of cryptographic APIs for digital signatures can lead to vulnerabilities

// True Positive Examples (Vulnerable/Insecure Code)
public class DigitalSignatureVulnerabilities {

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) throws Exception {
        // Using weak MD5 algorithm for digital signature with standard JCA
        String data = request.getParameter("data");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_2(HttpServletRequest request) throws Exception {
        // Using weak SHA1 algorithm with BouncyCastle provider
        String data = request.getParameter("message");
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA1withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedBytes = signature.sign();
    }

    public void bad_case_3(@RequestBody String payload) throws Exception {
        // Using weak DSA algorithm with small key size in Spring Web context
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ruleid: java-secure-algorithms-for-digital-signature
        keyGen.initialize(512); // Weak key size for DSA
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA1withDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload.getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_4(HttpServletRequest request) throws JOSEException {
        // Using weak HMAC_REDACTED_TWILIO_ID algorithm with Nimbus JOSE+JWT library
        String payload = request.getParameter("payload");
        
        // Generate a key for HMAC_REDACTED_TWILIO_ID
        SecretKey sharedKey = KeyGenerator.getInstance("HmacSHA1").generateKey();
        
        // Create JWS header with weak algorithm
        JWSHeader header = new JWSHeader.Builder(
            // ruleid: java-secure-algorithms-for-digital-signature
            JWSAlgorithm.HS256
        ).build();
        
        // Create the JWS object
        JWSObject jwsObject = new JWSObject(header, new Payload(payload));
        
        // Sign it with the HMAC_REDACTED_TWILIO_ID
        jwsObject.sign(new MAC_REDACTED_TWILIO_ID(sharedKey));
        
        String serializedJWS = jwsObject.serialize();
    }

    public void bad_case_5(HttpServletRequest request) throws Exception {
        // Using weak RSA algorithm with JJWT library
        String subject = request.getParameter("subject");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        String jws = Jwts.builder()
            .setSubject(subject)
            .signWith(SignatureAlgorithm.RS256, keyPair.getPrivate())
            .compact();
    }

    public void bad_case_6(HttpServletRequest request) throws Exception {
        // Using weak ECDSA algorithm with Auth0 JWT library
        String userId = request.getParameter("userId");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ruleid: java-secure-algorithms-for-digital-signature
        keyGen.initialize(192); // Weak key size for EC
        KeyPair keyPair = keyGen.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        
        Algorithm algorithm = Algorithm.ECDSA192(null, privateKey);
        String token = JWT.create()
            .withSubject(userId)
            .sign(algorithm);
    }

    public void bad_case_7(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Jose4j library
        String payload = request.getParameter("payload");
        
        // Generate a key
        Key key = KeyGenerator.getInstance("HmacSHA1").generateKey();
        
        // Create a new JsonWebSignature
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        
        // Set the signature algorithm
        // ruleid: java-secure-algorithms-for-digital-signature
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA1);
        
        // Set the verification key
        jws.setKey(new HmacKey(key.getEncoded()));
        
        // Sign and produce the JWS
        String jwsCompactSerialization = jws.getCompactSerialization();
    }

    public void bad_case_8(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Apache Commons SSL
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
        
        String hexSignature = Hex.encodeHexString(signedData);
    }

    public void bad_case_9(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Vert.x JWT Auth
        String userId = request.getParameter("userId");
        
        Vertx vertx = Vertx.vertx();
        JWTAuthOptions config = new JWTAuthOptions()
            .addPubSecKey(new PubSecKeyOptions()
                // ruleid: java-secure-algorithms-for-digital-signature
                .setAlgorithm("HS256")
                .setBuffer("keyboard cat")
            );
        
        JWTAuth provider = JWTAuth.create(vertx, config);
        
        String token = provider.generateToken(
            new io.vertx.core.json.JsonObject().put("sub", userId),
            new JWTOptions()
        );
    }

    public void bad_case_10(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Keycloak JWS
        String payload = request.getParameter("payload");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        String token = new JWSBuilder()
            .jsonContent(payload)
            .rsa256(keyPair.getPrivate());
    }

    public void bad_case_11(HttpServletRequest request) throws Exception {
        // Using weak algorithm with WSO2 Carbon Crypto
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }

    public void bad_case_12(HttpServletRequest request) throws Exception {
        // Using weak algorithm with AWS KMS
        String message = request.getParameter("message");
        
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        SignRequest req = new SignRequest()
            .withKeyId("alias/my-key")
            .withMessage(message.getBytes())
            // ruleid: java-secure-algorithms-for-digital-signature
            .withSigningAlgorithm("RSASSA_PKCS1_V1_5_SHA_1");
        
        SignResult result = kmsClient.sign(req);
        byte[] signature = result.getSignature().array();
    }

    public void bad_case_13(HttpServletRequest request) throws Exception {
        // Using weak algorithm with AWS SDK v2 KMS
        String message = request.getParameter("message");
        
        KmsClient kmsClient = KmsClient.create();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        software.amazon.awssdk.services.kms.model.SignRequest req = 
            software.amazon.awssdk.services.kms.model.SignRequest.builder()
                .keyId("alias/my-key")
                .message(software.amazon.awssdk.core.SdkBytes.fromByteArray(message.getBytes()))
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_1)
                .build();
        
        software.amazon.awssdk.services.kms.model.SignResponse result = kmsClient.sign(req);
    }

    public void bad_case_14(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Google API Client
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data.getBytes());
        byte[] signatureBytes = signer.sign();
    }

    public void bad_case_15(HttpServletRequest request) throws Exception {
        // Using weak algorithm with Conscrypt
        String data = request.getParameter("data");
        
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "Conscrypt");
        keyGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ruleid: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA1withRSA", "Conscrypt");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request) throws Exception {
        // Using strong algorithm for digital signature with standard JCA
        String data = request.getParameter("data");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_2(HttpServletRequest request) throws Exception {
        // Using strong algorithm with BouncyCastle provider
        String data = request.getParameter("message");
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA512withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedBytes = signature.sign();
    }

    public void good_case_3(@RequestBody String payload) throws Exception {
        // Using strong DSA algorithm with adequate key size in Spring Web context
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        // ok: java-secure-algorithms-for-digital-signature
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload.getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_4(HttpServletRequest request) throws JOSEException {
        // Using strong HMAC_REDACTED_TWILIO_ID algorithm with Nimbus JOSE+JWT library
        String payload = request.getParameter("payload");
        
        // Generate a key for HMAC_REDACTED_TWILIO_ID
        SecretKey sharedKey = KeyGenerator.getInstance("HmacSHA512").generateKey();
        
        // Create JWS header with strong algorithm
        JWSHeader header = new JWSHeader.Builder(
            // ok: java-secure-algorithms-for-digital-signature
            JWSAlgorithm.HS512
        ).build();
        
        // Create the JWS object
        JWSObject jwsObject = new JWSObject(header, new Payload(payload));
        
        // Sign it with the HMAC_REDACTED_TWILIO_ID
        jwsObject.sign(new MAC_REDACTED_TWILIO_ID(sharedKey));
        
        String serializedJWS = jwsObject.serialize();
    }

    public void good_case_5(HttpServletRequest request) throws Exception {
        // Using strong RSA algorithm with JJWT library
        String subject = request.getParameter("subject");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        String jws = Jwts.builder()
            .setSubject(subject)
            .signWith(SignatureAlgorithm.RS512, keyPair.getPrivate())
            .compact();
    }

    public void good_case_6(HttpServletRequest request) throws Exception {
        // Using strong ECDSA algorithm with Auth0 JWT library
        String userId = request.getParameter("userId");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        // ok: java-secure-algorithms-for-digital-signature
        keyGen.initialize(384);
        KeyPair keyPair = keyGen.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        
        Algorithm algorithm = Algorithm.ECDSA384(null, privateKey);
        String token = JWT.create()
            .withSubject(userId)
            .sign(algorithm);
    }

    public void good_case_7(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Jose4j library
        String payload = request.getParameter("payload");
        
        // Generate a key
        Key key = KeyGenerator.getInstance("HmacSHA512").generateKey();
        
        // Create a new JsonWebSignature
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        
        // Set the signature algorithm
        // ok: java-secure-algorithms-for-digital-signature
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_REDACTED_TWILIO_ID_SHA512);
        
        // Set the verification key
        jws.setKey(new HmacKey(key.getEncoded()));
        
        // Sign and produce the JWS
        String jwsCompactSerialization = jws.getCompactSerialization();
    }

    public void good_case_8(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Apache Commons SSL
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
        
        String hexSignature = Hex.encodeHexString(signedData);
    }

    public void good_case_9(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Vert.x JWT Auth
        String userId = request.getParameter("userId");
        
        Vertx vertx = Vertx.vertx();
        JWTAuthOptions config = new JWTAuthOptions()
            .addPubSecKey(new PubSecKeyOptions()
                // ok: java-secure-algorithms-for-digital-signature
                .setAlgorithm("RS512")
                .setBuffer("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLO4HLM4bPaH73\n-----END PRIVATE KEY-----")
            );
        
        JWTAuth provider = JWTAuth.create(vertx, config);
        
        String token = provider.generateToken(
            new io.vertx.core.json.JsonObject().put("sub", userId),
            new JWTOptions()
        );
    }

    public void good_case_10(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Keycloak JWS
        String payload = request.getParameter("payload");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        String token = new JWSBuilder()
            .jsonContent(payload)
            .rsa512(keyPair.getPrivate());
    }

    public void good_case_11(HttpServletRequest request) throws Exception {
        // Using strong algorithm with WSO2 Carbon Crypto
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }

    public void good_case_12(HttpServletRequest request) throws Exception {
        // Using strong algorithm with AWS KMS
        String message = request.getParameter("message");
        
        AWSKMS kmsClient = AWSKMSClientBuilder.standard().build();
        
        SignRequest req = new SignRequest()
            .withKeyId("alias/my-key")
            .withMessage(message.getBytes())
            // ok: java-secure-algorithms-for-digital-signature
            .withSigningAlgorithm("RSASSA_PSS_SHA_512");
        
        SignResult result = kmsClient.sign(req);
        byte[] signature = result.getSignature().array();
    }

    public void good_case_13(HttpServletRequest request) throws Exception {
        // Using strong algorithm with AWS SDK v2 KMS
        String message = request.getParameter("message");
        
        KmsClient kmsClient = KmsClient.create();
        
        // ok: java-secure-algorithms-for-digital-signature
        software.amazon.awssdk.services.kms.model.SignRequest req = 
            software.amazon.awssdk.services.kms.model.SignRequest.builder()
                .keyId("alias/my-key")
                .message(software.amazon.awssdk.core.SdkBytes.fromByteArray(message.getBytes()))
                .signingAlgorithm(SigningAlgorithmSpec.RSASSA_PSS_SHA_512)
                .build();
        
        software.amazon.awssdk.services.kms.model.SignResponse result = kmsClient.sign(req);
    }

    public void good_case_14(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Google API Client
        String data = request.getParameter("data");
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        java.security.Signature signer = java.security.Signature.getInstance("SHA512withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(data.getBytes());
        byte[] signatureBytes = signer.sign();
    }

    public void good_case_15(HttpServletRequest request) throws Exception {
        // Using strong algorithm with Conscrypt
        String data = request.getParameter("data");
        
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "Conscrypt");
        keyGen.initialize(3072);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // ok: java-secure-algorithms-for-digital-signature
        Signature signature = Signature.getInstance("SHA512withRSA", "Conscrypt");
        signature.initSign(keyPair.getPrivate());
        signature.update(data.getBytes());
        byte[] signedData = signature.sign();
    }
}
// {/fact}