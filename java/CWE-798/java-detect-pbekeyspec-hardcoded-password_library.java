import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import org.hashids.Hashids;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.mindrot.jbcrypt.BCrypt;
import com.lambdaworks.crypto.SCryptUtil;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;
import javax.servlet.http.HttpServletRequest;

// Security Issue: Hardcoded passwords in PBEKeySpec instances

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1() {
    // Standard Java Crypto API with hardcoded password
    byte[] salt = new byte[16];
    int iterations = 1000;
    int keyLength = 256;
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec spec = new PBEKeySpec("hardcoded_password".toCharArray(), salt, iterations, keyLength);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(spec);
        // Use the key for encryption
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        e.printStackTrace();
    } finally {
        spec.clearPassword();
    }
}

public void bad_case_2(HttpServletRequest request) {
    // Spring Security with hardcoded password in PBEKeySpec
    String username = request.getParameter("username");
    byte[] salt = username.getBytes();
    int iterations = 10000;
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec pbeKeySpec = new PBEKeySpec("Spring_S3curity_P@ss!".toCharArray(), salt, iterations, 256);
    
    try {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        // Use key for authentication
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        pbeKeySpec.clearPassword();
    }
}

public void bad_case_3() {
    // Apache Commons Configuration with hardcoded password
    try {
        Configuration config = new PropertiesConfiguration("app.properties");
        byte[] salt = config.getString("salt").getBytes();
        int iterations = config.getInt("iterations", 1000);
        
        // ruleid: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec("Apache_Commons_Fixed_Password".toCharArray(), salt, iterations, 128);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_256");
        SecretKey key = keyFactory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_4() {
    // Jasypt encryption library with hardcoded password
    BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
    textEncryptor.setPassword("jasypt_encryption_password");
    
    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    encryptor.setAlgorithm("PBEWithMD5AndDES");
    
    // Custom implementation using PBEKeySpec with hardcoded password
    byte[] salt = new byte[8];
    new SecureRandom().nextBytes(salt);
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("jasypt_hardcoded_master_password".toCharArray(), salt, 1000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_5() {
    // AWS SDK with hardcoded credentials and PBEKeySpec
    AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec pbeKeySpec = new PBEKeySpec("aws_encryption_password".toCharArray(), salt, 2000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(pbeKeySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_6(HttpServletRequest request) {
    // Google Cloud Secret Manager with hardcoded password in PBEKeySpec
    String projectId = request.getParameter("projectId");
    String secretId = request.getParameter("secretId");
    
    byte[] salt = (projectId + secretId).getBytes();
    int iterations = 10000;
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec pbeKeySpec = new PBEKeySpec("gcp_master_password_123".toCharArray(), salt, iterations, 256);
    
    try {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_7() {
    // Hashids library with hardcoded salt and PBEKeySpec
    Hashids hashids = new Hashids("this is my salt");
    String hash = hashids.encode(1, 2, 3);
    
    byte[] salt = hash.getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("hashids_master_key_2023".toCharArray(), salt, 5000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_8() {
    // BouncyCastle with hardcoded password
    PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    // Custom implementation using PBEKeySpec with hardcoded password
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("bouncy_castle_fixed_password".toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_9() {
    // Apache Shiro with hardcoded password
    RandomNumberGenerator rng = new SecureRandomNumberGenerator();
    ByteSource salt = rng.nextBytes();
    
    // Using PBEKeySpec with hardcoded password alongside Shiro
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("shiro_admin_password".toCharArray(), salt.getBytes(), 2000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_10() {
    // jBCrypt with hardcoded password for PBEKeySpec
    String hashed = BCrypt.hashpw("user_password", BCrypt.gensalt(12));
    
    // Using PBEKeySpec with hardcoded password for additional encryption
    byte[] salt = hashed.getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("bcrypt_master_key_2023".toCharArray(), salt, 1000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_11() {
    // SCrypt with hardcoded password for PBEKeySpec
    String hashed = SCryptUtil.scrypt("user_password", 16384, 8, 1);
    
    // Using PBEKeySpec with hardcoded password
    byte[] salt = hashed.substring(0, 16).getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("scrypt_master_password".toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_12() {
    // Azure Key Vault with hardcoded password for PBEKeySpec
    SecretClient secretClient = new SecretClientBuilder()
        .vaultUrl("https://myvault.vault.azure.net/")
        .credential(new DefaultAzureCredentialBuilder().build())
        .buildClient();
    
    // Still using hardcoded password for PBEKeySpec
    byte[] salt = "azure_salt".getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("azure_vault_backup_key".toCharArray(), salt, 5000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_13() {
    // Nimbus JOSE + JWT with hardcoded password
    // Initialize Bouncy Castle provider
    BouncyCastleProviderSingleton.getInstance();
    
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("jwt_signing_password".toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for JWT signing
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_14() {
    // Spring Vault with hardcoded password
    VaultTemplate vaultTemplate = new VaultTemplate();
    
    byte[] salt = "vault_salt".getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("spring_vault_master_key".toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void bad_case_15(HttpServletRequest request) {
    // Custom implementation with hardcoded password
    String userId = request.getParameter("userId");
    byte[] salt = userId.getBytes();
    
    // ruleid: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec("custom_implementation_password".toCharArray(), salt, 20000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    // Standard Java Crypto API with password from request
    String password = request.getParameter("password");
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    int iterations = 10000;
    int keyLength = 256;
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(spec);
        // Use the key for encryption
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
        e.printStackTrace();
    } finally {
        spec.clearPassword();
    }
}

public void good_case_2(HttpServletRequest request) {
    // Spring Security with password from request
    String password = request.getParameter("password");
    String username = request.getParameter("username");
    byte[] salt = username.getBytes();
    int iterations = 10000;
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
    
    try {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        // Use key for authentication
    } catch (Exception e) {
        e.printStackTrace();
    } finally {
        pbeKeySpec.clearPassword();
    }
}

public void good_case_3(HttpServletRequest request) {
    // Apache Commons Configuration with password from properties file
    try {
        Configuration config = new PropertiesConfiguration("app.properties");
        String password = config.getString("encryption.password");
        byte[] salt = config.getString("salt").getBytes();
        int iterations = config.getInt("iterations", 1000);
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, 128);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_256");
        SecretKey key = keyFactory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_4(HttpServletRequest request) {
    // Jasypt encryption library with password from request
    String password = request.getParameter("encryptionPassword");
    
    BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
    textEncryptor.setPassword(password);
    
    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    encryptor.setAlgorithm("PBEWithMD5AndDES");
    encryptor.setPassword(password);
    
    // Custom implementation using PBEKeySpec with password from request
    byte[] salt = new byte[8];
    new SecureRandom().nextBytes(salt);
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_5(HttpServletRequest request) {
    // AWS Secrets Manager to retrieve password
    String region = request.getParameter("region");
    String secretName = request.getParameter("secretName");
    
    AWSSecretsManager client = AWSSecretsManagerClientBuilder.standard()
                                .withRegion(region)
                                .build();
    
    GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                                                .withSecretId(secretName);
    GetSecretValueResult getSecretValueResult = client.getSecretValue(getSecretValueRequest);
    
    String password = getSecretValueResult.getSecretString();
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 2000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(pbeKeySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_6(HttpServletRequest request) {
    // Google Cloud Secret Manager to retrieve password
    String projectId = request.getParameter("projectId");
    String secretId = request.getParameter("secretId");
    String versionId = request.getParameter("versionId");
    
    try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
        SecretVersionName secretVersionName = SecretVersionName.of(projectId, secretId, versionId);
        String password = client.accessSecretVersion(secretVersionName).getPayload().getData().toStringUtf8();
        
        byte[] salt = (projectId + secretId).getBytes();
        int iterations = 10000;
        
        // ok: java-detect-pbekeyspec-hardcoded-password
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = keyFactory.generateSecret(pbeKeySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_7(HttpServletRequest request) {
    // Hashids library with salt from request and PBEKeySpec
    String salt = request.getParameter("salt");
    Hashids hashids = new Hashids(salt);
    String hash = hashids.encode(1, 2, 3);
    
    String password = request.getParameter("password");
    byte[] saltBytes = hash.getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 5000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_8(HttpServletRequest request) {
    // BouncyCastle with password from request
    PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    String password = request.getParameter("password");
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_9(HttpServletRequest request) {
    // Apache Shiro with password from request
    RandomNumberGenerator rng = new SecureRandomNumberGenerator();
    ByteSource salt = rng.nextBytes();
    
    String password = request.getParameter("password");
    
    // Using PBEKeySpec with password from request alongside Shiro
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 2000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_10(HttpServletRequest request) {
    // jBCrypt with password from request for PBEKeySpec
    String userPassword = request.getParameter("userPassword");
    String masterPassword = request.getParameter("masterPassword");
    
    String hashed = BCrypt.hashpw(userPassword, BCrypt.gensalt(12));
    
    // Using PBEKeySpec with password from request for additional encryption
    byte[] salt = hashed.getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(masterPassword.toCharArray(), salt, 1000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_11(HttpServletRequest request) {
    // SCrypt with password from request for PBEKeySpec
    String userPassword = request.getParameter("userPassword");
    String masterPassword = request.getParameter("masterPassword");
    
    String hashed = SCryptUtil.scrypt(userPassword, 16384, 8, 1);
    
    // Using PBEKeySpec with password from request
    byte[] salt = hashed.substring(0, 16).getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(masterPassword.toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_12(HttpServletRequest request) {
    // Azure Key Vault to retrieve password
    String vaultUrl = request.getParameter("vaultUrl");
    String secretName = request.getParameter("secretName");
    
    SecretClient secretClient = new SecretClientBuilder()
        .vaultUrl(vaultUrl)
        .credential(new DefaultAzureCredentialBuilder().build())
        .buildClient();
    
    String password = secretClient.getSecret(secretName).getValue();
    byte[] salt = "azure_salt".getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 5000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_13(HttpServletRequest request) {
    // Nimbus JOSE + JWT with password from request
    // Initialize Bouncy Castle provider
    BouncyCastleProviderSingleton.getInstance();
    
    String password = request.getParameter("jwtSigningPassword");
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for JWT signing
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_14(HttpServletRequest request) {
    // Spring Vault to retrieve password
    VaultTemplate vaultTemplate = new VaultTemplate();
    String secretPath = request.getParameter("secretPath");
    
    VaultResponseSupport<Map<String, Object>> response = vaultTemplate.read(secretPath);
    String password = (String) response.getData().get("password");
    
    byte[] salt = "vault_salt".getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public void good_case_15(HttpServletRequest request) {
    // Custom implementation with password from properties file
    Properties props = new Properties();
    try (FileInputStream fis = new FileInputStream("config.properties")) {
        props.load(fis);
    } catch (IOException e) {
        e.printStackTrace();
    }
    
    String password = props.getProperty("encryption.password");
    String userId = request.getParameter("userId");
    byte[] salt = userId.getBytes();
    
    // ok: java-detect-pbekeyspec-hardcoded-password
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 20000, 256);
    
    try {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = factory.generateSecret(keySpec);
        // Use key for encryption
    } catch (Exception e) {
        e.printStackTrace();
    }
}