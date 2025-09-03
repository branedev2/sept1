import java.util.Arrays;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.util.Base64;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.util.ByteSource;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import retrofit2.Call;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.http.GET;
import retrofit2.http.Header;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.apis.GoogleApi20;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessToken;

// Security Issue: Using equals() for comparing secrets is vulnerable to timing attacks.
// Instead, constant-time comparison methods like MessageDigest.isEqual() should be used.

// True Positive Examples (Vulnerable/Insecure Code)

public class UnsecureComparisonExamples {

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring Security - Insecure API key validation
        String expectedApiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        String receivedApiKey = request.getHeader("X-API-Key");
        
        // ruleid: java-unsecure-comparison
        if (expectedApiKey.equals(receivedApiKey)) {
            System.out.println("API key is valid");
        }
    }

    public void bad_case_2(HttpServletRequest request) {
        // Apache Shiro - Insecure token comparison
        String storedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String requestToken = request.getParameter("token");
        
        // ruleid: java-unsecure-comparison
        if (storedToken.equals(requestToken)) {
            System.out.println("Shiro token is valid");
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        // JJWT Library - Insecure secret comparison
        byte[] secretKey = "secret".getBytes();
        String receivedSignature = request.getHeader("X-Signature");
        String expectedSignature = Jwts.builder()
            .setSubject("user")
            .signWith(Keys.hmacShaKeyFor(secretKey), SignatureAlgorithm.HS256)
            .compact();
        
        // ruleid: java-unsecure-comparison
        if (expectedSignature.equals(receivedSignature)) {
            System.out.println("JWT signature is valid");
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        // Auth0 JWT - Insecure token validation
        String storedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        String requestToken = request.getHeader("Authorization").substring(7); // Remove "Bearer "
        
        // ruleid: java-unsecure-comparison
        if (storedToken.equals(requestToken)) {
            System.out.println("Auth0 token is valid");
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        // AWS Secrets Manager - Insecure secret comparison
        String storedSecret = "aws_secret_key_123456";
        String providedSecret = request.getParameter("secret");
        
        // ruleid: java-unsecure-comparison
        if (storedSecret.equals(providedSecret)) {
            System.out.println("AWS secret is valid");
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        // Azure Key Vault - Insecure secret comparison
        String azureSecret = "azure_key_vault_secret_123";
        String clientSecret = request.getHeader("X-Client-Secret");
        
        // ruleid: java-unsecure-comparison
        if (azureSecret.equals(clientSecret)) {
            System.out.println("Azure secret is valid");
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        // Google Cloud Secret Manager - Insecure comparison
        String gcpSecret = "gcp_secret_manager_key_456";
        String providedSecret = request.getParameter("gcp_secret");
        
        // ruleid: java-unsecure-comparison
        if (gcpSecret.equals(providedSecret)) {
            System.out.println("GCP secret is valid");
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        // OkHttp - Insecure bearer token validation
        String validToken = "valid_okhttp_bearer_token";
        String requestToken = request.getHeader("Authorization").substring(7);
        
        // ruleid: java-unsecure-comparison
        if (validToken.equals(requestToken)) {
            System.out.println("OkHttp bearer token is valid");
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        // Apache HttpClient - Insecure API key validation
        String validApiKey = "apache_http_client_api_key";
        String receivedApiKey = request.getHeader("X-API-Key");
        
        // ruleid: java-unsecure-comparison
        if (validApiKey.equals(receivedApiKey)) {
            System.out.println("Apache HttpClient API key is valid");
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        // Java 11 HttpClient - Insecure token validation
        String validToken = "java11_http_client_token";
        String receivedToken = request.getParameter("token");
        
        // ruleid: java-unsecure-comparison
        if (validToken.equals(receivedToken)) {
            System.out.println("Java 11 HttpClient token is valid");
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        // Retrofit - Insecure authentication token comparison
        String validAuthToken = "retrofit_auth_token_789";
        String receivedToken = request.getHeader("X-Auth-Token");
        
        // ruleid: java-unsecure-comparison
        if (validAuthToken.equals(receivedToken)) {
            System.out.println("Retrofit auth token is valid");
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        // ScribeJava OAuth - Insecure access token validation
        String storedAccessToken = "scribe_oauth_access_token";
        String receivedToken = request.getParameter("access_token");
        
        // ruleid: java-unsecure-comparison
        if (storedAccessToken.equals(receivedToken)) {
            System.out.println("ScribeJava OAuth token is valid");
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        // Keycloak - Insecure token validation
        String keycloakToken = "keycloak_admin_token_123";
        String receivedToken = request.getHeader("X-Keycloak-Token");
        
        // ruleid: java-unsecure-comparison
        if (keycloakToken.equals(receivedToken)) {
            System.out.println("Keycloak token is valid");
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        // HMAC_REDACTED_TWILIO_ID signature validation - Insecure comparison
        String expectedHmac = "hmac_signature_abcdef123456";
        String receivedHmac = request.getHeader("X-HMAC_REDACTED_TWILIO_ID-Signature");
        
        // ruleid: java-unsecure-comparison
        if (expectedHmac.equals(receivedHmac)) {
            System.out.println("HMAC_REDACTED_TWILIO_ID signature is valid");
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        // Custom API authentication - Insecure comparison
        byte[] expectedAuthBytes = Base64.getDecoder().decode("c2VjcmV0X2F1dGhfY29kZQ==");
        byte[] receivedAuthBytes = Base64.getDecoder().decode(request.getParameter("auth_code"));
        
        // ruleid: java-unsecure-comparison
        if (Arrays.equals(expectedAuthBytes, receivedAuthBytes)) {
            System.out.println("Authentication code is valid");
        }
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1(HttpServletRequest request) {
        // Spring Security - Secure API key validation
        String expectedApiKey = "sk_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY";
        String receivedApiKey = request.getHeader("X-API-Key");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(expectedApiKey.getBytes(), receivedApiKey.getBytes())) {
            System.out.println("API key is valid");
        }
    }

    public void good_case_2(HttpServletRequest request) {
        // Apache Shiro - Secure token comparison
        String storedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String requestToken = request.getParameter("token");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedToken.getBytes(), requestToken.getBytes())) {
            System.out.println("Shiro token is valid");
        }
    }

    public void good_case_3(HttpServletRequest request) {
        // JJWT Library - Secure secret comparison
        try {
            byte[] secretKey = "secret".getBytes();
            String receivedSignature = request.getHeader("X-Signature");
            String expectedSignature = Jwts.builder()
                .setSubject("user")
                .signWith(Keys.hmacShaKeyFor(secretKey), SignatureAlgorithm.HS256)
                .compact();
            
            // ok: java-unsecure-comparison
            if (MessageDigest.isEqual(expectedSignature.getBytes(), receivedSignature.getBytes())) {
                System.out.println("JWT signature is valid");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request) {
        // Auth0 JWT - Secure token validation
        String storedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
        String requestToken = request.getHeader("Authorization").substring(7); // Remove "Bearer "
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedToken.getBytes(), requestToken.getBytes())) {
            System.out.println("Auth0 token is valid");
        }
    }

    public void good_case_5(HttpServletRequest request) {
        // AWS Secrets Manager - Secure secret comparison
        String storedSecret = "aws_secret_key_123456";
        String providedSecret = request.getParameter("secret");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedSecret.getBytes(), providedSecret.getBytes())) {
            System.out.println("AWS secret is valid");
        }
    }

    public void good_case_6(HttpServletRequest request) {
        // Azure Key Vault - Secure secret comparison
        String azureSecret = "azure_key_vault_secret_123";
        String clientSecret = request.getHeader("X-Client-Secret");
        
        // Using a custom constant-time comparison method
        // ok: java-unsecure-comparison
        boolean isValid = constantTimeEquals(azureSecret.getBytes(), clientSecret.getBytes());
        if (isValid) {
            System.out.println("Azure secret is valid");
        }
    }

    public void good_case_7(HttpServletRequest request) {
        // Google Cloud Secret Manager - Secure comparison
        String gcpSecret = "gcp_secret_manager_key_456";
        String providedSecret = request.getParameter("gcp_secret");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(gcpSecret.getBytes(), providedSecret.getBytes())) {
            System.out.println("GCP secret is valid");
        }
    }

    public void good_case_8(HttpServletRequest request) {
        // OkHttp - Secure bearer token validation
        String validToken = "valid_okhttp_bearer_token";
        String requestToken = request.getHeader("Authorization").substring(7);
        
        // ok: java-unsecure-comparison
        boolean isValid = MessageDigest.isEqual(validToken.getBytes(), requestToken.getBytes());
        if (isValid) {
            System.out.println("OkHttp bearer token is valid");
        }
    }

    public void good_case_9(HttpServletRequest request) {
        // Apache HttpClient - Secure API key validation
        String validApiKey = "apache_http_client_api_key";
        String receivedApiKey = request.getHeader("X-API-Key");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(validApiKey.getBytes(), receivedApiKey.getBytes())) {
            System.out.println("Apache HttpClient API key is valid");
        }
    }

    public void good_case_10(HttpServletRequest request) {
        // Java 11 HttpClient - Secure token validation using Spring Security utility
        String validToken = "java11_http_client_token";
        String receivedToken = request.getParameter("token");
        
        // ok: java-unsecure-comparison
        if (org.springframework.security.crypto.util.ConstantTimeComparator.equals(
                validToken.getBytes(), receivedToken.getBytes())) {
            System.out.println("Java 11 HttpClient token is valid");
        }
    }

    public void good_case_11(HttpServletRequest request) {
        // Retrofit - Secure authentication token comparison
        String validAuthToken = "retrofit_auth_token_789";
        String receivedToken = request.getHeader("X-Auth-Token");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(validAuthToken.getBytes(), receivedToken.getBytes())) {
            System.out.println("Retrofit auth token is valid");
        }
    }

    public void good_case_12(HttpServletRequest request) {
        // ScribeJava OAuth - Secure access token validation
        String storedAccessToken = "scribe_oauth_access_token";
        String receivedToken = request.getParameter("access_token");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(storedAccessToken.getBytes(), receivedToken.getBytes())) {
            System.out.println("ScribeJava OAuth token is valid");
        }
    }

    public void good_case_13(HttpServletRequest request) {
        // Keycloak - Secure token validation
        String keycloakToken = "keycloak_admin_token_123";
        String receivedToken = request.getHeader("X-Keycloak-Token");
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(keycloakToken.getBytes(), receivedToken.getBytes())) {
            System.out.println("Keycloak token is valid");
        }
    }

    public void good_case_14(HttpServletRequest request) {
        // HMAC_REDACTED_TWILIO_ID signature validation - Secure comparison
        String expectedHmac = "hmac_signature_abcdef123456";
        String receivedHmac = request.getHeader("X-HMAC_REDACTED_TWILIO_ID-Signature");
        
        // ok: java-unsecure-comparison
        boolean isValid = MessageDigest.isEqual(expectedHmac.getBytes(), receivedHmac.getBytes());
        if (isValid) {
            System.out.println("HMAC_REDACTED_TWILIO_ID signature is valid");
        }
    }

    public void good_case_15(HttpServletRequest request) {
        // Custom API authentication - Secure comparison
        byte[] expectedAuthBytes = Base64.getDecoder().decode("c2VjcmV0X2F1dGhfY29kZQ==");
        byte[] receivedAuthBytes = Base64.getDecoder().decode(request.getParameter("auth_code"));
        
        // ok: java-unsecure-comparison
        if (MessageDigest.isEqual(expectedAuthBytes, receivedAuthBytes)) {
            System.out.println("Authentication code is valid");
        }
    }
    
    // Helper method for constant-time comparison
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
// {/fact}