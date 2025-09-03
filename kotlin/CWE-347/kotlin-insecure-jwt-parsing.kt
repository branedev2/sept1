import io.jsonwebtoken.Jwts
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.JwtParserBuilder
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.io.Decoders
import java.security.Key
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.security.WeakKeyException
import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.Keys
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Date
import java.time.Instant
import java.time.temporal.ChronoUnit
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.SigningKeyResolverAdapter
import io.jsonwebtoken.io.Encoders
import java.nio.charset.StandardCharsets
import java.util.HashMap
import javax.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.RequestHeader

// True Positives (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_1(jwtToken: String) {
    val secretKey = "insecureHardcodedKeyThatIsTooShortAndWeak12345"
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .setSigningKey(secretKey.toByteArray())
        .parseClaimsJws(jwtToken)
        .body
    
    val username = claims.subject
    println("Authenticated user: $username")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_2(jwtToken: String) {
    val secretKey = "anotherWeakHardcodedKeyForJwtSigning123456789"
    
    try {
        // ruleid: kotlin-insecure-jwt-parsing
        val claims = Jwts.parserBuilder()
            .setSigningKey(secretKey.toByteArray())
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        val userId = claims["userId"] as String
        println("User ID: $userId")
    } catch (e: Exception) {
        println("Invalid token: ${e.message}")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_3(jwtToken: String) {
    // No signature verification at all
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .parseClaimsJwt(jwtToken) // Using parseClaimsJwt instead of parseClaimsJws - doesn't verify signature
        .body
    
    val role = claims["role"] as String
    println("User role: $role")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_4(jwtToken: String) {
    val key = "ThisIsAHardcodedKeyForJwtSigningAndVerification"
    val keyBytes = key.toByteArray(StandardCharsets.UTF_8)
    val secretKey = SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.jcaName)
    
    // ruleid: kotlin-insecure-jwt-parsing
    val parser = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .setAllowedClockSkewSeconds(Integer.MAX_VALUE) // Extremely large clock skew
        .build()
    
    val claims = parser.parseClaimsJws(jwtToken).body
    println("Token parsed with excessive clock skew: ${claims.subject}")
}
// {/fact}

@RestController
class JwtController {
    @GetMapping("/api/verify")
    fun bad_case_5(@RequestHeader("Authorization") authHeader: String) {
        val jwtToken = authHeader.replace("Bearer ", "")
        val hardcodedKey = "hardcodedSecretKeyForJwtVerification12345"
        
        // ruleid: kotlin-insecure-jwt-parsing
        val claims = Jwts.parser()
            .setSigningKey(hardcodedKey.toByteArray())
            .parseClaimsJws(jwtToken)
            .body
        
        val username = claims.subject
        println("API authenticated user: $username")
    }
}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_6(jwtToken: String) {
    // Using weak HMAC algorithm with short key
    val key = "short"
    val secretKey = SecretKeySpec(key.toByteArray(), SignatureAlgorithm.HS256.jcaName)
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("User email: ${claims["email"]}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_7(jwtToken: String) {
    // Using a resolver that always returns the same key regardless of the token
    val hardcodedKey = "staticKeyForAllTokens123456789"
    val keyBytes = hardcodedKey.toByteArray(StandardCharsets.UTF_8)
    val secretKey = SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.jcaName)
    
    val resolver = object : SigningKeyResolverAdapter() {
        override fun resolveSigningKey(header: io.jsonwebtoken.Header<*>, claims: Claims): Key {
            return secretKey
        }
    }
    
    // ruleid: kotlin-insecure-jwt-parsing
    val parsedClaims = Jwts.parserBuilder()
        .setSigningKeyResolver(resolver)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Parsed with static key resolver: ${parsedClaims.subject}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_8(jwtToken: String) {
    // Using a key that's too short for the algorithm
    val weakKey = "tooShort"
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .setSigningKey(weakKey.toByteArray())
        .parseClaimsJws(jwtToken)
        .body
    
    println("Permission: ${claims["permission"]}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_9(request: HttpServletRequest) {
    val jwtToken = request.getHeader("Authorization").substring(7) // Remove "Bearer "
    val hardcodedSecret = "myStaticSecretKeyForAllUsers12345"
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(hardcodedSecret.toByteArray())
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    val userId = claims["id"] as String
    println("Processing request for user: $userId")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_10(jwtToken: String) {
    // No expiration validation
    val key = "hardcodedKeyWithoutExpirationCheck123"
    
    // ruleid: kotlin-insecure-jwt-parsing
    val parser = Jwts.parserBuilder()
        .setSigningKey(key.toByteArray())
        .requireSubject() // Only validating subject
        .build()
    
    val claims = parser.parseClaimsJws(jwtToken).body
    println("Token accepted without expiration check: ${claims.subject}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_11(jwtToken: String) {
    // Using Base64-encoded key directly without proper key construction
    val base64Key = "c29tZXJhbmRvbWtleWZvcmp3dHNpZ25pbmc="
    val decodedKey = Base64.getDecoder().decode(base64Key)
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .setSigningKey(decodedKey)
        .parseClaimsJws(jwtToken)
        .body
    
    println("Organization: ${claims["org"]}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_12(jwtToken: String) {
    // Accepting any algorithm (vulnerable to algorithm confusion attacks)
    val key = "hardcodedKeyVulnerableToAlgConfusion"
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .setSigningKey(key.toByteArray())
        .parseClaimsJws(jwtToken) // No algorithm restriction
        .body
    
    println("Data processed for: ${claims.subject}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_13(jwtToken: String) {
    // Catching all exceptions and proceeding anyway
    val key = "insecureKeyWithBadExceptionHandling"
    
    try {
        // ruleid: kotlin-insecure-jwt-parsing
        val claims = Jwts.parser()
            .setSigningKey(key.toByteArray())
            .parseClaimsJws(jwtToken)
            .body
        
        println("User authenticated: ${claims.subject}")
    } catch (e: Exception) {
        // Dangerous: proceeding with authentication despite failure
        println("Warning occurred but proceeding anyway")
        processAuthenticatedRequest("defaultUser")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_14(jwtToken: String) {
    // Using a key that's stored as a string constant in the code
    val secretKeyString = "ThisIsAHardcodedSecretKeyForJwtVerification123456789"
    val key = SecretKeySpec(secretKeyString.toByteArray(), "HmacSHA256")
    
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    val username = claims.subject
    println("Authenticated with hardcoded key: $username")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
fun bad_case_15(jwtToken: String) {
    // Using unsecured JWT (no signature)
    // ruleid: kotlin-insecure-jwt-parsing
    val claims = Jwts.parser()
        .parseClaimsJwt(jwtToken) // Using parseClaimsJwt for unsecured tokens
        .body
    
    val userId = claims["userId"] as String
    println("Processing unsecured token for user: $userId")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_1(jwtToken: String) {
    // Using environment variable for key
    val secretKey = System.getenv("JWT_SECRET_KEY")
    if (secretKey == null || secretKey.length < 32) {
        throw SecurityException("Invalid JWT secret key configuration")
    }
    
    // ok: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(secretKey.toByteArray())
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    val username = claims.subject
    println("Authenticated user: $username")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_2(jwtToken: String) {
    // Using a properly generated key with sufficient length
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512)
    
    try {
        // ok: kotlin-insecure-jwt-parsing
        val claims = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        val userId = claims["userId"] as String
        println("User ID: $userId")
    } catch (e: SignatureException) {
        println("Invalid JWT signature")
    } catch (e: MalformedJwtException) {
        println("Invalid JWT token")
    } catch (e: ExpiredJwtException) {
        println("Expired JWT token")
    } catch (e: UnsupportedJwtException) {
        println("Unsupported JWT token")
    } catch (e: IllegalArgumentException) {
        println("JWT claims string is empty")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_3(jwtToken: String) {
    // Using asymmetric key (RSA) with proper key generation
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    val keyPair = keyPairGenerator.generateKeyPair()
    val publicKey = keyPair.public
    
    try {
        // ok: kotlin-insecure-jwt-parsing
        val claims = Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        val role = claims["role"] as String
        println("User role: $role")
    } catch (e: Exception) {
        println("Token validation failed: ${e.message}")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_4(jwtToken: String) {
    // Using a secure key with proper clock skew
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS384)
    
    // ok: kotlin-insecure-jwt-parsing
    val parser = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .setAllowedClockSkewSeconds(60) // Reasonable clock skew
        .requireExpiration() // Explicitly require expiration time
        .requireIssuedAt()
        .build()
    
    try {
        val claims = parser.parseClaimsJws(jwtToken).body
        println("Token validated with proper settings: ${claims.subject}")
    } catch (e: ExpiredJwtException) {
        println("Token has expired")
    }
}
// {/fact}

@RestController
class SecureJwtController {
    private val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512)
    
    @GetMapping("/api/secure-verify")
    fun good_case_5(@RequestHeader("Authorization") authHeader: String) {
        val jwtToken = authHeader.replace("Bearer ", "")
        
        try {
            // ok: kotlin-insecure-jwt-parsing
            val claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .requireExpiration()
                .requireIssuedAt()
                .requireSubject()
                .build()
                .parseClaimsJws(jwtToken)
                .body
            
            val username = claims.subject
            println("API authenticated user: $username")
        } catch (e: Exception) {
            println("Authentication failed: ${e.message}")
        }
    }
}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_6(jwtToken: String) {
    // Using a key with proper length for the algorithm
    val keyBytes = ByteArray(64) // 512 bits for HS512
    val secureRandom = java.security.SecureRandom()
    secureRandom.nextBytes(keyBytes)
    val secretKey = SecretKeySpec(keyBytes, SignatureAlgorithm.HS512.jcaName)
    
    try {
        // ok: kotlin-insecure-jwt-parsing
        val claims = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        println("User email: ${claims["email"]}")
    } catch (e: WeakKeyException) {
        println("Key is too weak for the algorithm")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_7(jwtToken: String) {
    // Using a key resolver that looks up keys based on token content
    val keyMap = HashMap<String, Key>()
    // In a real scenario, these would be loaded from a secure store
    keyMap["user1"] = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    keyMap["user2"] = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    
    val resolver = object : SigningKeyResolverAdapter() {
        override fun resolveSigningKey(header: io.jsonwebtoken.Header<*>, claims: Claims): Key {
            val keyId = claims.subject ?: throw IllegalArgumentException("Token missing subject")
            return keyMap[keyId] ?: throw IllegalArgumentException("No key found for: $keyId")
        }
    }
    
    // ok: kotlin-insecure-jwt-parsing
    val parsedClaims = Jwts.parserBuilder()
        .setSigningKeyResolver(resolver)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Parsed with dynamic key resolver: ${parsedClaims.subject}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_8(jwtToken: String) {
    // Using a key from a secure key store
    val keyStore = java.security.KeyStore.getInstance("PKCS12")
    val keyStoreFile = java.io.FileInputStream("keystore.p12")
    keyStore.load(keyStoreFile, "keystorePassword".toCharArray())
    
    val key = keyStore.getKey("jwtKey", "keyPassword".toCharArray()) as SecretKey
    
    // ok: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Permission: ${claims["permission"]}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_9(request: HttpServletRequest) {
    val jwtToken = request.getHeader("Authorization").substring(7) // Remove "Bearer "
    val secretKeyString = System.getenv("JWT_SECRET")
    
    if (secretKeyString == null || secretKeyString.length < 32) {
        throw SecurityException("Invalid JWT secret configuration")
    }
    
    // ok: kotlin-insecure-jwt-parsing
    try {
        val claims = Jwts.parserBuilder()
            .setSigningKey(secretKeyString.toByteArray())
            .requireExpiration()
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        val userId = claims["id"] as String
        println("Processing request for user: $userId")
    } catch (e: ExpiredJwtException) {
        println("Token expired")
    } catch (e: Exception) {
        println("Token validation failed: ${e.message}")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_10(jwtToken: String) {
    // Proper expiration validation
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    
    // ok: kotlin-insecure-jwt-parsing
    val parser = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .requireExpiration()
        .setAllowedClockSkewSeconds(30)
        .build()
    
    try {
        val claims = parser.parseClaimsJws(jwtToken).body
        val now = Date.from(Instant.now())
        
        if (claims.expiration.before(now)) {
            throw ExpiredJwtException(null, claims, "Token has expired")
        }
        
        println("Token validated with expiration check: ${claims.subject}")
    } catch (e: ExpiredJwtException) {
        println("Token expired")
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_11(jwtToken: String) {
    // Proper key construction from Base64
    val base64Key = System.getenv("JWT_SECRET_BASE64")
    if (base64Key == null || base64Key.isEmpty()) {
        throw SecurityException("JWT secret not configured")
    }
    
    val keyBytes = Decoders.BASE64.decode(base64Key)
    val key = Keys.hmacShaKeyFor(keyBytes)
    
    // ok: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Organization: ${claims["org"]}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_12(jwtToken: String) {
    // Explicitly requiring specific algorithm
    val key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    
    // ok: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .requireAlgorithm(SignatureAlgorithm.HS256) // Explicitly require algorithm
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Data processed for: ${claims.subject}")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_13(jwtToken: String) {
    // Proper exception handling with specific catches
    val key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    
    try {
        // ok: kotlin-insecure-jwt-parsing
        val claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        println("User authenticated: ${claims.subject}")
    } catch (e: SignatureException) {
        println("Invalid JWT signature")
        // Proper handling - deny access
    } catch (e: MalformedJwtException) {
        println("Invalid JWT token")
        // Proper handling - deny access
    } catch (e: ExpiredJwtException) {
        println("Expired JWT token")
        // Proper handling - deny access or request refresh
    } catch (e: UnsupportedJwtException) {
        println("Unsupported JWT token")
        // Proper handling - deny access
    } catch (e: IllegalArgumentException) {
        println("JWT claims string is empty")
        // Proper handling - deny access
    }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_14(jwtToken: String) {
    // Using a key from a secure configuration service
    val configService = getConfigurationService() // Assume this is a secure config service
    val secretKey = configService.getSecretKey("jwt.signing.key")
    
    // ok: kotlin-insecure-jwt-parsing
    val claims = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .requireExpiration()
        .requireIssuedAt()
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    val username = claims.subject
    println("Authenticated with secure key: $username")
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
fun good_case_15(jwtToken: String) {
    // Using asymmetric keys with proper validation
    val keyPair = generateRsaKeyPair()
    val publicKey = keyPair.public
    
    // ok: kotlin-insecure-jwt-parsing
    try {
        val claims = Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .requireExpiration()
            .requireIssuedAt()
            .requireAudience("secure-app")
            .requireIssuer("auth-service")
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        println("Validated token with full checks for user: ${claims.subject}")
    } catch (e: Exception) {
        println("Token validation failed: ${e.message}")
    }
}
// {/fact}

// Helper functions
fun processAuthenticatedRequest(username: String) {
    println("Processing request for $username")
}

fun getConfigurationService(): ConfigurationService {
    return ConfigurationService()
}

class ConfigurationService {
    fun getSecretKey(keyName: String): Key {
        // In a real implementation, this would retrieve from a secure store
        return Keys.secretKeyFor(SignatureAlgorithm.HS256)
    }
}

fun generateRsaKeyPair(): KeyPair {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    return keyPairGenerator.generateKeyPair()
}