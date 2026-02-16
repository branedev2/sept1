import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.security.SignatureException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.security.WeakKeyException
import java.security.Key
import java.util.Date
import javax.crypto.SecretKey
import java.util.Base64

// True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_1() {
    // Creating a JWT token with "none" algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user123")
        .claim("role", "admin")
        // ruleid: kotlin-jwt-none-algorithm
        .signWith(SignatureAlgorithm.NONE)
        .compact()
    
    println("Generated JWT: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_2() {
    // Using "none" algorithm with explicit null key
    val jwtToken = Jwts.builder()
        .setSubject("user456")
        .claim("permissions", "read,write")
        // ruleid: kotlin-jwt-none-algorithm
        .signWith(SignatureAlgorithm.NONE, null)
        .compact()
    
    println("Generated insecure JWT: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_3() {
    // Using "none" algorithm with string-based method
    val jwtToken = Jwts.builder()
        .setSubject("user789")
        .claim("department", "engineering")
        // ruleid: kotlin-jwt-none-algorithm
        .signWith(SignatureAlgorithm.valueOf("NONE"))
        .compact()
    
    println("Generated JWT with string-based none: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_4() {
    // Using "none" algorithm with variable
    val algorithm = SignatureAlgorithm.NONE
    val jwtToken = Jwts.builder()
        .setSubject("user101")
        .claim("access", "full")
        // ruleid: kotlin-jwt-none-algorithm
        .signWith(algorithm)
        .compact()
    
    println("Generated JWT with variable algorithm: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_5() {
    // Using "none" algorithm with conditional
    val isTestEnvironment = true
    val algorithm = if (isTestEnvironment) SignatureAlgorithm.NONE else SignatureAlgorithm.HS256
    val jwtToken = Jwts.builder()
        .setSubject("user202")
        .claim("type", "temporary")
        // ruleid: kotlin-jwt-none-algorithm
        .signWith(algorithm)
        .compact()
    
    println("Generated JWT with conditional algorithm: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_6() {
    // Using "none" algorithm with parser
    val jwtToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIn0."
    
    // ruleid: kotlin-jwt-none-algorithm
    val parser = Jwts.parser().setSigningKey("").build()
    val claims = parser.parseClaimsJws(jwtToken).body
    
    println("Parsed claims: $claims")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_7() {
    // Using "none" algorithm with parser builder
    val jwtToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMTIzIn0."
    
    // ruleid: kotlin-jwt-none-algorithm
    val claims = Jwts.parserBuilder()
        .setAllowedClockSkewSeconds(60)
        .setSigningKey("")
        .build()
        .parseClaimsJws(jwtToken)
        .body
    
    println("Parsed claims with builder: $claims")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_8() {
    // Using "none" algorithm with explicit configuration
    val config = mapOf(
        "algorithm" to "none",
        "subject" to "user303"
    )
    
    // ruleid: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject(config["subject"])
        .signWith(SignatureAlgorithm.valueOf(config["algorithm"]!!.uppercase()))
        .compact()
    
    println("Generated JWT with config: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_9() {
    // Using "none" algorithm with function parameter
    fun createToken(algorithm: SignatureAlgorithm): String {
        return Jwts.builder()
            .setSubject("user404")
            .claim("purpose", "testing")
            // ruleid: kotlin-jwt-none-algorithm
            .signWith(algorithm)
            .compact()
    }
    
    val jwtToken = createToken(SignatureAlgorithm.NONE)
    println("Generated JWT from function: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_10() {
    // Using "none" algorithm with try-catch
    try {
        val jwtToken = Jwts.builder()
            .setSubject("user505")
            .claim("status", "active")
            // ruleid: kotlin-jwt-none-algorithm
            .signWith(SignatureAlgorithm.NONE)
            .compact()
        
        println("Generated JWT in try block: $jwtToken")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_11() {
    // Using "none" algorithm with custom wrapper
    class JwtGenerator(private val algorithm: SignatureAlgorithm) {
        fun generate(subject: String): String {
            // ruleid: kotlin-jwt-none-algorithm
            return Jwts.builder()
                .setSubject(subject)
                .signWith(algorithm)
                .compact()
        }
    }
    
    val generator = JwtGenerator(SignatureAlgorithm.NONE)
    val jwtToken = generator.generate("user606")
    println("Generated JWT with wrapper: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_12() {
    // Using "none" algorithm with string comparison
    val algorithmName = "NONE"
    val algorithm = SignatureAlgorithm.values().first { it.name == algorithmName }
    
    // ruleid: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user707")
        .signWith(algorithm)
        .compact()
    
    println("Generated JWT with string comparison: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_13() {
    // Using "none" algorithm with map lookup
    val algorithms = mapOf(
        "secure" to SignatureAlgorithm.HS256,
        "insecure" to SignatureAlgorithm.NONE
    )
    
    // ruleid: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user808")
        .signWith(algorithms["insecure"]!!)
        .compact()
    
    println("Generated JWT with map lookup: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_14() {
    // Using "none" algorithm with explicit unsafe flag
    val useUnsafeAlgorithm = true
    val algorithm = if (useUnsafeAlgorithm) SignatureAlgorithm.NONE else SignatureAlgorithm.HS256
    
    // ruleid: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user909")
        .signWith(algorithm)
        .compact()
    
    println("Generated JWT with unsafe flag: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
fun bad_case_15() {
    // Using "none" algorithm with environment check
    val environment = "development"
    val algorithm = when (environment) {
        "development" -> SignatureAlgorithm.NONE
        else -> SignatureAlgorithm.HS256
    }
    
    // ruleid: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user1010")
        .signWith(algorithm)
        .compact()
    
    println("Generated JWT with environment check: $jwtToken")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_1() {
    // Using secure HS256 algorithm
    val key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user123")
        .claim("role", "admin")
        .signWith(key, SignatureAlgorithm.HS256)
        .compact()
    
    println("Generated secure JWT: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_2() {
    // Using secure RS256 algorithm
    val keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user456")
        .claim("permissions", "read,write")
        .signWith(keyPair.private, SignatureAlgorithm.RS256)
        .compact()
    
    println("Generated secure JWT with RS256: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_3() {
    // Using secure ES256 algorithm
    val keyPair = Keys.keyPairFor(SignatureAlgorithm.ES256)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user789")
        .claim("department", "engineering")
        .signWith(keyPair.private, SignatureAlgorithm.ES256)
        .compact()
    
    println("Generated secure JWT with ES256: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_4() {
    // Using secure algorithm with variable
    val algorithm = SignatureAlgorithm.HS512
    val key = Keys.secretKeyFor(algorithm)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user101")
        .claim("access", "full")
        .signWith(key, algorithm)
        .compact()
    
    println("Generated secure JWT with variable algorithm: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_5() {
    // Using secure algorithm with conditional
    val isProduction = true
    val algorithm = if (isProduction) SignatureAlgorithm.HS256 else SignatureAlgorithm.HS384
    val key = Keys.secretKeyFor(algorithm)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user202")
        .claim("type", "permanent")
        .signWith(key, algorithm)
        .compact()
    
    println("Generated secure JWT with conditional algorithm: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_6() {
    // Using secure algorithm with parser
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val jwtToken = Jwts.builder()
        .setSubject("user303")
        .signWith(secretKey)
        .compact()
    
    // ok: kotlin-jwt-none-algorithm
    val parser = Jwts.parserBuilder()
        .setSigningKey(secretKey)
        .build()
    val claims = parser.parseClaimsJws(jwtToken).body
    
    println("Parsed claims securely: $claims")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_7() {
    // Using secure algorithm with expiration
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val expirationDate = Date(System.currentTimeMillis() + 3600000) // 1 hour
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user404")
        .setExpiration(expirationDate)
        .signWith(secretKey)
        .compact()
    
    println("Generated secure JWT with expiration: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_8() {
    // Using secure algorithm with custom claims
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val claims = mapOf(
        "userId" to "12345",
        "email" to "user@example.com",
        "roles" to listOf("user", "editor")
    )
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setClaims(claims)
        .signWith(secretKey)
        .compact()
    
    println("Generated secure JWT with custom claims: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_9() {
    // Using secure algorithm with function parameter
    fun createToken(key: Key): String {
        // ok: kotlin-jwt-none-algorithm
        return Jwts.builder()
            .setSubject("user505")
            .claim("purpose", "production")
            .signWith(key)
            .compact()
    }
    
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val jwtToken = createToken(secretKey)
    println("Generated secure JWT from function: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_10() {
    // Using secure algorithm with try-catch for verification
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val jwtToken = Jwts.builder()
        .setSubject("user606")
        .signWith(secretKey)
        .compact()
    
    try {
        // ok: kotlin-jwt-none-algorithm
        val claims = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(jwtToken)
            .body
        
        println("Verified JWT: $claims")
    } catch (e: SignatureException) {
        println("Invalid signature")
    } catch (e: MalformedJwtException) {
        println("Malformed JWT")
    } catch (e: ExpiredJwtException) {
        println("Expired JWT")
    } catch (e: UnsupportedJwtException) {
        println("Unsupported JWT")
    } catch (e: Exception) {
        println("Error: ${e.message}")
    }
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_11() {
    // Using secure algorithm with custom wrapper
    class SecureJwtGenerator(private val key: Key) {
        fun generate(subject: String): String {
            // ok: kotlin-jwt-none-algorithm
            return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(Date())
                .signWith(key)
                .compact()
        }
    }
    
    val secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    val generator = SecureJwtGenerator(secretKey)
    val jwtToken = generator.generate("user707")
    println("Generated secure JWT with wrapper: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_12() {
    // Using secure algorithm with string comparison
    val algorithmName = "HS256"
    val algorithm = SignatureAlgorithm.valueOf(algorithmName)
    val key = Keys.secretKeyFor(algorithm)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user808")
        .signWith(key, algorithm)
        .compact()
    
    println("Generated secure JWT with string comparison: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_13() {
    // Using secure algorithm with map lookup
    val algorithms = mapOf(
        "hs256" to SignatureAlgorithm.HS256,
        "rs256" to SignatureAlgorithm.RS256,
        "es256" to SignatureAlgorithm.ES256
    )
    
    val selectedAlgorithm = algorithms["hs256"]!!
    val key = Keys.secretKeyFor(selectedAlgorithm)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user909")
        .signWith(key, selectedAlgorithm)
        .compact()
    
    println("Generated secure JWT with map lookup: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_14() {
    // Using secure algorithm with environment check
    val environment = "production"
    val algorithm = when (environment) {
        "production" -> SignatureAlgorithm.HS512
        "staging" -> SignatureAlgorithm.HS384
        else -> SignatureAlgorithm.HS256
    }
    
    val key = Keys.secretKeyFor(algorithm)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user1010")
        .signWith(key, algorithm)
        .compact()
    
    println("Generated secure JWT with environment check: $jwtToken")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
fun good_case_15() {
    // Using secure algorithm with base64 encoded key
    val base64Key = "c2VjcmV0S2V5Rm9ySnNvbldlYlRva2VuU2lnbmluZw=="
    val decodedKey = Base64.getDecoder().decode(base64Key)
    val key = Keys.hmacShaKeyFor(decodedKey)
    
    // ok: kotlin-jwt-none-algorithm
    val jwtToken = Jwts.builder()
        .setSubject("user1111")
        .claim("app", "secure-service")
        .signWith(key)
        .compact()
    
    println("Generated secure JWT with base64 key: $jwtToken")
}
// {/fact}