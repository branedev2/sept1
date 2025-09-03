import kotlin.random.Random
import java.security.SecureRandom
import java.util.UUID
import kotlin.math.abs

// True Positives (Vulnerable Code)

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_1() {
    // Using kotlin.random.Random for generating a session token
    val random = Random
    val sessionToken = StringBuilder()
    repeat(16) {
        sessionToken.append(random.nextInt(0, 36).toString(36))
    }
    // ruleid: kotlin-pseudorandom-number-generators
    val token = sessionToken.toString()
    println("Generated session token: $token")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_2() {
    // Using kotlin.random.Random for password reset token
    // ruleid: kotlin-pseudorandom-number-generators
    val resetToken = Random.nextBytes(32).joinToString("") { "%02x".format(it) }
    println("Password reset token: $resetToken")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_3() {
    // Using kotlin.random.Random for generating a temporary API key
    val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    // ruleid: kotlin-pseudorandom-number-generators
    val apiKey = (1..32).map { chars[Random.nextInt(chars.size)] }.joinToString("")
    println("Generated API key: $apiKey")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_4() {
    // Using kotlin.random.Random for generating initialization vector for encryption
    val ivSize = 16
    val iv = ByteArray(ivSize)
    // ruleid: kotlin-pseudorandom-number-generators
    Random.nextBytes(iv)
    println("Generated IV: ${iv.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_5() {
    // Using kotlin.random.Random for generating salt for password hashing
    val saltSize = 16
    val salt = ByteArray(saltSize)
    // ruleid: kotlin-pseudorandom-number-generators
    Random.nextBytes(salt)
    println("Generated salt: ${salt.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_6() {
    // Using kotlin.random.Random.Default for generating a nonce
    // ruleid: kotlin-pseudorandom-number-generators
    val nonce = Random.Default.nextLong().toString(16)
    println("Generated nonce: $nonce")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_7() {
    // Using kotlin.random.Random for generating a 2FA backup code
    val backupCodes = mutableListOf<String>()
    repeat(10) {
        // ruleid: kotlin-pseudorandom-number-generators
        val code = Random.nextInt(100000, 999999).toString()
        backupCodes.add(code)
    }
    println("Generated backup codes: $backupCodes")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_8() {
    // Using kotlin.random.Random for generating a cryptographic key
    val keySize = 32
    val key = ByteArray(keySize)
    // ruleid: kotlin-pseudorandom-number-generators
    Random.nextBytes(key)
    println("Generated key: ${key.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_9() {
    // Using kotlin.random.Random for generating a CSRF token
    val tokenBuilder = StringBuilder()
    // ruleid: kotlin-pseudorandom-number-generators
    repeat(24) {
        tokenBuilder.append(Random.nextInt(0, 16).toString(16))
    }
    val csrfToken = tokenBuilder.toString()
    println("CSRF token: $csrfToken")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_10() {
    // Using kotlin.random.Random for generating a random seed for another operation
    // ruleid: kotlin-pseudorandom-number-generators
    val seed = Random.nextLong()
    val seededRandom = Random(seed)
    println("Generated seed: $seed")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_11() {
    // Using kotlin.random.Random for generating a random filename for sensitive data
    val prefix = "sensitive_data_"
    // ruleid: kotlin-pseudorandom-number-generators
    val randomPart = Random.nextInt(1000000, 9999999).toString()
    val filename = "${prefix}${randomPart}.dat"
    println("Generated filename: $filename")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_12() {
    // Using kotlin.random.Random for generating a random port for a security service
    // ruleid: kotlin-pseudorandom-number-generators
    val port = Random.nextInt(10000, 65535)
    println("Selected port for security service: $port")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_13() {
    // Using kotlin.random.Random in a custom function for generating authentication tokens
    fun generateAuthToken(): String {
        val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('-', '_', '.')
        // ruleid: kotlin-pseudorandom-number-generators
        return (1..40).map { chars[Random.nextInt(chars.size)] }.joinToString("")
    }
    
    val token = generateAuthToken()
    println("Generated auth token: $token")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_14() {
    // Using kotlin.random.Random for generating a random challenge in an authentication protocol
    // ruleid: kotlin-pseudorandom-number-generators
    val challenge = (1..32).map { Random.nextInt(0, 256).toByte() }.toByteArray()
    println("Generated challenge: ${challenge.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
fun bad_case_15() {
    // Using kotlin.random.Random for generating a random UUID-like identifier
    // ruleid: kotlin-pseudorandom-number-generators
    val uuid = "${Random.nextInt().toString(16)}-${Random.nextInt().toString(16)}-${Random.nextInt().toString(16)}-${Random.nextInt().toString(16)}"
    println("Generated UUID-like: $uuid")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_1() {
    // Using SecureRandom for generating a session token
    val secureRandom = SecureRandom()
    val sessionToken = StringBuilder()
    repeat(16) {
        // ok: kotlin-pseudorandom-number-generators
        sessionToken.append(secureRandom.nextInt(36).toString(36))
    }
    val token = sessionToken.toString()
    println("Generated secure session token: $token")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_2() {
    // Using SecureRandom for password reset token
    val secureRandom = SecureRandom()
    val resetTokenBytes = ByteArray(32)
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(resetTokenBytes)
    val resetToken = resetTokenBytes.joinToString("") { "%02x".format(it) }
    println("Secure password reset token: $resetToken")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_3() {
    // Using SecureRandom for generating a temporary API key
    val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    val secureRandom = SecureRandom()
    // ok: kotlin-pseudorandom-number-generators
    val apiKey = (1..32).map { chars[secureRandom.nextInt(chars.size)] }.joinToString("")
    println("Generated secure API key: $apiKey")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_4() {
    // Using SecureRandom for generating initialization vector for encryption
    val ivSize = 16
    val iv = ByteArray(ivSize)
    val secureRandom = SecureRandom()
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(iv)
    println("Generated secure IV: ${iv.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_5() {
    // Using SecureRandom for generating salt for password hashing
    val saltSize = 16
    val salt = ByteArray(saltSize)
    val secureRandom = SecureRandom()
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(salt)
    println("Generated secure salt: ${salt.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_6() {
    // Using UUID.randomUUID() which uses SecureRandom internally
    // ok: kotlin-pseudorandom-number-generators
    val uuid = UUID.randomUUID().toString()
    println("Generated UUID: $uuid")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_7() {
    // Using SecureRandom for generating a 2FA backup code
    val secureRandom = SecureRandom()
    val backupCodes = mutableListOf<String>()
    repeat(10) {
        // ok: kotlin-pseudorandom-number-generators
        val code = secureRandom.nextInt(900000) + 100000
        backupCodes.add(code.toString())
    }
    println("Generated secure backup codes: $backupCodes")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_8() {
    // Using SecureRandom for generating a cryptographic key
    val keySize = 32
    val key = ByteArray(keySize)
    val secureRandom = SecureRandom()
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(key)
    println("Generated secure key: ${key.joinToString("") { "%02x".format(it) }}")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_9() {
    // Using SecureRandom for generating a CSRF token
    val secureRandom = SecureRandom()
    val tokenBytes = ByteArray(12)
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(tokenBytes)
    val csrfToken = tokenBytes.joinToString("") { "%02x".format(it) }
    println("Secure CSRF token: $csrfToken")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_10() {
    // Using kotlin.random.Random for non-security related randomization (this is fine)
    // ok: kotlin-pseudorandom-number-generators
    val diceRoll = Random.nextInt(1, 7)
    println("Dice roll: $diceRoll")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_11() {
    // Using kotlin.random.Random for game-related randomization (this is fine)
    // ok: kotlin-pseudorandom-number-generators
    val randomCardIndex = Random.nextInt(52)
    println("Random card index: $randomCardIndex")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_12() {
    // Using SecureRandom for generating a random filename for sensitive data
    val prefix = "sensitive_data_"
    val secureRandom = SecureRandom()
    // ok: kotlin-pseudorandom-number-generators
    val randomPart = abs(secureRandom.nextInt()).toString()
    val filename = "${prefix}${randomPart}.dat"
    println("Generated secure filename: $filename")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_13() {
    // Using SecureRandom in a custom function for generating authentication tokens
    fun generateSecureAuthToken(): String {
        val chars = ('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('-', '_', '.')
        val secureRandom = SecureRandom()
        // ok: kotlin-pseudorandom-number-generators
        return (1..40).map { chars[secureRandom.nextInt(chars.size)] }.joinToString("")
    }
    
    val token = generateSecureAuthToken()
    println("Generated secure auth token: $token")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_14() {
    // Using kotlin.random.Random for UI animation randomization (this is fine)
    // ok: kotlin-pseudorandom-number-generators
    val animationDelay = Random.nextInt(100, 500)
    println("Animation delay: $animationDelay ms")
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
fun good_case_15() {
    // Using SecureRandom for generating a random challenge in an authentication protocol
    val secureRandom = SecureRandom()
    val challenge = ByteArray(32)
    // ok: kotlin-pseudorandom-number-generators
    secureRandom.nextBytes(challenge)
    println("Generated secure challenge: ${challenge.joinToString("") { "%02x".format(it) }}")
}
// {/fact}