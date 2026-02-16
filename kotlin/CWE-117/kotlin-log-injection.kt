import org.apache.commons.lang3.StringEscapeUtils
import org.slf4j.LoggerFactory
import org.slf4j.Logger
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger as Log4jLogger
import java.util.logging.Logger as JavaLogger
import android.util.Log

// True Positives (Vulnerable Code)

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_1(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val username = call.request.queryParameters["username"]
    
    // ruleid: kotlin-log-injection
    logger.info("User login attempt: $username")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_2(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val searchTerm = call.request.queryParameters["q"]
    val ipAddress = call.request.origin.remoteHost
    
    // ruleid: kotlin-log-injection
    logger.warn("Search query '$searchTerm' from IP: $ipAddress")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_3(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val userAgent = call.request.headers["User-Agent"]
    
    // ruleid: kotlin-log-injection
    logger.error("Failed request with User-Agent: $userAgent")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_4(call: ApplicationCall) {
    val log4jLogger = LogManager.getLogger("SecurityLogger")
    val referrer = call.request.headers["Referer"]
    
    // ruleid: kotlin-log-injection
    log4jLogger.info("Request referred from: $referrer")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_5(call: ApplicationCall) {
    val javaLogger = JavaLogger.getLogger("SecurityLogger")
    val email = call.request.queryParameters["email"]
    
    // ruleid: kotlin-log-injection
    javaLogger.info("Password reset requested for: $email")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_6(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val requestBody = call.receiveText()
    
    // ruleid: kotlin-log-injection
    logger.debug("Received request body: $requestBody")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_7(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val cookie = call.request.cookies["sessionId"]
    
    // ruleid: kotlin-log-injection
    logger.info("Session activity for cookie: $cookie")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_8(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val authHeader = call.request.headers["Authorization"]
    
    if (authHeader == null) {
        // ruleid: kotlin-log-injection
        logger.warn("Missing auth header in request from ${call.request.origin.remoteHost}")
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_9() {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val url = URL("https://api.example.com/data")
    val connection = url.openConnection() as HttpURLConnection
    val response = BufferedReader(InputStreamReader(connection.inputStream)).readText()
    
    // ruleid: kotlin-log-injection
    logger.info("API response: $response")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_10(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val formParams = call.receiveParameters()
    val comment = formParams["comment"]
    
    // ruleid: kotlin-log-injection
    logger.info("New comment posted: $comment")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_11() {
    val androidTag = "SecurityAudit"
    val url = URL("https://api.example.com/user")
    val connection = url.openConnection() as HttpURLConnection
    val userData = BufferedReader(InputStreamReader(connection.inputStream)).readText()
    
    // ruleid: kotlin-log-injection
    Log.d(androidTag, "User data received: $userData")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_12(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val headers = call.request.headers.entries()
        .joinToString(", ") { "${it.key}: ${it.value}" }
    
    // ruleid: kotlin-log-injection
    logger.debug("Request headers: $headers")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_13(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val filename = call.request.queryParameters["file"]
    
    try {
        // Some file operation
        // ruleid: kotlin-log-injection
        logger.info("File access attempt: $filename")
    } catch (e: Exception) {
        // ruleid: kotlin-log-injection
        logger.error("Error accessing file: $filename", e)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_14(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val params = call.request.queryParameters.entries()
        .joinToString("&") { "${it.key}=${it.value}" }
    
    // ruleid: kotlin-log-injection
    logger.info("Query string: $params")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=1}
fun bad_case_15(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    
    for (header in call.request.headers.entries()) {
        // ruleid: kotlin-log-injection
        logger.debug("Header ${header.key}: ${header.value}")
    }
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_1(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val username = call.request.queryParameters["username"]
    
    // ok: kotlin-log-injection
    logger.info("User login attempt: ${StringEscapeUtils.escapeJava(username ?: "")}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_2(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val searchTerm = call.request.queryParameters["q"]
    val ipAddress = call.request.origin.remoteHost
    
    // ok: kotlin-log-injection
    logger.warn("Search query '${StringEscapeUtils.escapeJava(searchTerm ?: "")}' from IP: ${StringEscapeUtils.escapeJava(ipAddress)}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_3(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val userAgent = call.request.headers["User-Agent"]
    
    // ok: kotlin-log-injection
    logger.error("Failed request with User-Agent: ${StringEscapeUtils.escapeJava(userAgent ?: "")}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_4(call: ApplicationCall) {
    val log4jLogger = LogManager.getLogger("SecurityLogger")
    val referrer = call.request.headers["Referer"]
    val sanitizedReferrer = StringEscapeUtils.escapeJava(referrer ?: "")
    
    // ok: kotlin-log-injection
    log4jLogger.info("Request referred from: $sanitizedReferrer")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_5(call: ApplicationCall) {
    val javaLogger = JavaLogger.getLogger("SecurityLogger")
    val email = call.request.queryParameters["email"]
    
    // Sanitize the email before logging
    val sanitizedEmail = StringEscapeUtils.escapeJava(email ?: "")
    
    // ok: kotlin-log-injection
    javaLogger.info("Password reset requested for: $sanitizedEmail")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_6(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val requestBody = call.receiveText()
    
    // ok: kotlin-log-injection
    logger.debug("Received request body length: ${requestBody.length}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_7(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val cookie = call.request.cookies["sessionId"]
    
    // Mask most of the cookie value for security
    val maskedCookie = if (cookie != null && cookie.length > 4) {
        val visiblePart = StringEscapeUtils.escapeJava(cookie.substring(0, 4))
        "$visiblePart${cookie.substring(4).map { '*' }.joinToString("")}"
    } else {
        "null"
    }
    
    // ok: kotlin-log-injection
    logger.info("Session activity for cookie: $maskedCookie")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_8(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val authHeader = call.request.headers["Authorization"]
    
    if (authHeader == null) {
        val safeIp = StringEscapeUtils.escapeJava(call.request.origin.remoteHost)
        // ok: kotlin-log-injection
        logger.warn("Missing auth header in request from $safeIp")
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_9() {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val url = URL("https://api.example.com/data")
    val connection = url.openConnection() as HttpURLConnection
    val response = BufferedReader(InputStreamReader(connection.inputStream)).readText()
    
    // ok: kotlin-log-injection
    logger.info("API response received with length: ${response.length}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_10(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val formParams = call.receiveParameters()
    val comment = formParams["comment"]
    
    // ok: kotlin-log-injection
    logger.info("New comment posted with length: ${comment?.length ?: 0}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_11() {
    val androidTag = "SecurityAudit"
    val url = URL("https://api.example.com/user")
    val connection = url.openConnection() as HttpURLConnection
    val userData = BufferedReader(InputStreamReader(connection.inputStream)).readText()
    
    // ok: kotlin-log-injection
    Log.d(androidTag, "User data received with byte count: ${userData.toByteArray().size}")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_12(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    
    // ok: kotlin-log-injection
    logger.debug("Request received with ${call.request.headers.entries().count()} headers")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_13(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    val filename = call.request.queryParameters["file"]
    val sanitizedFilename = StringEscapeUtils.escapeJava(filename ?: "")
    
    try {
        // Some file operation
        // ok: kotlin-log-injection
        logger.info("File access attempt: $sanitizedFilename")
    } catch (e: Exception) {
        // ok: kotlin-log-injection
        logger.error("Error accessing file: $sanitizedFilename", e)
    }
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_14(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    
    // Log only the parameter names, not values
    val paramNames = call.request.queryParameters.names().joinToString(", ")
    
    // ok: kotlin-log-injection
    logger.info("Query parameters received: $paramNames")
}
// {/fact}

// {fact rule=ldap-injection@v1.0 defects=0}
fun good_case_15(call: ApplicationCall) {
    val logger = LoggerFactory.getLogger("SecurityLogger")
    
    // Using a constant string, not external data
    val staticMessage = "Application processing request"
    
    // ok: kotlin-log-injection
    logger.info(staticMessage)
}
// {/fact}