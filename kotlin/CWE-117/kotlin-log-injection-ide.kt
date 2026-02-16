package com.example.loginjection

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.apache.logging.log4j.LogManager
import java.util.logging.Level
import javax.servlet.http.HttpServletRequest
import io.ktor.application.*
import io.ktor.request.*
import io.ktor.http.*
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.owasp.encoder.Encode

// True Positive Examples (Vulnerable Code)

@Controller
class LogInjectionVulnerableController {
    private val logger = LoggerFactory.getLogger(LogInjectionVulnerableController::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=1}
    @GetMapping("/bad1")
    fun bad_case_1(request: HttpServletRequest) {
        val username = request.getParameter("username")
        // ruleid: kotlin-log-injection-ide
        logger.info("User login attempt: $username")
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    @PostMapping("/bad2")
    fun bad_case_2(request: HttpServletRequest) {
        val ipAddress = request.getHeader("X-Forwarded-For")
        // ruleid: kotlin-log-injection-ide
        logger.error("Failed login attempt from IP: $ipAddress")
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    @GetMapping("/bad3")
    fun bad_case_3(request: HttpServletRequest) {
        val query = request.getParameter("query")
        val log4jLogger = LogManager.getLogger(LogInjectionVulnerableController::class.java)
        // ruleid: kotlin-log-injection-ide
        log4jLogger.warn("Search query executed: " + query)
    }
// {/fact}
}

class KtorLogInjectionExample {
    private val logger = LoggerFactory.getLogger(KtorLogInjectionExample::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_4(call: ApplicationCall) {
        val userAgent = call.request.headers["User-Agent"]
        // ruleid: kotlin-log-injection-ide
        logger.info("Request from user agent: $userAgent")
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_5(call: ApplicationCall) {
        val referrer = call.request.headers["Referer"] ?: "unknown"
        // ruleid: kotlin-log-injection-ide
        logger.debug("User came from: " + referrer)
    }
// {/fact}
}

@RestController
class SpringLogInjectionController {
    private val logger = LoggerFactory.getLogger(SpringLogInjectionController::class.java)
    
    @GetMapping("/bad6")
    fun bad_case_6(@RequestParam("email") email: String) {
        // ruleid: kotlin-log-injection-ide
        logger.info("Password reset requested for email: $email")
    }
    
// {fact rule=ldap-injection@v1.0 defects=1}
    @PostMapping("/bad7")
    fun bad_case_7(@RequestBody payload: Map<String, String>) {
        val username = payload["username"] ?: "anonymous"
        // ruleid: kotlin-log-injection-ide
        logger.warn("Failed authentication attempt for user: $username")
    }
// {/fact}
}

class JavaUtilLoggerExample {
    private val logger = java.util.logging.Logger.getLogger(JavaUtilLoggerExample::class.java.name)
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_8(request: HttpServletRequest) {
        val sessionId = request.getParameter("sessionId")
        // ruleid: kotlin-log-injection-ide
        logger.log(Level.INFO, "Session validation for: {0}", sessionId)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_9(request: HttpServletRequest) {
        val cookie = request.getHeader("Cookie")
        // ruleid: kotlin-log-injection-ide
        logger.severe("Problematic cookie detected: $cookie")
    }
// {/fact}
}

class StringFormatLogInjection {
    private val logger = LoggerFactory.getLogger(StringFormatLogInjection::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_10(request: HttpServletRequest) {
        val userId = request.getParameter("id")
        // ruleid: kotlin-log-injection-ide
        logger.info(String.format("User profile accessed: %s", userId))
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_11(request: HttpServletRequest) {
        val searchTerm = request.getParameter("q")
        // ruleid: kotlin-log-injection-ide
        logger.warn("Search performed with potentially malicious term: {}".format(searchTerm))
    }
// {/fact}
}

class ComplexLogInjection {
    private val logger = LoggerFactory.getLogger(ComplexLogInjection::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_12(request: HttpServletRequest) {
        val username = request.getParameter("username")
        val action = request.getParameter("action")
        // ruleid: kotlin-log-injection-ide
        logger.info("User $username performed action: $action")
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_13(call: ApplicationCall) {
        val params = call.request.queryParameters
        val searchQuery = params["query"] ?: ""
        val category = params["category"] ?: "all"
        // ruleid: kotlin-log-injection-ide
        logger.info("Search in category '$category' with query: $searchQuery")
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_14(request: HttpServletRequest) {
        val data = request.getParameter("data")
        try {
            processData(data)
        } catch (e: Exception) {
            // ruleid: kotlin-log-injection-ide
            logger.error("Error processing user data: $data", e)
        }
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=1}
    fun bad_case_15(call: ApplicationCall) {
        val token = call.request.headers["Authorization"]?.removePrefix("Bearer ")
        if (token == null) {
            // ruleid: kotlin-log-injection-ide
            logger.warn("Missing authorization token in request from ${call.request.origin.remoteHost}")
        }
    }
// {/fact}
    
    private fun processData(data: String) {
        // Processing logic
    }
}

// True Negative Examples (Safe Code)

@Controller
class LogInjectionSafeController {
    private val logger = LoggerFactory.getLogger(LogInjectionSafeController::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=0}
    @GetMapping("/good1")
    fun good_case_1(request: HttpServletRequest) {
        val username = request.getParameter("username")
        // ok: kotlin-log-injection-ide
        logger.info("User login attempt: {}", username)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    @PostMapping("/good2")
    fun good_case_2(request: HttpServletRequest) {
        val ipAddress = request.getHeader("X-Forwarded-For")
        // ok: kotlin-log-injection-ide
        logger.error("Failed login attempt from IP: {}", ipAddress)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    @GetMapping("/good3")
    fun good_case_3(request: HttpServletRequest) {
        val query = request.getParameter("query")
        val sanitizedQuery = Encode.forJava(query)
        // ok: kotlin-log-injection-ide
        logger.warn("Search query executed: $sanitizedQuery")
    }
// {/fact}
}

class KtorSafeLogExample {
    private val logger = LoggerFactory.getLogger(KtorSafeLogExample::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_4(call: ApplicationCall) {
        val userAgent = call.request.headers["User-Agent"]
        // ok: kotlin-log-injection-ide
        logger.info("Request from user agent: {}", userAgent)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_5(call: ApplicationCall) {
        val referrer = call.request.headers["Referer"] ?: "unknown"
        val sanitizedReferrer = referrer.replace("\n", "").replace("\r", "")
        // ok: kotlin-log-injection-ide
        logger.debug("User came from: $sanitizedReferrer")
    }
// {/fact}
}

@RestController
class SpringSafeLogController {
    private val logger = LoggerFactory.getLogger(SpringSafeLogController::class.java)
    
    @GetMapping("/good6")
    fun good_case_6(@RequestParam("email") email: String) {
        // ok: kotlin-log-injection-ide
        logger.info("Password reset requested for email: {}", email)
    }
    
// {fact rule=ldap-injection@v1.0 defects=0}
    @PostMapping("/good7")
    fun good_case_7(@RequestBody payload: Map<String, String>) {
        val username = payload["username"] ?: "anonymous"
        val sanitizedUsername = username.replace("[\\r\\n]".toRegex(), "")
        // ok: kotlin-log-injection-ide
        logger.warn("Failed authentication attempt for user: $sanitizedUsername")
    }
// {/fact}
}

class JavaUtilLoggerSafeExample {
    private val logger = java.util.logging.Logger.getLogger(JavaUtilLoggerSafeExample::class.java.name)
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_8(request: HttpServletRequest) {
        val sessionId = request.getParameter("sessionId")
        val sanitizedSessionId = sessionId?.replace("[\r\n]".toRegex(), "") ?: "null"
        // ok: kotlin-log-injection-ide
        logger.log(Level.INFO, "Session validation for: {0}", sanitizedSessionId)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_9(request: HttpServletRequest) {
        val cookie = request.getHeader("Cookie")
        // Using a whitelist approach for logging
        val allowedChars = "[^a-zA-Z0-9=;\\-_.]".toRegex()
        val sanitizedCookie = cookie?.replace(allowedChars, "") ?: "null"
        // ok: kotlin-log-injection-ide
        logger.severe("Problematic cookie detected: $sanitizedCookie")
    }
// {/fact}
}

class SafeStringFormatLog {
    private val logger = LoggerFactory.getLogger(SafeStringFormatLog::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_10(request: HttpServletRequest) {
        val userId = request.getParameter("id")
        // ok: kotlin-log-injection-ide
        logger.info("User profile accessed: {}", userId)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_11(request: HttpServletRequest) {
        val searchTerm = request.getParameter("q")
        // Using a dedicated sanitization function
        val sanitized = sanitizeForLog(searchTerm)
        // ok: kotlin-log-injection-ide
        logger.warn("Search performed with term: $sanitized")
    }
// {/fact}
    
    private fun sanitizeForLog(input: String?): String {
        if (input == null) return "null"
        return input.replace("[\r\n]".toRegex(), "")
    }
}

class ComplexSafeLogging {
    private val logger = LoggerFactory.getLogger(ComplexSafeLogging::class.java)
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_12(request: HttpServletRequest) {
        val username = request.getParameter("username")
        val action = request.getParameter("action")
        // ok: kotlin-log-injection-ide
        logger.info("User {} performed action: {}", username, action)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_13(call: ApplicationCall) {
        val params = call.request.queryParameters
        val searchQuery = params["query"] ?: ""
        val category = params["category"] ?: "all"
        
        val sanitizedQuery = Encode.forJava(searchQuery)
        val sanitizedCategory = Encode.forJava(category)
        // ok: kotlin-log-injection-ide
        logger.info("Search in category '{}' with query: {}", sanitizedCategory, sanitizedQuery)
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_14(request: HttpServletRequest) {
        val data = request.getParameter("data")
        try {
            processData(data)
        } catch (e: Exception) {
            // ok: kotlin-log-injection-ide
            logger.error("Error processing user data: {}", data, e)
        }
    }
// {/fact}
    
// {fact rule=ldap-injection@v1.0 defects=0}
    fun good_case_15(call: ApplicationCall) {
        val token = call.request.headers["Authorization"]?.removePrefix("Bearer ")
        if (token == null) {
            val host = call.request.origin.remoteHost
            val sanitizedHost = host.replace("[\\r\\n]".toRegex(), "")
            // ok: kotlin-log-injection-ide
            logger.warn("Missing authorization token in request from {}", sanitizedHost)
        }
    }
// {/fact}
    
    private fun processData(data: String) {
        // Processing logic
    }
}