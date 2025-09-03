import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.http.ResponseCookie
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseEntity
import jakarta.servlet.http.Cookie as JakartaCookie
import jakarta.servlet.http.HttpServletResponse as JakartaResponse
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.server.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cookies.*

// True Positives (Vulnerable Code Examples)

@RestController
class CookieController {
    // Example 1: Basic cookie without secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_1(response: HttpServletResponse) {
        val cookie = Cookie("sessionId", "abc123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-secure-flag
        response.addCookie(cookie)
    }
// {/fact}

    // Example 2: Cookie with explicit secure=false
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_2(response: HttpServletResponse) {
        val cookie = Cookie("authToken", "xyz789")
        cookie.maxAge = 86400
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-secure-flag
        cookie.secure = false
        response.addCookie(cookie)
    }
// {/fact}

    // Example 3: Multiple cookies, none with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_3(response: HttpServletResponse) {
        val userCookie = Cookie("userId", "12345")
        userCookie.maxAge = 3600
        
        val prefCookie = Cookie("preferences", "theme=dark")
        prefCookie.maxAge = 604800
        
        // ruleid: kotlin-cookie-missing-secure-flag
        response.addCookie(userCookie)
        // ruleid: kotlin-cookie-missing-secure-flag
        response.addCookie(prefCookie)
    }
// {/fact}

    // Example 4: Using Spring's ResponseCookie without secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/api/login")
    fun bad_case_4(): ResponseEntity<String> {
        val cookie = ResponseCookie.from("sessionToken", "token123")
            .maxAge(3600)
            .path("/")
            .httpOnly(true)
            .build()
        
        // ruleid: kotlin-cookie-missing-secure-flag
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Login successful")
    }
// {/fact}

    // Example 5: Using Jakarta Cookie API without secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_5(response: JakartaResponse) {
        val cookie = JakartaCookie("rememberMe", "true")
        cookie.maxAge = 604800
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-secure-flag
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 6: Using Ktor without secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_6() {
    embeddedServer(Netty, port = 8080) {
        routing {
            get("/") {
                // ruleid: kotlin-cookie-missing-secure-flag
                call.response.cookies.append(Cookie("session", "abc123", maxAge = 3600))
                call.respondText("Hello, world!")
            }
        }
    }.start(wait = true)
}
// {/fact}

// Example 7: Setting multiple properties but forgetting secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_7(response: HttpServletResponse) {
    val cookie = Cookie("userData", "johndoe")
    cookie.maxAge = 86400
    cookie.path = "/"
    cookie.domain = "example.com"
    cookie.isHttpOnly = true
    // ruleid: kotlin-cookie-missing-secure-flag
    response.addCookie(cookie)
}
// {/fact}

// Example 8: Using conditional logic but never setting secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_8(response: HttpServletResponse, isPremiumUser: Boolean) {
    val cookie = Cookie("userType", if (isPremiumUser) "premium" else "standard")
    cookie.maxAge = 3600
    
    if (isPremiumUser) {
        cookie.path = "/premium"
    } else {
        cookie.path = "/standard"
    }
    
    // ruleid: kotlin-cookie-missing-secure-flag
    response.addCookie(cookie)
}
// {/fact}

// Example 9: Using Spring's ResponseCookie builder pattern without secure
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_9(): ResponseEntity<String> {
    val cookieValue = ResponseCookie.from("apiKey", "key123")
        .domain("api.example.com")
        .path("/")
        .maxAge(3600)
        .httpOnly(true)
        .sameSite("Strict")
        .build()
    
    // ruleid: kotlin-cookie-missing-secure-flag
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookieValue.toString())
        .body("API key set")
}
// {/fact}

// Example 10: Using a helper function that doesn't set secure flag
fun createCookie(name: String, value: String): Cookie {
    val cookie = Cookie(name, value)
    cookie.maxAge = 3600
    cookie.path = "/"
    cookie.isHttpOnly = true
    return cookie
}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_10(response: HttpServletResponse) {
    // ruleid: kotlin-cookie-missing-secure-flag
    response.addCookie(createCookie("trackingId", "visitor123"))
}
// {/fact}

// Example 11: Using Ktor with detailed configuration but missing secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_11() {
    embeddedServer(Netty, port = 8080) {
        install(Cookies)
        routing {
            get("/dashboard") {
                // ruleid: kotlin-cookie-missing-secure-flag
                call.response.cookies.append(Cookie(
                    name = "dashboard_settings",
                    value = "compact_view",
                    encoding = CookieEncoding.URI_ENCODING,
                    maxAge = 86400,
                    path = "/dashboard",
                    domain = "app.example.com",
                    httpOnly = true
                ))
                call.respondText("Dashboard loaded")
            }
        }
    }.start(wait = true)
}
// {/fact}

// Example 12: Setting secure flag based on environment but defaulting to false
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_12(response: HttpServletResponse, isProduction: Boolean) {
    val cookie = Cookie("environment", if (isProduction) "prod" else "dev")
    cookie.maxAge = 3600
    cookie.path = "/"
    
    if (isProduction) {
        cookie.secure = true
    } else {
        // ruleid: kotlin-cookie-missing-secure-flag
        cookie.secure = false
    }
    
    response.addCookie(cookie)
}
// {/fact}

// Example 13: Using Jakarta Cookie with multiple settings but no secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_13(response: JakartaResponse) {
    val cookie = JakartaCookie("cartId", "cart123456")
    cookie.maxAge = 86400
    cookie.path = "/"
    cookie.domain = "shop.example.com"
    cookie.isHttpOnly = true
    cookie.comment = "Shopping cart identifier"
    
    // ruleid: kotlin-cookie-missing-secure-flag
    response.addCookie(cookie)
}
// {/fact}

// Example 14: Creating a session cookie without secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_14(response: HttpServletResponse) {
    val cookie = Cookie("JSESSIONID", "session123456789")
    cookie.path = "/"
    cookie.isHttpOnly = true
    // Session cookies are particularly sensitive
    // ruleid: kotlin-cookie-missing-secure-flag
    response.addCookie(cookie)
}
// {/fact}

// Example 15: Using Spring ResponseCookie with complex configuration but no secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=1}
fun bad_case_15(): ResponseEntity<String> {
    val expirationTime = System.currentTimeMillis() + 3600000
    
    val cookie = ResponseCookie.from("lastVisit", expirationTime.toString())
        .domain("stats.example.com")
        .path("/")
        .maxAge(3600)
        .httpOnly(true)
        .sameSite("Lax")
        .build()
    
    // ruleid: kotlin-cookie-missing-secure-flag
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body("Visit recorded")
}
// {/fact}

// True Negatives (Secure Code Examples)

@RestController
class SecureCookieController {
    // Example 1: Basic cookie with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_1(response: HttpServletResponse) {
        val cookie = Cookie("sessionId", "abc123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ok: kotlin-cookie-missing-secure-flag
        cookie.secure = true
        response.addCookie(cookie)
    }
// {/fact}

    // Example 2: Multiple cookies, all with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_2(response: HttpServletResponse) {
        val userCookie = Cookie("userId", "12345")
        userCookie.maxAge = 3600
        // ok: kotlin-cookie-missing-secure-flag
        userCookie.secure = true
        
        val prefCookie = Cookie("preferences", "theme=dark")
        prefCookie.maxAge = 604800
        // ok: kotlin-cookie-missing-secure-flag
        prefCookie.secure = true
        
        response.addCookie(userCookie)
        response.addCookie(prefCookie)
    }
// {/fact}

    // Example 3: Using Spring's ResponseCookie with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/api/secure-login")
    fun good_case_3(): ResponseEntity<String> {
        val cookie = ResponseCookie.from("sessionToken", "token123")
            .maxAge(3600)
            .path("/")
            .httpOnly(true)
            // ok: kotlin-cookie-missing-secure-flag
            .secure(true)
            .build()
        
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Login successful")
    }
// {/fact}

    // Example 4: Using Jakarta Cookie API with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_4(response: JakartaResponse) {
        val cookie = JakartaCookie("rememberMe", "true")
        cookie.maxAge = 604800
        cookie.path = "/"
        // ok: kotlin-cookie-missing-secure-flag
        cookie.secure = true
        response.addCookie(cookie)
    }
// {/fact}

    // Example 5: Using Ktor with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_5() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    // ok: kotlin-cookie-missing-secure-flag
                    call.response.cookies.append(Cookie(
                        name = "session", 
                        value = "abc123", 
                        maxAge = 3600,
                        secure = true
                    ))
                    call.respondText("Hello, world!")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 6: Setting multiple properties including secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_6(response: HttpServletResponse) {
    val cookie = Cookie("userData", "johndoe")
    cookie.maxAge = 86400
    cookie.path = "/"
    cookie.domain = "example.com"
    cookie.isHttpOnly = true
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = true
    response.addCookie(cookie)
}
// {/fact}

// Example 7: Using conditional logic and always setting secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_7(response: HttpServletResponse, isPremiumUser: Boolean) {
    val cookie = Cookie("userType", if (isPremiumUser) "premium" else "standard")
    cookie.maxAge = 3600
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = true
    
    if (isPremiumUser) {
        cookie.path = "/premium"
    } else {
        cookie.path = "/standard"
    }
    
    response.addCookie(cookie)
}
// {/fact}

// Example 8: Using Spring's ResponseCookie builder pattern with secure
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_8(): ResponseEntity<String> {
    val cookieValue = ResponseCookie.from("apiKey", "key123")
        .domain("api.example.com")
        .path("/")
        .maxAge(3600)
        .httpOnly(true)
        // ok: kotlin-cookie-missing-secure-flag
        .secure(true)
        .sameSite("Strict")
        .build()
    
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookieValue.toString())
        .body("API key set")
}
// {/fact}

// Example 9: Using a helper function that sets secure flag
fun createSecureCookie(name: String, value: String): Cookie {
    val cookie = Cookie(name, value)
    cookie.maxAge = 3600
    cookie.path = "/"
    cookie.isHttpOnly = true
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = true
    return cookie
}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_9(response: HttpServletResponse) {
    response.addCookie(createSecureCookie("trackingId", "visitor123"))
}
// {/fact}

// Example 10: Using Ktor with detailed configuration including secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_10() {
    embeddedServer(Netty, port = 8080) {
        install(Cookies)
        routing {
            get("/dashboard") {
                // ok: kotlin-cookie-missing-secure-flag
                call.response.cookies.append(Cookie(
                    name = "dashboard_settings",
                    value = "compact_view",
                    encoding = CookieEncoding.URI_ENCODING,
                    maxAge = 86400,
                    path = "/dashboard",
                    domain = "app.example.com",
                    secure = true,
                    httpOnly = true
                ))
                call.respondText("Dashboard loaded")
            }
        }
    }.start(wait = true)
}
// {/fact}

// Example 11: Setting secure flag based on environment but defaulting to true
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_11(response: HttpServletResponse, isLocalDevelopment: Boolean) {
    val cookie = Cookie("environment", if (isLocalDevelopment) "dev" else "prod")
    cookie.maxAge = 3600
    cookie.path = "/"
    
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = !isLocalDevelopment // Secure by default except in local dev
    
    response.addCookie(cookie)
}
// {/fact}

// Example 12: Using Jakarta Cookie with all security settings
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_12(response: JakartaResponse) {
    val cookie = JakartaCookie("cartId", "cart123456")
    cookie.maxAge = 86400
    cookie.path = "/"
    cookie.domain = "shop.example.com"
    cookie.isHttpOnly = true
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = true
    cookie.comment = "Shopping cart identifier"
    
    response.addCookie(cookie)
}
// {/fact}

// Example 13: Creating a session cookie with secure flag
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_13(response: HttpServletResponse) {
    val cookie = Cookie("JSESSIONID", "session123456789")
    cookie.path = "/"
    cookie.isHttpOnly = true
    // ok: kotlin-cookie-missing-secure-flag
    cookie.secure = true
    response.addCookie(cookie)
}
// {/fact}

// Example 14: Using Spring ResponseCookie with all security flags
// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_14(): ResponseEntity<String> {
    val expirationTime = System.currentTimeMillis() + 3600000
    
    val cookie = ResponseCookie.from("lastVisit", expirationTime.toString())
        .domain("stats.example.com")
        .path("/")
        .maxAge(3600)
        .httpOnly(true)
        // ok: kotlin-cookie-missing-secure-flag
        .secure(true)
        .sameSite("Strict")
        .build()
    
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body("Visit recorded")
}
// {/fact}

// Example 15: Using a configuration class to ensure all cookies are secure
class CookieSecurityConfig {
    fun createCookie(name: String, value: String): Cookie {
        val cookie = Cookie(name, value)
        // ok: kotlin-cookie-missing-secure-flag
        cookie.secure = true
        cookie.isHttpOnly = true
        return cookie
    }
}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
fun good_case_15(response: HttpServletResponse) {
    val config = CookieSecurityConfig()
    val authCookie = config.createCookie("authToken", "secure-token-123")
    authCookie.maxAge = 3600
    response.addCookie(authCookie)
}
// {/fact}