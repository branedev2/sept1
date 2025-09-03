package com.example.cookiesecurity

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import jakarta.servlet.http.Cookie as JakartaCookie
import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseCookie
import org.springframework.http.HttpCookie
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*

// True Positives (Vulnerable Code)

// Example 1: Basic Cookie without HttpOnly flag
@RestController
class BadCookieController1 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_1")
    fun bad_case_1(response: HttpServletResponse) {
        val cookie = Cookie("sessionId", "abc123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 2: Setting multiple properties but forgetting HttpOnly
@RestController
class BadCookieController2 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_2")
    fun bad_case_2(response: HttpServletResponse) {
        val cookie = Cookie("authToken", "xyz789")
        cookie.maxAge = 86400
        cookie.path = "/"
        cookie.secure = true // Setting secure but not HttpOnly
        cookie.domain = "example.com"
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 3: Explicitly setting HttpOnly to false
@RestController
class BadCookieController3 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_3")
    fun bad_case_3(response: HttpServletResponse) {
        val cookie = Cookie("userId", "user123")
        cookie.maxAge = 7200
        cookie.path = "/"
        cookie.httpOnly = false // Explicitly setting to false
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 4: Using Jakarta Cookie without HttpOnly
@RestController
class BadCookieController4 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_4")
    fun bad_case_4(response: jakarta.servlet.http.HttpServletResponse) {
        val cookie = JakartaCookie("rememberMe", "true")
        cookie.maxAge = 604800 // 1 week
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 5: Using Spring ResponseCookie builder without HttpOnly
@RestController
class BadCookieController5 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_5")
    fun bad_case_5(): org.springframework.http.ResponseEntity<String> {
        val cookie = ResponseCookie.from("theme", "dark")
            .maxAge(2592000) // 30 days
            .path("/")
            .secure(true)
            .build()
        // ruleid: kotlin-cookie-missing-httponly
        return org.springframework.http.ResponseEntity.ok()
            .header(org.springframework.http.HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Cookie set")
    }
// {/fact}
}

// Example 6: Using Ktor without HttpOnly
class BadCookieController6 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    fun bad_case_6() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    // ruleid: kotlin-cookie-missing-httponly
                    call.response.cookies.append(Cookie("sessionId", "abc123", secure = true))
                    call.respondText("Cookie set")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 7: Using Ktor with explicit configuration but missing HttpOnly
class BadCookieController7 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    fun bad_case_7() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    val cookie = Cookie(
                        name = "userData",
                        value = "user456",
                        maxAge = 3600,
                        path = "/",
                        domain = "example.com",
                        secure = true
                    )
                    // ruleid: kotlin-cookie-missing-httponly
                    call.response.cookies.append(cookie)
                    call.respondText("Cookie set")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 8: Using Ktor with explicit httpOnly = false
class BadCookieController8 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    fun bad_case_8() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    val cookie = Cookie(
                        name = "preference",
                        value = "darkmode",
                        httpOnly = false
                    )
                    // ruleid: kotlin-cookie-missing-httponly
                    call.response.cookies.append(cookie)
                    call.respondText("Cookie set")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 9: Using Spring WebFlux without HttpOnly
@RestController
class BadCookieController9 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_9")
    fun bad_case_9(): org.springframework.http.server.reactive.ServerHttpResponse {
        val response = org.springframework.mock.http.server.reactive.MockServerHttpResponse()
        val cookie = ResponseCookie.from("analyticsId", "visitor123")
            .path("/")
            .maxAge(2592000)
            .domain("example.com")
            .build()
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
        return response
    }
// {/fact}
}

// Example 10: Setting cookie in a conditional block without HttpOnly
@RestController
class BadCookieController10 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_10")
    fun bad_case_10(request: HttpServletRequest, response: HttpServletResponse) {
        val rememberMe = request.getParameter("remember") == "true"
        
        if (rememberMe) {
            val cookie = Cookie("rememberUser", "yes")
            cookie.maxAge = 2592000 // 30 days
            cookie.path = "/"
            // ruleid: kotlin-cookie-missing-httponly
            response.addCookie(cookie)
        } else {
            val cookie = Cookie("rememberUser", "no")
            cookie.maxAge = 3600 // 1 hour
            cookie.path = "/"
            // ruleid: kotlin-cookie-missing-httponly
            response.addCookie(cookie)
        }
    }
// {/fact}
}

// Example 11: Using a loop to set multiple cookies without HttpOnly
@RestController
class BadCookieController11 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_11")
    fun bad_case_11(response: HttpServletResponse) {
        val preferences = mapOf(
            "theme" to "dark",
            "fontSize" to "large",
            "language" to "en"
        )
        
        for ((key, value) in preferences) {
            val cookie = Cookie(key, value)
            cookie.maxAge = 86400
            cookie.path = "/"
            // ruleid: kotlin-cookie-missing-httponly
            response.addCookie(cookie)
        }
    }
// {/fact}
}

// Example 12: Using a helper function that doesn't set HttpOnly
@RestController
class BadCookieController12 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_12")
    fun bad_case_12(response: HttpServletResponse) {
        createCookie(response, "sessionId", "abc123")
    }
// {/fact}
    
    private fun createCookie(response: HttpServletResponse, name: String, value: String) {
        val cookie = Cookie(name, value)
        cookie.maxAge = 3600
        cookie.path = "/"
        cookie.secure = true
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
}

// Example 13: Using Jakarta Servlet with a dynamic cookie name
@RestController
class BadCookieController13 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_13")
    fun bad_case_13(response: jakarta.servlet.http.HttpServletResponse, @RequestParam userId: String) {
        val cookieName = "user_${userId}_session"
        val cookie = JakartaCookie(cookieName, "session_token_123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ruleid: kotlin-cookie-missing-httponly
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 14: Using Spring ResponseCookie with a builder pattern but missing HttpOnly
@RestController
class BadCookieController14 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    @GetMapping("/bad_case_14")
    fun bad_case_14(): org.springframework.http.ResponseEntity<String> {
        val cookieValue = generateSessionId()
        val cookie = ResponseCookie.from("sessionId", cookieValue)
            .domain("example.com")
            .path("/")
            .maxAge(3600)
            .secure(true)
            .sameSite("Strict")
            .build()
        // ruleid: kotlin-cookie-missing-httponly
        return org.springframework.http.ResponseEntity.ok()
            .header(org.springframework.http.HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Session created")
    }
// {/fact}
    
    private fun generateSessionId(): String {
        return java.util.UUID.randomUUID().toString()
    }
}

// Example 15: Using Ktor with complex configuration but missing HttpOnly
class BadCookieController15 {
// {fact rule=insecure-file-permissions@v1.0 defects=1}
    fun bad_case_15() {
        embeddedServer(Netty, port = 8080) {
            install(Sessions) {
                cookie<UserSession>("USER_SESSION") {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                    cookie.secure = true
                    // HttpOnly is missing
                }
            }
            
            routing {
                get("/") {
                    // ruleid: kotlin-cookie-missing-httponly
                    call.sessions.set(UserSession(userId = "123", username = "user"))
                    call.respondText("Session started")
                }
            }
        }.start(wait = true)
    }
// {/fact}
    
    data class UserSession(val userId: String, val username: String)
}

// True Negatives (Secure Code)

// Example 1: Basic Cookie with HttpOnly flag
@RestController
class GoodCookieController1 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_1")
    fun good_case_1(response: HttpServletResponse) {
        val cookie = Cookie("sessionId", "abc123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ok: kotlin-cookie-missing-httponly
        cookie.isHttpOnly = true
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 2: Setting multiple properties including HttpOnly
@RestController
class GoodCookieController2 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_2")
    fun good_case_2(response: HttpServletResponse) {
        val cookie = Cookie("authToken", "xyz789")
        cookie.maxAge = 86400
        cookie.path = "/"
        cookie.secure = true
        cookie.domain = "example.com"
        // ok: kotlin-cookie-missing-httponly
        cookie.httpOnly = true
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 3: Using Jakarta Cookie with HttpOnly
@RestController
class GoodCookieController3 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_3")
    fun good_case_3(response: jakarta.servlet.http.HttpServletResponse) {
        val cookie = JakartaCookie("rememberMe", "true")
        cookie.maxAge = 604800 // 1 week
        cookie.path = "/"
        // ok: kotlin-cookie-missing-httponly
        cookie.isHttpOnly = true
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 4: Using Spring ResponseCookie builder with HttpOnly
@RestController
class GoodCookieController4 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_4")
    fun good_case_4(): org.springframework.http.ResponseEntity<String> {
        val cookie = ResponseCookie.from("theme", "dark")
            .maxAge(2592000) // 30 days
            .path("/")
            .secure(true)
            // ok: kotlin-cookie-missing-httponly
            .httpOnly(true)
            .build()
        return org.springframework.http.ResponseEntity.ok()
            .header(org.springframework.http.HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Cookie set")
    }
// {/fact}
}

// Example 5: Using Ktor with HttpOnly
class GoodCookieController5 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    fun good_case_5() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    // ok: kotlin-cookie-missing-httponly
                    call.response.cookies.append(Cookie("sessionId", "abc123", secure = true, httpOnly = true))
                    call.respondText("Cookie set")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 6: Using Ktor with explicit configuration including HttpOnly
class GoodCookieController6 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    fun good_case_6() {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    val cookie = Cookie(
                        name = "userData",
                        value = "user456",
                        maxAge = 3600,
                        path = "/",
                        domain = "example.com",
                        secure = true,
                        // ok: kotlin-cookie-missing-httponly
                        httpOnly = true
                    )
                    call.response.cookies.append(cookie)
                    call.respondText("Cookie set")
                }
            }
        }.start(wait = true)
    }
// {/fact}
}

// Example 7: Using Spring WebFlux with HttpOnly
@RestController
class GoodCookieController7 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_7")
    fun good_case_7(): org.springframework.http.server.reactive.ServerHttpResponse {
        val response = org.springframework.mock.http.server.reactive.MockServerHttpResponse()
        val cookie = ResponseCookie.from("analyticsId", "visitor123")
            .path("/")
            .maxAge(2592000)
            .domain("example.com")
            // ok: kotlin-cookie-missing-httponly
            .httpOnly(true)
            .build()
        response.addCookie(cookie)
        return response
    }
// {/fact}
}

// Example 8: Setting cookie in a conditional block with HttpOnly
@RestController
class GoodCookieController8 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_8")
    fun good_case_8(request: HttpServletRequest, response: HttpServletResponse) {
        val rememberMe = request.getParameter("remember") == "true"
        
        if (rememberMe) {
            val cookie = Cookie("rememberUser", "yes")
            cookie.maxAge = 2592000 // 30 days
            cookie.path = "/"
            // ok: kotlin-cookie-missing-httponly
            cookie.isHttpOnly = true
            response.addCookie(cookie)
        } else {
            val cookie = Cookie("rememberUser", "no")
            cookie.maxAge = 3600 // 1 hour
            cookie.path = "/"
            // ok: kotlin-cookie-missing-httponly
            cookie.isHttpOnly = true
            response.addCookie(cookie)
        }
    }
// {/fact}
}

// Example 9: Using a loop to set multiple cookies with HttpOnly
@RestController
class GoodCookieController9 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_9")
    fun good_case_9(response: HttpServletResponse) {
        val preferences = mapOf(
            "theme" to "dark",
            "fontSize" to "large",
            "language" to "en"
        )
        
        for ((key, value) in preferences) {
            val cookie = Cookie(key, value)
            cookie.maxAge = 86400
            cookie.path = "/"
            // ok: kotlin-cookie-missing-httponly
            cookie.isHttpOnly = true
            response.addCookie(cookie)
        }
    }
// {/fact}
}

// Example 10: Using a helper function that sets HttpOnly
@RestController
class GoodCookieController10 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_10")
    fun good_case_10(response: HttpServletResponse) {
        createSecureCookie(response, "sessionId", "abc123")
    }
// {/fact}
    
    private fun createSecureCookie(response: HttpServletResponse, name: String, value: String) {
        val cookie = Cookie(name, value)
        cookie.maxAge = 3600
        cookie.path = "/"
        cookie.secure = true
        // ok: kotlin-cookie-missing-httponly
        cookie.isHttpOnly = true
        response.addCookie(cookie)
    }
}

// Example 11: Using Jakarta Servlet with a dynamic cookie name and HttpOnly
@RestController
class GoodCookieController11 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_11")
    fun good_case_11(response: jakarta.servlet.http.HttpServletResponse, @RequestParam userId: String) {
        val cookieName = "user_${userId}_session"
        val cookie = JakartaCookie(cookieName, "session_token_123")
        cookie.maxAge = 3600
        cookie.path = "/"
        // ok: kotlin-cookie-missing-httponly
        cookie.isHttpOnly = true
        response.addCookie(cookie)
    }
// {/fact}
}

// Example 12: Using Spring ResponseCookie with a builder pattern including HttpOnly
@RestController
class GoodCookieController12 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_12")
    fun good_case_12(): org.springframework.http.ResponseEntity<String> {
        val cookieValue = generateSessionId()
        val cookie = ResponseCookie.from("sessionId", cookieValue)
            .domain("example.com")
            .path("/")
            .maxAge(3600)
            .secure(true)
            .sameSite("Strict")
            // ok: kotlin-cookie-missing-httponly
            .httpOnly(true)
            .build()
        return org.springframework.http.ResponseEntity.ok()
            .header(org.springframework.http.HttpHeaders.SET_COOKIE, cookie.toString())
            .body("Session created")
    }
// {/fact}
    
    private fun generateSessionId(): String {
        return java.util.UUID.randomUUID().toString()
    }
}

// Example 13: Using Ktor with complex configuration including HttpOnly
class GoodCookieController13 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    fun good_case_13() {
        embeddedServer(Netty, port = 8080) {
            install(Sessions) {
                cookie<UserSession>("USER_SESSION") {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                    cookie.secure = true
                    // ok: kotlin-cookie-missing-httponly
                    cookie.httpOnly = true
                }
            }
            
            routing {
                get("/") {
                    call.sessions.set(UserSession(userId = "123", username = "user"))
                    call.respondText("Session started")
                }
            }
        }.start(wait = true)
    }
// {/fact}
    
    data class UserSession(val userId: String, val username: String)
}

// Example 14: Using a function to create secure cookies with HttpOnly
@RestController
class GoodCookieController14 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_14")
    fun good_case_14(response: HttpServletResponse) {
        val sessionData = mapOf(
            "userId" to "123",
            "role" to "admin",
            "lastLogin" to System.currentTimeMillis().toString()
        )
        
        for ((key, value) in sessionData) {
            val cookie = Cookie(key, value)
            cookie.path = "/"
            cookie.secure = true
            // ok: kotlin-cookie-missing-httponly
            cookie.isHttpOnly = true
            response.addCookie(cookie)
        }
    }
// {/fact}
}

// Example 15: Using a comprehensive cookie configuration with HttpOnly
@RestController
class GoodCookieController15 {
// {fact rule=insecure-file-permissions@v1.0 defects=0}
    @GetMapping("/good_case_15")
    fun good_case_15(response: HttpServletResponse) {
        val cookie = Cookie("authToken", generateToken())
        cookie.path = "/"
        cookie.domain = "example.com"
        cookie.maxAge = 3600
        cookie.secure = true
        cookie.comment = "Authentication token"
        // ok: kotlin-cookie-missing-httponly
        cookie.isHttpOnly = true
        response.addCookie(cookie)
    }
// {/fact}
    
    private fun generateToken(): String {
        return java.util.UUID.randomUUID().toString()
    }
}