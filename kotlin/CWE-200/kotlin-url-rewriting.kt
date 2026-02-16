import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import org.springframework.web.bind.annotation.*
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import jakarta.servlet.http.HttpServletRequest as JakartaRequest
import jakarta.servlet.http.HttpServletResponse as JakartaResponse
import jakarta.servlet.http.HttpSession as JakartaSession
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import io.ktor.server.sessions.*
import io.ktor.http.*

// True Positives - Vulnerable code examples

@Controller
class UrlRewritingVulnerabilities {

    // Example 1: Basic URL rewriting with encodeURL
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/bad1")
    fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("username", "user123")
        
        // ruleid: kotlin-url-rewriting
        val encodedURL = response.encodeURL("/dashboard")
        return "redirect:$encodedURL"
    }
// {/fact}

    // Example 2: URL rewriting with encodeRedirectURL
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/bad2")
    fun bad_case_2(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("userData", mapOf("role" to "admin"))
        
        // ruleid: kotlin-url-rewriting
        val redirectURL = response.encodeRedirectURL("/profile")
        return "redirect:$redirectURL"
    }
// {/fact}

    // Example 3: URL rewriting in a more complex scenario
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/bad3")
    fun bad_case_3(request: HttpServletRequest, response: HttpServletResponse, model: Model): String {
        val session = request.getSession(true)
        val userId = request.getParameter("id") ?: "guest"
        session.setAttribute("userId", userId)
        
        // ruleid: kotlin-url-rewriting
        val nextPage = response.encodeURL("/user/details?id=$userId")
        model.addAttribute("nextPageUrl", nextPage)
        return "userView"
    }
// {/fact}

    // Example 4: URL rewriting with Jakarta servlet API
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/bad4")
    fun bad_case_4(request: JakartaRequest, response: JakartaResponse): String {
        val session = request.getSession(true)
        session.setAttribute("authToken", "abc123xyz")
        
        // ruleid: kotlin-url-rewriting
        val securedUrl = response.encodeURL("/secure/content")
        return "redirect:$securedUrl"
    }
// {/fact}

    // Example 5: URL rewriting with conditional logic
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/bad5")
    fun bad_case_5(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        val userType = request.getParameter("type") ?: "standard"
        
        session.setAttribute("userType", userType)
        val targetUrl = if (userType == "premium") "/premium/content" else "/standard/content"
        
        // ruleid: kotlin-url-rewriting
        return "redirect:" + response.encodeURL(targetUrl)
    }
// {/fact}
}

// Example 6: URL rewriting in a REST controller
@RestController
class ApiUrlRewritingController {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/api/bad6")
    fun bad_case_6(request: HttpServletRequest, response: HttpServletResponse): Map<String, String> {
        val session = request.getSession(true)
        session.setAttribute("apiKey", "key-12345")
        
        // ruleid: kotlin-url-rewriting
        val nextEndpoint = response.encodeURL("/api/data")
        return mapOf("nextUrl" to nextEndpoint)
    }
// {/fact}
    
    // Example 7: URL rewriting with Jakarta API in REST context
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    @GetMapping("/api/bad7")
    fun bad_case_7(request: JakartaRequest, response: JakartaResponse): Map<String, Any> {
        val session = request.getSession(true)
        session.setAttribute("sessionData", mapOf("timestamp" to System.currentTimeMillis()))
        
        // ruleid: kotlin-url-rewriting
        val callbackUrl = response.encodeURL("/api/callback")
        return mapOf(
            "status" to "success",
            "callback" to callbackUrl
        )
    }
// {/fact}
}

// Example 8: URL rewriting in a service class
class UserNavigationService(private val response: HttpServletResponse) {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_8(session: HttpSession): String {
        session.setAttribute("lastAccess", System.currentTimeMillis())
        
        // ruleid: kotlin-url-rewriting
        return response.encodeURL("/user/home")
    }
// {/fact}
}

// Example 9: URL rewriting with Ktor
class KtorUrlRewritingExample {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_9(call: ApplicationCall) {
        call.sessions.set(UserSession(userId = "12345"))
        
        // ruleid: kotlin-url-rewriting
        val nextUrl = call.application.plugin(UrlRewriterPlugin).encodeUrl("/dashboard", call)
        call.respondRedirect(nextUrl)
    }
// {/fact}
    
    data class UserSession(val userId: String)
}

// Example 10: URL rewriting with custom implementation
class CustomUrlRewriter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_10(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("customData", "value")
        
        // ruleid: kotlin-url-rewriting
        val baseUrl = "/app/page"
        val rewrittenUrl = if (request.isRequestedSessionIdFromCookie) {
            baseUrl
        } else {
            baseUrl + ";jsessionid=" + session.id
        }
        
        return rewrittenUrl
    }
// {/fact}
}

// Example 11: URL rewriting in a filter
class SessionUrlRewritingFilter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_11(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val session = request.getSession(true)
        session.setAttribute("filterAttribute", "filtered")
        
        // ruleid: kotlin-url-rewriting
        val wrappedResponse = HttpServletResponseWrapper(response) {
            override fun encodeURL(url: String): String {
                return super.encodeURL(url)
            }
        }
        
        chain.doFilter(request, wrappedResponse)
    }
// {/fact}
}

// Example 12: URL rewriting with multiple URLs
class MultipleUrlRewriter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_12(request: HttpServletRequest, response: HttpServletResponse): List<String> {
        val session = request.getSession(true)
        session.setAttribute("multiData", listOf(1, 2, 3))
        
        // ruleid: kotlin-url-rewriting
        return listOf(
            response.encodeURL("/page1"),
            response.encodeURL("/page2"),
            response.encodeURL("/page3")
        )
    }
// {/fact}
}

// Example 13: URL rewriting with dynamic path construction
class DynamicPathRewriter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_13(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        val category = request.getParameter("category") ?: "default"
        session.setAttribute("category", category)
        
        val basePath = "/products"
        val fullPath = "$basePath/$category"
        
        // ruleid: kotlin-url-rewriting
        return response.encodeURL(fullPath)
    }
// {/fact}
}

// Example 14: URL rewriting in an interceptor
class SessionUrlInterceptor {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_14(request: HttpServletRequest, response: HttpServletResponse): Boolean {
        val session = request.getSession(true)
        session.setAttribute("interceptorData", "intercepted")
        
        // ruleid: kotlin-url-rewriting
        val targetUrl = response.encodeURL(request.requestURI)
        response.sendRedirect(targetUrl)
        return false
    }
// {/fact}
}

// Example 15: URL rewriting with StringBuilder
class UrlBuilderRewriter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    fun bad_case_15(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("builderData", "constructed")
        
        val urlBuilder = StringBuilder()
        urlBuilder.append("/complex/path")
        urlBuilder.append("?param=value")
        
        // ruleid: kotlin-url-rewriting
        return response.encodeURL(urlBuilder.toString())
    }
// {/fact}
}

// True Negatives - Secure code examples

@Controller
class SecureSessionHandling {

    // Example 1: Using cookies for session tracking instead of URL rewriting
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/good1")
    fun good_case_1(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("username", "user123")
        
        // Disable URL rewriting
        // ok: kotlin-url-rewriting
        request.setAttribute("org.apache.catalina.SEND_JSESSIONID", false)
        return "redirect:/dashboard"
    }
// {/fact}

    // Example 2: Direct URL without encoding
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/good2")
    fun good_case_2(request: HttpServletRequest, response: HttpServletResponse): String {
        val session = request.getSession(true)
        session.setAttribute("userData", mapOf("role" to "admin"))
        
        // ok: kotlin-url-rewriting
        return "redirect:/profile"
    }
// {/fact}

    // Example 3: Using path variables without session ID
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/good3")
    fun good_case_3(request: HttpServletRequest, model: Model): String {
        val session = request.getSession(true)
        val userId = request.getParameter("id") ?: "guest"
        session.setAttribute("userId", userId)
        
        // ok: kotlin-url-rewriting
        model.addAttribute("nextPageUrl", "/user/details?id=$userId")
        return "userView"
    }
// {/fact}

    // Example 4: Using Jakarta servlet API without URL rewriting
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/good4")
    fun good_case_4(request: JakartaRequest): String {
        val session = request.getSession(true)
        session.setAttribute("authToken", "abc123xyz")
        
        // ok: kotlin-url-rewriting
        return "redirect:/secure/content"
    }
// {/fact}

    // Example 5: Using conditional logic without URL rewriting
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/good5")
    fun good_case_5(request: HttpServletRequest): String {
        val session = request.getSession(true)
        val userType = request.getParameter("type") ?: "standard"
        
        session.setAttribute("userType", userType)
        
        // ok: kotlin-url-rewriting
        val targetUrl = if (userType == "premium") "/premium/content" else "/standard/content"
        return "redirect:$targetUrl"
    }
// {/fact}
}

// Example 6: REST controller without URL rewriting
@RestController
class SecureApiController {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/api/good6")
    fun good_case_6(request: HttpServletRequest): Map<String, String> {
        val session = request.getSession(true)
        session.setAttribute("apiKey", "key-12345")
        
        // ok: kotlin-url-rewriting
        return mapOf("nextUrl" to "/api/data")
    }
// {/fact}
    
    // Example 7: Jakarta API in REST context without URL rewriting
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    @GetMapping("/api/good7")
    fun good_case_7(request: JakartaRequest): Map<String, Any> {
        val session = request.getSession(true)
        session.setAttribute("sessionData", mapOf("timestamp" to System.currentTimeMillis()))
        
        // ok: kotlin-url-rewriting
        return mapOf(
            "status" to "success",
            "callback" to "/api/callback"
        )
    }
// {/fact}
}

// Example 8: Service class without URL rewriting
class SecureNavigationService {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_8(session: HttpSession): String {
        session.setAttribute("lastAccess", System.currentTimeMillis())
        
        // ok: kotlin-url-rewriting
        return "/user/home"
    }
// {/fact}
}

// Example 9: Ktor with secure session handling
class KtorSecureSessionExample {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_9(call: ApplicationCall) {
        call.sessions.set(UserSession(userId = "12345"))
        
        // Using cookie-based sessions instead of URL rewriting
        // ok: kotlin-url-rewriting
        call.respondRedirect("/dashboard")
    }
// {/fact}
    
    data class UserSession(val userId: String)
}

// Example 10: Custom implementation without URL rewriting
class SecureUrlHandler {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_10(request: HttpServletRequest): String {
        val session = request.getSession(true)
        session.setAttribute("customData", "value")
        
        // ok: kotlin-url-rewriting
        return "/app/page"
    }
// {/fact}
}

// Example 11: Filter without URL rewriting
class SecureSessionFilter {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_11(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        val session = request.getSession(true)
        session.setAttribute("filterAttribute", "filtered")
        
        // Explicitly disable URL rewriting
        // ok: kotlin-url-rewriting
        response.setHeader("Set-Cookie", "JSESSIONID=" + session.id + "; HttpOnly; Secure; SameSite=Strict")
        
        chain.doFilter(request, response)
    }
// {/fact}
}

// Example 12: Multiple URLs without rewriting
class SecureMultipleUrlHandler {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_12(request: HttpServletRequest): List<String> {
        val session = request.getSession(true)
        session.setAttribute("multiData", listOf(1, 2, 3))
        
        // ok: kotlin-url-rewriting
        return listOf("/page1", "/page2", "/page3")
    }
// {/fact}
}

// Example 13: Dynamic path construction without URL rewriting
class SecureDynamicPathHandler {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_13(request: HttpServletRequest): String {
        val session = request.getSession(true)
        val category = request.getParameter("category") ?: "default"
        session.setAttribute("category", category)
        
        // ok: kotlin-url-rewriting
        val basePath = "/products"
        return "$basePath/$category"
    }
// {/fact}
}

// Example 14: Interceptor without URL rewriting
class SecureSessionInterceptor {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_14(request: HttpServletRequest, response: HttpServletResponse): Boolean {
        val session = request.getSession(true)
        session.setAttribute("interceptorData", "intercepted")
        
        // ok: kotlin-url-rewriting
        response.sendRedirect(request.requestURI)
        return false
    }
// {/fact}
}

// Example 15: Using token-based authentication instead of session IDs
class TokenAuthenticationHandler {
    
// {fact rule=sensitive-information-leak@v1.0 defects=0}
    fun good_case_15(request: HttpServletRequest, response: HttpServletResponse): String {
        val userId = request.getParameter("id") ?: "guest"
        val token = generateJwtToken(userId)
        
        // Using Authorization header instead of URL-based session
        // ok: kotlin-url-rewriting
        response.setHeader("Authorization", "Bearer $token")
        return "redirect:/secure/resource"
    }
// {/fact}
    
    private fun generateJwtToken(userId: String): String {
        // JWT token generation logic would go here
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${userId}.signature"
    }
}