import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.LoggerFactory;
import org.owasp.encoder.Encode;
import java.util.regex.Pattern;
import org.apache.commons.text.StringEscapeUtils;

// True Positive Examples (Vulnerable Code)

@WebServlet("/bad1")
public class LogInjectionExamples extends HttpServlet {
    private static final Logger javaLogger = Logger.getLogger(LogInjectionExamples.class.getName());
    private static final org.apache.logging.log4j.Logger log4jLogger = LogManager.getLogger(LogInjectionExamples.class);
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(LogInjectionExamples.class);
    
// {fact rule=ldap-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        // ruleid: java-log-injection-ide
        javaLogger.info("User login attempt: " + username);
        response.getWriter().println("Login attempt logged");
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        // ruleid: java-log-injection-ide
        log4jLogger.error("Failed login attempt from IP: " + ipAddress + " with user agent: " + userAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        // ruleid: java-log-injection-ide
        slf4jLogger.info("Search query executed: {}", searchQuery);
        response.getWriter().println("Search results for: " + searchQuery);
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorCode = request.getParameter("errorCode");
        String errorMessage = request.getParameter("errorMessage");
        // ruleid: java-log-injection-ide
        javaLogger.severe("Application error: " + errorCode + " - " + errorMessage);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String action = request.getParameter("action");
        // ruleid: java-log-injection-ide
        log4jLogger.warn("User " + userId + " attempted restricted action: " + action);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referrer = request.getHeader("Referer");
        // ruleid: java-log-injection-ide
        slf4jLogger.debug("Request referred from: " + referrer);
        response.getWriter().println("Welcome");
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        // ruleid: java-log-injection-ide
        javaLogger.log(Level.INFO, "Password reset requested for email: " + email);
        response.getWriter().println("Password reset instructions sent");
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        // ruleid: java-log-injection-ide
        log4jLogger.info("File download requested: " + fileName);
        response.getWriter().println("Downloading file: " + fileName);
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String username = request.getParameter("username");
        // ruleid: java-log-injection-ide
        slf4jLogger.info("Session {} created for user {}", sessionId, username);
        response.getWriter().println("Session created");
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String paymentAmount = request.getParameter("amount");
        String paymentMethod = request.getParameter("method");
        // ruleid: java-log-injection-ide
        javaLogger.warning("Unusual payment amount detected: " + paymentAmount + " via " + paymentMethod);
        response.getWriter().println("Payment processing");
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentText = request.getParameter("comment");
        // ruleid: java-log-injection-ide
        log4jLogger.debug("New comment posted: " + commentText);
        response.getWriter().println("Comment posted");
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        // ruleid: java-log-injection-ide
        slf4jLogger.warn("Potentially malformed cookie: {}", cookie);
        response.getWriter().println("Cookie validation failed");
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String quantity = request.getParameter("quantity");
        StringBuilder logMessage = new StringBuilder("Order placed for product: ");
        logMessage.append(productId).append(", quantity: ").append(quantity);
        // ruleid: java-log-injection-ide
        javaLogger.info(logMessage.toString());
        response.getWriter().println("Order placed");
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String loginStatus = "failed";
        if (username != null && username.equals("admin")) {
            loginStatus = "success";
        }
        // ruleid: java-log-injection-ide
        log4jLogger.info("Login " + loginStatus + " for user: " + username);
        response.getWriter().println("Login processed");
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String requestedUrl = request.getRequestURL().toString();
        // ruleid: java-log-injection-ide
        slf4jLogger.info("Request from {} to access {}", ipAddress, requestedUrl);
        response.getWriter().println("Access logged");
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        // ok: java-log-injection-ide
        javaLogger.info("User login attempt: " + Encode.forJava(username));
        response.getWriter().println("Login attempt logged");
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        // ok: java-log-injection-ide
        log4jLogger.error("Failed login attempt from IP: {} with user agent: {}", ipAddress, userAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        String sanitizedQuery = StringEscapeUtils.escapeJava(searchQuery);
        // ok: java-log-injection-ide
        slf4jLogger.info("Search query executed: {}", sanitizedQuery);
        response.getWriter().println("Search results for: " + searchQuery);
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorCode = request.getParameter("errorCode");
        String errorMessage = request.getParameter("errorMessage");
        // ok: java-log-injection-ide
        javaLogger.log(Level.SEVERE, "Application error: {0} - {1}", new Object[]{errorCode, errorMessage});
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String action = request.getParameter("action");
        
        // Sanitize inputs
        userId = userId.replaceAll("[\\r\\n]", "");
        action = action.replaceAll("[\\r\\n]", "");
        
        // ok: java-log-injection-ide
        log4jLogger.warn("User {} attempted restricted action: {}", userId, action);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referrer = request.getHeader("Referer");
        // Validate against allowlist
        Pattern allowedPattern = Pattern.compile("^https?://[a-zA-Z0-9.-]+\\.(com|org|net)/.*$");
        boolean isValid = referrer != null && allowedPattern.matcher(referrer).matches();
        
        // ok: java-log-injection-ide
        slf4jLogger.debug("Request referred from: {}", isValid ? referrer : "invalid-referrer");
        response.getWriter().println("Welcome");
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        // ok: java-log-injection-ide
        javaLogger.log(Level.INFO, "Password reset requested for email: {0}", new Object[]{email});
        response.getWriter().println("Password reset instructions sent");
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        // Remove any CRLF characters
        if (fileName != null) {
            fileName = fileName.replace('\n', '_').replace('\r', '_');
        }
        // ok: java-log-injection-ide
        log4jLogger.info("File download requested: {}", fileName);
        response.getWriter().println("Downloading file: " + fileName);
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String username = request.getParameter("username");
        // Sanitize username
        String sanitizedUsername = Encode.forJava(username);
        // ok: java-log-injection-ide
        slf4jLogger.info("Session {} created for user {}", sessionId, sanitizedUsername);
        response.getWriter().println("Session created");
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String paymentAmount = request.getParameter("amount");
        String paymentMethod = request.getParameter("method");
        // ok: java-log-injection-ide
        javaLogger.log(Level.WARNING, "Unusual payment amount detected: {0} via {1}", 
                      new Object[]{StringEscapeUtils.escapeJava(paymentAmount), StringEscapeUtils.escapeJava(paymentMethod)});
        response.getWriter().println("Payment processing");
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentText = request.getParameter("comment");
        // Truncate long comments for logging
        String truncatedComment = commentText.length() > 100 ? 
            commentText.substring(0, 100) + "..." : commentText;
        // Sanitize for log
        truncatedComment = truncatedComment.replaceAll("[\\r\\n]", " ");
        // ok: java-log-injection-ide
        log4jLogger.debug("New comment posted: {}", truncatedComment);
        response.getWriter().println("Comment posted");
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        // Mask sensitive data
        String maskedCookie = cookie;
        if (cookie != null && cookie.contains("session=")) {
            maskedCookie = cookie.replaceAll("(session=)[^;]+", "$1***MASKED***");
        }
        // ok: java-log-injection-ide
        slf4jLogger.warn("Potentially malformed cookie: {}", Encode.forJava(maskedCookie));
        response.getWriter().println("Cookie validation failed");
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String quantity = request.getParameter("quantity");
        
        // Validate inputs are numeric
        boolean validProductId = productId != null && productId.matches("\\d+");
        boolean validQuantity = quantity != null && quantity.matches("\\d+");
        
        // ok: java-log-injection-ide
        javaLogger.log(Level.INFO, "Order placed for product: {0}, quantity: {1}", 
                      new Object[]{validProductId ? productId : "invalid", validQuantity ? quantity : "invalid"});
        response.getWriter().println("Order placed");
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String loginStatus = "failed";
        if (username != null && username.equals("admin")) {
            loginStatus = "success";
        }
        
        // Sanitize username for logging
        String sanitizedUsername = username;
        if (username != null) {
            sanitizedUsername = username.replaceAll("[\\r\\n]", "");
        }
        
        // ok: java-log-injection-ide
        log4jLogger.info("Login {} for user: {}", loginStatus, sanitizedUsername);
        response.getWriter().println("Login processed");
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String requestedUrl = request.getRequestURL().toString();
        
        // Validate URL format
        if (requestedUrl != null && !requestedUrl.matches("^https?://[a-zA-Z0-9.-]+\\.[a-z]{2,}(/[^\\s]*)?$")) {
            requestedUrl = "invalid-url";
        }
        
        // ok: java-log-injection-ide
        slf4jLogger.info("Request from {} to access {}", Encode.forJava(ipAddress), Encode.forJava(requestedUrl));
        response.getWriter().println("Access logged");
    }
}
// {/fact}