import java.io.IOException;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.LoggerFactory;

// True Positive Examples (Vulnerable Code)

@WebServlet("/log-injection-1")
public class LogInjectionExamples extends HttpServlet {
    private static final Logger logger = Logger.getLogger(LogInjectionExamples.class.getName());
    private static final org.apache.logging.log4j.Logger log4jLogger = LogManager.getLogger(LogInjectionExamples.class);
    private static final org.slf4j.Logger slf4jLogger = LoggerFactory.getLogger(LogInjectionExamples.class);
    
// {fact rule=file-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        // ruleid: java-log-injection
        logger.info("User login attempt: " + username);
        response.getWriter().println("Login attempt logged");
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        // ruleid: java-log-injection
        log4jLogger.error("Failed login attempt from IP: " + ipAddress + " with user agent: " + userAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        // ruleid: java-log-injection
        logger.warning("User searched for: " + searchQuery);
        response.getWriter().println("Search results for: " + searchQuery);
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referrer = request.getHeader("Referer");
        // ruleid: java-log-injection
        log4jLogger.info("Request referred from: {}", referrer);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorMessage = request.getParameter("error");
        // ruleid: java-log-injection
        logger.severe("Application error: " + errorMessage);
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String action = request.getParameter("action");
        // ruleid: java-log-injection
        slf4jLogger.info("Session {} performed action: {}", sessionId, action);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        // ruleid: java-log-injection
        logger.log(Level.INFO, "Password reset requested for email: {0}", email);
        response.getWriter().println("Password reset email sent");
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String quantity = request.getParameter("quantity");
        // ruleid: java-log-injection
        log4jLogger.debug("Added to cart - Product: " + productId + ", Quantity: " + quantity);
        response.sendRedirect("/cart");
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentText = request.getParameter("comment");
        // ruleid: java-log-injection
        logger.info("New comment posted: " + commentText);
        response.getWriter().println("Comment posted successfully");
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        // ruleid: java-log-injection
        slf4jLogger.warn("Attempted to access file: {}", fileName);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        // ruleid: java-log-injection
        logger.info("Login attempt with username: " + username + " and password length: " + password.length());
        response.sendRedirect("/dashboard");
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        // ruleid: java-log-injection
        log4jLogger.info("Request with cookie: " + cookie);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String paymentMethod = request.getParameter("payment");
        String amount = request.getParameter("amount");
        // ruleid: java-log-injection
        slf4jLogger.info("Payment processed: {} amount using {}", amount, paymentMethod);
        response.getWriter().println("Payment processed");
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String query = request.getQueryString();
        // ruleid: java-log-injection
        logger.info("Request query string: " + query);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contentType = request.getHeader("Content-Type");
        String contentLength = request.getHeader("Content-Length");
        // ruleid: java-log-injection
        log4jLogger.info("Received request with Content-Type: " + contentType + " and Content-Length: " + contentLength);
        response.setStatus(HttpServletResponse.SC_AC_REDACTED_TWILIO_ID);
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        // ok: java-log-injection
        logger.info("User login attempt: " + username.replaceAll("[\r\n]", ""));
        response.getWriter().println("Login attempt logged");
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        String sanitizedUserAgent = userAgent != null ? userAgent.replaceAll("[\r\n]", "") : "null";
        // ok: java-log-injection
        log4jLogger.error("Failed login attempt from IP: {} with user agent: {}", 
                          ipAddress.replaceAll("[\r\n]", ""), sanitizedUserAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("q");
        // ok: java-log-injection
        logger.warning("User searched for: " + Encode.forJava(searchQuery));
        response.getWriter().println("Search results for: " + searchQuery);
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referrer = request.getHeader("Referer");
        String sanitizedReferrer = referrer != null ? referrer.replaceAll("[\n\r]", "") : "null";
        // ok: java-log-injection
        log4jLogger.info("Request referred from: {}", sanitizedReferrer);
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorMessage = request.getParameter("error");
        // ok: java-log-injection
        logger.severe("Application error: " + StringEscapeUtils.escapeJava(errorMessage));
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String action = request.getParameter("action");
        // ok: java-log-injection
        slf4jLogger.info("Session {} performed action: {}", 
                         sessionId, 
                         action != null ? action.replaceAll("[\r\n]", "") : "null");
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String email = request.getParameter("email");
        String sanitizedEmail = email != null ? email.replaceAll("[\r\n]", "") : "null";
        // ok: java-log-injection
        logger.log(Level.INFO, "Password reset requested for email: {0}", sanitizedEmail);
        response.getWriter().println("Password reset email sent");
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String productId = request.getParameter("productId");
        String quantity = request.getParameter("quantity");
        
        // Validate inputs are numeric
        if (!productId.matches("\\d+") || !quantity.matches("\\d+")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        
        // ok: java-log-injection
        log4jLogger.debug("Added to cart - Product: {} Quantity: {}", productId, quantity);
        response.sendRedirect("/cart");
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String commentText = request.getParameter("comment");
        // ok: java-log-injection
        logger.info("New comment posted: " + commentText.replaceAll("[\r\n]", "[newline]"));
        response.getWriter().println("Comment posted successfully");
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String fileName = request.getParameter("file");
        // ok: java-log-injection
        slf4jLogger.warn("Attempted to access file: {}", Encode.forJava(fileName));
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        // ok: java-log-injection
        logger.info("Login attempt with username: {} and password length: {}", 
                    username.replaceAll("[\r\n]", ""), 
                    password != null ? password.length() : 0);
        response.sendRedirect("/dashboard");
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        // Mask sensitive information
        String maskedCookie = cookie != null ? cookie.replaceAll("(session|auth)=[^;]+", "$1=***") : "null";
        // ok: java-log-injection
        log4jLogger.info("Request with cookie: {}", StringEscapeUtils.escapeJava(maskedCookie));
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String paymentMethod = request.getParameter("payment");
        String amount = request.getParameter("amount");
        
        // Validate amount is numeric
        if (!amount.matches("\\d+(\\.\\d{1,2})?")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        
        // ok: java-log-injection
        slf4jLogger.info("Payment processed: {} amount using {}", 
                         amount, 
                         paymentMethod != null ? paymentMethod.replaceAll("[\r\n]", "") : "unknown");
        response.getWriter().println("Payment processed");
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String query = request.getQueryString();
        // ok: java-log-injection
        if (query != null) {
            // Remove any CRLF characters
            String sanitizedQuery = query.replaceAll("[\r\n]", "");
            logger.info("Request query string: " + sanitizedQuery);
        } else {
            logger.info("Request with no query string");
        }
        response.setStatus(HttpServletResponse.SC_OK);
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contentType = request.getHeader("Content-Type");
        String contentLength = request.getHeader("Content-Length");
        
        // Sanitize headers
        String safeContentType = contentType != null ? contentType.replaceAll("[\r\n]", "") : "null";
        String safeContentLength = contentLength != null ? contentLength.replaceAll("[\r\n]", "") : "null";
        
        // ok: java-log-injection
        log4jLogger.info("Received request with Content-Type: {} and Content-Length: {}", 
                         safeContentType, safeContentLength);
        response.setStatus(HttpServletResponse.SC_AC_REDACTED_TWILIO_ID);
    }
}
// {/fact}