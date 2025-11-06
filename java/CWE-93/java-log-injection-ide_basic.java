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

// True Positives (Vulnerable Code)

@WebServlet("/bad1")
public class BadCase1 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadCase1.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        // ruleid: java-log-injection-ide
        logger.info("User login attempt: " + username);
        response.getWriter().println("Login attempt logged");
    }
}

@WebServlet("/bad2")
public class BadCase2 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(BadCase2.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        // ruleid: java-log-injection-ide
        logger.error("Failed login from IP: " + ipAddress + " with User-Agent: " + userAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}

@WebServlet("/bad3")
public class BadCase3 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BadCase3.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        // ruleid: java-log-injection-ide
        logger.warn("User searched for potentially malicious term: " + searchTerm);
        response.getWriter().println("Search completed");
    }
}

@WebServlet("/bad4")
public class BadCase4 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadCase4.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        // ruleid: java-log-injection-ide
        logger.log(Level.INFO, "Request came from: " + referer);
        response.getWriter().println("Request processed");
    }
}

@WebServlet("/bad5")
public class BadCase5 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(BadCase5.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String email = request.getParameter("email");
        String action = request.getParameter("action");
        
        // ruleid: java-log-injection-ide
        logger.info("User with email " + email + " performed action: " + action);
        response.getWriter().println("Action recorded");
    }
}

@WebServlet("/bad6")
public class BadCase6 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BadCase6.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String requestedPage = request.getParameter("page");
        
        // ruleid: java-log-injection-ide
        logger.debug("Session " + sessionId + " requested page: " + requestedPage);
        response.sendRedirect(requestedPage);
    }
}

@WebServlet("/bad7")
public class BadCase7 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadCase7.class.getName());
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String errorMessage = request.getParameter("error");
        
        if (errorMessage != null) {
            // ruleid: java-log-injection-ide
            logger.severe("Error for user " + username + ": " + errorMessage);
        }
        response.getWriter().println("Error logged");
    }
}

@WebServlet("/bad8")
public class BadCase8 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(BadCase8.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        // ruleid: java-log-injection-ide
        logger.warn("Suspicious cookie detected: " + cookie);
        response.getWriter().println("Security check completed");
    }
}

@WebServlet("/bad9")
public class BadCase9 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BadCase9.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password"); // Should never log passwords
        
        // ruleid: java-log-injection-ide
        logger.info("Login attempt with username: " + username + " and password length: " + password.length());
        response.getWriter().println("Login processed");
    }
}

@WebServlet("/bad10")
public class BadCase10 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadCase10.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String query = request.getQueryString();
        // ruleid: java-log-injection-ide
        logger.info("Raw query string: " + query);
        response.getWriter().println("Query processed");
    }
}

@WebServlet("/bad11")
public class BadCase11 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(BadCase11.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String contentType = request.getHeader("Content-Type");
        String payload = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
        
        // ruleid: java-log-injection-ide
        logger.info("Received " + contentType + " request with payload: " + payload);
        response.getWriter().println("Request received");
    }
}

@WebServlet("/bad12")
public class BadCase12 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BadCase12.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String language = request.getHeader("Accept-Language");
        
        try {
            throw new Exception("Language processing error");
        } catch (Exception e) {
            // ruleid: java-log-injection-ide
            logger.error("Error processing language: " + language, e);
        }
        response.getWriter().println("Error handled");
    }
}

@WebServlet("/bad13")
public class BadCase13 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadCase13.class.getName());
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        
        StringBuilder logMessage = new StringBuilder();
        logMessage.append("User activity: ");
        logMessage.append(username);
        
        // ruleid: java-log-injection-ide
        logger.info(logMessage.toString());
        response.getWriter().println("Activity logged");
    }
}

@WebServlet("/bad14")
public class BadCase14 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(BadCase14.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String filename = request.getParameter("file");
        
        if (filename == null || filename.isEmpty()) {
            // ruleid: java-log-injection-ide
            logger.error("Invalid file requested: " + request.getRequestURI() + "?" + request.getQueryString());
        }
        response.getWriter().println("File check completed");
    }
}

@WebServlet("/bad15")
public class BadCase15 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BadCase15.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        String action = request.getParameter("action");
        
        // Concatenation in a separate variable still vulnerable
        String logEntry = "User " + userId + " attempted to " + action;
        // ruleid: java-log-injection-ide
        logger.info(logEntry);
        response.getWriter().println("Action processed");
    }
}

// True Negatives (Safe Code)

@WebServlet("/good1")
public class GoodCase1 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodCase1.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        // ok: java-log-injection-ide
        logger.log(Level.INFO, "User login attempt: {0}", Encode.forJava(username));
        response.getWriter().println("Login attempt logged safely");
    }
}

@WebServlet("/good2")
public class GoodCase2 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodCase2.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        
        // ok: java-log-injection-ide
        logger.error("Failed login from IP: {} with User-Agent: {}", ipAddress, userAgent);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}

@WebServlet("/good3")
public class GoodCase3 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GoodCase3.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String searchTerm = request.getParameter("search");
        
        // Sanitize input before logging
        String sanitizedTerm = searchTerm.replaceAll("[\r\n]", "");
        // ok: java-log-injection-ide
        logger.warn("User searched for potentially malicious term: {}", sanitizedTerm);
        response.getWriter().println("Search completed safely");
    }
}

@WebServlet("/good4")
public class GoodCase4 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodCase4.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        
        // ok: java-log-injection-ide
        logger.log(Level.INFO, "Request came from: {0}", new Object[]{referer != null ? Encode.forJava(referer) : "unknown"});
        response.getWriter().println("Request processed safely");
    }
}

@WebServlet("/good5")
public class GoodCase5 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodCase5.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String email = request.getParameter("email");
        String action = request.getParameter("action");
        
        // Using pattern validation before logging
        Pattern emailPattern = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
        if (emailPattern.matcher(email).matches()) {
            // ok: java-log-injection-ide
            logger.info("User with validated email {} performed action: {}", email, action);
        } else {
            logger.warn("Invalid email format attempted");
        }
        response.getWriter().println("Action recorded safely");
    }
}

@WebServlet("/good6")
public class GoodCase6 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GoodCase6.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String sessionId = request.getSession().getId();
        String requestedPage = request.getParameter("page");
        
        // Sanitizing input with StringEscapeUtils
        String safePage = StringEscapeUtils.escapeJava(requestedPage);
        // ok: java-log-injection-ide
        logger.debug("Session {} requested page: {}", sessionId, safePage);
        response.sendRedirect(requestedPage);
    }
}

@WebServlet("/good7")
public class GoodCase7 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodCase7.class.getName());
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String errorMessage = request.getParameter("error");
        
        if (errorMessage != null) {
            // ok: java-log-injection-ide
            logger.log(Level.SEVERE, "Error for user {0}: {1}", 
                    new Object[]{Encode.forJava(username), Encode.forJava(errorMessage)});
        }
        response.getWriter().println("Error logged safely");
    }
}

@WebServlet("/good8")
public class GoodCase8 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodCase8.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        
        // Redact sensitive information before logging
        String redactedCookie = cookie != null ? cookie.replaceAll("(session|auth)=[^;]+", "$1=REDAC_REDACTED_TWILIO_ID") : "null";
        // ok: java-log-injection-ide
        logger.warn("Suspicious cookie detected: {}", redactedCookie);
        response.getWriter().println("Security check completed safely");
    }
}

@WebServlet("/good9")
public class GoodCase9 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GoodCase9.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password"); // Should never log passwords
        
        // ok: java-log-injection-ide
        logger.info("Login attempt with username: {}", Encode.forJava(username));
        // Note: Not logging password at all, even length
        response.getWriter().println("Login processed safely");
    }
}

@WebServlet("/good10")
public class GoodCase10 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodCase10.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // Instead of logging raw query string, log specific parameters
        String action = request.getParameter("action");
        String id = request.getParameter("id");
        
        // ok: java-log-injection-ide
        logger.log(Level.INFO, "Processing action: {0} for ID: {1}", 
                new Object[]{action != null ? Encode.forJava(action) : "none", 
                             id != null ? Encode.forJava(id) : "none"});
        response.getWriter().println("Query processed safely");
    }
}

@WebServlet("/good11")
public class GoodCase11 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodCase11.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String contentType = request.getHeader("Content-Type");
        
        // Only log content type, not the payload
        // ok: java-log-injection-ide
        logger.info("Received request with content type: {}", contentType);
        response.getWriter().println("Request received safely");
    }
}

@WebServlet("/good12")
public class GoodCase12 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GoodCase12.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String language = request.getHeader("Accept-Language");
        
        try {
            throw new Exception("Language processing error");
        } catch (Exception e) {
            // Using parameterized logging for the exception
            // ok: java-log-injection-ide
            logger.error("Error processing language: {}", 
                    language != null ? language.replaceAll("[\\r\\n]", "") : "unknown", e);
        }
        response.getWriter().println("Error handled safely");
    }
}

@WebServlet("/good13")
public class GoodCase13 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodCase13.class.getName());
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        
        // Using a whitelist approach
        if (username != null && username.matches("[a-zA-Z0-9_]{3,20}")) {
            // ok: java-log-injection-ide
            logger.log(Level.INFO, "Valid user activity: {0}", username);
        } else {
            logger.warning("Invalid username format detected");
        }
        response.getWriter().println("Activity logged safely");
    }
}

@WebServlet("/good14")
public class GoodCase14 extends HttpServlet {
    private static final org.apache.logging.log4j.Logger logger = LogManager.getLogger(GoodCase14.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String filename = request.getParameter("file");
        
        if (filename == null || filename.isEmpty()) {
            // Only log the URI path, not query parameters
            String path = request.getRequestURI();
            // ok: java-log-injection-ide
            logger.error("Invalid file requested at path: {}", path);
        }
        response.getWriter().println("File check completed safely");
    }
}

@WebServlet("/good15")
public class GoodCase15 extends HttpServlet {
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GoodCase15.class);
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        String action = request.getParameter("action");
        
        // Create a custom sanitization function
        String sanitizedId = userId != null ? userId.replaceAll("[^a-zA-Z0-9]", "") : "unknown";
        String sanitizedAction = action != null ? action.replaceAll("[^a-zA-Z0-9_-]", "") : "unknown";
        
        // ok: java-log-injection-ide
        logger.info("User {} attempted to {}", sanitizedId, sanitizedAction);
        response.getWriter().println("Action processed safely");
    }
}