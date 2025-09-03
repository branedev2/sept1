import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.HashMap;
import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.commons.lang3.StringUtils;

public class UntrustedSessionDataExamples extends HttpServlet {
    
    // True Positive Examples (Vulnerable Code)
    
// {fact rule=resource-leak@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userRole = request.getParameter("role");
        HttpSession session = request.getSession();
        // ruleid: java-untrusted-session-data
        session.setAttribute("userRole", userRole);
        response.getWriter().println("Role updated");
    }
    
    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        HttpSession session = request.getSession();
        // ruleid: java-untrusted-session-data
        session.setAttribute("currentUser", username);
        response.sendRedirect("/dashboard");
    }
    
    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String preferredLanguage = request.getHeader("X-Preferred-Language");
        HttpSession session = request.getSession(true);
        // ruleid: java-untrusted-session-data
        session.setAttribute("language", preferredLanguage);
        response.getWriter().println("Language preference saved");
    }
    
    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Map<String, String[]> paramMap = request.getParameterMap();
        HttpSession session = request.getSession();
        for (String key : paramMap.keySet()) {
            String value = paramMap.get(key)[0];
            // ruleid: java-untrusted-session-data
            session.setAttribute(key, value);
        }
        response.getWriter().println("Settings updated");
    }
    
    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String theme = request.getParameter("theme");
        String layout = request.getParameter("layout");
        HttpSession session = request.getSession();
        
        if (theme != null && !theme.isEmpty()) {
            // ruleid: java-untrusted-session-data
            session.setAttribute("userTheme", theme);
        }
        
        if (layout != null && !layout.isEmpty()) {
            // ruleid: java-untrusted-session-data
            session.setAttribute("userLayout", layout);
        }
        
        response.sendRedirect("/preferences");
    }
    
    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        HttpSession session = request.getSession();
        
        if (userId != null) {
            try {
                int id = Integer.parseInt(userId);
                // Even though we parse to int, it's still untrusted user input
                // ruleid: java-untrusted-session-data
                session.setAttribute("userId", id);
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }
    
    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchHistory = request.getParameter("searchQuery");
        HttpSession session = request.getSession();
        
        // Appending to existing session data is still using untrusted input
        String existingHistory = (String) session.getAttribute("searchHistory");
        String updatedHistory = (existingHistory != null) ? existingHistory + "," + searchHistory : searchHistory;
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("searchHistory", updatedHistory);
        response.sendRedirect("/search-results");
    }
    
    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String accessLevel = request.getParameter("accessLevel");
        HttpSession session = request.getSession();
        
        switch (accessLevel) {
            case "admin":
            case "user":
            case "guest":
                // ruleid: java-untrusted-session-data
                session.setAttribute("accessLevel", accessLevel);
                break;
            default:
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid access level");
        }
    }
    
    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userEmail = request.getParameter("email");
        HttpSession session = request.getSession();
        
        if (userEmail.contains("@")) {  // Very basic check, still vulnerable
            // ruleid: java-untrusted-session-data
            session.setAttribute("userEmail", userEmail);
            response.getWriter().println("Email saved");
        } else {
            response.getWriter().println("Invalid email format");
        }
    }
    
    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String cookie = request.getHeader("Cookie");
        HttpSession session = request.getSession();
        
        if (cookie != null) {
            // ruleid: java-untrusted-session-data
            session.setAttribute("lastCookie", cookie);
        }
        
        response.getWriter().println("Cookie information saved");
    }
    
    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        HttpSession session = request.getSession();
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("userAgent", userAgent);
        response.getWriter().println("User agent recorded");
    }
    
    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        HttpSession session = request.getSession();
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("lastReferer", referer);
        response.sendRedirect("/welcome");
    }
    
    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String profileData = request.getParameter("profileJson");
        HttpSession session = request.getSession();
        
        try {
            // Even if we're trying to parse JSON, it's still untrusted input
            // ruleid: java-untrusted-session-data
            session.setAttribute("userProfile", profileData);
            response.getWriter().println("Profile updated");
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid profile data");
        }
    }
    
    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] interests = request.getParameterValues("interests");
        HttpSession session = request.getSession();
        
        if (interests != null && interests.length > 0) {
            // ruleid: java-untrusted-session-data
            session.setAttribute("userInterests", interests);
            response.getWriter().println("Interests saved");
        }
    }
    
    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Map<String, Object> userSettings = new HashMap<>();
        userSettings.put("displayName", request.getParameter("displayName"));
        userSettings.put("timezone", request.getParameter("timezone"));
        userSettings.put("notifications", request.getParameter("notifications"));
        
        HttpSession session = request.getSession();
        // ruleid: java-untrusted-session-data
        session.setAttribute("userSettings", userSettings);
        response.sendRedirect("/dashboard");
    }
    
    // True Negative Examples (Safe Code)
    
    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userRole = request.getParameter("role");
        HttpSession session = request.getSession();
        
        // Validate against a whitelist of allowed roles
        String[] validRoles = {"admin", "user", "guest"};
        boolean isValid = false;
        
        for (String role : validRoles) {
            if (role.equals(userRole)) {
                isValid = true;
                break;
            }
        }
        
        if (isValid) {
            // ok: java-untrusted-session-data
            session.setAttribute("userRole", userRole);
            response.getWriter().println("Role updated");
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid role");
        }
    }
    
    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        HttpSession session = request.getSession();
        
        // Sanitize the input to prevent injection
        String sanitizedUsername = Encode.forHtml(username);
        
        // ok: java-untrusted-session-data
        session.setAttribute("currentUser", sanitizedUsername);
        response.sendRedirect("/dashboard");
    }
    
    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String preferredLanguage = request.getHeader("X-Preferred-Language");
        HttpSession session = request.getSession(true);
        
        // Validate against a whitelist of supported languages
        String[] supportedLanguages = {"en", "es", "fr", "de", "zh"};
        boolean isSupported = false;
        
        for (String lang : supportedLanguages) {
            if (lang.equals(preferredLanguage)) {
                isSupported = true;
                break;
            }
        }
        
        if (isSupported) {
            // ok: java-untrusted-session-data
            session.setAttribute("language", preferredLanguage);
            response.getWriter().println("Language preference saved");
        } else {
            // Default to English if unsupported
            session.setAttribute("language", "en");
            response.getWriter().println("Unsupported language, defaulted to English");
        }
    }
    
    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String theme = request.getParameter("theme");
        HttpSession session = request.getSession();
        
        // Use a constant value instead of user input
        String defaultTheme = "light";
        
        // ok: java-untrusted-session-data
        session.setAttribute("userTheme", defaultTheme);
        response.sendRedirect("/preferences");
    }
    
    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("id");
        HttpSession session = request.getSession();
        
        if (userId != null) {
            try {
                int id = Integer.parseInt(userId);
                
                // Validate the user ID exists in the database
                boolean userExists = validateUserExists(id);
                
                if (userExists) {
                    // ok: java-untrusted-session-data
                    session.setAttribute("userId", id);
                } else {
                    response.sendError(HttpServletResponse.SC_NOT_FOUND, "User not found");
                }
            } catch (NumberFormatException e) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }
    
    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userEmail = request.getParameter("email");
        HttpSession session = request.getSession();
        
        // Proper email validation
        EmailValidator validator = EmailValidator.getInstance();
        if (validator.isValid(userEmail)) {
            // ok: java-untrusted-session-data
            session.setAttribute("userEmail", userEmail);
            response.getWriter().println("Email saved");
        } else {
            response.getWriter().println("Invalid email format");
        }
    }
    
    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("searchQuery");
        HttpSession session = request.getSession();
        
        // Sanitize the search query
        String sanitizedQuery = StringEscapeUtils.escapeHtml4(searchQuery);
        
        // Limit the length to prevent abuse
        if (sanitizedQuery.length() > 100) {
            sanitizedQuery = sanitizedQuery.substring(0, 100);
        }
        
        // ok: java-untrusted-session-data
        session.setAttribute("lastSearch", sanitizedQuery);
        response.sendRedirect("/search-results");
    }
    
    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String accessLevel = request.getParameter("accessLevel");
        HttpSession session = request.getSession();
        
        // Validate against a strict whitelist with default
        switch (accessLevel) {
            case "admin":
                // Additional verification for admin access
                if (isAdminUser(request)) {
                    // ok: java-untrusted-session-data
                    session.setAttribute("accessLevel", "admin");
                } else {
                    session.setAttribute("accessLevel", "user");
                }
                break;
            case "user":
                // ok: java-untrusted-session-data
                session.setAttribute("accessLevel", "user");
                break;
            default:
                // Default to lowest privilege
                session.setAttribute("accessLevel", "guest");
        }
    }
    
    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using hardcoded values instead of user input
        HttpSession session = request.getSession();
        
        // ok: java-untrusted-session-data
        session.setAttribute("appVersion", "1.2.3");
        session.setAttribute("lastUpdated", System.currentTimeMillis());
        
        response.getWriter().println("Session initialized");
    }
    
    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String profileData = request.getParameter("profileJson");
        HttpSession session = request.getSession();
        
        // Validate and sanitize the profile data
        Map<String, String> validatedProfile = validateProfileData(profileData);
        
        if (validatedProfile != null) {
            // ok: java-untrusted-session-data
            session.setAttribute("userProfile", validatedProfile);
            response.getWriter().println("Profile updated");
        } else {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid profile data");
        }
    }
    
    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String[] interests = request.getParameterValues("interests");
        HttpSession session = request.getSession();
        
        if (interests != null && interests.length > 0) {
            // Validate against allowed interests
            String[] validatedInterests = validateInterests(interests);
            
            // ok: java-untrusted-session-data
            session.setAttribute("userInterests", validatedInterests);
            response.getWriter().println("Interests saved");
        }
    }
    
    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String timezone = request.getParameter("timezone");
        HttpSession session = request.getSession();
        
        // Validate timezone against a list of valid timezones
        if (isValidTimezone(timezone)) {
            // ok: java-untrusted-session-data
            session.setAttribute("userTimezone", timezone);
            response.getWriter().println("Timezone saved");
        } else {
            // Default to UTC
            session.setAttribute("userTimezone", "UTC");
            response.getWriter().println("Invalid timezone, defaulted to UTC");
        }
    }
    
    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String displayName = request.getParameter("displayName");
        HttpSession session = request.getSession();
        
        // Sanitize and validate display name
        if (displayName != null && !displayName.isEmpty()) {
            // Remove any potentially harmful characters
            String sanitized = displayName.replaceAll("[<>\"'&]", "");
            
            // Enforce length limits
            if (sanitized.length() > 50) {
                sanitized = sanitized.substring(0, 50);
            }
            
            // ok: java-untrusted-session-data
            session.setAttribute("displayName", sanitized);
            response.getWriter().println("Display name updated");
        }
    }
    
    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Using server-generated values
        HttpSession session = request.getSession();
        
        // Generate a secure session token
        String sessionToken = generateSecureToken();
        
        // ok: java-untrusted-session-data
        session.setAttribute("secureToken", sessionToken);
        session.setAttribute("tokenCreated", System.currentTimeMillis());
        session.setAttribute("tokenExpires", System.currentTimeMillis() + 3600000);
        
        response.getWriter().println("Session secured");
    }
    
    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Map<String, String[]> paramMap = request.getParameterMap();
        HttpSession session = request.getSession();
        Map<String, Object> sanitizedSettings = new HashMap<>();
        
        // Process each parameter with appropriate validation
        if (paramMap.containsKey("displayName")) {
            String displayName = StringUtils.abbreviate(
                StringEscapeUtils.escapeHtml4(paramMap.get("displayName")[0]), 50);
            sanitizedSettings.put("displayName", displayName);
        }
        
        if (paramMap.containsKey("timezone")) {
            String timezone = paramMap.get("timezone")[0];
            if (isValidTimezone(timezone)) {
                sanitizedSettings.put("timezone", timezone);
            } else {
                sanitizedSettings.put("timezone", "UTC");
            }
        }
        
        // ok: java-untrusted-session-data
        session.setAttribute("userSettings", sanitizedSettings);
        response.sendRedirect("/dashboard");
    }
    
    // Helper methods
    private boolean validateUserExists(int userId) {
        // Implementation would check against a database
        return userId > 0 && userId < 10000;
    }
    
    private boolean isAdminUser(HttpServletRequest request) {
        // Implementation would verify admin credentials
        return false;
    }
    
    private Map<String, String> validateProfileData(String profileJson) {
        // Implementation would validate and sanitize profile data
        Map<String, String> result = new HashMap<>();
        // Validation logic here
        return result;
    }
    
    private String[] validateInterests(String[] interests) {
        // Implementation would validate interests against allowed values
        return interests;
    }
    
    private boolean isValidTimezone(String timezone) {
        // Implementation would check against valid timezone list
        String[] validTimezones = {"UTC", "GMT", "EST", "CST", "PST"};
        for (String valid : validTimezones) {
            if (valid.equals(timezone)) {
                return true;
            }
        }
        return false;
    }
    
    private String generateSecureToken() {
        // Implementation would generate a secure random token
        return "secure-token-" + System.currentTimeMillis();
    }
}
// {/fact}