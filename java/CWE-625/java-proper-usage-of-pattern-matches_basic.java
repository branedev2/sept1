import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class PatternMatchesUsageExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=permissive-regex@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        
        // Using String.matches directly with user input
        // ruleid: java-proper-usage-of-pattern-matches
        boolean isMatch = userInput.matches("^[a-zA-Z0-9]+$");
        
        response.getWriter().println("Input validation result: " + isMatch);
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userPattern = request.getParameter("pattern");
        String testString = "test123";
        
        // Using dynamically constructed pattern directly in matches
        // ruleid: java-proper-usage-of-pattern-matches
        boolean isMatch = testString.matches(userPattern);
        
        response.getWriter().println("Pattern match result: " + isMatch);
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("username");
        String dynamicPattern = "^" + userInput + "$";
        String testValue = "admin";
        
        // Using a pattern constructed with user input
        // ruleid: java-proper-usage-of-pattern-matches
        if (testValue.matches(dynamicPattern)) {
            response.getWriter().println("Username matches pattern");
        }
    }
    
    @WebServlet("/validate")
    public class bad_case_4 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String email = request.getParameter("email");
            String customDomain = request.getParameter("domain");
            
            // Constructing regex with user input
            String emailPattern = "^[A-Za-z0-9+_.-]+@" + customDomain + "$";
            
            // ruleid: java-proper-usage-of-pattern-matches
            boolean isValid = email.matches(emailPattern);
            
            response.getWriter().println("Email validation: " + isValid);
        }
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String> userInputs = new HashMap<>();
        userInputs.put("pattern", request.getParameter("pattern"));
        userInputs.put("text", request.getParameter("text"));
        
        // Using user-provided pattern directly
        // ruleid: java-proper-usage-of-pattern-matches
        boolean result = userInputs.get("text").matches(userInputs.get("pattern"));
        
        response.getWriter().println("Match result: " + result);
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] allowedPatterns = {"[a-z]+", "[0-9]+"};
        int patternIndex = Integer.parseInt(request.getParameter("patternIndex"));
        String input = request.getParameter("input");
        
        if (patternIndex >= 0 && patternIndex < allowedPatterns.length) {
            // Using array index from user input without proper validation
            // ruleid: java-proper-usage-of-pattern-matches
            boolean matches = input.matches(allowedPatterns[patternIndex]);
            response.getWriter().println("Match result: " + matches);
        }
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userRegex = request.getParameter("regex");
        String testData = "test@example.com";
        
        try {
            // Using user input directly in matches
            // ruleid: java-proper-usage-of-pattern-matches
            if (testData.matches(userRegex)) {
                response.getWriter().println("Valid format");
            } else {
                response.getWriter().println("Invalid format");
            }
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String prefix = request.getParameter("prefix");
        String suffix = request.getParameter("suffix");
        String content = "test content";
        
        // Constructing regex from multiple user inputs
        String regex = prefix + ".*" + suffix;
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean matches = content.matches(regex);
        
        response.getWriter().println("Content matches pattern: " + matches);
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        String dataToCheck = "sensitive data";
        
        // Concatenating user input into regex
        String dynamicRegex = "^" + userInput + ".*";
        
        // ruleid: java-proper-usage-of-pattern-matches
        if (dataToCheck.matches(dynamicRegex)) {
            response.getWriter().println("Data matches the pattern");
        }
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userPattern = request.getParameter("pattern");
        String[] testStrings = {"test1", "test2", "test3"};
        
        for (String str : testStrings) {
            // Using user input pattern in a loop
            // ruleid: java-proper-usage-of-pattern-matches
            boolean isMatch = str.matches(userPattern);
            response.getWriter().println(str + " matches: " + isMatch);
        }
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        String patternStr = "^" + userInput.replaceAll("[^a-zA-Z0-9]", "") + "$";
        String testValue = "abc123";
        
        // Even with some sanitization, still using dynamic pattern directly
        // ruleid: java-proper-usage-of-pattern-matches
        boolean matches = testValue.matches(patternStr);
        
        response.getWriter().println("Match result: " + matches);
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String category = request.getParameter("category");
        String searchTerm = request.getParameter("search");
        
        // Constructing complex pattern with user input
        String regex = "\\b" + category + "\\b.*\\b" + searchTerm + "\\b";
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean found = "Product category books with title Java Programming".matches(regex);
        
        response.getWriter().println("Search result: " + found);
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userRegex = request.getParameter("regex");
        String testString = request.getParameter("test");
        
        try {
            // Both pattern and test string from user input
            // ruleid: java-proper-usage-of-pattern-matches
            boolean result = testString.matches(userRegex);
            response.getWriter().println("Result: " + result);
        } catch (Exception e) {
            response.getWriter().println("Invalid regex");
        }
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String allowedChars = request.getParameter("allowed");
        String input = request.getParameter("input");
        
        // Creating character class from user input
        String pattern = "^[" + allowedChars + "]+$";
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean valid = input.matches(pattern);
        
        response.getWriter().println("Input validation: " + valid);
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String format = request.getParameter("format");
        String value = "2023-10-15";
        
        // Using format specification from user
        String datePattern = format.replace("YYYY", "\\d{4}")
                                  .replace("MM", "\\d{2}")
                                  .replace("DD", "\\d{2}");
        
        // ruleid: java-proper-usage-of-pattern-matches
        boolean isValidDate = value.matches(datePattern);
        
        response.getWriter().println("Date format valid: " + isValidDate);
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        
        // Pre-compile the pattern
        // ok: java-proper-usage-of-pattern-matches
        Pattern pattern = Pattern.compile("^[a-zA-Z0-9]+$");
        Matcher matcher = pattern.matcher(userInput);
        boolean isMatch = matcher.matches();
        
        response.getWriter().println("Input validation result: " + isMatch);
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String testString = "test123";
        
        // Using a predefined set of patterns
        Map<String, Pattern> safePatterns = new HashMap<>();
        safePatterns.put("alphanumeric", Pattern.compile("^[a-zA-Z0-9]+$"));
        safePatterns.put("numeric", Pattern.compile("^[0-9]+$"));
        
        String patternKey = request.getParameter("pattern");
        if (safePatterns.containsKey(patternKey)) {
            // ok: java-proper-usage-of-pattern-matches
            Pattern selectedPattern = safePatterns.get(patternKey);
            boolean isMatch = selectedPattern.matcher(testString).matches();
            response.getWriter().println("Pattern match result: " + isMatch);
        } else {
            response.getWriter().println("Invalid pattern selection");
        }
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("username");
        String testValue = "admin";
        
        // Validating user input before using it in pattern
        if (!userInput.matches("^[a-zA-Z0-9]+$")) {
            response.getWriter().println("Invalid username format");
            return;
        }
        
        // Pre-compiling pattern after validation
        // ok: java-proper-usage-of-pattern-matches
        Pattern pattern = Pattern.compile("^" + userInput + "$");
        boolean matches = pattern.matcher(testValue).matches();
        
        response.getWriter().println("Username matches pattern: " + matches);
    }
    
    @WebServlet("/validate-email")
    public class good_case_4 extends HttpServlet {
        // Pre-compiled patterns for different domains
        private static final Map<String, Pattern> EMAIL_PATTERNS = new HashMap<>();
        
        static {
            EMAIL_PATTERNS.put("gmail.com", Pattern.compile("^[A-Za-z0-9+_.-]+@gmail\\.com$"));
            EMAIL_PATTERNS.put("yahoo.com", Pattern.compile("^[A-Za-z0-9+_.-]+@yahoo\\.com$"));
            EMAIL_PATTERNS.put("hotmail.com", Pattern.compile("^[A-Za-z0-9+_.-]+@hotmail\\.com$"));
        }
        
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String email = request.getParameter("email");
            String domain = request.getParameter("domain");
            
            if (EMAIL_PATTERNS.containsKey(domain)) {
                // ok: java-proper-usage-of-pattern-matches
                Pattern pattern = EMAIL_PATTERNS.get(domain);
                boolean isValid = pattern.matcher(email).matches();
                response.getWriter().println("Email validation: " + isValid);
            } else {
                response.getWriter().println("Unsupported domain");
            }
        }
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Pre-compiled pattern
        final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");
        
        String userInput = request.getParameter("text");
        
        // ok: java-proper-usage-of-pattern-matches
        boolean result = SAFE_PATTERN.matcher(userInput).matches();
        
        response.getWriter().println("Match result: " + result);
    }
    
    private static final Map<Integer, Pattern> PATTERN_CAC_REDACTED_TWILIO_ID = new ConcurrentHashMap<>();
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] patternStrings = {"[a-z]+", "[0-9]+"};
        int patternIndex = Integer.parseInt(request.getParameter("patternIndex"));
        String input = request.getParameter("input");
        
        if (patternIndex >= 0 && patternIndex < patternStrings.length) {
            // Using cached pre-compiled patterns
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = PATTERN_CAC_REDACTED_TWILIO_ID.computeIfAbsent(patternIndex, 
                k -> Pattern.compile(patternStrings[k]));
            boolean matches = pattern.matcher(input).matches();
            response.getWriter().println("Match result: " + matches);
        }
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String testData = "test@example.com";
        
        // Using a whitelist of pre-compiled patterns
        Map<String, Pattern> validPatterns = new HashMap<>();
        validPatterns.put("email", Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$"));
        validPatterns.put("phone", Pattern.compile("^\\d{10}$"));
        
        String patternType = request.getParameter("type");
        
        if (validPatterns.containsKey(patternType)) {
            // ok: java-proper-usage-of-pattern-matches
            Pattern selectedPattern = validPatterns.get(patternType);
            boolean isValid = selectedPattern.matcher(testData).matches();
            response.getWriter().println("Valid format: " + isValid);
        } else {
            response.getWriter().println("Invalid pattern type");
        }
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String content = "test content";
        
        // Using enum to restrict pattern choices
        enum PatternType {
            START_WITH_A(Pattern.compile("^a.*")),
            END_WITH_Z(Pattern.compile(".*z$")),
            CONTAINS_NUMBER(Pattern.compile(".*\\d.*"));
            
            private final Pattern pattern;
            
            PatternType(Pattern pattern) {
                this.pattern = pattern;
            }
            
            public Pattern getPattern() {
                return pattern;
            }
        }
        
        try {
            String patternName = request.getParameter("pattern");
            PatternType selectedType = PatternType.valueOf(patternName);
            
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = selectedType.getPattern();
            boolean matches = pattern.matcher(content).matches();
            
            response.getWriter().println("Content matches pattern: " + matches);
        } catch (IllegalArgumentException e) {
            response.getWriter().println("Invalid pattern selection");
        }
    }
    
    // Cache of pre-compiled patterns
    private static final Map<String, Pattern> patternCache = new ConcurrentHashMap<>();
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String patternKey = request.getParameter("pattern");
        String dataToCheck = "sensitive data";
        
        // Whitelist of allowed pattern keys
        Map<String, String> allowedPatterns = new HashMap<>();
        allowedPatterns.put("alpha", "^[a-zA-Z]+$");
        allowedPatterns.put("numeric", "^[0-9]+$");
        allowedPatterns.put("alphanumeric", "^[a-zA-Z0-9]+$");
        
        if (allowedPatterns.containsKey(patternKey)) {
            String patternStr = allowedPatterns.get(patternKey);
            
            // Using pattern cache for efficiency
            // ok: java-proper-usage-of-pattern-matches
            Pattern pattern = patternCache.computeIfAbsent(patternStr, Pattern::compile);
            boolean matches = pattern.matcher(dataToCheck).matches();
            
            response.getWriter().println("Data matches the pattern: " + matches);
        } else {
            response.getWriter().println("Invalid pattern key");
        }
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] testStrings = {"test1", "test2", "test3"};
        
        // Pre-defined patterns
        String[] patternOptions = {"^test\\d$", "^[a-z]+\\d$"};
        int patternIndex = Integer.parseInt(request.getParameter("patternIndex"));
        
        if (patternIndex >= 0 && patternIndex < patternOptions.length) {
            // ok: java-proper-usage-of-pattern-matches
            Pattern selectedPattern = Pattern.compile(patternOptions[patternIndex]);
            
            for (String str : testStrings) {
                boolean isMatch = selectedPattern.matcher(str).matches();
                response.getWriter().println(str + " matches: " + isMatch);
            }
        } else {
            response.getWriter().println("Invalid pattern index");
        }
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        String testValue = "abc123";
        
        // Sanitize and validate input before using it
        if (!userInput.matches("^[a-zA-Z0-9]+$")) {
            response.getWriter().println("Invalid input format");
            return;
        }
        
        // Pre-compile pattern after validation
        // ok: java-proper-usage-of-pattern-matches
        Pattern pattern = Pattern.compile("^" + userInput + "$");
        boolean matches = pattern.matcher(testValue).matches();
        
        response.getWriter().println("Match result: " + matches);
    }
    
    // Singleton pattern for regex patterns
    public static class PatternRegistry {
        private static final PatternRegistry INSTANCE = new PatternRegistry();
        private final Map<String, Pattern> patterns = new HashMap<>();
        
        private PatternRegistry() {
            patterns.put("product", Pattern.compile("\\bproduct\\b.*\\b([a-zA-Z0-9]+)\\b"));
            patterns.put("category", Pattern.compile("\\bcategory\\b.*\\b([a-zA-Z0-9]+)\\b"));
        }
        
        public static PatternRegistry getInstance() {
            return INSTANCE;
        }
        
        public Pattern getPattern(String key) {
            return patterns.get(key);
        }
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchType = request.getParameter("type");
        String text = "Product category books with title Java Programming";
        
        PatternRegistry registry = PatternRegistry.getInstance();
        Pattern pattern = registry.getPattern(searchType);
        
        if (pattern != null) {
            // ok: java-proper-usage-of-pattern-matches
            Matcher matcher = pattern.matcher(text);
            boolean found = matcher.matches();
            response.getWriter().println("Search result: " + found);
        } else {
            response.getWriter().println("Invalid search type");
        }
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String testString = request.getParameter("test");
        
        // Fixed set of pre-compiled patterns
        Pattern emailPattern = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");
        Pattern phonePattern = Pattern.compile("^\\d{10}$");
        Pattern zipPattern = Pattern.compile("^\\d{5}(-\\d{4})?$");
        
        String type = request.getParameter("type");
        boolean result = false;
        
        switch (type) {
            case "email":
                // ok: java-proper-usage-of-pattern-matches
                result = emailPattern.matcher(testString).matches();
                break;
            case "phone":
                result = phonePattern.matcher(testString).matches();
                break;
            case "zip":
                result = zipPattern.matcher(testString).matches();
                break;
            default:
                response.getWriter().println("Invalid type");
                return;
        }
        
        response.getWriter().println("Validation result: " + result);
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String input = request.getParameter("input");
        
        // Using a builder pattern for safe regex construction
        class RegexBuilder {
            private StringBuilder pattern = new StringBuilder();
            
            public RegexBuilder startsWith(String prefix) {
                pattern.append("^").append(Pattern.quote(prefix));
                return this;
            }
            
            public RegexBuilder contains(String text) {
                pattern.append(".*").append(Pattern.quote(text));
                return this;
            }
            
            public RegexBuilder endsWith(String suffix) {
                pattern.append(".*").append(Pattern.quote(suffix)).append("$");
                return this;
            }
            
            public Pattern build() {
                return Pattern.compile(pattern.toString());
            }
        }
        
        String prefix = request.getParameter("prefix");
        String suffix = request.getParameter("suffix");
        
        // ok: java-proper-usage-of-pattern-matches
        Pattern safePattern = new RegexBuilder()
            .startsWith(prefix)
            .endsWith(suffix)
            .build();
        
        boolean valid = safePattern.matcher(input).matches();
        response.getWriter().println("Input validation: " + valid);
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String value = "2023-10-15";
        
        // Pre-defined date format patterns
        Map<String, Pattern> datePatterns = new HashMap<>();
        datePatterns.put("iso", Pattern.compile("^\\d{4}-\\d{2}-\\d{2}$"));
        datePatterns.put("us", Pattern.compile("^\\d{2}/\\d{2}/\\d{4}$"));
        datePatterns.put("eu", Pattern.compile("^\\d{2}\\.\\d{2}\\.\\d{4}$"));
        
        String format = request.getParameter("format");
        
        if (datePatterns.containsKey(format)) {
            // ok: java-proper-usage-of-pattern-matches
            Pattern datePattern = datePatterns.get(format);
            boolean isValidDate = datePattern.matcher(value).matches();
            response.getWriter().println("Date format valid: " + isValidDate);
        } else {
            response.getWriter().println("Unsupported date format");
        }
    }
}
// {/fact}