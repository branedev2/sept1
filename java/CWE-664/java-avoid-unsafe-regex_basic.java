import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.HttpURLConnection;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

public class UnsafeRegexExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=resource-leak@v1.0 defects=1}
    @GetMapping("/search")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("pattern");
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(userInput);
        Matcher matcher = pattern.matcher("Some text to match against");
        
        response.getWriter().write("Pattern matches: " + matcher.find());
    }
    
    @PostMapping("/validate")
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userRegex = request.getParameter("regex");
        String textToMatch = request.getParameter("text");
        
        try {
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(userRegex);
            boolean isMatch = pattern.matcher(textToMatch).matches();
            response.getWriter().write("Match result: " + isMatch);
        } catch (Exception e) {
            response.getWriter().write("Invalid regex pattern");
        }
    }
    
    @RequestMapping("/filter")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String regexFilter = request.getHeader("X-Filter-Pattern");
        String[] words = {"apple", "banana", "cherry", "date", "elderberry"};
        
        List<String> matches = new ArrayList<>();
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexFilter);
        
        for (String word : words) {
            if (pattern.matcher(word).find()) {
                matches.add(word);
            }
        }
        
        response.getWriter().write("Matches: " + String.join(", ", matches));
    }
    
    @GetMapping("/split/{delimiter}")
    public void bad_case_4(@PathVariable String delimiter, HttpServletResponse response) throws IOException {
        String text = "This is a test string for splitting";
        
        // ruleid: java-avoid-unsafe-regex
        String[] parts = text.split(delimiter);
        
        response.getWriter().write("Split results: " + parts.length);
    }
    
    @RestController
    class RegexController {
        @PostMapping("/regex-replace")
        public String bad_case_5(@RequestParam String text, @RequestParam String regex, @RequestParam String replacement) {
            // ruleid: java-avoid-unsafe-regex
            return text.replaceAll(regex, replacement);
        }
    }
    
    @GetMapping("/extract")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userPattern = request.getParameter("pattern");
        String content = "Extract data from this text: user@example.com, phone: 123-456-7890";
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(userPattern);
        Matcher matcher = pattern.matcher(content);
        
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            result.append(matcher.group()).append("\n");
        }
        
        response.getWriter().write(result.toString());
    }
    
    @PostMapping("/validate-form")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formValue = request.getParameter("value");
        String validationPattern = request.getParameter("validation");
        
        // ruleid: java-avoid-unsafe-regex
        boolean isValid = formValue.matches(validationPattern);
        
        response.getWriter().write("Validation result: " + isValid);
    }
    
    @GetMapping("/search-multiple")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] patterns = request.getParameterValues("patterns");
        String text = "Text to search through for multiple patterns";
        
        List<String> matches = new ArrayList<>();
        for (String patternStr : patterns) {
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(patternStr);
            Matcher matcher = pattern.matcher(text);
            
            if (matcher.find()) {
                matches.add(patternStr);
            }
        }
        
        response.getWriter().write("Matching patterns: " + String.join(", ", matches));
    }
    
    @Controller
    class WebController {
        @PostMapping("/process")
        public String bad_case_9(@RequestParam String regex, @RequestParam String text, Model model) {
            List<String> matches = new ArrayList<>();
            
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(text);
            
            while (matcher.find()) {
                matches.add(matcher.group());
            }
            
            model.addAttribute("matches", matches);
            return "results";
        }
    }
    
    @GetMapping("/find-all")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userRegex = request.getParameter("regex");
        String content = request.getParameter("content");
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(userRegex, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        
        response.getWriter().write("Found " + count + " matches");
    }
    
    @PostMapping("/api/regex")
    public Map<String, Object> bad_case_11(@RequestBody Map<String, String> payload) {
        String regexPattern = payload.get("pattern");
        String testString = payload.get("test");
        
        Map<String, Object> result = new HashMap<>();
        try {
            // ruleid: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regexPattern);
            Matcher matcher = pattern.matcher(testString);
            
            result.put("matches", matcher.matches());
            result.put("success", true);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @GetMapping("/validate-email")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String emailPattern = request.getParameter("pattern");
        String email = request.getParameter("email");
        
        // ruleid: java-avoid-unsafe-regex
        boolean isValid = Pattern.matches(emailPattern, email);
        
        response.getWriter().write("Email validation result: " + isValid);
    }
    
    @PostMapping("/extract-groups")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String groupPattern = request.getParameter("pattern");
        String text = request.getParameter("text");
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(groupPattern);
        Matcher matcher = pattern.matcher(text);
        
        StringBuilder result = new StringBuilder();
        if (matcher.find()) {
            for (int i = 0; i <= matcher.groupCount(); i++) {
                result.append("Group ").append(i).append(": ").append(matcher.group(i)).append("\n");
            }
        }
        
        response.getWriter().write(result.toString());
    }
    
    @GetMapping("/count-matches")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("regex");
        String content = "This is a test string with multiple words and numbers 123456";
        
        // ruleid: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(userInput);
        Matcher matcher = pattern.matcher(content);
        
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        
        response.getWriter().write("Number of matches: " + count);
    }
    
    @PostMapping("/replace-dynamic")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String text = request.getParameter("text");
        String regex = request.getParameter("regex");
        String replacement = request.getParameter("replacement");
        
        // ruleid: java-avoid-unsafe-regex
        String result = text.replaceAll(regex, replacement);
        
        response.getWriter().write("Result: " + result);
    }
    
    // True Negative Examples (Safe Code)
    
    @GetMapping("/search-safe")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("pattern");
        
        // Validate the pattern against a whitelist
        Map<String, String> safePatterns = new HashMap<>();
        safePatterns.put("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        safePatterns.put("phone", "^\\d{3}-\\d{3}-\\d{4}$");
        safePatterns.put("zipcode", "^\\d{5}(-\\d{4})?$");
        
        String selectedPattern = safePatterns.getOrDefault(userInput, "^[a-zA-Z0-9]+$");
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(selectedPattern);
        Matcher matcher = pattern.matcher("Some text to match against");
        
        response.getWriter().write("Pattern matches: " + matcher.find());
    }
    
    @PostMapping("/validate-safe")
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userRegex = request.getParameter("regex");
        String textToMatch = request.getParameter("text");
        
        // Limit pattern complexity and length
        if (userRegex.length() > 100) {
            userRegex = userRegex.substring(0, 100);
        }
        
        // Remove potentially dangerous constructs
        userRegex = userRegex.replaceAll("\\{\\d+,\\}", "{0,10}");
        
        try {
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(userRegex);
            boolean isMatch = pattern.matcher(textToMatch).matches();
            response.getWriter().write("Match result: " + isMatch);
        } catch (Exception e) {
            response.getWriter().write("Invalid regex pattern");
        }
    }
    
    @RequestMapping("/filter-safe")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Use predefined patterns instead of user input
        String filterType = request.getHeader("X-Filter-Type");
        String regexFilter;
        
        switch (filterType) {
            case "startsWithVowel":
                regexFilter = "^[aeiouAEIOU].*";
                break;
            case "containsDigit":
                regexFilter = ".*\\d.*";
                break;
            default:
                regexFilter = ".*";
        }
        
        String[] words = {"apple", "banana", "cherry", "date", "elderberry"};
        
        List<String> matches = new ArrayList<>();
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexFilter);
        
        for (String word : words) {
            if (pattern.matcher(word).find()) {
                matches.add(word);
            }
        }
        
        response.getWriter().write("Matches: " + String.join(", ", matches));
    }
    
    @GetMapping("/split-safe/{delimiterType}")
    public void good_case_4(@PathVariable String delimiterType, HttpServletResponse response) throws IOException {
        String text = "This is a test string for splitting";
        String delimiter;
        
        // Use predefined delimiters based on type
        switch (delimiterType) {
            case "space":
                delimiter = "\\s+";
                break;
            case "comma":
                delimiter = ",";
                break;
            case "dot":
                delimiter = "\\.";
                break;
            default:
                delimiter = "\\s+";
        }
        
        // ok: java-avoid-unsafe-regex
        String[] parts = text.split(delimiter);
        
        response.getWriter().write("Split results: " + parts.length);
    }
    
    @RestController
    class SafeRegexController {
        private final Map<String, String> allowedPatterns = Map.of(
            "email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
            "phone", "^\\d{3}-\\d{3}-\\d{4}$",
            "date", "^\\d{4}-\\d{2}-\\d{2}$"
        );
        
        @PostMapping("/regex-replace-safe")
        public String good_case_5(@RequestParam String text, @RequestParam String regexType, @RequestParam String replacement) {
            String regex = allowedPatterns.getOrDefault(regexType, "\\s+");
            
            // ok: java-avoid-unsafe-regex
            return text.replaceAll(regex, replacement);
        }
    }
    
    @GetMapping("/extract-safe")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String patternType = request.getParameter("type");
        String content = "Extract data from this text: user@example.com, phone: 123-456-7890";
        
        String patternString;
        switch (patternType) {
            case "email":
                patternString = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}";
                break;
            case "phone":
                patternString = "\\d{3}-\\d{3}-\\d{4}";
                break;
            default:
                patternString = "\\w+";
        }
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(patternString);
        Matcher matcher = pattern.matcher(content);
        
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            result.append(matcher.group()).append("\n");
        }
        
        response.getWriter().write(result.toString());
    }
    
    @PostMapping("/validate-form-safe")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formValue = request.getParameter("value");
        String validationType = request.getParameter("type");
        
        String validationPattern;
        switch (validationType) {
            case "username":
                validationPattern = "^[a-zA-Z0-9_]{3,20}$";
                break;
            case "password":
                validationPattern = "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$";
                break;
            default:
                validationPattern = "^.+$";
        }
        
        // ok: java-avoid-unsafe-regex
        boolean isValid = formValue.matches(validationPattern);
        
        response.getWriter().write("Validation result: " + isValid);
    }
    
    @GetMapping("/search-multiple-safe")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] patternTypes = request.getParameterValues("types");
        String text = "Text to search through for multiple patterns";
        
        Map<String, String> safePatterns = new HashMap<>();
        safePatterns.put("digit", "\\d+");
        safePatterns.put("word", "\\b\\w+\\b");
        safePatterns.put("email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        
        List<String> matches = new ArrayList<>();
        for (String type : patternTypes) {
            String patternStr = safePatterns.getOrDefault(type, "\\w+");
            
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(patternStr);
            Matcher matcher = pattern.matcher(text);
            
            if (matcher.find()) {
                matches.add(type);
            }
        }
        
        response.getWriter().write("Matching patterns: " + String.join(", ", matches));
    }
    
    @Controller
    class SafeWebController {
        private final Map<String, String> validPatterns = Map.of(
            "digits", "\\d+",
            "words", "\\b[a-zA-Z]+\\b",
            "emails", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
        );
        
        @PostMapping("/process-safe")
        public String good_case_9(@RequestParam String patternType, @RequestParam String text, Model model) {
            List<String> matches = new ArrayList<>();
            
            String regex = validPatterns.getOrDefault(patternType, "\\w+");
            
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(text);
            
            while (matcher.find()) {
                matches.add(matcher.group());
            }
            
            model.addAttribute("matches", matches);
            return "results";
        }
    }
    
    @GetMapping("/find-all-safe")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String patternType = request.getParameter("type");
        String content = request.getParameter("content");
        
        // Use a predefined set of patterns
        String regexPattern;
        switch (patternType) {
            case "url":
                regexPattern = "https?://[\\w.-]+\\.[a-zA-Z]{2,}(/[\\w.-]*)*";
                break;
            case "hashtag":
                regexPattern = "#[\\w]+";
                break;
            default:
                regexPattern = "\\w+";
        }
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        
        response.getWriter().write("Found " + count + " matches");
    }
    
    @PostMapping("/api/regex-safe")
    public Map<String, Object> good_case_11(@RequestBody Map<String, String> payload) {
        String patternType = payload.get("patternType");
        String testString = payload.get("test");
        
        // Predefined patterns
        Map<String, String> safePatterns = new HashMap<>();
        safePatterns.put("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        safePatterns.put("url", "^https?://[\\w.-]+\\.[a-zA-Z]{2,}(/[\\w.-]*)*$");
        safePatterns.put("date", "^\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$");
        
        String regexPattern = safePatterns.getOrDefault(patternType, "^[a-zA-Z0-9]+$");
        
        Map<String, Object> result = new HashMap<>();
        try {
            // ok: java-avoid-unsafe-regex
            Pattern pattern = Pattern.compile(regexPattern);
            Matcher matcher = pattern.matcher(testString);
            
            result.put("matches", matcher.matches());
            result.put("success", true);
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @GetMapping("/validate-email-safe")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String email = request.getParameter("email");
        
        // Use a fixed, safe email validation pattern
        String emailPattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        
        // ok: java-avoid-unsafe-regex
        boolean isValid = Pattern.matches(emailPattern, email);
        
        response.getWriter().write("Email validation result: " + isValid);
    }
    
    @PostMapping("/extract-groups-safe")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String groupType = request.getParameter("type");
        String text = request.getParameter("text");
        
        String groupPattern;
        switch (groupType) {
            case "date":
                groupPattern = "(\\d{4})-(\\d{2})-(\\d{2})";
                break;
            case "name":
                groupPattern = "([A-Z][a-z]+)\\s([A-Z][a-z]+)";
                break;
            default:
                groupPattern = "(\\w+)\\s(\\w+)";
        }
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(groupPattern);
        Matcher matcher = pattern.matcher(text);
        
        StringBuilder result = new StringBuilder();
        if (matcher.find()) {
            for (int i = 0; i <= matcher.groupCount(); i++) {
                result.append("Group ").append(i).append(": ").append(matcher.group(i)).append("\n");
            }
        }
        
        response.getWriter().write(result.toString());
    }
    
    @GetMapping("/count-matches-safe")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String patternType = request.getParameter("type");
        String content = "This is a test string with multiple words and numbers 123456";
        
        String regexPattern;
        switch (patternType) {
            case "digits":
                regexPattern = "\\d+";
                break;
            case "words":
                regexPattern = "\\b[a-zA-Z]+\\b";
                break;
            default:
                regexPattern = "\\S+";
        }
        
        // ok: java-avoid-unsafe-regex
        Pattern pattern = Pattern.compile(regexPattern);
        Matcher matcher = pattern.matcher(content);
        
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        
        response.getWriter().write("Number of matches: " + count);
    }
    
    @PostMapping("/replace-dynamic-safe")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String text = request.getParameter("text");
        String regexType = request.getParameter("regexType");
        String replacement = request.getParameter("replacement");
        
        // Limit replacement string length for safety
        if (replacement.length() > 100) {
            replacement = replacement.substring(0, 100);
        }
        
        String regex;
        switch (regexType) {
            case "whitespace":
                regex = "\\s+";
                break;
            case "digits":
                regex = "\\d+";
                break;
            case "punctuation":
                regex = "[.,;:!?]";
                break;
            default:
                regex = "\\s";
        }
        
        // ok: java-avoid-unsafe-regex
        String result = text.replaceAll(regex, replacement);
        
        response.getWriter().write("Result: " + result);
    }
}
// {/fact}