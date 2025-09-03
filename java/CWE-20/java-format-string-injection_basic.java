import java.util.Formatter;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

public class FormatStringInjectionExamples {
    private static final Logger logger = Logger.getLogger(FormatStringInjectionExamples.class.getName());

    // True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        
        // ruleid: java-format-string-injection
        String formattedString = String.format(userInput);
        
        PrintWriter out = response.getWriter();
        out.println("Formatted message: " + formattedString);
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("template");
        Object[] data = {"John", 25, "New York"};
        
        // ruleid: java-format-string-injection
        String result = String.format(userInput, data);
        
        response.getWriter().println(result);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        String formatString = request.getHeader("X-Format-Template");
        int value1 = 42;
        String value2 = "test";
        
        // ruleid: java-format-string-injection
        logger.info(String.format(formatString, value1, value2));
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("format");
        Formatter formatter = new Formatter();
        
        // ruleid: java-format-string-injection
        formatter.format(userInput, "Hello", 123);
        
        response.getWriter().println(formatter.toString());
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String template = request.getParameter("template");
        StringBuilder sb = new StringBuilder();
        Formatter formatter = new Formatter(sb);
        
        // ruleid: java-format-string-injection
        formatter.format(template, "World");
        
        response.getWriter().println(sb.toString());
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> paramMap = request.getParameterMap();
        String format = paramMap.get("fmt")[0];
        
        // ruleid: java-format-string-injection
        String result = String.format(format, 100, 200);
        
        response.getWriter().println(result);
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookieValue = null;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("formatTemplate".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            // ruleid: java-format-string-injection
            String formatted = String.format(cookieValue, "data1", "data2");
            response.getWriter().println(formatted);
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        
        // ruleid: java-format-string-injection
        String logMessage = String.format(userAgent, "visited", request.getRequestURI());
        
        logger.info(logMessage);
        response.getWriter().println("Request logged");
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formatParam = request.getParameter("format");
        if (formatParam == null) {
            formatParam = "%s: %d";
        }
        
        // ruleid: java-format-string-injection
        String result = String.format(formatParam, "Count", 42);
        
        response.getWriter().println(result);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String queryString = request.getQueryString();
        
        // ruleid: java-format-string-injection
        String formatted = String.format(queryString, "arg1", "arg2");
        
        response.getWriter().println(formatted);
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formatString = request.getParameter("format");
        StringBuilder sb = new StringBuilder();
        
        try (Formatter formatter = new Formatter(sb)) {
            // ruleid: java-format-string-injection
            formatter.format(formatString, 100, 200, 300);
        }
        
        response.getWriter().println(sb.toString());
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] formats = request.getParameterValues("formats");
        
        if (formats != null && formats.length > 0) {
            // ruleid: java-format-string-injection
            String result = String.format(formats[0], "Hello", "World");
            response.getWriter().println(result);
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String format = "";
        
        // Get the format from a request parameter
        format = request.getParameter("outputFormat");
        
        // ruleid: java-format-string-injection
        String output = String.format(format, "Username", request.getRemoteUser());
        
        response.getWriter().println(output);
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Object> userData = new HashMap<>();
        userData.put("name", "John");
        userData.put("age", 30);
        
        String formatTemplate = request.getParameter("template");
        
        // ruleid: java-format-string-injection
        String formattedOutput = String.format(formatTemplate, userData.get("name"), userData.get("age"));
        
        response.getWriter().println(formattedOutput);
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formatPattern = request.getParameter("pattern");
        if (formatPattern == null || formatPattern.isEmpty()) {
            formatPattern = "%s - %s";
        }
        
        // ruleid: java-format-string-injection
        logger.warning(String.format(formatPattern, "Warning", "Potential security issue"));
        
        response.getWriter().println("Logged with pattern: " + formatPattern);
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("message");
        
        // ok: java-format-string-injection
        String formattedString = String.format("%s", userInput);
        
        PrintWriter out = response.getWriter();
        out.println("Formatted message: " + formattedString);
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userName = request.getParameter("name");
        int userAge = Integer.parseInt(request.getParameter("age"));
        String userCity = request.getParameter("city");
        
        // ok: java-format-string-injection
        String result = String.format("Name: %s, Age: %d, City: %s", userName, userAge, userCity);
        
        response.getWriter().println(result);
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        String userName = request.getHeader("X-User-Name");
        int value = 42;
        
        // ok: java-format-string-injection
        logger.info(String.format("User %s accessed resource with value %d", userName, value));
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("input");
        Formatter formatter = new Formatter();
        
        // ok: java-format-string-injection
        formatter.format("User input: %s, processed at: %tF", userInput, new java.util.Date());
        
        response.getWriter().println(formatter.toString());
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String message = request.getParameter("message");
        StringBuilder sb = new StringBuilder();
        Formatter formatter = new Formatter(sb);
        
        // ok: java-format-string-injection
        formatter.format("Message from user: %s", message);
        
        response.getWriter().println(sb.toString());
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> paramMap = request.getParameterMap();
        String userName = paramMap.get("user")[0];
        int userId = Integer.parseInt(paramMap.get("id")[0]);
        
        // ok: java-format-string-injection
        String result = String.format("User %s (ID: %d) logged in", userName, userId);
        
        response.getWriter().println(result);
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookieValue = null;
        javax.servlet.http.Cookie[] cookies = request.getCookies();
        
        if (cookies != null) {
            for (javax.servlet.http.Cookie cookie : cookies) {
                if ("userPreference".equals(cookie.getName())) {
                    cookieValue = cookie.getValue();
                    break;
                }
            }
        }
        
        if (cookieValue != null) {
            // ok: java-format-string-injection
            String formatted = String.format("User preference: %s", cookieValue);
            response.getWriter().println(formatted);
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        
        // ok: java-format-string-injection
        String logMessage = String.format("User with agent '%s' visited %s", userAgent, request.getRequestURI());
        
        logger.info(logMessage);
        response.getWriter().println("Request logged");
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String formatType = request.getParameter("type");
        String formatString;
        
        if ("detailed".equals(formatType)) {
            formatString = "Detailed view - Name: %s, Count: %d, Date: %tF";
        } else {
            formatString = "Simple view - %s: %d";
        }
        
        // ok: java-format-string-injection
        String result = String.format(formatString, "Product", 42, new java.util.Date());
        
        response.getWriter().println(result);
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String queryString = request.getQueryString();
        
        // ok: java-format-string-injection
        String formatted = String.format("Query: %s", queryString);
        
        response.getWriter().println(formatted);
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int value1 = Integer.parseInt(request.getParameter("val1"));
        int value2 = Integer.parseInt(request.getParameter("val2"));
        int value3 = Integer.parseInt(request.getParameter("val3"));
        
        StringBuilder sb = new StringBuilder();
        
        try (Formatter formatter = new Formatter(sb)) {
            // ok: java-format-string-injection
            formatter.format("Values: %d, %d, %d", value1, value2, value3);
        }
        
        response.getWriter().println(sb.toString());
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String[] values = request.getParameterValues("values");
        
        if (values != null && values.length > 0) {
            // ok: java-format-string-injection
            String result = String.format("First value: %s, count: %d", values[0], values.length);
            response.getWriter().println(result);
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String outputType = request.getParameter("output");
        String formatPattern;
        
        if ("json".equals(outputType)) {
            formatPattern = "{\"user\": \"%s\", \"role\": \"%s\"}";
        } else if ("xml".equals(outputType)) {
            formatPattern = "<user name=\"%s\" role=\"%s\" />";
        } else {
            formatPattern = "User: %s, Role: %s";
        }
        
        // ok: java-format-string-injection
        String output = String.format(formatPattern, request.getRemoteUser(), "admin");
        
        response.getWriter().println(output);
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Object> userData = new HashMap<>();
        userData.put("name", request.getParameter("name"));
        userData.put("age", Integer.parseInt(request.getParameter("age")));
        
        // ok: java-format-string-injection
        String formattedOutput = String.format("User Details - Name: %s, Age: %d", 
                                              userData.get("name"), userData.get("age"));
        
        response.getWriter().println(formattedOutput);
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String logLevel = request.getParameter("level");
        String message = request.getParameter("message");
        
        if ("warning".equalsIgnoreCase(logLevel)) {
            // ok: java-format-string-injection
            logger.warning(String.format("WARNING: %s", message));
        } else if ("severe".equalsIgnoreCase(logLevel)) {
            // ok: java-format-string-injection
            logger.severe(String.format("SEVERE: %s", message));
        } else {
            // ok: java-format-string-injection
            logger.info(String.format("INFO: %s", message));
        }
        
        response.getWriter().println("Message logged with level: " + logLevel);
    }
}
// {/fact}