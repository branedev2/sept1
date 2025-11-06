import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import org.owasp.encoder.Encode;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.ui.Model;

public class XSSVulnerabilityExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("comment");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<div>" + userInput + "</div>");
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<h1>Welcome, " + username + "!</h1>");
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<p>Search results for: " + searchTerm + "</p>");
    }

    @GetMapping("/profile")
    @ResponseBody
    public String bad_case_4(HttpServletRequest request) {
        String userId = request.getParameter("id");
        
        // ruleid: java-cross-site-scripting
        return "<div class='profile' data-id='" + userId + "'>User profile</div>";
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<div style='background-color:" + color + "'>Colored div</div>");
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<p>Your browser: " + userAgent + "</p>");
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String lastVisit = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("lastVisit")) {
                    lastVisit = cookie.getValue();
                    break;
                }
            }
        }
        
        PrintWriter out = response.getWriter();
        // ruleid: java-cross-site-scripting
        out.println("<p>Last visit: " + lastVisit + "</p>");
    }

    @PostMapping("/comment")
    @ResponseBody
    public String bad_case_8(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        String username = request.getParameter("username");
        
        // ruleid: java-cross-site-scripting
        return "<div class='comment'><span class='author'>" + username + 
               "</span><p>" + comment + "</p></div>";
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String referer = request.getHeader("Referer");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<p>You came from: <a href='" + referer + "'>" + referer + "</a></p>");
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String message = request.getParameter("message");
        String script = "function showMessage() { alert('" + message + "'); }";
        
        PrintWriter out = response.getWriter();
        // ruleid: java-cross-site-scripting
        out.println("<script>" + script + "</script>");
    }

    @GetMapping("/error")
    @ResponseBody
    public String bad_case_11(HttpServletRequest request) {
        String errorMessage = request.getParameter("message");
        
        // ruleid: java-cross-site-scripting
        return "<div class='error'>" + errorMessage + "</div>";
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String customJs = request.getParameter("js");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<script>" + customJs + "</script>");
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<html><head><title>" + title + "</title></head><body>...</body></html>");
    }

    @GetMapping("/redirect")
    @ResponseBody
    public String bad_case_14(HttpServletRequest request) {
        String redirectUrl = request.getParameter("url");
        
        // ruleid: java-cross-site-scripting
        return "<meta http-equiv='refresh' content='0;url=" + redirectUrl + "'>";
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting
        out.println("<script>const data = " + jsonData + ";</script>");
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("comment");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<div>" + Encode.forHtml(userInput) + "</div>");
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<h1>Welcome, " + Encode.forHtml(username) + "!</h1>");
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        String sanitizedSearchTerm = Encode.forHtml(searchTerm);
        out.println("<p>Search results for: " + sanitizedSearchTerm + "</p>");
    }

    @GetMapping("/profile")
    @ResponseBody
    public String good_case_4(HttpServletRequest request) {
        String userId = request.getParameter("id");
        
        // ok: java-cross-site-scripting
        return "<div class='profile' data-id='" + Encode.forHtmlAttribute(userId) + "'>User profile</div>";
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<div style='background-color:" + Encode.forCssString(color) + "'>Colored div</div>");
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<p>Your browser: " + Encode.forHtml(userAgent) + "</p>");
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String lastVisit = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("lastVisit")) {
                    lastVisit = cookie.getValue();
                    break;
                }
            }
        }
        
        PrintWriter out = response.getWriter();
        // ok: java-cross-site-scripting
        out.println("<p>Last visit: " + Encode.forHtml(lastVisit) + "</p>");
    }

    @PostMapping("/comment")
    @ResponseBody
    public String good_case_8(HttpServletRequest request) {
        String comment = request.getParameter("comment");
        String username = request.getParameter("username");
        
        // ok: java-cross-site-scripting
        return "<div class='comment'><span class='author'>" + Encode.forHtml(username) + 
               "</span><p>" + Encode.forHtml(comment) + "</p></div>";
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String referer = request.getHeader("Referer");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        String safeReferer = Encode.forHtml(referer);
        String safeHref = Encode.forHtmlAttribute(referer);
        out.println("<p>You came from: <a href='" + safeHref + "'>" + safeReferer + "</a></p>");
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String message = request.getParameter("message");
        
        // ok: java-cross-site-scripting
        String safeMessage = Encode.forJavaScriptString(message);
        String script = "function showMessage() { alert('" + safeMessage + "'); }";
        
        PrintWriter out = response.getWriter();
        out.println("<script>" + script + "</script>");
    }

    @GetMapping("/error")
    @ResponseBody
    public String good_case_11(HttpServletRequest request) {
        String errorMessage = request.getParameter("message");
        
        // ok: java-cross-site-scripting
        PolicyFactory policy = new HtmlPolicyBuilder().allowElements("b", "i", "u").toFactory();
        String safeHtml = policy.sanitize(errorMessage);
        
        return "<div class='error'>" + safeHtml + "</div>";
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-cross-site-scripting
        // Instead of directly including user JS, use a predefined set of options
        String jsOption = request.getParameter("jsOption");
        PrintWriter out = response.getWriter();
        
        if ("option1".equals(jsOption)) {
            out.println("<script>console.log('Option 1 selected');</script>");
        } else if ("option2".equals(jsOption)) {
            out.println("<script>console.log('Option 2 selected');</script>");
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String title = request.getParameter("title");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        out.println("<html><head><title>" + Encode.forHtml(title) + "</title></head><body>...</body></html>");
    }

    @GetMapping("/redirect")
    @ResponseBody
    public String good_case_14(HttpServletRequest request) {
        String redirectUrl = request.getParameter("url");
        
        // Validate URL against whitelist
        boolean isValidUrl = false;
        String[] allowedDomains = {"example.com", "mydomain.org"};
        
        for (String domain : allowedDomains) {
            if (redirectUrl != null && redirectUrl.startsWith("https://" + domain)) {
                isValidUrl = true;
                break;
            }
        }
        
        // ok: java-cross-site-scripting
        if (isValidUrl) {
            return "<meta http-equiv='refresh' content='0;url=" + Encode.forHtmlAttribute(redirectUrl) + "'>";
        } else {
            return "<p>Invalid redirect URL</p>";
        }
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting
        // Parse and validate JSON before outputting
        try {
            // Assume JsonParser is a valid JSON parser that validates the structure
            // For a real implementation, use a library like Jackson or Gson
            // JsonObject parsedJson = JsonParser.parse(jsonData);
            // String validatedJson = parsedJson.toString();
            
            // For this example, we'll use proper JavaScript encoding
            String safeJsonData = Encode.forJavaScript(jsonData);
            out.println("<script>const data = JSON.parse(\"" + safeJsonData + "\");</script>");
        } catch (Exception e) {
            out.println("<script>const data = {};</script>");
        }
    }
}
// {/fact}