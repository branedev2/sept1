import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.annotation.WebServlet;
import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.ui.Model;

// True Positive Examples (Vulnerable Code)

@WebServlet("/bad1")
public class bad_case_1 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userInput = request.getParameter("name");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<h1>Hello, " + userInput + "!</h1>");
        out.println("</body></html>");
    }
}

@WebServlet("/bad2")
public class bad_case_2 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userComment = request.getParameter("comment");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<p>Your comment:</p>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<div class='comment'>" + userComment + "</div>");
        out.println("</body></html>");
    }
}

@WebServlet("/bad3")
public class bad_case_3 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String searchTerm = request.getParameter("q");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<p>Search results for: " + searchTerm + "</p>");
        out.println("</body></html>");
    }
}

@Controller
public class bad_case_4 {
    @GetMapping("/profile")
    @ResponseBody
    public String showProfile(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String userBio = getUserBioFromDatabase(userId); // Assume this returns user-controlled content
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>User Profile</h1>");
        // ruleid: java-cross-site-scripting-ide
        html.append("<div class='bio'>" + userBio + "</div>");
        html.append("</body></html>");
        
        return html.toString();
    }
    
    private String getUserBioFromDatabase(String userId) {
        // Simulated database fetch
        return "User bio for " + userId;
    }
}

@WebServlet("/bad5")
public class bad_case_5 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<p>You came from: " + referer + "</p>");
        out.println("</body></html>");
    }
}

@WebServlet("/bad6")
public class bad_case_6 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String userTheme = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("theme")) {
                    userTheme = cookie.getValue();
                    break;
                }
            }
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<div style='background-color:" + userTheme + "'>Content</div>");
        out.println("</body></html>");
    }
}

@Controller
public class bad_case_7 {
    @PostMapping("/feedback")
    @ResponseBody
    public String processFeedback(HttpServletRequest request) {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String message = request.getParameter("message");
        
        StringBuilder responseHtml = new StringBuilder();
        responseHtml.append("<html><body>");
        responseHtml.append("<h1>Thank you for your feedback!</h1>");
        // ruleid: java-cross-site-scripting-ide
        responseHtml.append("<p>Name: " + name + "</p>");
        // ruleid: java-cross-site-scripting-ide
        responseHtml.append("<p>Email: " + email + "</p>");
        // ruleid: java-cross-site-scripting-ide
        responseHtml.append("<p>Message: " + message + "</p>");
        responseHtml.append("</body></html>");
        
        return responseHtml.toString();
    }
}

@WebServlet("/bad8")
public class bad_case_8 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<p>Your browser: " + userAgent + "</p>");
        out.println("</body></html>");
    }
}

@WebServlet("/bad9")
public class bad_case_9 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String errorMsg = request.getParameter("error");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        if (errorMsg != null && !errorMsg.isEmpty()) {
            // ruleid: java-cross-site-scripting-ide
            out.println("<div class='error'>" + errorMsg + "</div>");
        }
        out.println("</body></html>");
    }
}

@Controller
public class bad_case_10 {
    @GetMapping("/search")
    @ResponseBody
    public String search(HttpServletRequest request) {
        String query = request.getParameter("q");
        String category = request.getParameter("category");
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        html.append("<h1>Search results for: " + query + " in " + category + "</h1>");
        html.append("<ul><li>Result 1</li><li>Result 2</li></ul>");
        html.append("</body></html>");
        
        return html.toString();
    }
}

@WebServlet("/bad11")
public class bad_case_11 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String redirectUrl = request.getParameter("redirect");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<a href='" + redirectUrl + "'>Click here to continue</a>");
        out.println("</body></html>");
    }
}

@WebServlet("/bad12")
public class bad_case_12 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        if (username == null || username.isEmpty()) {
            out.println("<p>Username is required</p>");
        } else {
            // ruleid: java-cross-site-scripting-ide
            out.println("<script>document.getElementById('welcome').innerHTML = 'Welcome, " + username + "';</script>");
        }
        out.println("</body></html>");
    }
}

@Controller
public class bad_case_13 {
    @GetMapping("/article")
    @ResponseBody
    public String getArticle(HttpServletRequest request) {
        String articleId = request.getParameter("id");
        String articleTitle = getArticleTitle(articleId); // Assume this returns user-controlled content
        String articleContent = getArticleContent(articleId); // Assume this returns user-controlled content
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        html.append("<h1>" + articleTitle + "</h1>");
        // ruleid: java-cross-site-scripting-ide
        html.append("<div>" + articleContent + "</div>");
        html.append("</body></html>");
        
        return html.toString();
    }
    
    private String getArticleTitle(String id) {
        // Simulated database fetch
        return "Article " + id;
    }
    
    private String getArticleContent(String id) {
        // Simulated database fetch
        return "Content for article " + id;
    }
}

@WebServlet("/bad14")
public class bad_case_14 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String lang = request.getParameter("lang");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<html lang='" + lang + "'>");
        out.println("<body><h1>Welcome</h1></body></html>");
    }
}

@WebServlet("/bad15")
public class bad_case_15 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String customJs = request.getParameter("js");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-ide
        out.println("<script>" + customJs + "</script>");
        out.println("<h1>Welcome</h1></body></html>");
    }
}

// True Negative Examples (Safe Code)

@WebServlet("/good1")
public class good_case_1 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userInput = request.getParameter("name");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<h1>Hello, " + Encode.forHtml(userInput) + "!</h1>");
        out.println("</body></html>");
    }
}

@WebServlet("/good2")
public class good_case_2 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userComment = request.getParameter("comment");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<p>Your comment:</p>");
        // ok: java-cross-site-scripting-ide
        out.println("<div class='comment'>" + StringEscapeUtils.escapeHtml4(userComment) + "</div>");
        out.println("</body></html>");
    }
}

@WebServlet("/good3")
public class good_case_3 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String searchTerm = request.getParameter("q");
        
        // Sanitize input
        searchTerm = searchTerm.replaceAll("[<>\"'&]", "");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<p>Search results for: " + searchTerm + "</p>");
        out.println("</body></html>");
    }
}

@Controller
public class good_case_4 {
    @GetMapping("/profile")
    @ResponseBody
    public String showProfile(HttpServletRequest request) {
        String userId = request.getParameter("id");
        String userBio = getUserBioFromDatabase(userId); // Assume this returns user-controlled content
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>User Profile</h1>");
        // ok: java-cross-site-scripting-ide
        html.append("<div class='bio'>" + Encode.forHtml(userBio) + "</div>");
        html.append("</body></html>");
        
        return html.toString();
    }
    
    private String getUserBioFromDatabase(String userId) {
        // Simulated database fetch
        return "User bio for " + userId;
    }
}

@WebServlet("/good5")
public class good_case_5 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<p>You came from: " + StringEscapeUtils.escapeHtml4(referer) + "</p>");
        out.println("</body></html>");
    }
}

@WebServlet("/good6")
public class good_case_6 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        Cookie[] cookies = request.getCookies();
        String userTheme = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("theme")) {
                    userTheme = cookie.getValue();
                    break;
                }
            }
        }
        
        // Validate theme value against allowed list
        if (!isValidTheme(userTheme)) {
            userTheme = "light"; // Default theme
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<div style='background-color:" + userTheme + "'>Content</div>");
        out.println("</body></html>");
    }
    
    private boolean isValidTheme(String theme) {
        return theme.equals("light") || theme.equals("dark") || theme.equals("blue");
    }
}

@Controller
public class good_case_7 {
    @PostMapping("/feedback")
    public String processFeedback(HttpServletRequest request, Model model) {
        String name = request.getParameter("name");
        String email = request.getParameter("email");
        String message = request.getParameter("message");
        
        // Add sanitized data to model instead of directly to HTML
        // ok: java-cross-site-scripting-ide
        model.addAttribute("name", name);
        model.addAttribute("email", email);
        model.addAttribute("message", message);
        
        // Return template name - Thymeleaf or similar will handle escaping
        return "feedback-confirmation";
    }
}

@WebServlet("/good8")
public class good_case_8 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<p>Your browser: " + Encode.forHtml(userAgent) + "</p>");
        out.println("</body></html>");
    }
}

@WebServlet("/good9")
public class good_case_9 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String errorMsg = request.getParameter("error");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        if (errorMsg != null && !errorMsg.isEmpty()) {
            // ok: java-cross-site-scripting-ide
            out.println("<div class='error'>" + StringEscapeUtils.escapeHtml4(errorMsg) + "</div>");
        }
        out.println("</body></html>");
    }
}

@Controller
public class good_case_10 {
    @GetMapping("/search")
    @ResponseBody
    public String search(HttpServletRequest request) {
        String query = request.getParameter("q");
        String category = request.getParameter("category");
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        // ok: java-cross-site-scripting-ide
        html.append("<h1>Search results for: " + Encode.forHtml(query) + 
                    " in " + Encode.forHtml(category) + "</h1>");
        html.append("<ul><li>Result 1</li><li>Result 2</li></ul>");
        html.append("</body></html>");
        
        return html.toString();
    }
}

@WebServlet("/good11")
public class good_case_11 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String redirectUrl = request.getParameter("redirect");
        
        // Validate URL against allowed domains
        if (!isValidRedirectUrl(redirectUrl)) {
            redirectUrl = "/home"; // Default safe URL
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<a href='" + Encode.forHtmlAttribute(redirectUrl) + "'>Click here to continue</a>");
        out.println("</body></html>");
    }
    
    private boolean isValidRedirectUrl(String url) {
        return url != null && (url.startsWith("/") || url.startsWith("https://example.com/"));
    }
}

@WebServlet("/good12")
public class good_case_12 extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        if (username == null || username.isEmpty()) {
            out.println("<p>Username is required</p>");
        } else {
            // ok: java-cross-site-scripting-ide
            out.println("<script>document.getElementById('welcome').innerHTML = 'Welcome, " + 
                       Encode.forJavaScript(username) + "';</script>");
        }
        out.println("</body></html>");
    }
}

@Controller
public class good_case_13 {
    @GetMapping("/article")
    @ResponseBody
    public String getArticle(HttpServletRequest request) {
        String articleId = request.getParameter("id");
        String articleTitle = getArticleTitle(articleId); // Assume this returns user-controlled content
        String articleContent = getArticleContent(articleId); // Assume this returns user-controlled content
        
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        // ok: java-cross-site-scripting-ide
        html.append("<h1>" + Encode.forHtml(articleTitle) + "</h1>");
        // ok: java-cross-site-scripting-ide
        html.append("<div>" + Encode.forHtml(articleContent) + "</div>");
        html.append("</body></html>");
        
        return html.toString();
    }
    
    private String getArticleTitle(String id) {
        // Simulated database fetch
        return "Article " + id;
    }
    
    private String getArticleContent(String id) {
        // Simulated database fetch
        return "Content for article " + id;
    }
}

@WebServlet("/good14")
public class good_case_14 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String lang = request.getParameter("lang");
        
        // Validate language code
        if (!isValidLanguageCode(lang)) {
            lang = "en"; // Default to English
        }
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        // ok: java-cross-site-scripting-ide
        out.println("<html lang='" + lang + "'>");
        out.println("<body><h1>Welcome</h1></body></html>");
    }
    
    private boolean isValidLanguageCode(String lang) {
        // Check if lang is a valid ISO language code
        return lang != null && lang.matches("^[a-z]{2}(-[A-Z]{2})?$");
    }
}

@WebServlet("/good15")
public class good_case_15 extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // Instead of accepting arbitrary JS, use a parameter to select from predefined scripts
        String scriptId = request.getParameter("scriptId");
        String script = getScriptById(scriptId);
        
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-ide
        out.println("<script>" + script + "</script>");
        out.println("<h1>Welcome</h1></body></html>");
    }
    
    private String getScriptById(String id) {
        // Return only predefined scripts
        if ("1".equals(id)) {
            return "console.log('Script 1 loaded');";
        } else if ("2".equals(id)) {
            return "document.getElementById('status').innerText = 'Ready';";
        }
        return ""; // Default empty script
    }
}