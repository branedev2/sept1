import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

public class XSSExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("userInput");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<div>" + userInput + "</div>");
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<script>var currentUser = '" + username + "';</script>");
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<div style='background-color:" + color + "'>Colored div</div>");
    }

    @GetMapping("/profile")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        String userComment = request.getParameter("comment");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        out.println("<h1>User Profile: " + userId + "</h1>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<div class='comment'>" + userComment + "</div>");
        out.println("</body></html>");
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<h2>Search results for: " + searchTerm + "</h2>");
        out.println("</body></html>");
    }

    @PostMapping("/feedback")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String feedback = request.getParameter("feedback");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<div class='alert'>Thanks for your feedback: " + feedback + "</div>");
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<div>Your browser: " + userAgent + "</div>");
    }

    @RequestMapping("/error")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String errorMsg = request.getParameter("message");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<div class='error' onclick='logError()'>" + errorMsg + "</div>");
        out.println("</body></html>");
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-cross-site-scripting-exp
        out.println("<a href='" + redirectUrl + "'>Click here to continue</a>");
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String lastSearch = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("lastSearch")) {
                    lastSearch = cookie.getValue();
                    break;
                }
            }
        }
        
        PrintWriter out = response.getWriter();
        // ruleid: java-cross-site-scripting-exp
        out.println("<div>Your last search was: " + lastSearch + "</div>");
    }

    @GetMapping("/welcome")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String title = request.getParameter("title");
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<h1 title='" + title + "'>Welcome, " + name + "!</h1>");
        out.println("</body></html>");
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String customJs = request.getParameter("js");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<script>" + customJs + "</script>");
        out.println("</body></html>");
    }

    @RequestMapping("/image")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String imageUrl = request.getParameter("url");
        String altText = request.getParameter("alt");
        
        PrintWriter out = response.getWriter();
        // ruleid: java-cross-site-scripting-exp
        out.println("<img src='" + imageUrl + "' alt='" + altText + "'>");
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<script>var appData = " + jsonData + ";</script>");
        out.println("</body></html>");
    }

    @PostMapping("/comment")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String commentText = request.getParameter("comment");
        
        PrintWriter out = response.getWriter();
        out.println("<div class='comment-container'>");
        out.println("<div class='comment-header'>Posted by: ");
        // ruleid: java-cross-site-scripting-exp
        out.println(username);
        out.println("</div>");
        // ruleid: java-cross-site-scripting-exp
        out.println("<div class='comment-body'>" + commentText + "</div>");
        out.println("</div>");
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userInput = request.getParameter("userInput");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting-exp
        out.println("<div>" + StringEscapeUtils.escapeHtml4(userInput) + "</div>");
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting-exp
        out.println("<script>var currentUser = '" + Encode.forJavaScript(username) + "';</script>");
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String color = request.getParameter("color");
        PrintWriter out = response.getWriter();
        
        // Validate input against a whitelist of allowed colors
        if (!color.matches("^[a-zA-Z0-9]+$")) {
            color = "white"; // Default safe value
        }
        
        // ok: java-cross-site-scripting-exp
        out.println("<div style='background-color:" + color + "'>Colored div</div>");
    }

    @GetMapping("/profile")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        String userComment = request.getParameter("comment");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ok: java-cross-site-scripting-exp
        out.println("<h1>User Profile: " + Encode.forHtml(userId) + "</h1>");
        out.println("<div class='comment'>" + Encode.forHtml(userComment) + "</div>");
        out.println("</body></html>");
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ok: java-cross-site-scripting-exp
        out.println("<h2>Search results for: " + StringEscapeUtils.escapeHtml4(searchTerm) + "</h2>");
        out.println("</body></html>");
    }

    @PostMapping("/feedback")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String feedback = request.getParameter("feedback");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting-exp
        out.println("<div class='alert'>Thanks for your feedback: " + Encode.forHtml(feedback) + "</div>");
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ok: java-cross-site-scripting-exp
        out.println("<div>Your browser: " + StringEscapeUtils.escapeHtml4(userAgent) + "</div>");
    }

    @RequestMapping("/error")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String errorMsg = request.getParameter("message");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ok: java-cross-site-scripting-exp
        out.println("<div class='error' onclick='logError()'>" + Encode.forHtmlContent(errorMsg) + "</div>");
        out.println("</body></html>");
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String redirectUrl = request.getParameter("redirect");
        PrintWriter out = response.getWriter();
        
        // Validate URL before using it
        if (!redirectUrl.startsWith("https://trusted-domain.com/")) {
            redirectUrl = "https://trusted-domain.com/";
        }
        
        // ok: java-cross-site-scripting-exp
        out.println("<a href='" + Encode.forHtmlAttribute(redirectUrl) + "'>Click here to continue</a>");
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String lastSearch = "";
        
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("lastSearch")) {
                    lastSearch = cookie.getValue();
                    break;
                }
            }
        }
        
        PrintWriter out = response.getWriter();
        // ok: java-cross-site-scripting-exp
        out.println("<div>Your last search was: " + StringEscapeUtils.escapeHtml4(lastSearch) + "</div>");
    }

    @GetMapping("/welcome")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        String title = request.getParameter("title");
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-exp
        out.println("<h1 title='" + Encode.forHtmlAttribute(title) + "'>Welcome, " + 
                    Encode.forHtml(name) + "!</h1>");
        out.println("</body></html>");
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Instead of allowing arbitrary JS, use a predefined set of options
        String jsOption = request.getParameter("jsOption");
        String customJs = "";
        
        if ("option1".equals(jsOption)) {
            customJs = "console.log('Option 1 selected');";
        } else if ("option2".equals(jsOption)) {
            customJs = "console.log('Option 2 selected');";
        } else {
            customJs = "console.log('Default option');";
        }
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-cross-site-scripting-exp
        out.println("<script>" + customJs + "</script>");
        out.println("</body></html>");
    }

    @RequestMapping("/image")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String imageUrl = request.getParameter("url");
        String altText = request.getParameter("alt");
        
        // Validate URL against whitelist
        if (!imageUrl.matches("^https://trusted-images\\.com/[a-zA-Z0-9/._-]+$")) {
            imageUrl = "https://trusted-images.com/default.jpg";
        }
        
        PrintWriter out = response.getWriter();
        // ok: java-cross-site-scripting-exp
        out.println("<img src='" + Encode.forHtmlAttribute(imageUrl) + 
                    "' alt='" + Encode.forHtmlAttribute(altText) + "'>");
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("data");
        PrintWriter out = response.getWriter();
        
        // Validate JSON structure and content before using
        try {
            // This is a simplified example - in real code, you would parse and validate the JSON
            if (!jsonData.matches("^\\{\"[a-zA-Z]+\":\"[a-zA-Z0-9 ]+\"\\}$")) {
                jsonData = "{}";
            }
            
            out.println("<html><body>");
            // ok: java-cross-site-scripting-exp
            out.println("<script>var appData = " + jsonData + ";</script>");
            out.println("</body></html>");
        } catch (Exception e) {
            // Handle invalid JSON
            out.println("<html><body><script>var appData = {};</script></body></html>");
        }
    }

    @PostMapping("/comment")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String commentText = request.getParameter("comment");
        
        PrintWriter out = response.getWriter();
        out.println("<div class='comment-container'>");
        out.println("<div class='comment-header'>Posted by: ");
        // ok: java-cross-site-scripting-exp
        out.println(Encode.forHtml(username));
        out.println("</div>");
        out.println("<div class='comment-body'>" + Encode.forHtml(commentText) + "</div>");
        out.println("</div>");
    }
}
// {/fact}