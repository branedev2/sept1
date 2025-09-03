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
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

public class XSSVulnerabilityExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("username");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div>Welcome, " + userInput + "!</div>");
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<h3>Search results for: " + searchTerm + "</h3>");
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorMsg = request.getParameter("error");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div class='error'>" + errorMsg + "</div>");
        out.println("</body></html>");
    }
    
    @WebServlet("/comment")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String comment = request.getParameter("comment");
        String username = request.getParameter("user");
        PrintWriter out = response.getWriter();
        
        out.println("<div class='comment'>");
        // ruleid: java-reflectedcrosssitescripting
        out.println("<p>" + comment + "</p>");
        out.println("<p>Posted by: " + username + "</p>");
        out.println("</div>");
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div>Your browser: " + userAgent + "</div>");
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ruleid: java-reflectedcrosssitescripting
        out.println("<p>You came from: " + referer + "</p>");
        out.println("</body></html>");
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div>Last visit: " + lastVisit + "</div>");
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String url = request.getRequestURL().toString();
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<a href='" + url + "'>Refresh</a>");
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String message = request.getParameter("message");
        String color = request.getParameter("color");
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div style='color:" + color + "'>" + message + "</div>");
        out.println("</body></html>");
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<input type='hidden' id='userId' value='" + id + "'>");
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String query = request.getQueryString();
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<p>Query parameters: " + query + "</p>");
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String title = request.getParameter("title");
        String content = request.getParameter("content");
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ruleid: java-reflectedcrosssitescripting
        out.println("<h1>" + title + "</h1>");
        out.println("<div>" + content + "</div>");
        out.println("</body></html>");
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String language = request.getParameter("lang");
        PrintWriter out = response.getWriter();
        
        // ruleid: java-reflectedcrosssitescripting
        out.println("<script>var userLanguage = '" + language + "';</script>");
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("user");
        String userInput = "Welcome, " + username;
        
        PrintWriter out = response.getWriter();
        // ruleid: java-reflectedcrosssitescripting
        out.println("<div>" + userInput + "</div>");
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        StringBuilder htmlBuilder = new StringBuilder();
        String name = request.getParameter("name");
        
        htmlBuilder.append("<html><body>");
        // ruleid: java-reflectedcrosssitescripting
        htmlBuilder.append("<h2>Hello, ").append(name).append("!</h2>");
        htmlBuilder.append("</body></html>");
        
        PrintWriter out = response.getWriter();
        out.println(htmlBuilder.toString());
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userInput = request.getParameter("username");
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<div>Welcome, " + Encode.forHtml(userInput) + "!</div>");
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchTerm = request.getParameter("q");
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<h3>Search results for: " + StringEscapeUtils.escapeHtml4(searchTerm) + "</h3>");
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String errorMsg = request.getParameter("error");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ok: java-reflectedcrosssitescripting
        out.println("<div class='error'>" + Jsoup.clean(errorMsg, Safelist.basic()) + "</div>");
        out.println("</body></html>");
    }
    
    @WebServlet("/comment")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String comment = request.getParameter("comment");
        String username = request.getParameter("user");
        PrintWriter out = response.getWriter();
        
        out.println("<div class='comment'>");
        // ok: java-reflectedcrosssitescripting
        out.println("<p>" + Encode.forHtml(comment) + "</p>");
        out.println("<p>Posted by: " + Encode.forHtml(username) + "</p>");
        out.println("</div>");
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<div>Your browser: " + StringEscapeUtils.escapeHtml4(userAgent) + "</div>");
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String referer = request.getHeader("Referer");
        PrintWriter out = response.getWriter();
        
        out.println("<html><body>");
        // ok: java-reflectedcrosssitescripting
        out.println("<p>You came from: " + Encode.forHtml(referer) + "</p>");
        out.println("</body></html>");
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
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
        // ok: java-reflectedcrosssitescripting
        out.println("<div>Last visit: " + StringEscapeUtils.escapeHtml4(lastVisit) + "</div>");
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String url = request.getRequestURL().toString();
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<a href='" + Encode.forHtmlAttribute(url) + "'>Refresh</a>");
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String message = request.getParameter("message");
        String color = request.getParameter("color");
        
        // Validate color using a whitelist
        Pattern colorPattern = Pattern.compile("^[a-zA-Z]+$|^#[0-9a-fA-F]{6}$");
        if (!colorPattern.matcher(color).matches()) {
            color = "black"; // Default safe value
        }
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-reflectedcrosssitescripting
        out.println("<div style='color:" + color + "'>" + Encode.forHtml(message) + "</div>");
        out.println("</body></html>");
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<input type='hidden' id='userId' value='" + Encode.forHtmlAttribute(id) + "'>");
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String query = request.getQueryString();
        PrintWriter out = response.getWriter();
        
        // ok: java-reflectedcrosssitescripting
        out.println("<p>Query parameters: " + StringEscapeUtils.escapeHtml4(query) + "</p>");
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String title = request.getParameter("title");
        String content = request.getParameter("content");
        
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        // ok: java-reflectedcrosssitescripting
        out.println("<h1>" + Encode.forHtml(title) + "</h1>");
        out.println("<div>" + Jsoup.clean(content, Safelist.basic()) + "</div>");
        out.println("</body></html>");
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String language = request.getParameter("lang");
        
        // Validate language using a whitelist
        Pattern langPattern = Pattern.compile("^[a-z]{2}(-[A-Z]{2})?$");
        if (!langPattern.matcher(language).matches()) {
            language = "en"; // Default safe value
        }
        
        PrintWriter out = response.getWriter();
        // ok: java-reflectedcrosssitescripting
        out.println("<script>var userLanguage = '" + language + "';</script>");
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("user");
        
        // Sanitize input using a custom function
        username = sanitizeInput(username);
        
        String userInput = "Welcome, " + username;
        
        PrintWriter out = response.getWriter();
        // ok: java-reflectedcrosssitescripting
        out.println("<div>" + userInput + "</div>");
    }
    
    private String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }
        // Remove all HTML tags and encode special characters
        return StringEscapeUtils.escapeHtml4(input.replaceAll("<[^>]*>", ""));
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        StringBuilder htmlBuilder = new StringBuilder();
        String name = request.getParameter("name");
        
        htmlBuilder.append("<html><body>");
        // ok: java-reflectedcrosssitescripting
        htmlBuilder.append("<h2>Hello, ").append(Encode.forHtml(name)).append("!</h2>");
        htmlBuilder.append("</body></html>");
        
        PrintWriter out = response.getWriter();
        out.println(htmlBuilder.toString());
    }
}
// {/fact}