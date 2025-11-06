import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import java.net.URL;
import org.apache.catalina.connector.Response;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import jakarta.servlet.http.*;

// True Positive Examples (Vulnerable Code)

@Controller
public class URLRewritingExamples {

    // Example 1: Basic URL rewriting with encodeURL
// {fact rule=sensitive-information-leak@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // Create a hyperlink with session ID embedded in URL
        String url = "/dashboard";
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(url);
        
        out.println("<a href='" + encodedURL + "'>Dashboard</a>");
    }

    // Example 2: URL rewriting with encodeRedirectURL
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String targetURL = "/profile";
        
        // ruleid: java-url-rewriting
        String encodedRedirectURL = response.encodeRedirectURL(targetURL);
        response.sendRedirect(encodedRedirectURL);
    }

    // Example 3: URL rewriting in a form action
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String formAction = "/submit";
        // ruleid: java-url-rewriting
        String encodedFormAction = response.encodeURL(formAction);
        
        out.println("<form action='" + encodedFormAction + "' method='post'>");
        out.println("  <input type='submit' value='Submit'>");
        out.println("</form>");
    }

    // Example 4: URL rewriting with complex URL
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String url = "/products?category=electronics&sort=price";
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(url);
        
        out.println("<a href='" + encodedURL + "'>View Products</a>");
    }

    // Example 5: URL rewriting with dynamic URL construction
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getParameter("id");
        String baseUrl = "/user/profile?id=" + userId;
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(baseUrl);
        response.sendRedirect(encodedURL);
    }

    // Example 6: URL rewriting with encodeURL in a loop
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String[] pages = {"home", "products", "about", "contact"};
        
        for (String page : pages) {
            String url = "/" + page;
            // ruleid: java-url-rewriting
            String encodedURL = response.encodeURL(url);
            out.println("<a href='" + encodedURL + "'>" + page + "</a><br>");
        }
    }

    // Example 7: URL rewriting with conditional logic
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String userType = request.getParameter("type");
        String targetUrl;
        
        if ("admin".equals(userType)) {
            targetUrl = "/admin/dashboard";
        } else {
            targetUrl = "/user/dashboard";
        }
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(targetUrl);
        out.println("<a href='" + encodedURL + "'>Go to Dashboard</a>");
    }

    // Example 8: URL rewriting with string concatenation
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String baseUrl = "/reports";
        String reportId = request.getParameter("id");
        String fullUrl = baseUrl + "?id=" + reportId;
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(fullUrl);
        response.sendRedirect(encodedURL);
    }

    // Example 9: URL rewriting with Jakarta servlet response
    public void bad_case_9(jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) throws IOException {
        String url = "/dashboard";
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(url);
        response.sendRedirect(encodedURL);
    }

    // Example 10: URL rewriting with variable assignment
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String url = "/checkout";
        String encodedURL;
        
        // ruleid: java-url-rewriting
        encodedURL = response.encodeURL(url);
        out.println("<a href='" + encodedURL + "'>Proceed to Checkout</a>");
    }

    // Example 11: URL rewriting with method chaining
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String targetUrl = "/login";
        
        // ruleid: java-url-rewriting
        response.sendRedirect(response.encodeRedirectURL(targetUrl));
    }

    // Example 12: URL rewriting with try-catch
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        try {
            String url = "/secure/data";
            // ruleid: java-url-rewriting
            String encodedURL = response.encodeURL(url);
            response.sendRedirect(encodedURL);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Example 13: URL rewriting with Tomcat Response
    public void bad_case_13(HttpServletRequest request, Response response) throws IOException {
        String url = "/dashboard";
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(url);
        response.sendRedirect(encodedURL);
    }

    // Example 14: URL rewriting with multiple parameters
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String baseUrl = "/search";
        String query = request.getParameter("q");
        String category = request.getParameter("cat");
        
        String fullUrl = baseUrl + "?q=" + query + "&cat=" + category;
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(fullUrl);
        response.sendRedirect(encodedURL);
    }

    // Example 15: URL rewriting with encodeURL in a helper method
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String url = "/account";
        
        // ruleid: java-url-rewriting
        String encodedURL = response.encodeURL(url);
        out.println("<a href='" + encodedURL + "'>My Account</a>");
    }

    // True Negative Examples (Safe Code)

    // Example 1: Using direct URL without encoding
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // ok: java-url-rewriting
        String url = "/dashboard";
        out.println("<a href='" + url + "'>Dashboard</a>");
    }

    // Example 2: Using cookies for session management
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-url-rewriting
        HttpSession session = request.getSession();
        session.setAttribute("user", "john");
        
        response.sendRedirect("/dashboard");
    }

    // Example 3: Using direct redirect without URL encoding
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-url-rewriting
        response.sendRedirect("/profile");
    }

    // Example 4: Using form submission without URL encoding
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // ok: java-url-rewriting
        out.println("<form action='/submit' method='post'>");
        out.println("  <input type='submit' value='Submit'>");
        out.println("</form>");
    }

    // Example 5: Using token-based authentication
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = generateAuthToken(request.getParameter("username"));
        
        // ok: java-url-rewriting
        response.setContentType("application/json");
        response.getWriter().write("{\"token\":\"" + token + "\"}");
    }

    // Example 6: Using direct URLs in a loop
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String[] pages = {"home", "products", "about", "contact"};
        
        // ok: java-url-rewriting
        for (String page : pages) {
            String url = "/" + page;
            out.println("<a href='" + url + "'>" + page + "</a><br>");
        }
    }

    // Example 7: Using JWT for authentication
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jwt = createJWT(request.getParameter("username"));
        
        // ok: java-url-rewriting
        response.setHeader("Authorization", "Bearer " + jwt);
        response.sendRedirect("/dashboard");
    }

    // Example 8: Using direct URL with parameters
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String reportId = request.getParameter("id");
        
        // ok: java-url-rewriting
        String url = "/reports?id=" + reportId;
        response.sendRedirect(url);
    }

    // Example 9: Using session attributes instead of URL rewriting
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-url-rewriting
        HttpSession session = request.getSession();
        session.setAttribute("reportId", request.getParameter("id"));
        
        response.sendRedirect("/reports");
    }

    // Example 10: Using POST form with hidden fields
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        String userId = request.getParameter("id");
        
        // ok: java-url-rewriting
        out.println("<form action='/user/profile' method='post'>");
        out.println("  <input type='hidden' name='id' value='" + userId + "'>");
        out.println("  <input type='submit' value='View Profile'>");
        out.println("</form>");
    }

    // Example 11: Using direct URL with query parameters
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        String category = request.getParameter("cat");
        
        // ok: java-url-rewriting
        String url = "/search?q=" + query + "&cat=" + category;
        response.sendRedirect(url);
    }

    // Example 12: Using OAuth for authentication
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-url-rewriting
        String authorizationUrl = "https://oauth-provider.com/auth?client_id=client123&redirect_uri=https://myapp.com/callback";
        response.sendRedirect(authorizationUrl);
    }

    // Example 13: Using AJAX for data loading
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // ok: java-url-rewriting
        out.println("<script>");
        out.println("  fetch('/api/data').then(response => response.json()).then(data => {");
        out.println("    document.getElementById('content').innerHTML = data.html;");
        out.println("  });");
        out.println("</script>");
    }

    // Example 14: Using Spring Security for authentication
    @GetMapping("/secure")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-url-rewriting
        // Spring Security handles authentication without URL rewriting
        response.sendRedirect("/dashboard");
    }

    // Example 15: Using stateless REST API
    @GetMapping("/api/user/{id}")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response, @PathVariable String id) throws IOException {
        // ok: java-url-rewriting
        // RESTful API doesn't need session tracking in URL
        response.setContentType("application/json");
        response.getWriter().write("{\"id\":\"" + id + "\",\"name\":\"John Doe\"}");
    }

    // Helper method for good_case_5
    private String generateAuthToken(String username) {
        // Implementation of token generation
        return "auth_token_" + username + "_" + System.currentTimeMillis();
    }

    // Helper method for good_case_7
    private String createJWT(String username) {
        // Implementation of JWT creation
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." + username;
    }
}
// {/fact}