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
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.ui.Model;

public class CrossSiteScriptingExamples {

    // True Positive Examples (Vulnerable Code)

    @WebServlet("/bad1")
    public class bad_case_1 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String userInput = request.getParameter("username");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<div>Welcome, " + userInput + "!</div>");
        }
    }

    @WebServlet("/bad2")
    public class bad_case_2 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String comment = request.getParameter("comment");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            out.println("<html><body>");
            // ruleid: java-cross-site-scripting-ide
            out.println("<div class='comment'>" + comment + "</div>");
            out.println("</body></html>");
        }
    }

    @Controller
    public class bad_case_3 {
        @GetMapping("/profile")
        @ResponseBody
        public String showProfile(HttpServletRequest request) {
            String userId = request.getParameter("id");
            // ruleid: java-cross-site-scripting-ide
            return "<h1>User Profile</h1><div>ID: " + userId + "</div>";
        }
    }

    @WebServlet("/bad4")
    public class bad_case_4 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String searchTerm = request.getParameter("q");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            out.println("<html><head><title>Search Results</title></head><body>");
            // ruleid: java-cross-site-scripting-ide
            out.println("<h1>Search results for: " + searchTerm + "</h1>");
            out.println("</body></html>");
        }
    }

    @Controller
    public class bad_case_5 {
        @PostMapping("/feedback")
        @ResponseBody
        public String processFeedback(@RequestParam String feedback) {
            // ruleid: java-cross-site-scripting-ide
            return "<div class='alert alert-success'>Thanks for your feedback: " + feedback + "</div>";
        }
    }

    @WebServlet("/bad6")
    public class bad_case_6 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String referer = request.getHeader("Referer");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<div>You came from: " + referer + "</div>");
        }
    }

    @Controller
    public class bad_case_7 {
        @GetMapping("/error")
        @ResponseBody
        public String showError(HttpServletRequest request) {
            String errorMsg = request.getParameter("message");
            StringBuilder html = new StringBuilder();
            html.append("<html><body>");
            // ruleid: java-cross-site-scripting-ide
            html.append("<div class='error'>" + errorMsg + "</div>");
            html.append("</body></html>");
            return html.toString();
        }
    }

    @WebServlet("/bad8")
    public class bad_case_8 extends HttpServlet {
        @Override
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
            
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<div style='background-color:" + userTheme + "'>Content</div>");
        }
    }

    @Controller
    public class bad_case_9 {
        @GetMapping("/user/{username}")
        @ResponseBody
        public String getUserProfile(@PathVariable String username) {
            // ruleid: java-cross-site-scripting-ide
            return "<h1>Profile for " + username + "</h1><div>User details go here</div>";
        }
    }

    @WebServlet("/bad10")
    public class bad_case_10 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String email = request.getParameter("email");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<script>var userEmail = '" + email + "';</script>");
        }
    }

    @Controller
    public class bad_case_11 {
        @GetMapping("/search")
        @ResponseBody
        public String search(@RequestParam String query, @RequestHeader("User-Agent") String userAgent) {
            StringBuilder result = new StringBuilder();
            result.append("<html><body>");
            result.append("<h1>Search Results</h1>");
            // ruleid: java-cross-site-scripting-ide
            result.append("<div>You searched for: " + query + "</div>");
            // ruleid: java-cross-site-scripting-ide
            result.append("<div>Your browser: " + userAgent + "</div>");
            result.append("</body></html>");
            return result.toString();
        }
    }

    @WebServlet("/bad12")
    public class bad_case_12 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String lang = request.getParameter("lang");
            if (lang == null) {
                lang = "en";
            }
            
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<html lang='" + lang + "'><body>Content</body></html>");
        }
    }

    @Controller
    public class bad_case_13 {
        @PostMapping("/comment")
        @ResponseBody
        public String addComment(HttpServletRequest request) {
            String name = request.getParameter("name");
            String comment = request.getParameter("comment");
            
            StringBuilder html = new StringBuilder();
            html.append("<div class='comment-added'>");
            // ruleid: java-cross-site-scripting-ide
            html.append("<p>From: " + name + "</p>");
            // ruleid: java-cross-site-scripting-ide
            html.append("<p>" + comment + "</p>");
            html.append("</div>");
            
            return html.toString();
        }
    }

    @WebServlet("/bad14")
    public class bad_case_14 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String redirectUrl = request.getParameter("redirect");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ruleid: java-cross-site-scripting-ide
            out.println("<a href='" + redirectUrl + "'>Click here to continue</a>");
        }
    }

    @Controller
    public class bad_case_15 {
        @GetMapping("/widget")
        @ResponseBody
        public String getWidget(HttpServletRequest request) {
            String widgetId = request.getParameter("id");
            String widgetColor = request.getParameter("color");
            
            StringBuilder html = new StringBuilder();
            html.append("<div class='widget'>");
            // ruleid: java-cross-site-scripting-ide
            html.append("<div id='" + widgetId + "' style='color:" + widgetColor + "'>Widget Content</div>");
            html.append("</div>");
            
            return html.toString();
        }
    }

    // True Negative Examples (Safe Code)

    @WebServlet("/good1")
    public class good_case_1 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String userInput = request.getParameter("username");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ok: java-cross-site-scripting-ide
            out.println("<div>Welcome, " + Encode.forHtml(userInput) + "!</div>");
        }
    }

    @WebServlet("/good2")
    public class good_case_2 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String comment = request.getParameter("comment");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            out.println("<html><body>");
            // ok: java-cross-site-scripting-ide
            out.println("<div class='comment'>" + StringEscapeUtils.escapeHtml4(comment) + "</div>");
            out.println("</body></html>");
        }
    }

    @Controller
    public class good_case_3 {
        @GetMapping("/profile")
        @ResponseBody
        public String showProfile(HttpServletRequest request) {
            String userId = request.getParameter("id");
            // ok: java-cross-site-scripting-ide
            return "<h1>User Profile</h1><div>ID: " + Encode.forHtml(userId) + "</div>";
        }
    }

    @WebServlet("/good4")
    public class good_case_4 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String searchTerm = request.getParameter("q");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            out.println("<html><head><title>Search Results</title></head><body>");
            // ok: java-cross-site-scripting-ide
            out.println("<h1>Search results for: " + StringEscapeUtils.escapeHtml4(searchTerm) + "</h1>");
            out.println("</body></html>");
        }
    }

    @Controller
    public class good_case_5 {
        @PostMapping("/feedback")
        public String processFeedback(@RequestParam String feedback, Model model) {
            // ok: java-cross-site-scripting-ide
            model.addAttribute("feedback", feedback);
            return "feedback-success"; // Using a template engine that automatically escapes output
        }
    }

    @WebServlet("/good6")
    public class good_case_6 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String referer = request.getHeader("Referer");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ok: java-cross-site-scripting-ide
            out.println("<div>You came from: " + Encode.forHtml(referer) + "</div>");
        }
    }

    @Controller
    public class good_case_7 {
        @GetMapping("/error")
        @ResponseBody
        public String showError(HttpServletRequest request) {
            String errorMsg = request.getParameter("message");
            StringBuilder html = new StringBuilder();
            html.append("<html><body>");
            // ok: java-cross-site-scripting-ide
            html.append("<div class='error'>" + StringEscapeUtils.escapeHtml4(errorMsg) + "</div>");
            html.append("</body></html>");
            return html.toString();
        }
    }

    @WebServlet("/good8")
    public class good_case_8 extends HttpServlet {
        @Override
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
            
            // Validate the theme against a whitelist of allowed values
            String[] allowedThemes = {"light", "dark", "blue", "green"};
            boolean validTheme = false;
            for (String theme : allowedThemes) {
                if (theme.equals(userTheme)) {
                    validTheme = true;
                    break;
                }
            }
            
            if (!validTheme) {
                userTheme = "light"; // Default theme
            }
            
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ok: java-cross-site-scripting-ide
            out.println("<div style='background-color:" + userTheme + "'>Content</div>");
        }
    }

    @Controller
    public class good_case_9 {
        @GetMapping("/user/{username}")
        @ResponseBody
        public String getUserProfile(@PathVariable String username) {
            // ok: java-cross-site-scripting-ide
            return "<h1>Profile for " + Encode.forHtml(username) + "</h1><div>User details go here</div>";
        }
    }

    @WebServlet("/good10")
    public class good_case_10 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String email = request.getParameter("email");
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ok: java-cross-site-scripting-ide
            out.println("<script>var userEmail = '" + Encode.forJavaScript(email) + "';</script>");
        }
    }

    @Controller
    public class good_case_11 {
        @GetMapping("/search")
        @ResponseBody
        public String search(@RequestParam String query, @RequestHeader("User-Agent") String userAgent) {
            StringBuilder result = new StringBuilder();
            result.append("<html><body>");
            result.append("<h1>Search Results</h1>");
            // ok: java-cross-site-scripting-ide
            result.append("<div>You searched for: " + StringEscapeUtils.escapeHtml4(query) + "</div>");
            // ok: java-cross-site-scripting-ide
            result.append("<div>Your browser: " + StringEscapeUtils.escapeHtml4(userAgent) + "</div>");
            result.append("</body></html>");
            return result.toString();
        }
    }

    @WebServlet("/good12")
    public class good_case_12 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String lang = request.getParameter("lang");
            
            // Validate language code against a whitelist
            String[] validLangs = {"en", "es", "fr", "de", "it", "ja", "zh"};
            boolean isValid = false;
            
            if (lang != null) {
                for (String validLang : validLangs) {
                    if (validLang.equals(lang)) {
                        isValid = true;
                        break;
                    }
                }
            }
            
            if (!isValid) {
                lang = "en"; // Default to English if invalid
            }
            
            PrintWriter out = response.getWriter();
            response.setContentType("text/html");
            
            // ok: java-cross-site-scripting-ide
            out.println("<html lang='" + lang + "'><body>Content</body></html>");
        }
    }

    @Controller
    public class good_case_13 {
        @PostMapping("/comment")
        @ResponseBody
        public String addComment(HttpServletRequest request) {
            String name = request.getParameter("name");
            String comment = request.getParameter("comment");
            
            StringBuilder html = new StringBuilder();
            html.append("<div class='comment-added'>");
            // ok: java-cross-site-scripting-ide
            html.append("<p>From: " + Encode.forHtml(name) + "</p>");
            // ok: java-cross-site-scripting-ide
            html.append("<p>" + Encode.forHtml(comment) + "</p>");
            html.append("</div>");
            
            return html.toString();
        }
    }

    @WebServlet("/good14")
    public class good_case_14 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String redirectUrl = request.getParameter("redirect");
            
            // Validate URL to prevent XSS and open redirect
            if (redirectUrl != null && !redirectUrl.startsWith("http:") && !redirectUrl.startsWith("https:") && !redirectUrl.startsWith("javascript:")) {
                // Only allow relative URLs within our site
                PrintWriter out = response.getWriter();
                response.setContentType("text/html");
                
                // ok: java-cross-site-scripting-ide
                out.println("<a href='" + Encode.forHtmlAttribute(redirectUrl) + "'>Click here to continue</a>");
            } else {
                // Default redirect if invalid
                response.sendRedirect("/home");
            }
        }
    }

    @Controller
    public class good_case_15 {
        @GetMapping("/widget")
        @ResponseBody
        public String getWidget(HttpServletRequest request) {
            String widgetId = request.getParameter("id");
            String widgetColor = request.getParameter("color");
            
            // Validate color against a whitelist
            String[] validColors = {"red", "blue", "green", "black", "white"};
            boolean validColor = false;
            
            for (String color : validColors) {
                if (color.equals(widgetColor)) {
                    validColor = true;
                    break;
                }
            }
            
            if (!validColor) {
                widgetColor = "black"; // Default color
            }
            
            StringBuilder html = new StringBuilder();
            html.append("<div class='widget'>");
            // ok: java-cross-site-scripting-ide
            html.append("<div id='" + Encode.forHtmlAttribute(widgetId) + "' style='color:" + widgetColor + "'>Widget Content</div>");
            html.append("</div>");
            
            return html.toString();
        }
    }
}