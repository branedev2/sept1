import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.ServletActionContext;
import org.springframework.stereotype.Controller;
import play.mvc.Http;
import spark.Request;
import io.javalin.http.Context;
import io.micronaut.http.HttpRequest;
import io.vertx.ext.web.RoutingContext;
import ratpack.handling.Context;
import com.vaadin.flow.server.VaadinRequest;
import org.jooby.Request;
import org.apache.wicket.request.Request;
import com.gargoylesoftware.htmlunit.WebRequest;
import org.glassfish.jersey.server.ContainerRequest;

// Security Issue: Null dereference when using getParameter() without null check

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
    // ruleid: java-null-dereference
    String username = request.getParameter("username");
    int usernameLength = username.length(); // Potential NPE if username parameter is not provided
}

public void bad_case_2() {
    // Using Spring MVC request
    @Controller
    class UserController {
        @GetMapping("/user")
        public String getUser(HttpServletRequest request) {
            // ruleid: java-null-dereference
            String userId = request.getParameter("id");
            return "User ID: " + userId.trim(); // Potential NPE
        }
    }
}

public void bad_case_3() {
    // Using Apache Struts
    public class LoginAction {
        public String execute() {
            HttpServletRequest request = ServletActionContext.getRequest();
            // ruleid: java-null-dereference
            String password = request.getParameter("password");
            if (password.equals("admin")) { // Potential NPE
                return "success";
            }
            return "failure";
        }
    }
}

public void bad_case_4() {
    // Using Play Framework
    public class UserController extends play.mvc.Controller {
        public play.mvc.Result login(Http.Request request) {
            // ruleid: java-null-dereference
            String email = request.getQueryString("email");
            return ok("Email domain: " + email.split("@")[1]); // Potential NPE
        }
    }
}

public void bad_case_5() {
    // Using Spark Java
    public void setupRoutes() {
        spark.Spark.get("/profile", (Request request, spark.Response response) -> {
            // ruleid: java-null-dereference
            String profileId = request.queryParams("id");
            return "Loading profile: " + profileId.toLowerCase(); // Potential NPE
        });
    }
}

public void bad_case_6() {
    // Using Javalin
    public void configureRoutes(io.javalin.Javalin app) {
        app.get("/api/data", ctx -> {
            // ruleid: java-null-dereference
            String dataType = ctx.queryParam("type");
            ctx.result("Data type: " + dataType.toUpperCase()); // Potential NPE
        });
    }
}

public void bad_case_7() {
    // Using Micronaut
    public class ProductController {
        public String getProduct(HttpRequest<?> request) {
            // ruleid: java-null-dereference
            String productId = request.getParameters().get("id");
            return "Product ID hash: " + productId.hashCode(); // Potential NPE
        }
    }
}

public void bad_case_8() {
    // Using Vert.x
    public void handleRequest(io.vertx.ext.web.RoutingContext context) {
        // ruleid: java-null-dereference
        String action = context.request().getParam("action");
        if (action.startsWith("save")) { // Potential NPE
            // Save operation
        }
    }
}

public void bad_case_9() {
    // Using Ratpack
    public void handleRequest(ratpack.handling.Context ctx) {
        // ruleid: java-null-dereference
        String token = ctx.getRequest().getQueryParams().get("token");
        ctx.render("Token validation: " + token.substring(0, 10)); // Potential NPE
    }
}

public void bad_case_10() {
    // Using Vaadin
    public class MainView extends com.vaadin.flow.component.orderedlayout.VerticalLayout {
        public MainView(VaadinRequest request) {
            // ruleid: java-null-dereference
            String theme = request.getParameter("theme");
            setTheme(theme.toLowerCase()); // Potential NPE
        }
        
        private void setTheme(String theme) {
            // Theme setting logic
        }
    }
}

public void bad_case_11() {
    // Using Jooby
    public class ApiController {
        public String handleRequest(org.jooby.Request req) {
            // ruleid: java-null-dereference
            String format = req.param("format").value();
            return "Format: " + format.toUpperCase(); // Potential NPE
        }
    }
}

public void bad_case_12() {
    // Using Apache Wicket
    public class HomePage extends org.apache.wicket.markup.html.WebPage {
        public void onInitialize() {
            super.onInitialize();
            org.apache.wicket.request.Request request = getRequest();
            // ruleid: java-null-dereference
            String locale = request.getQueryParameters().getParameterValue("locale").toString();
            setLocale(new java.util.Locale(locale)); // Potential NPE
        }
    }
}

public void bad_case_13() {
    // Using HtmlUnit
    public void processWebRequest(com.gargoylesoftware.htmlunit.WebRequest webRequest) {
        // ruleid: java-null-dereference
        String referrer = webRequest.getAdditionalHeaders().get("Referer");
        System.out.println("Request from: " + referrer.substring(0, 20)); // Potential NPE
    }
}

public void bad_case_14() {
    // Using Jersey
    public class ResourceHandler {
        public void handleRequest(org.glassfish.jersey.server.ContainerRequest request) {
            // ruleid: java-null-dereference
            String authHeader = request.getHeaderString("Authorization");
            String token = authHeader.replace("Bearer ", ""); // Potential NPE
            validateToken(token);
        }
        
        private void validateToken(String token) {
            // Token validation logic
        }
    }
}

public void bad_case_15() {
    // Using Apache Tomcat
    public class CustomServlet extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) {
            // ruleid: java-null-dereference
            String callback = request.getParameter("callback");
            response.getWriter().write(callback + "(" + getJsonData() + ")"); // Potential NPE
        }
        
        private String getJsonData() {
            return "{\"status\":\"success\"}";
        }
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
    // ok: java-null-dereference
    String username = request.getParameter("username");
    if (username != null) {
        int usernameLength = username.length();
    } else {
        // Handle null case
    }
}

public void good_case_2() {
    // Using Spring MVC request with null check
    @Controller
    class UserController {
        @GetMapping("/user")
        public String getUser(HttpServletRequest request) {
            // ok: java-null-dereference
            String userId = request.getParameter("id");
            if (userId != null) {
                return "User ID: " + userId.trim();
            } else {
                return "User ID not provided";
            }
        }
    }
}

public void good_case_3() {
    // Using Apache Struts with null check
    public class LoginAction {
        public String execute() {
            HttpServletRequest request = ServletActionContext.getRequest();
            // ok: java-null-dereference
            String password = request.getParameter("password");
            if (password != null && password.equals("admin")) {
                return "success";
            }
            return "failure";
        }
    }
}

public void good_case_4() {
    // Using Play Framework with null check
    public class UserController extends play.mvc.Controller {
        public play.mvc.Result login(Http.Request request) {
            // ok: java-null-dereference
            String email = request.getQueryString("email");
            if (email != null && email.contains("@")) {
                return ok("Email domain: " + email.split("@")[1]);
            } else {
                return badRequest("Invalid email");
            }
        }
    }
}

public void good_case_5() {
    // Using Spark Java with null check
    public void setupRoutes() {
        spark.Spark.get("/profile", (Request request, spark.Response response) -> {
            // ok: java-null-dereference
            String profileId = request.queryParams("id");
            if (profileId != null) {
                return "Loading profile: " + profileId.toLowerCase();
            } else {
                return "Profile ID required";
            }
        });
    }
}

public void good_case_6() {
    // Using Javalin with null check
    public void configureRoutes(io.javalin.Javalin app) {
        app.get("/api/data", ctx -> {
            // ok: java-null-dereference
            String dataType = ctx.queryParam("type");
            if (dataType != null) {
                ctx.result("Data type: " + dataType.toUpperCase());
            } else {
                ctx.result("Data type not specified");
            }
        });
    }
}

public void good_case_7() {
    // Using Micronaut with null check
    public class ProductController {
        public String getProduct(HttpRequest<?> request) {
            // ok: java-null-dereference
            String productId = request.getParameters().get("id");
            if (productId != null) {
                return "Product ID hash: " + productId.hashCode();
            } else {
                return "Product ID not provided";
            }
        }
    }
}

public void good_case_8() {
    // Using Vert.x with null check
    public void handleRequest(io.vertx.ext.web.RoutingContext context) {
        // ok: java-null-dereference
        String action = context.request().getParam("action");
        if (action != null && action.startsWith("save")) {
            // Save operation
        } else {
            // Handle null or invalid action
        }
    }
}

public void good_case_9() {
    // Using Ratpack with null check
    public void handleRequest(ratpack.handling.Context ctx) {
        // ok: java-null-dereference
        String token = ctx.getRequest().getQueryParams().get("token");
        if (token != null && token.length() >= 10) {
            ctx.render("Token validation: " + token.substring(0, 10));
        } else {
            ctx.render("Invalid token");
        }
    }
}

public void good_case_10() {
    // Using Vaadin with null check
    public class MainView extends com.vaadin.flow.component.orderedlayout.VerticalLayout {
        public MainView(VaadinRequest request) {
            // ok: java-null-dereference
            String theme = request.getParameter("theme");
            if (theme != null) {
                setTheme(theme.toLowerCase());
            } else {
                setTheme("default");
            }
        }
        
        private void setTheme(String theme) {
            // Theme setting logic
        }
    }
}

public void good_case_11() {
    // Using Jooby with null check
    public class ApiController {
        public String handleRequest(org.jooby.Request req) {
            // ok: java-null-dereference
            String format = req.param("format").value("json"); // Default value provided
            return "Format: " + format.toUpperCase();
        }
    }
}

public void good_case_12() {
    // Using Apache Wicket with null check
    public class HomePage extends org.apache.wicket.markup.html.WebPage {
        public void onInitialize() {
            super.onInitialize();
            org.apache.wicket.request.Request request = getRequest();
            // ok: java-null-dereference
            String locale = request.getQueryParameters().getParameterValue("locale").toString("en");
            setLocale(new java.util.Locale(locale));
        }
    }
}

public void good_case_13() {
    // Using HtmlUnit with null check
    public void processWebRequest(com.gargoylesoftware.htmlunit.WebRequest webRequest) {
        // ok: java-null-dereference
        String referrer = webRequest.getAdditionalHeaders().get("Referer");
        if (referrer != null) {
            System.out.println("Request from: " + referrer.substring(0, Math.min(referrer.length(), 20)));
        } else {
            System.out.println("No referrer");
        }
    }
}

public void good_case_14() {
    // Using Jersey with null check
    public class ResourceHandler {
        public void handleRequest(org.glassfish.jersey.server.ContainerRequest request) {
            // ok: java-null-dereference
            String authHeader = request.getHeaderString("Authorization");
            if (authHeader != null) {
                String token = authHeader.replace("Bearer ", "");
                validateToken(token);
            } else {
                // Handle missing authorization
            }
        }
        
        private void validateToken(String token) {
            // Token validation logic
        }
    }
}

public void good_case_15() {
    // Using Apache Tomcat with null check
    public class CustomServlet extends javax.servlet.http.HttpServlet {
        protected void doGet(HttpServletRequest request, HttpServletResponse response) {
            // ok: java-null-dereference
            String callback = request.getParameter("callback");
            if (callback != null) {
                response.getWriter().write(callback + "(" + getJsonData() + ")");
            } else {
                response.getWriter().write(getJsonData());
            }
        }
        
        private String getJsonData() {
            return "{\"status\":\"success\"}";
        }
    }
}