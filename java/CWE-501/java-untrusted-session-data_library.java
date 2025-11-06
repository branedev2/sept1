import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.ServletException;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.interceptor.ServletRequestAware;
import com.opensymphony.xwork2.ActionSupport;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import io.javalin.http.Context;
import io.javalin.Javalin;
import spark.Request;
import spark.Response;
import spark.Spark;
import org.apache.wicket.request.Request;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.protocol.http.servlet.ServletWebRequest;
import org.apache.wicket.protocol.http.WebSession;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.VaadinSession;
import org.glassfish.jersey.server.ContainerRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import ratpack.handling.Context;
import ratpack.handling.Handler;
import ratpack.server.RatpackServer;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.annotation.Controller as MicronautController;
import io.micronaut.http.annotation.Get;
import io.quarkus.vertx.web.Route;
import io.vertx.ext.web.RoutingContext;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import java.util.regex.Pattern;
import org.owasp.encoder.Encode;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import java.util.HashMap;
import java.util.Map;

// Security Issue: User input is used directly in setAttribute to modify the session, which could lead to a trust boundary violation.

// True Positive Examples (Vulnerable/Insecure Code)

public class UntrustedSessionDataExamples {

    // Standard Servlet API
// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();
        String userRole = request.getParameter("role");
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("userRole", userRole);
    }

    // Spring MVC Framework
    @Controller
    public class bad_case_2 {
        @PostMapping("/profile")
        public String updateProfile(@RequestParam String theme) {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            HttpSession session = request.getSession();
            
            // ruleid: java-untrusted-session-data
            session.setAttribute("userTheme", theme);
            
            return "profile";
        }
    }

    // Jakarta EE 9+ Servlet API
    public void bad_case_3(jakarta.servlet.http.HttpServletRequest request) {
        jakarta.servlet.http.HttpSession session = request.getSession();
        String preferredLanguage = request.getParameter("language");
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("language", preferredLanguage);
    }

    // Apache Struts 2
    public class bad_case_4 extends ActionSupport implements ServletRequestAware {
        private HttpServletRequest request;
        private String displayName;
        
        public String execute() {
            HttpSession session = request.getSession();
            
            // ruleid: java-untrusted-session-data
            session.setAttribute("displayName", displayName);
            
            return SUCCESS;
        }
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }
    }

    // Play Framework
    public class bad_case_5 extends Controller {
        public Result setUserPreferences() {
            String timezone = Http.Context.current().request().getQueryString("timezone");
            Http.Session session = Http.Context.current().session();
            
            // ruleid: java-untrusted-session-data
            session.put("userTimezone", timezone);
            
            return ok("Preferences updated");
        }
    }

    // Javalin Framework
    public void bad_case_6() {
        Javalin app = Javalin.create().start(7000);
        
        app.post("/settings", ctx -> {
            String fontStyle = ctx.formParam("fontStyle");
            
            // ruleid: java-untrusted-session-data
            ctx.sessionAttribute("fontStyle", fontStyle);
        });
    }

    // Spark Framework
    public void bad_case_7() {
        Spark.post("/account", (Request request, Response response) -> {
            String accountType = request.queryParams("accountType");
            
            // ruleid: java-untrusted-session-data
            request.session().attribute("accountType", accountType);
            
            return "Account updated";
        });
    }

    // Apache Wicket
    public void bad_case_8() {
        Request request = RequestCycle.get().getRequest();
        if (request instanceof ServletWebRequest) {
            String userCountry = request.getRequestParameters().getParameterValue("country").toString();
            WebSession session = WebSession.get();
            
            // ruleid: java-untrusted-session-data
            session.setAttribute("country", userCountry);
        }
    }

    // Vaadin Framework
    public void bad_case_9() {
        VaadinRequest request = VaadinService.getCurrentRequest();
        String colorScheme = request.getParameter("colorScheme");
        VaadinSession session = VaadinSession.getCurrent();
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("colorScheme", colorScheme);
    }

    // Jersey (JAX-RS)
    @Path("/user")
    public class bad_case_10 {
        @GET
        @Path("/preferences")
        public String setPreferences(@Context ContainerRequest request) {
            String notificationSetting = request.getUriInfo().getQueryParameters().getFirst("notifications");
            HttpSession session = request.getProperty("session");
            
            // ruleid: java-untrusted-session-data
            session.setAttribute("notificationSetting", notificationSetting);
            
            return "Preferences updated";
        }
    }

    // Ratpack Framework
    public void bad_case_11() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .post("settings", ctx -> {
                    ctx.getRequest().getBody().then(body -> {
                        String jsonBody = body.getText();
                        String fontSize = jsonBody.split("fontSize\":\"")[1].split("\"")[0];
                        
                        // ruleid: java-untrusted-session-data
                        ctx.getRequest().getSession().set("fontSize", fontSize);
                        
                        ctx.render("Settings updated");
                    });
                })
            )
        );
    }

    // Micronaut Framework
    @MicronautController("/api")
    public class bad_case_12 {
        @Get("/settings")
        public String updateSettings(HttpRequest<?> request) {
            String currency = request.getParameters().get("currency");
            
            // ruleid: java-untrusted-session-data
            request.getSession().put("preferredCurrency", currency);
            
            return "Settings updated";
        }
    }

    // Quarkus with Vert.x Web
    public class bad_case_13 {
        @Route(path = "/profile", methods = Route.HttpMethod.POST)
        void updateProfile(RoutingContext rc) {
            String avatar = rc.request().getParam("avatar");
            
            // ruleid: java-untrusted-session-data
            rc.session().put("userAvatar", avatar);
            
            rc.response().end("Profile updated");
        }
    }

    // Spring WebFlux
    public class bad_case_14 {
        public Mono<Void> handleRequest(ServerRequest request, ServerWebExchange exchange) {
            return request.formData()
                .flatMap(formData -> {
                    String userStatus = formData.getFirst("status");
                    return exchange.getSession()
                        .flatMap(session -> {
                            // ruleid: java-untrusted-session-data
                            session.getAttributes().put("userStatus", userStatus);
                            return Mono.empty();
                        });
                });
        }
    }

    // GWT RequestFactory
    public void bad_case_15(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String accessLevel = request.getHeader("X-Access-Level");
        
        // ruleid: java-untrusted-session-data
        session.setAttribute("accessLevel", accessLevel);
    }

    // True Negative Examples (Safe/Secure Code)

    // Standard Servlet API with validation
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        HttpSession session = request.getSession();
        String userRole = request.getParameter("role");
        
        // Validate against a whitelist of allowed roles
        String[] allowedRoles = {"user", "editor", "admin"};
        boolean isValidRole = false;
        for (String role : allowedRoles) {
            if (role.equals(userRole)) {
                isValidRole = true;
                break;
            }
        }
        
        if (isValidRole) {
            // ok: java-untrusted-session-data
            session.setAttribute("userRole", userRole);
        } else {
            // Default to lowest privilege if invalid
            session.setAttribute("userRole", "user");
        }
    }

    // Spring MVC Framework with sanitization
    @Controller
    public class good_case_2 {
        @PostMapping("/profile")
        public String updateProfile(@RequestParam String theme) {
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            HttpSession session = request.getSession();
            
            // Sanitize the theme value
            String sanitizedTheme = StringEscapeUtils.escapeHtml4(theme);
            
            // ok: java-untrusted-session-data
            session.setAttribute("userTheme", sanitizedTheme);
            
            return "profile";
        }
    }

    // Jakarta EE 9+ Servlet API with pattern matching
    public void good_case_3(jakarta.servlet.http.HttpServletRequest request) {
        jakarta.servlet.http.HttpSession session = request.getSession();
        String preferredLanguage = request.getParameter("language");
        
        // Validate language code format (e.g., en-US, fr-FR)
        Pattern languagePattern = Pattern.compile("^[a-z]{2}-[A-Z]{2}$");
        if (languagePattern.matcher(preferredLanguage).matches()) {
            // ok: java-untrusted-session-data
            session.setAttribute("language", preferredLanguage);
        } else {
            // Default to English if invalid format
            session.setAttribute("language", "en-US");
        }
    }

    // Apache Struts 2 with validation
    public class good_case_4 extends ActionSupport implements ServletRequestAware {
        private HttpServletRequest request;
        private String displayName;
        
        public String execute() {
            HttpSession session = request.getSession();
            
            // Validate display name (no special chars, reasonable length)
            if (displayName != null && displayName.matches("^[a-zA-Z0-9_\\s]{3,20}$")) {
                // ok: java-untrusted-session-data
                session.setAttribute("displayName", displayName);
            } else {
                addActionError("Invalid display name");
            }
            
            return SUCCESS;
        }
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }
    }

    // Play Framework with validation
    public class good_case_5 extends Controller {
        public Result setUserPreferences() {
            String timezone = Http.Context.current().request().getQueryString("timezone");
            Http.Session session = Http.Context.current().session();
            
            // Validate timezone format
            if (timezone != null && timezone.matches("^[A-Za-z_/]+$")) {
                // ok: java-untrusted-session-data
                session.put("userTimezone", timezone);
                return ok("Preferences updated");
            } else {
                return badRequest("Invalid timezone format");
            }
        }
    }

    // Javalin Framework with sanitization
    public void good_case_6() {
        Javalin app = Javalin.create().start(7000);
        
        app.post("/settings", ctx -> {
            String fontStyle = ctx.formParam("fontStyle");
            
            // Sanitize and validate font style
            String sanitizedFontStyle = Encode.forHtml(fontStyle);
            String[] allowedFonts = {"serif", "sans-serif", "monospace", "cursive", "fantasy"};
            
            boolean isValidFont = false;
            for (String font : allowedFonts) {
                if (font.equals(sanitizedFontStyle)) {
                    isValidFont = true;
                    break;
                }
            }
            
            if (isValidFont) {
                // ok: java-untrusted-session-data
                ctx.sessionAttribute("fontStyle", sanitizedFontStyle);
                ctx.result("Font style updated");
            } else {
                ctx.result("Invalid font style");
            }
        });
    }

    // Spark Framework with validation
    public void good_case_7() {
        Spark.post("/account", (Request request, Response response) -> {
            String accountType = request.queryParams("accountType");
            
            // Validate account type
            Map<String, Boolean> validAccountTypes = new HashMap<>();
            validAccountTypes.put("personal", true);
            validAccountTypes.put("business", true);
            validAccountTypes.put("enterprise", true);
            
            if (validAccountTypes.containsKey(accountType)) {
                // ok: java-untrusted-session-data
                request.session().attribute("accountType", accountType);
                return "Account updated";
            } else {
                response.status(400);
                return "Invalid account type";
            }
        });
    }

    // Apache Wicket with validation
    public void good_case_8() {
        Request request = RequestCycle.get().getRequest();
        if (request instanceof ServletWebRequest) {
            String userCountry = request.getRequestParameters().getParameterValue("country").toString();
            WebSession session = WebSession.get();
            
            // Validate country code (ISO 3166-1 alpha-2)
            if (userCountry != null && userCountry.matches("^[A-Z]{2}$")) {
                // ok: java-untrusted-session-data
                session.setAttribute("country", userCountry);
            } else {
                // Default to US if invalid
                session.setAttribute("country", "US");
            }
        }
    }

    // Vaadin Framework with validation
    public void good_case_9() {
        VaadinRequest request = VaadinService.getCurrentRequest();
        String colorScheme = request.getParameter("colorScheme");
        VaadinSession session = VaadinSession.getCurrent();
        
        // Validate color scheme
        String[] validSchemes = {"light", "dark", "system", "high-contrast"};
        boolean isValidScheme = false;
        
        for (String scheme : validSchemes) {
            if (scheme.equals(colorScheme)) {
                isValidScheme = true;
                break;
            }
        }
        
        if (isValidScheme) {
            // ok: java-untrusted-session-data
            session.setAttribute("colorScheme", colorScheme);
        } else {
            // Default to system if invalid
            session.setAttribute("colorScheme", "system");
        }
    }

    // Jersey (JAX-RS) with validation
    @Path("/user")
    public class good_case_10 {
        @GET
        @Path("/preferences")
        public String setPreferences(@Context ContainerRequest request) {
            String notificationSetting = request.getUriInfo().getQueryParameters().getFirst("notifications");
            HttpSession session = request.getProperty("session");
            
            // Validate notification setting
            if ("enabled".equals(notificationSetting) || "disabled".equals(notificationSetting)) {
                // ok: java-untrusted-session-data
                session.setAttribute("notificationSetting", notificationSetting);
                return "Preferences updated";
            } else {
                return "Invalid notification setting";
            }
        }
    }

    // Ratpack Framework with validation
    public void good_case_11() throws Exception {
        RatpackServer.start(server -> server
            .handlers(chain -> chain
                .post("settings", ctx -> {
                    ctx.getRequest().getBody().then(body -> {
                        String jsonBody = body.getText();
                        String fontSize = jsonBody.split("fontSize\":\"")[1].split("\"")[0];
                        
                        // Validate font size
                        if (fontSize != null && fontSize.matches("^(small|medium|large|x-large)$")) {
                            // ok: java-untrusted-session-data
                            ctx.getRequest().getSession().set("fontSize", fontSize);
                            ctx.render("Settings updated");
                        } else {
                            ctx.render("Invalid font size");
                        }
                    });
                })
            )
        );
    }

    // Micronaut Framework with validation
    @MicronautController("/api")
    public class good_case_12 {
        @Get("/settings")
        public String updateSettings(HttpRequest<?> request) {
            String currency = request.getParameters().get("currency");
            
            // Validate currency code (ISO 4217)
            if (currency != null && currency.matches("^[A-Z]{3}$")) {
                // ok: java-untrusted-session-data
                request.getSession().put("preferredCurrency", currency);
                return "Settings updated";
            } else {
                return "Invalid currency code";
            }
        }
    }

    // Quarkus with Vert.x Web and validation
    public class good_case_13 {
        @Route(path = "/profile", methods = Route.HttpMethod.POST)
        void updateProfile(RoutingContext rc) {
            String avatar = rc.request().getParam("avatar");
            
            // Validate avatar URL (simple check for demonstration)
            if (avatar != null && avatar.startsWith("https://") && avatar.endsWith(".png")) {
                // ok: java-untrusted-session-data
                rc.session().put("userAvatar", avatar);
                rc.response().end("Profile updated");
            } else {
                rc.response().setStatusCode(400).end("Invalid avatar URL");
            }
        }
    }

    // Spring WebFlux with validation
    public class good_case_14 {
        public Mono<Void> handleRequest(ServerRequest request, ServerWebExchange exchange) {
            return request.formData()
                .flatMap(formData -> {
                    String userStatus = formData.getFirst("status");
                    
                    // Validate status
                    String[] validStatuses = {"online", "away", "busy", "offline"};
                    boolean isValidStatus = false;
                    
                    for (String status : validStatuses) {
                        if (status.equals(userStatus)) {
                            isValidStatus = true;
                            break;
                        }
                    }
                    
                    return exchange.getSession()
                        .flatMap(session -> {
                            if (isValidStatus) {
                                // ok: java-untrusted-session-data
                                session.getAttributes().put("userStatus", userStatus);
                            } else {
                                // Default to offline if invalid
                                session.getAttributes().put("userStatus", "offline");
                            }
                            return Mono.empty();
                        });
                });
        }
    }

    // GWT RequestFactory with validation
    public void good_case_15(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String accessLevel = request.getHeader("X-Access-Level");
        
        // Validate access level
        if ("read".equals(accessLevel) || "write".equals(accessLevel) || "admin".equals(accessLevel)) {
            // ok: java-untrusted-session-data
            session.setAttribute("accessLevel", accessLevel);
        } else {
            // Default to lowest privilege if invalid
            session.setAttribute("accessLevel", "read");
        }
    }
}
// {/fact}