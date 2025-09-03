// Imports for all examples
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.MappedInterceptor;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter;
import org.apache.struts2.interceptor.TokenInterceptor;
import org.apache.struts2.interceptor.TokenSessionStoreInterceptor;
import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.interceptor.MethodFilterInterceptor;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.jboss.resteasy.core.ResourceMethodRegistry;
import org.jboss.resteasy.core.SynchronousDispatcher;
import org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.filter.CsrfProtectionFilter;
import org.glassfish.jersey.servlet.ServletContainer;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.protocol.http.WicketFilter;
import org.apache.wicket.request.cycle.RequestCycle;
import org.apache.wicket.request.http.WebRequest;
import org.apache.wicket.util.crypt.ICrypt;
import org.apache.wicket.util.crypt.Base64;
import org.apache.wicket.util.string.Strings;
import spark.Spark;
import spark.Filter;
import spark.Request;
import spark.Response;
import ratpack.server.RatpackServer;
import ratpack.handling.Handler;
import ratpack.handling.Context;
import ratpack.handling.Chain;
import io.javalin.Javalin;
import io.javalin.http.Handler;
import io.javalin.http.Context;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.CSRFHandler;
import io.vertx.ext.web.handler.BodyHandler;
import com.vaadin.flow.server.VaadinServlet;
import com.vaadin.flow.server.VaadinService;
import com.vaadin.flow.server.HandlerHelper;
import com.vaadin.flow.server.RequestHandler;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.server.VaadinResponse;
import com.vaadin.flow.server.VaadinSession;
import org.apache.tapestry5.http.services.RequestFilter;
import org.apache.tapestry5.http.services.RequestHandler;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.services.ComponentRequestHandler;
import org.apache.tapestry5.http.services.Response;
import play.mvc.Controller;
import play.mvc.Result;
import play.mvc.Http;
import play.mvc.Security;
import play.filters.csrf.CSRF;
import play.filters.csrf.CSRFFilter;
import play.filters.csrf.CSRFConfig;

// Security Issue: CSRF vulnerability in state-changing operations without proper protection

// True Positive Examples (Vulnerable/Insecure Code)

public class CsrfVulnerabilityExamples {
    
    // Spring MVC example without CSRF protection
    @Controller
    public static class bad_case_1 {
        // ruleid: java-coral-csrf
        @PostMapping("/update-profile")
        public ResponseEntity<String> updateProfile(HttpServletRequest request) {
            String username = request.getParameter("username");
            // Update user profile without CSRF token validation
            return ResponseEntity.ok("Profile updated");
        }
    }
    
    // JAX-RS (Jersey) example without CSRF protection
    @Path("/users")
    public static class bad_case_2 {
        // ruleid: java-coral-csrf
        @POST
        @Path("/update")
        @Consumes(MediaType.APPLICATION_JSON)
        public Response updateUser(User user) {
            // Update user in database without CSRF protection
            return Response.ok("User updated").build();
        }
    }
    
    // Servlet API example without CSRF protection
    @WebServlet("/delete-account")
    public static class bad_case_3 extends HttpServlet {
        @Override
        // ruleid: java-coral-csrf
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            String userId = req.getParameter("userId");
            // Delete user account without CSRF protection
            resp.getWriter().write("Account deleted");
        }
    }
    
    // Spark framework example without CSRF protection
    public static class bad_case_4 {
        public void setupRoutes() {
            // ruleid: java-coral-csrf
            Spark.post("/transfer-funds", (req, res) -> {
                String amount = req.queryParams("amount");
                String toAccount = req.queryParams("toAccount");
                // Transfer funds without CSRF protection
                return "Funds transferred";
            });
        }
    }
    
    // Javalin example without CSRF protection
    public static class bad_case_5 {
        public void configureApp() {
            Javalin app = Javalin.create();
            // ruleid: java-coral-csrf
            app.post("/change-password", ctx -> {
                String newPassword = ctx.formParam("password");
                // Change password without CSRF protection
                ctx.result("Password changed");
            });
        }
    }
    
    // Ratpack example without CSRF protection
    public static class bad_case_6 {
        public void setupServer() throws Exception {
            RatpackServer.start(server -> server
                .handlers(chain -> chain
                    // ruleid: java-coral-csrf
                    .post("submit-order", ctx -> {
                        String orderId = ctx.getRequest().getQueryParams().get("orderId");
                        // Process order without CSRF protection
                        ctx.render("Order submitted");
                    })
                )
            );
        }
    }
    
    // Vert.x example without CSRF protection
    public static class bad_case_7 {
        public void setupRouter() {
            Vertx vertx = Vertx.vertx();
            Router router = Router.router(vertx);
            
            router.route().handler(BodyHandler.create());
            
            // ruleid: java-coral-csrf
            router.post("/api/update-settings").handler(ctx -> {
                String settings = ctx.request().getParam("settings");
                // Update settings without CSRF protection
                ctx.response().end("Settings updated");
            });
        }
    }
    
    // Struts 2 example without CSRF protection
    public static class bad_case_8 extends ActionSupport {
        private String data;
        
        public String getData() { return data; }
        public void setData(String data) { this.data = data; }
        
        // ruleid: java-coral-csrf
        public String updateData() {
            // Update data without CSRF protection
            return SUCCESS;
        }
    }
    
    // Wicket example without CSRF protection
    public static class bad_case_9 extends WebApplication {
        @Override
        public void init() {
            // ruleid: java-coral-csrf
            mountPage("/admin/update", AdminUpdatePage.class);
            // No CSRF protection configured
        }
    }
    
    // RESTEasy example without CSRF protection
    @Path("/admin")
    public static class bad_case_10 {
        // ruleid: java-coral-csrf
        @POST
        @Path("/configure")
        public Response configureSystem(ConfigData data) {
            // Configure system without CSRF protection
            return Response.ok("System configured").build();
        }
    }
    
    // Vaadin example without CSRF protection
    public static class bad_case_11 extends VaadinServlet {
        @Override
        // ruleid: java-coral-csrf
        protected void service(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            if (request.getParameter("action").equals("delete")) {
                // Delete operation without CSRF protection
            }
            super.service(request, response);
        }
    }
    
    // Play Framework example without CSRF protection
    public static class bad_case_12 extends Controller {
        // ruleid: java-coral-csrf
        public Result updateSettings() {
            Map<String, String[]> formData = request().body().asFormUrlEncoded();
            // Update settings without CSRF protection
            return ok("Settings updated");
        }
    }
    
    // Tapestry example without CSRF protection
    public static class bad_case_13 implements RequestFilter {
        @Override
        // ruleid: java-coral-csrf
        public boolean service(Request request, Response response, RequestHandler handler) 
                throws IOException {
            if (request.getMethod().equals("POST") && request.getPath().contains("/admin/")) {
                // Process admin request without CSRF protection
                return true;
            }
            return handler.service(request, response);
        }
    }
    
    // Custom MVC framework example without CSRF protection
    public static class bad_case_14 {
        // ruleid: java-coral-csrf
        public void handlePostRequest(HttpServletRequest request, HttpServletResponse response) 
                throws IOException {
            if (request.getRequestURI().equals("/api/modify")) {
                // Modify data without CSRF protection
                response.getWriter().write("Data modified");
            }
        }
    }
    
    // Dropwizard example without CSRF protection
    @Path("/account")
    public static class bad_case_15 {
        // ruleid: java-coral-csrf
        @POST
        @Path("/close")
        public Response closeAccount(@FormParam("accountId") String accountId) {
            // Close account without CSRF protection
            return Response.ok("Account closed").build();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Spring MVC example with CSRF protection
    @Controller
    public static class good_case_1 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ok: java-coral-csrf
            http.csrf().and().authorizeRequests()
                .antMatchers("/update-profile").authenticated();
        }
        
        @PostMapping("/update-profile")
        public ResponseEntity<String> updateProfile(HttpServletRequest request) {
            String username = request.getParameter("username");
            // CSRF protection is enabled at the configuration level
            return ResponseEntity.ok("Profile updated");
        }
    }
    
    // JAX-RS (Jersey) example with CSRF protection
    public static class good_case_2 extends ResourceConfig {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
        public good_case_2() {
            // ok: java-coral-csrf
            register(CsrfProtectionFilter.class);
            packages("com.example.resources");
        }
        
        @Path("/users")
        public static class UserResource {
            @POST
            @Path("/update")
            @Consumes(MediaType.APPLICATION_JSON)
            public Response updateUser(User user) {
                // Protected by the registered CsrfProtectionFilter
                return Response.ok("User updated").build();
            }
        }
    }
// {/fact}
    
    // Servlet API example with CSRF protection filter
    public static class good_case_3 extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, 
                                        HttpServletResponse response, 
                                        FilterChain filterChain) throws ServletException, IOException {
            if ("POST".equals(request.getMethod())) {
                String csrfToken = request.getHeader("X-CSRF-TOKEN");
                String sessionToken = (String) request.getSession().getAttribute("csrf_token");
                
                // ok: java-coral-csrf
                if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF token validation failed");
                    return;
                }
            }
            filterChain.doFilter(request, response);
        }
    }
    
    // Spark framework example with CSRF protection
    public static class good_case_4 {
        public void setupRoutes() {
            // CSRF protection filter
            // ok: java-coral-csrf
            Spark.before((request, response) -> {
                if ("POST".equals(request.requestMethod())) {
                    String csrfToken = request.headers("X-CSRF-TOKEN");
                    String sessionToken = request.session().attribute("csrf_token");
                    
                    if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                        Spark.halt(403, "CSRF token validation failed");
                    }
                }
            });
            
            Spark.post("/transfer-funds", (req, res) -> {
                // Protected by the CSRF filter above
                String amount = req.queryParams("amount");
                String toAccount = req.queryParams("toAccount");
                return "Funds transferred";
            });
        }
    }
    
    // Javalin example with CSRF protection
    public static class good_case_5 {
        public void configureApp() {
            Javalin app = Javalin.create();
            
            // ok: java-coral-csrf
            app.before(ctx -> {
                if (ctx.method().equals("POST")) {
                    String csrfToken = ctx.header("X-CSRF-TOKEN");
                    String sessionToken = ctx.sessionAttribute("csrf_token");
                    
                    if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                        ctx.status(403).result("CSRF token validation failed");
                        ctx.req.setAttribute("skip-request", true);
                    }
                }
            });
            
            app.post("/change-password", ctx -> {
                if (ctx.req.getAttribute("skip-request") != null) {
                    return;
                }
                String newPassword = ctx.formParam("password");
                ctx.result("Password changed");
            });
        }
    }
    
    // Ratpack example with CSRF protection
    public static class good_case_6 {
        public void setupServer() throws Exception {
            RatpackServer.start(server -> server
                .handlers(chain -> {
                    // ok: java-coral-csrf
                    chain.all(ctx -> {
                        if (ctx.getRequest().getMethod().isPost()) {
                            String csrfToken = ctx.getRequest().getHeaders().get("X-CSRF-TOKEN");
                            String sessionToken = ctx.getRequest().get(String.class, "csrf_token");
                            
                            if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                                ctx.getResponse().status(403).send("CSRF token validation failed");
                                return;
                            }
                        }
                        ctx.next();
                    });
                    
                    chain.post("submit-order", ctx -> {
                        String orderId = ctx.getRequest().getQueryParams().get("orderId");
                        // Protected by the CSRF handler above
                        ctx.render("Order submitted");
                    });
                })
            );
        }
    }
    
    // Vert.x example with CSRF protection
    public static class good_case_7 {
        public void setupRouter() {
            Vertx vertx = Vertx.vertx();
            Router router = Router.router(vertx);
            
            router.route().handler(BodyHandler.create());
            
            // ok: java-coral-csrf
            router.route().handler(CSRFHandler.create("secret-key"));
            
            router.post("/api/update-settings").handler(ctx -> {
                String settings = ctx.request().getParam("settings");
                // Protected by the CSRF handler above
                ctx.response().end("Settings updated");
            });
        }
    }
    
    // Struts 2 example with CSRF protection
    public static class good_case_8 {
        public void configureInterceptors() {
            // ok: java-coral-csrf
            interceptorStack.add(new TokenSessionStoreInterceptor());
            
            // Action is protected by the TokenSessionStoreInterceptor
            actionConfig.addInterceptor(interceptorStack);
        }
        
        public static class ProtectedAction extends ActionSupport {
            public String updateData() {
                // Protected by TokenSessionStoreInterceptor
                return SUCCESS;
            }
        }
    }
    
    // Wicket example with CSRF protection
    public static class good_case_9 extends WebApplication {
        @Override
        public void init() {
            // ok: java-coral-csrf
            getSecuritySettings().setCryptFactory(new CsrfProtectionCryptFactory());
            
            mountPage("/admin/update", AdminUpdatePage.class);
        }
        
        private static class CsrfProtectionCryptFactory implements ICryptFactory {
            @Override
            public ICrypt newCrypt() {
                return new CsrfProtectingCrypt();
            }
        }
    }
    
    // RESTEasy example with CSRF protection
    public static class good_case_10 {
        public void configureResteasy() {
            ResteasyProviderFactory factory = ResteasyProviderFactory.getInstance();
            
            // ok: java-coral-csrf
            factory.registerProvider(CsrfProtectionFilter.class);
            
            // All resources will be protected by the CSRF filter
        }
        
        @Path("/admin")
        public static class AdminResource {
            @POST
            @Path("/configure")
            public Response configureSystem(ConfigData data) {
                // Protected by the registered CSRF filter
                return Response.ok("System configured").build();
            }
        }
    }
    
    // Vaadin example with CSRF protection
    public static class good_case_11 implements RequestHandler {
        @Override
        public boolean handleRequest(VaadinSession session, VaadinRequest request, VaadinResponse response) 
                throws IOException {
            // ok: java-coral-csrf
            if (request.getMethod().equals("POST")) {
                String csrfToken = request.getHeader("X-CSRF-TOKEN");
                String sessionToken = session.getAttribute("csrf_token").toString();
                
                if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF token validation failed");
                    return true;
                }
            }
            return false; // Continue processing
        }
    }
    
    // Play Framework example with CSRF protection
    public static class good_case_12 extends Controller {
        // ok: java-coral-csrf
        @Security.Authenticated(CSRFCheck.class)
        public Result updateSettings() {
            Map<String, String[]> formData = request().body().asFormUrlEncoded();
            // Protected by the CSRFCheck security annotation
            return ok("Settings updated");
        }
        
        public static class CSRFCheck extends Security.Authenticator {
            @Override
            public String getUsername(Http.Context ctx) {
                if (!CSRF.requireCSRFCheck(ctx.request())) {
                    return null;
                }
                return "user"; // Continue processing
            }
        }
    }
    
    // Tapestry example with CSRF protection
    public static class good_case_13 implements RequestFilter {
        @Override
        public boolean service(Request request, Response response, RequestHandler handler) 
                throws IOException {
            // ok: java-coral-csrf
            if (request.getMethod().equals("POST")) {
                String csrfToken = request.getHeader("X-CSRF-TOKEN");
                String sessionToken = request.getSession(true).getAttribute("csrf_token").toString();
                
                if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                    response.sendError(403, "CSRF token validation failed");
                    return true;
                }
            }
            return handler.service(request, response);
        }
    }
    
    // Custom MVC framework example with CSRF protection
    public static class good_case_14 {
        // ok: java-coral-csrf
        public void handlePostRequest(HttpServletRequest request, HttpServletResponse response) 
                throws IOException {
            if (request.getMethod().equals("POST")) {
                String csrfToken = request.getHeader("X-CSRF-TOKEN");
                String sessionToken = (String) request.getSession().getAttribute("csrf_token");
                
                if (csrfToken == null || !csrfToken.equals(sessionToken)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF token validation failed");
                    return;
                }
            }
            
            if (request.getRequestURI().equals("/api/modify")) {
                // Protected by CSRF check above
                response.getWriter().write("Data modified");
            }
        }
    }
    
    // Dropwizard example with CSRF protection
    public static class good_case_15 {
        public void configure(Environment environment) {
            // ok: java-coral-csrf
            environment.jersey().register(new CsrfProtectionFilter());
        }
        
        @Path("/account")
        public static class AccountResource {
            @POST
            @Path("/close")
            public Response closeAccount(@FormParam("accountId") String accountId) {
                // Protected by the registered CSRF filter
                return Response.ok("Account closed").build();
            }
        }
    }
}