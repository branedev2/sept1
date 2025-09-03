import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.PermitAll;
import play.mvc.Result;
import play.mvc.Controller;
import play.mvc.Security;
import spark.Request;
import spark.Response;
import spark.Route;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.core.security.AccessManager;
import io.javalin.core.security.Role;
import io.micronaut.http.annotation.*;
import io.micronaut.security.annotation.Secured;
import io.micronaut.http.HttpResponse;
import ratpack.handling.Handler;
import ratpack.handling.Context;
import ratpack.http.Request;
import ratpack.http.Response;
import com.vaadin.flow.server.VaadinRequest;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.server.VaadinSession;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.struts2.convention.annotation.Action;
import org.apache.struts2.convention.annotation.Result;
import com.opensymphony.xwork2.ActionSupport;
import ninja.Result;
import ninja.Results;
import ninja.Context;
import ninja.FilterWith;
import ninja.SecureFilter;
import com.google.inject.Inject;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.sparkjava.SparkWebContext;
import org.pac4j.sparkjava.SecurityFilter;
import org.pac4j.core.config.Config;

// Security Issue: Lack of access control checks allows unauthorized users to access sensitive data or perform unintended actions

// True Positive Examples (Vulnerable/Insecure Code)

public class UnauthenticatedHorizontalAccessControlExamples {

    // Spring MVC example without access control
    @Controller
    public class bad_case_1 {
        @GetMapping("/api/users/{userId}/profile")
        public ResponseEntity<String> getUserProfile(@PathVariable Long userId, HttpServletRequest request) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return ResponseEntity.ok("User profile for ID: " + userId);
            // No authentication or authorization check to verify the requesting user
            // has permission to access this user's profile
        }
    }

    // JAX-RS example without access control
    @Path("/accounts")
    public class bad_case_2 {
        @GET
        @Path("/{accountId}/transactions")
        @Produces("application/json")
        public Response getTransactions(@PathParam("accountId") String accountId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return Response.ok("Transactions for account: " + accountId).build();
            // No verification that the requesting user owns this account or has permission
        }
    }

    // Play Framework example without access control
    public class bad_case_3 extends play.mvc.Controller {
        public Result getDocument(Long documentId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return ok("Document content for ID: " + documentId);
            // No verification that the requesting user has permission to access this document
        }
    }

    // Spark Java example without access control
    public class bad_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/orders/:orderId", (req, res) -> {
                String orderId = req.params("orderId");
                // ruleid: java-unauthenticatedhorizontecontrollerrule
                return "Order details for ID: " + orderId;
                // No verification that the requesting user placed this order or has permission
            });
        }
    }

    // Javalin example without access control
    public class bad_case_5 {
        public void configureRoutes(Javalin app) {
            app.get("/medical-records/:patientId", ctx -> {
                String patientId = ctx.pathParam("patientId");
                // ruleid: java-unauthenticatedhorizontecontrollerrule
                ctx.result("Medical records for patient: " + patientId);
                // No verification that the requesting user is the patient or authorized medical staff
            });
        }
    }

    // Micronaut example without access control
    @Controller("/api/payments")
    public class bad_case_6 {
        @Get("/{paymentId}")
        public HttpResponse<String> getPaymentDetails(String paymentId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return HttpResponse.ok("Payment details for: " + paymentId);
            // No verification that the requesting user is authorized to view this payment
        }
    }

    // Ratpack example without access control
    public class bad_case_7 implements ratpack.handling.Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String userId = ctx.getPathTokens().get("userId");
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            ctx.render("User data for: " + userId);
            // No verification that the requesting user has permission to access this user's data
        }
    }

    // Vaadin example without access control
    @com.vaadin.flow.router.Route("user-settings/:userId")
    public class bad_case_8 extends UI {
        @Override
        protected void init(VaadinRequest request) {
            String userId = request.getParameter("userId");
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            showUserSettings(userId);
            // No verification that the requesting user has permission to access these settings
        }
        
        private void showUserSettings(String userId) {
            // Display user settings
        }
    }

    // Shiro example without access control
    @Controller
    public class bad_case_9 {
        @GetMapping("/api/files/{fileId}")
        public ResponseEntity<String> getFile(@PathVariable String fileId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return ResponseEntity.ok("File content for: " + fileId);
            // No verification using Shiro that the user has permission to access this file
        }
    }

    // Struts example without access control
    public class bad_case_10 extends ActionSupport {
        private String noteId;
        
        public void setNoteId(String noteId) {
            this.noteId = noteId;
        }
        
        @Action(value="/notes/view", results={@Result(name="success", location="/notes.jsp")})
        public String viewNote() {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return "success";
            // No verification that the requesting user has permission to view this note
        }
    }

    // Ninja Framework example without access control
    public class bad_case_11 {
        public Result getInvoice(Context context, String invoiceId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return Results.html().render("invoice", "Invoice #" + invoiceId);
            // No verification that the requesting user has permission to view this invoice
        }
    }

    // Servlet API example without access control
    public class bad_case_12 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String employeeId = request.getParameter("employeeId");
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            response.getWriter().write("Employee data for: " + employeeId);
            // No verification that the requesting user has permission to view this employee's data
        }
    }

    // Pac4j with Spark example without access control
    public class bad_case_13 {
        public void setupRoutes() {
            spark.Spark.get("/credit-score/:userId", (req, res) -> {
                String userId = req.params("userId");
                // ruleid: java-unauthenticatedhorizontecontrollerrule
                return "Credit score for user: " + userId;
                // No verification that the requesting user has permission to view this credit score
            });
        }
    }

    // Spring WebFlux example without access control
    @Controller
    public class bad_case_14 {
        @GetMapping("/api/messages/{conversationId}")
        public ResponseEntity<String> getConversation(@PathVariable String conversationId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return ResponseEntity.ok("Messages for conversation: " + conversationId);
            // No verification that the requesting user is a participant in this conversation
        }
    }

    // Dropwizard example without access control
    @Path("/subscriptions")
    public class bad_case_15 {
        @GET
        @Path("/{subscriptionId}")
        public Response getSubscription(@PathParam("subscriptionId") String subscriptionId) {
            // ruleid: java-unauthenticatedhorizontecontrollerrule
            return Response.ok("Subscription details for: " + subscriptionId).build();
            // No verification that the requesting user owns this subscription
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring MVC example with proper access control
    @Controller
    public class good_case_1 {
        @GetMapping("/api/users/{userId}/profile")
        public ResponseEntity<String> getUserProfile(@PathVariable Long userId, HttpServletRequest request) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Long currentUserId = ((UserDetails) authentication.getPrincipal()).getUserId();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!currentUserId.equals(userId) && !hasAdminRole(authentication)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
            }
            
            return ResponseEntity.ok("User profile for ID: " + userId);
        }
        
        private boolean hasAdminRole(Authentication authentication) {
            return authentication.getAuthorities().stream()
                .anyMatch(r -> r.getAuthority().equals("ROLE_ADMIN"));
        }
    }

    // JAX-RS example with proper access control
    @Path("/accounts")
    public class good_case_2 {
        @GET
        @Path("/{accountId}/transactions")
        @Produces("application/json")
        public Response getTransactions(@PathParam("accountId") String accountId, @Context SecurityContext securityContext) {
            String username = securityContext.getUserPrincipal().getName();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!isUserAuthorizedForAccount(username, accountId)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access denied").build();
            }
            
            return Response.ok("Transactions for account: " + accountId).build();
        }
        
        private boolean isUserAuthorizedForAccount(String username, String accountId) {
            // Implementation to check if user owns this account or has admin rights
            return true; // Simplified for example
        }
    }

    // Play Framework example with proper access control
    public class good_case_3 extends play.mvc.Controller {
        @Security.Authenticated(Secured.class)
        public Result getDocument(Long documentId) {
            String username = session("username");
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!DocumentPermissionService.canUserAccessDocument(username, documentId)) {
                return forbidden("You don't have permission to access this document");
            }
            
            return ok("Document content for ID: " + documentId);
        }
    }

    // Spark Java example with proper access control
    public class good_case_4 {
        public void setupRoutes() {
            spark.Spark.get("/orders/:orderId", (req, res) -> {
                String orderId = req.params("orderId");
                String userId = getUserIdFromSession(req);
                
                // ok: java-unauthenticatedhorizontecontrollerrule
                if (!isUserAuthorizedForOrder(userId, orderId)) {
                    res.status(403);
                    return "Access denied";
                }
                
                return "Order details for ID: " + orderId;
            });
        }
        
        private String getUserIdFromSession(spark.Request req) {
            return req.session().attribute("userId");
        }
        
        private boolean isUserAuthorizedForOrder(String userId, String orderId) {
            // Implementation to check if user placed this order or has admin rights
            return true; // Simplified for example
        }
    }

    // Javalin example with proper access control
    public class good_case_5 {
        public void configureRoutes(Javalin app) {
            app.get("/medical-records/:patientId", ctx -> {
                String patientId = ctx.pathParam("patientId");
                String currentUserId = ctx.sessionAttribute("userId");
                String userRole = ctx.sessionAttribute("role");
                
                // ok: java-unauthenticatedhorizontecontrollerrule
                if (!patientId.equals(currentUserId) && !"MEDICAL_STAFF".equals(userRole)) {
                    ctx.status(403).result("Access denied");
                    return;
                }
                
                ctx.result("Medical records for patient: " + patientId);
            });
        }
    }

    // Micronaut example with proper access control
    @Controller("/api/payments")
    public class good_case_6 {
        @Get("/{paymentId}")
        @Secured("isAuthenticated()")
        public HttpResponse<String> getPaymentDetails(String paymentId, Authentication authentication) {
            String username = authentication.getName();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!paymentService.isUserAuthorizedForPayment(username, paymentId)) {
                return HttpResponse.unauthorized();
            }
            
            return HttpResponse.ok("Payment details for: " + paymentId);
        }
        
        private PaymentService paymentService = new PaymentService();
        
        private class PaymentService {
            public boolean isUserAuthorizedForPayment(String username, String paymentId) {
                // Implementation to check if user is authorized for this payment
                return true; // Simplified for example
            }
        }
    }

    // Ratpack example with proper access control
    public class good_case_7 implements ratpack.handling.Handler {
        @Override
        public void handle(ratpack.handling.Context ctx) {
            String userId = ctx.getPathTokens().get("userId");
            String currentUser = ctx.getRequest().getHeaders().get("X-User-Id");
            String userRole = ctx.getRequest().getHeaders().get("X-User-Role");
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!userId.equals(currentUser) && !"ADMIN".equals(userRole)) {
                ctx.getResponse().status(403).send("Access denied");
                return;
            }
            
            ctx.render("User data for: " + userId);
        }
    }

    // Vaadin example with proper access control
    @com.vaadin.flow.router.Route("user-settings/:userId")
    public class good_case_8 extends UI {
        @Override
        protected void init(VaadinRequest request) {
            String userId = request.getParameter("userId");
            String currentUser = getCurrentUser();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!userId.equals(currentUser) && !isAdmin()) {
                showAccessDenied();
                return;
            }
            
            showUserSettings(userId);
        }
        
        private String getCurrentUser() {
            return VaadinSession.getCurrent().getAttribute("userId").toString();
        }
        
        private boolean isAdmin() {
            return "ADMIN".equals(VaadinSession.getCurrent().getAttribute("role"));
        }
        
        private void showUserSettings(String userId) {
            // Display user settings
        }
        
        private void showAccessDenied() {
            // Show access denied message
        }
    }

    // Shiro example with proper access control
    @Controller
    public class good_case_9 {
        @GetMapping("/api/files/{fileId}")
        public ResponseEntity<String> getFile(@PathVariable String fileId) {
            Subject currentUser = SecurityUtils.getSubject();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!currentUser.isPermitted("file:read:" + fileId)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
            }
            
            return ResponseEntity.ok("File content for: " + fileId);
        }
    }

    // Struts example with proper access control
    public class good_case_10 extends ActionSupport {
        private String noteId;
        
        public void setNoteId(String noteId) {
            this.noteId = noteId;
        }
        
        @Action(value="/notes/view", results={@Result(name="success", location="/notes.jsp"), @Result(name="error", location="/access-denied.jsp")})
        public String viewNote() {
            String currentUser = getCurrentUser();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!isUserAuthorizedForNote(currentUser, noteId)) {
                return "error";
            }
            
            return "success";
        }
        
        private String getCurrentUser() {
            // Get current user from session
            return "user123"; // Simplified for example
        }
        
        private boolean isUserAuthorizedForNote(String user, String noteId) {
            // Implementation to check if user has permission to view this note
            return true; // Simplified for example
        }
    }

    // Ninja Framework example with proper access control
    @FilterWith(SecureFilter.class)
    public class good_case_11 {
        @Inject
        private UserService userService;
        
        public Result getInvoice(Context context, String invoiceId) {
            String username = context.getSession().get("username");
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!userService.canAccessInvoice(username, invoiceId)) {
                return Results.forbidden().html().template("views/accessDenied.ftl.html");
            }
            
            return Results.html().render("invoice", "Invoice #" + invoiceId);
        }
        
        private class UserService {
            public boolean canAccessInvoice(String username, String invoiceId) {
                // Implementation to check if user has permission to view this invoice
                return true; // Simplified for example
            }
        }
    }

    // Servlet API example with proper access control
    public class good_case_12 extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String employeeId = request.getParameter("employeeId");
            String currentUser = (String) request.getSession().getAttribute("username");
            String userRole = (String) request.getSession().getAttribute("role");
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!employeeId.equals(currentUser) && !"HR".equals(userRole) && !"ADMIN".equals(userRole)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
                return;
            }
            
            response.getWriter().write("Employee data for: " + employeeId);
        }
    }

    // Pac4j with Spark example with proper access control
    public class good_case_13 {
        @Inject
        private Config pac4jConfig;
        
        public void setupRoutes() {
            spark.Spark.before("/credit-score/:userId", new SecurityFilter(pac4jConfig, "HeaderClient"));
            
            spark.Spark.get("/credit-score/:userId", (req, res) -> {
                String userId = req.params("userId");
                SparkWebContext context = new SparkWebContext(req, res);
                CommonProfile profile = context.getRequestAttribute(CommonProfile.class.getName());
                
                // ok: java-unauthenticatedhorizontecontrollerrule
                if (!userId.equals(profile.getId()) && !profile.getRoles().contains("FINANCIAL_ADVISOR")) {
                    res.status(403);
                    return "Access denied";
                }
                
                return "Credit score for user: " + userId;
            });
        }
    }

    // Spring WebFlux example with proper access control
    @Controller
    public class good_case_14 {
        @GetMapping("/api/messages/{conversationId}")
        public ResponseEntity<String> getConversation(@PathVariable String conversationId, Authentication authentication) {
            String currentUser = authentication.getName();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!conversationService.isUserParticipant(currentUser, conversationId)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
            }
            
            return ResponseEntity.ok("Messages for conversation: " + conversationId);
        }
        
        private ConversationService conversationService = new ConversationService();
        
        private class ConversationService {
            public boolean isUserParticipant(String username, String conversationId) {
                // Implementation to check if user is a participant in this conversation
                return true; // Simplified for example
            }
        }
    }

    // Dropwizard example with proper access control
    @Path("/subscriptions")
    public class good_case_15 {
        @GET
        @Path("/{subscriptionId}")
        public Response getSubscription(@PathParam("subscriptionId") String subscriptionId, @Context SecurityContext securityContext) {
            String username = securityContext.getUserPrincipal().getName();
            
            // ok: java-unauthenticatedhorizontecontrollerrule
            if (!subscriptionService.isUserAuthorized(username, subscriptionId)) {
                return Response.status(Response.Status.FORBIDDEN).entity("Access denied").build();
            }
            
            return Response.ok("Subscription details for: " + subscriptionId).build();
        }
        
        private SubscriptionService subscriptionService = new SubscriptionService();
        
        private class SubscriptionService {
            public boolean isUserAuthorized(String username, String subscriptionId) {
                // Implementation to check if user owns this subscription or has admin rights
                return true; // Simplified for example
            }
        }
    }
}