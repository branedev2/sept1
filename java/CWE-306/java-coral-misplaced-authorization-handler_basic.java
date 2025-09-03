package com.example.authorization;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

// Base interfaces for our handlers
interface Handler {
    void handle(HttpServletRequest request, HttpServletResponse response);
}

class AuthorizationHandler implements Handler {
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        // Authorization logic
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new SecurityException("Unauthorized access");
        }
    }
}

class ActivityHandler implements Handler {
    private String activityName;
    
    public ActivityHandler(String activityName) {
        this.activityName = activityName;
    }
    
    public void handle(HttpServletRequest request, HttpServletResponse response) {
        // Activity handling logic
        System.out.println("Handling activity: " + activityName);
    }
}

@Controller
public class AuthorizationExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
    @RequestMapping("/bad1")
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-coral-misplaced-authorization-handler
        handlers.add(new ActivityHandler("UserProfile"));
        // No AuthorizationHandler before ActivityHandler
        
        for (Handler handler : handlers) {
            handler.handle(request, response);
        }
    }
    
    @RequestMapping("/bad2")
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
        // ruleid: java-coral-misplaced-authorization-handler
        ActivityHandler activityHandler = new ActivityHandler("AdminDashboard");
        activityHandler.handle(request, response);
        // Missing authorization check before accessing admin dashboard
    }
    
    @RequestMapping("/bad3")
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) {
        Handler[] handlers = new Handler[2];
        // ruleid: java-coral-misplaced-authorization-handler
        handlers[0] = new ActivityHandler("PaymentProcessing");
        handlers[1] = new AuthorizationHandler(); // Authorization after activity is too late
        
        for (Handler handler : handlers) {
            handler.handle(request, response);
        }
    }
    
    @GetMapping("/bad4")
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Handler> handlerMap = new HashMap<>();
        // ruleid: java-coral-misplaced-authorization-handler
        handlerMap.put("activity", new ActivityHandler("SensitiveDataAccess"));
        // No authorization handler in the map
        
        handlerMap.get("activity").handle(request, response);
    }
    
    @PostMapping("/bad5")
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) {
        List<Handler> pipeline = new ArrayList<>();
        pipeline.add(new LoggingHandler());
        pipeline.add(new ValidationHandler());
        // ruleid: java-coral-misplaced-authorization-handler
        pipeline.add(new ActivityHandler("UserDeletion"));
        // Missing authorization check in the pipeline
        
        for (Handler handler : pipeline) {
            handler.handle(request, response);
        }
    }
    
    @RequestMapping("/bad6")
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        if (request.getParameter("bypass") != null) {
            // ruleid: java-coral-misplaced-authorization-handler
            new ActivityHandler("BypassableActivity").handle(request, response);
        } else {
            new AuthorizationHandler().handle(request, response);
            new ActivityHandler("NormalActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/bad7")
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) {
        String action = request.getParameter("action");
        // ruleid: java-coral-misplaced-authorization-handler
        switch (action) {
            case "view":
                new ActivityHandler("ViewData").handle(request, response);
                break;
            case "edit":
                new ActivityHandler("EditData").handle(request, response);
                break;
            default:
                new AuthorizationHandler().handle(request, response);
                break;
        }
    }
    
    @RequestMapping("/bad8")
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            // ruleid: java-coral-misplaced-authorization-handler
            ActivityHandler handler = new ActivityHandler("ExceptionProne");
            handler.handle(request, response);
        } catch (Exception e) {
            // Authorization only in exception handler is too late
            new AuthorizationHandler().handle(request, response);
        }
    }
    
    @RequestMapping("/bad9")
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) {
        boolean isPublic = "true".equals(request.getParameter("public"));
        
        if (isPublic) {
            // Public route, but still needs some authorization
            // ruleid: java-coral-misplaced-authorization-handler
            new ActivityHandler("PublicActivity").handle(request, response);
        } else {
            // Private route gets proper authorization
            new AuthorizationHandler().handle(request, response);
            new ActivityHandler("PrivateActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/bad10")
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        // Conditional that might skip authorization
        if (request.getSession().getAttribute("previouslyAuthorized") != null) {
            // ruleid: java-coral-misplaced-authorization-handler
            new ActivityHandler("SessionBasedActivity").handle(request, response);
        } else {
            new AuthorizationHandler().handle(request, response);
            new ActivityHandler("NewSessionActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/bad11")
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) {
        // Multiple activities without authorization
        // ruleid: java-coral-misplaced-authorization-handler
        new ActivityHandler("FirstActivity").handle(request, response);
        new ActivityHandler("SecondActivity").handle(request, response);
        new ActivityHandler("ThirdActivity").handle(request, response);
    }
    
    @RequestMapping("/bad12")
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) {
        // Authorization happens but for a different activity
        new AuthorizationHandler().handle(request, response);
        new ActivityHandler("AuthorizedActivity").handle(request, response);
        
        // New activity without its own authorization
        // ruleid: java-coral-misplaced-authorization-handler
        new ActivityHandler("UnauthorizedActivity").handle(request, response);
    }
    
    @RequestMapping("/bad13")
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) {
        // Nested handlers without proper authorization
        Runnable action = () -> {
            // ruleid: java-coral-misplaced-authorization-handler
            new ActivityHandler("NestedActivity").handle(request, response);
        };
        action.run();
    }
    
    @RequestMapping("/bad14")
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) {
        // Authorization handler created but never used
        AuthorizationHandler authHandler = new AuthorizationHandler();
        
        // ruleid: java-coral-misplaced-authorization-handler
        ActivityHandler activityHandler = new ActivityHandler("UnusedAuthActivity");
        activityHandler.handle(request, response);
    }
    
    @RequestMapping("/bad15")
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        // Custom handler chain implementation
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        handlers.add(new CacheHandler());
        // ruleid: java-coral-misplaced-authorization-handler
        handlers.add(new ActivityHandler("ChainedActivity"));
        
        executeHandlerChain(handlers, request, response);
    }
    
    // True Negative Examples (Secure Code)
    
    @RequestMapping("/good1")
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-coral-misplaced-authorization-handler
        handlers.add(new AuthorizationHandler());
        handlers.add(new ActivityHandler("UserProfile"));
        
        for (Handler handler : handlers) {
            handler.handle(request, response);
        }
    }
    
    @RequestMapping("/good2")
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        AuthorizationHandler authHandler = new AuthorizationHandler();
        authHandler.handle(request, response);
        
        ActivityHandler activityHandler = new ActivityHandler("AdminDashboard");
        activityHandler.handle(request, response);
    }
    
    @RequestMapping("/good3")
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) {
        Handler[] handlers = new Handler[2];
        // ok: java-coral-misplaced-authorization-handler
        handlers[0] = new AuthorizationHandler();
        handlers[1] = new ActivityHandler("PaymentProcessing");
        
        for (Handler handler : handlers) {
            handler.handle(request, response);
        }
    }
    
    @GetMapping("/good4")
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Handler> handlerMap = new HashMap<>();
        // ok: java-coral-misplaced-authorization-handler
        handlerMap.put("auth", new AuthorizationHandler());
        handlerMap.put("activity", new ActivityHandler("SensitiveDataAccess"));
        
        handlerMap.get("auth").handle(request, response);
        handlerMap.get("activity").handle(request, response);
    }
    
    @PostMapping("/good5")
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) {
        List<Handler> pipeline = new ArrayList<>();
        pipeline.add(new LoggingHandler());
        // ok: java-coral-misplaced-authorization-handler
        pipeline.add(new AuthorizationHandler());
        pipeline.add(new ValidationHandler());
        pipeline.add(new ActivityHandler("UserDeletion"));
        
        for (Handler handler : pipeline) {
            handler.handle(request, response);
        }
    }
    
    @RequestMapping("/good6")
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        new AuthorizationHandler().handle(request, response);
        
        if (request.getParameter("action") != null) {
            new ActivityHandler("ConditionalActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/good7")
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        new AuthorizationHandler().handle(request, response);
        
        String action = request.getParameter("action");
        switch (action) {
            case "view":
                new ActivityHandler("ViewData").handle(request, response);
                break;
            case "edit":
                new ActivityHandler("EditData").handle(request, response);
                break;
            default:
                // Default action
                break;
        }
    }
    
    @RequestMapping("/good8")
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) {
        try {
            // ok: java-coral-misplaced-authorization-handler
            new AuthorizationHandler().handle(request, response);
            ActivityHandler handler = new ActivityHandler("ExceptionProne");
            handler.handle(request, response);
        } catch (Exception e) {
            // Exception handling
        }
    }
    
    @RequestMapping("/good9")
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) {
        boolean isPublic = "true".equals(request.getParameter("public"));
        
        // ok: java-coral-misplaced-authorization-handler
        // Even public routes get appropriate authorization checks
        AuthorizationHandler publicAuthHandler = new PublicAuthorizationHandler();
        publicAuthHandler.handle(request, response);
        
        if (isPublic) {
            new ActivityHandler("PublicActivity").handle(request, response);
        } else {
            // Private routes get additional authorization
            new PrivateAuthorizationHandler().handle(request, response);
            new ActivityHandler("PrivateActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/good10")
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        // Always perform authorization regardless of session state
        new AuthorizationHandler().handle(request, response);
        
        if (request.getSession().getAttribute("previouslyAuthorized") != null) {
            new ActivityHandler("SessionBasedActivity").handle(request, response);
        } else {
            new ActivityHandler("NewSessionActivity").handle(request, response);
        }
    }
    
    @RequestMapping("/good11")
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        new AuthorizationHandler().handle(request, response);
        
        // Multiple activities after authorization
        new ActivityHandler("FirstActivity").handle(request, response);
        new ActivityHandler("SecondActivity").handle(request, response);
        new ActivityHandler("ThirdActivity").handle(request, response);
    }
    
    @RequestMapping("/good12")
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        new RoleBasedAuthorizationHandler("ADMIN").handle(request, response);
        new ActivityHandler("AdminActivity").handle(request, response);
        
        // Different authorization for different activity
        new RoleBasedAuthorizationHandler("USER").handle(request, response);
        new ActivityHandler("UserActivity").handle(request, response);
    }
    
    @RequestMapping("/good13")
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        new AuthorizationHandler().handle(request, response);
        
        // Nested handlers with proper authorization
        Runnable action = () -> {
            new ActivityHandler("NestedActivity").handle(request, response);
        };
        action.run();
    }
    
    @RequestMapping("/good14")
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) {
        // ok: java-coral-misplaced-authorization-handler
        AuthorizationHandler authHandler = new AuthorizationHandler();
        authHandler.handle(request, response);
        
        ActivityHandler activityHandler = new ActivityHandler("ProperlyAuthorizedActivity");
        activityHandler.handle(request, response);
    }
    
    @RequestMapping("/good15")
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        // Custom handler chain implementation with proper authorization
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ok: java-coral-misplaced-authorization-handler
        handlers.add(new AuthorizationHandler());
        handlers.add(new CacheHandler());
        handlers.add(new ActivityHandler("ChainedActivity"));
        
        executeHandlerChain(handlers, request, response);
    }
    
    // Helper methods and additional handler classes
    
    private void executeHandlerChain(List<Handler> handlers, HttpServletRequest request, HttpServletResponse response) {
        for (Handler handler : handlers) {
            handler.handle(request, response);
        }
    }
    
    class LoggingHandler implements Handler {
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            System.out.println("Logging request: " + request.getRequestURI());
        }
    }
    
    class ValidationHandler implements Handler {
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            // Validate request parameters
            if (request.getParameter("id") == null) {
                throw new IllegalArgumentException("Missing required parameter: id");
            }
        }
    }
    
    class CacheHandler implements Handler {
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            // Cache handling logic
            response.setHeader("Cache-Control", "max-age=3600");
        }
    }
    
    class PublicAuthorizationHandler extends AuthorizationHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            // Minimal authorization for public routes
            // Still checks for basic authentication
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null) {
                throw new SecurityException("Authentication required");
            }
        }
    }
    
    class PrivateAuthorizationHandler extends AuthorizationHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            // Stricter authorization for private routes
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || !auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                throw new SecurityException("Admin access required");
            }
        }
    }
    
    class RoleBasedAuthorizationHandler extends AuthorizationHandler {
        private String requiredRole;
        
        public RoleBasedAuthorizationHandler(String requiredRole) {
            this.requiredRole = requiredRole;
        }
        
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated() || !auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_" + requiredRole))) {
                throw new SecurityException("Required role not present: " + requiredRole);
            }
        }
    }
}
// {/fact}