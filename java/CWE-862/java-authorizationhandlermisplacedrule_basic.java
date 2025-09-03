package com.example.coralservice;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

// Common interfaces and classes for all examples
interface Handler {
    void handle(Request request, Response response, HandlerChain chain);
}

interface HandlerChain {
    void doChain(Request request, Response response);
}

class Request {
    private String path;
    private String method;
    
    public Request(String path, String method) {
        this.path = path;
        this.method = method;
    }
    
    public String getPath() {
        return path;
    }
    
    public String getMethod() {
        return method;
    }
}

class Response {
    private int status = 200;
    private String body = "";
    
    public void setStatus(int status) {
        this.status = status;
    }
    
    public void setBody(String body) {
        this.body = body;
    }
}

class HandlerChainImpl implements HandlerChain {
    private List<Handler> handlers;
    private int currentIndex = 0;
    
    public HandlerChainImpl(List<Handler> handlers) {
        this.handlers = handlers;
    }
    
    @Override
    public void doChain(Request request, Response response) {
        if (currentIndex < handlers.size()) {
            Handler handler = handlers.get(currentIndex++);
            handler.handle(request, response, this);
        }
    }
}

class AuthorizationHandler implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Authorization logic
        System.out.println("Authorizing request");
        chain.doChain(request, response);
    }
}

class AAA implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // AAA logic
        System.out.println("AAA handling");
        chain.doChain(request, response);
    }
}

class Auth implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Auth logic
        System.out.println("Auth handling");
        chain.doChain(request, response);
    }
}

class CloudAuth implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // CloudAuth logic
        System.out.println("CloudAuth handling");
        chain.doChain(request, response);
    }
}

class GuiceActivityHandler implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Activity handling logic
        System.out.println("Processing activity");
        chain.doChain(request, response);
    }
}

class ActivityHandler implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Activity handling logic
        System.out.println("Processing activity");
        chain.doChain(request, response);
    }
}

class LoggingHandler implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Logging logic
        System.out.println("Logging request");
        chain.doChain(request, response);
    }
}

class ErrorHandler implements Handler {
    @Override
    public void handle(Request request, Response response, HandlerChain chain) {
        // Error handling logic
        try {
            chain.doChain(request, response);
        } catch (Exception e) {
            response.setStatus(500);
            response.setBody("Internal Server Error");
        }
    }
}

public class CoralServiceHandlerExamples {

    // True Positives (Vulnerable Code)
    
// {fact rule=missing-authorization@v1.0 defects=1}
    public void bad_case_1() {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new AuthorizationHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/resource", "GET"), new Response());
    }
    
    public void bad_case_2() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new AAA());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/resource", "POST"), new Response());
    }
    
    public void bad_case_3() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new Auth());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/users", "GET"), new Response());
    }
    
    public void bad_case_4() {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new CloudAuth());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/data", "PUT"), new Response());
    }
    
    public void bad_case_5() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new AuthorizationHandler());
        handlers.add(new ErrorHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/admin", "DELETE"), new Response());
    }
    
    @Singleton
    public class BadService1 {
        private final List<Handler> handlers;
        
        @Inject
        public BadService1() {
            handlers = new ArrayList<>();
            // ruleid: java-authorizationhandlermisplacedrule
            handlers.add(new GuiceActivityHandler());
            handlers.add(new AAA());
        }
        
        public void processRequest(Request request, Response response) {
            HandlerChain chain = new HandlerChainImpl(handlers);
            chain.doChain(request, response);
        }
    }
    
    public void bad_case_6() {
        BadService1 service = new BadService1();
        service.processRequest(new Request("/api/resource", "GET"), new Response());
    }
    
    @Singleton
    public class BadService2 {
        private final List<Handler> handlers;
        
        @Inject
        public BadService2() {
            handlers = new ArrayList<>();
            handlers.add(new LoggingHandler());
            // ruleid: java-authorizationhandlermisplacedrule
            handlers.add(new ActivityHandler());
            handlers.add(new Auth());
        }
        
        public void processRequest(Request request, Response response) {
            HandlerChain chain = new HandlerChainImpl(handlers);
            chain.doChain(request, response);
        }
    }
    
    public void bad_case_7() {
        BadService2 service = new BadService2();
        service.processRequest(new Request("/api/resource", "POST"), new Response());
    }
    
    public void bad_case_8() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new CloudAuth());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/secure", "GET"), new Response());
    }
    
    public void bad_case_9() {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new AuthorizationHandler());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/data", "GET"), new Response());
    }
    
    public void bad_case_10() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new AAA());
        handlers.add(new ErrorHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/users", "POST"), new Response());
    }
    
    public void bad_case_11() {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new Auth());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/profile", "PUT"), new Response());
    }
    
    public void bad_case_12() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new CloudAuth());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/settings", "PATCH"), new Response());
    }
    
    public void bad_case_13() {
        List<Handler> handlers = new ArrayList<>();
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new AuthorizationHandler());
        handlers.add(new AAA());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/admin/users", "GET"), new Response());
    }
    
    public void bad_case_14() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new Auth());
        handlers.add(new CloudAuth());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/reports", "GET"), new Response());
    }
    
    public void bad_case_15() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new ActivityHandler());
        handlers.add(new AAA());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/analytics", "POST"), new Response());
    }
    
    // True Negatives (Secure Code)
    
    public void good_case_1() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AuthorizationHandler());
        handlers.add(new GuiceActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/resource", "GET"), new Response());
    }
    
    public void good_case_2() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AAA());
        handlers.add(new ActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/resource", "POST"), new Response());
    }
    
    public void good_case_3() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new Auth());
        handlers.add(new GuiceActivityHandler());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/users", "GET"), new Response());
    }
    
    public void good_case_4() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new CloudAuth());
        handlers.add(new ActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/data", "PUT"), new Response());
    }
    
    public void good_case_5() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AuthorizationHandler());
        handlers.add(new AAA());
        handlers.add(new GuiceActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/admin", "DELETE"), new Response());
    }
    
    @Singleton
    public class GoodService1 {
        private final List<Handler> handlers;
        
        @Inject
        public GoodService1() {
            handlers = new ArrayList<>();
            // ok: java-authorizationhandlermisplacedrule
            handlers.add(new AAA());
            handlers.add(new GuiceActivityHandler());
        }
        
        public void processRequest(Request request, Response response) {
            HandlerChain chain = new HandlerChainImpl(handlers);
            chain.doChain(request, response);
        }
    }
    
    public void good_case_6() {
        GoodService1 service = new GoodService1();
        service.processRequest(new Request("/api/resource", "GET"), new Response());
    }
    
    @Singleton
    public class GoodService2 {
        private final List<Handler> handlers;
        
        @Inject
        public GoodService2() {
            handlers = new ArrayList<>();
            handlers.add(new LoggingHandler());
            // ok: java-authorizationhandlermisplacedrule
            handlers.add(new Auth());
            handlers.add(new ActivityHandler());
        }
        
        public void processRequest(Request request, Response response) {
            HandlerChain chain = new HandlerChainImpl(handlers);
            chain.doChain(request, response);
        }
    }
    
    public void good_case_7() {
        GoodService2 service = new GoodService2();
        service.processRequest(new Request("/api/resource", "POST"), new Response());
    }
    
    public void good_case_8() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new CloudAuth());
        handlers.add(new GuiceActivityHandler());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/secure", "GET"), new Response());
    }
    
    public void good_case_9() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AuthorizationHandler());
        handlers.add(new ActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/data", "GET"), new Response());
    }
    
    public void good_case_10() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AAA());
        handlers.add(new Auth());
        handlers.add(new GuiceActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/users", "POST"), new Response());
    }
    
    public void good_case_11() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new Auth());
        handlers.add(new ActivityHandler());
        handlers.add(new LoggingHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/profile", "PUT"), new Response());
    }
    
    public void good_case_12() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new CloudAuth());
        handlers.add(new AuthorizationHandler());
        handlers.add(new GuiceActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/settings", "PATCH"), new Response());
    }
    
    public void good_case_13() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new LoggingHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AAA());
        handlers.add(new ActivityHandler());
        handlers.add(new ErrorHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/admin/users", "GET"), new Response());
    }
    
    public void good_case_14() {
        List<Handler> handlers = new ArrayList<>();
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new Auth());
        handlers.add(new CloudAuth());
        handlers.add(new GuiceActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/reports", "GET"), new Response());
    }
    
    public void good_case_15() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ErrorHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new AAA());
        handlers.add(new AuthorizationHandler());
        handlers.add(new ActivityHandler());
        
        HandlerChain chain = new HandlerChainImpl(handlers);
        chain.doChain(new Request("/api/analytics", "POST"), new Response());
    }
}
// {/fact}