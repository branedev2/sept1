import com.amazon.coral.service.*;
import com.amazon.coral.handler.*;
import com.amazon.coral.security.*;
import com.amazon.coral.auth.*;
import com.amazon.coral.cloudauth.*;
import com.amazon.coral.guice.*;
import com.amazon.coral.http.*;
import com.amazon.coral.validate.*;
import com.amazon.coral.metrics.*;
import com.amazon.coral.logging.*;
import com.amazon.coral.throttle.*;
import com.amazon.coral.router.*;
import com.amazon.coral.filter.*;
import com.amazon.coral.cache.*;
import com.amazon.coral.trace.*;
import com.amazon.coral.encryption.*;
import com.amazon.coral.exception.*;
import com.amazon.coral.retry.*;
import com.amazon.coral.timeout.*;
import java.util.*;

// Security Issue: Authorization Handler must be placed before Activity Handler in Coral services to ensure proper authentication and authorization

// True Positive Examples (Vulnerable/Insecure Code)
public class BadCase1 {
    public void configureService() {
        CoralService service = new CoralServiceBuilder()
            .withHandler(new MetricsHandler())
            .withHandler(new LoggingHandler())
            // ruleid: java-authorizationhandlermisplacedrule
            .withHandler(new GuiceActivityHandler())
            .withHandler(new AuthorizationHandler())
            .build();
    }
}

public class BadCase2 {
    public void setupCoralEndpoint() {
        CoralEndpoint endpoint = CoralEndpoint.builder()
            .withHandler(new ValidationHandler())
            // ruleid: java-authorizationhandlermisplacedrule
            .withHandler(new GuiceActivityHandler())
            .withHandler(new AAAHandler())
            .build();
    }
}

public class BadCase3 {
    public void initializeService() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ExceptionHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        handlers.add(new GuiceActivityHandler());
        handlers.add(new CloudAuthHandler());
        
        CoralService service = CoralService.create(handlers);
    }
}

public class BadCase4 {
    public void configureHandlerChain() {
        HandlerChain chain = new HandlerChain();
        chain.addHandler(new ThrottleHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        chain.addHandler(new GuiceActivityHandler());
        chain.addHandler(new AuthHandler());
        
        CoralServiceFactory.create(chain);
    }
}

public class BadCase5 {
    public void setupServiceWithRouter() {
        RouterHandler router = new RouterHandler();
        // ruleid: java-authorizationhandlermisplacedrule
        GuiceActivityHandler activityHandler = new GuiceActivityHandler();
        AuthorizationHandler authHandler = new AuthorizationHandler();
        
        CoralService service = new CoralServiceBuilder()
            .withHandler(router)
            .withHandler(activityHandler)
            .withHandler(authHandler)
            .build();
    }
}

public class BadCase6 {
    public void configureWithCustomHandlers() {
        CoralService service = CoralService.builder()
            .withHandler(new FilterHandler())
            // ruleid: java-authorizationhandlermisplacedrule
            .withHandler(new GuiceActivityHandler(new ActivityProvider()))
            .withHandler(new AAAHandler(new AuthProvider()))
            .build();
    }
}

public class BadCase7 {
    public void setupMultipleActivityHandlers() {
        HandlerRegistry registry = new HandlerRegistry();
        registry.register(new CacheHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        registry.register(new GuiceActivityHandler());
        registry.register(new TraceHandler());
        registry.register(new AuthorizationHandler());
        
        CoralService.create(registry);
    }
}

public class BadCase8 {
    public void configureWithConditionalHandlers() {
        boolean useMetrics = true;
        CoralServiceBuilder builder = new CoralServiceBuilder();
        
        if (useMetrics) {
            builder.withHandler(new MetricsHandler());
        }
        
        // ruleid: java-authorizationhandlermisplacedrule
        builder.withHandler(new GuiceActivityHandler());
        builder.withHandler(new AuthHandler());
        
        CoralService service = builder.build();
    }
}

public class BadCase9 {
    public void setupWithEncryption() {
        List<Handler> handlers = Arrays.asList(
            new EncryptionHandler(),
            // ruleid: java-authorizationhandlermisplacedrule
            new GuiceActivityHandler(),
            new CloudAuthHandler()
        );
        
        CoralService service = CoralService.withHandlers(handlers);
    }
}

public class BadCase10 {
    public void configureWithExceptionHandling() {
        CoralService service = new CoralServiceBuilder()
            .withHandler(new ExceptionHandler())
            .withHandler(new RetryHandler())
            // ruleid: java-authorizationhandlermisplacedrule
            .withHandler(new GuiceActivityHandler())
            .withHandler(new AuthorizationHandler())
            .build();
    }
}

public class BadCase11 {
    public void setupWithTimeouts() {
        HandlerChain chain = new HandlerChain();
        chain.addHandler(new TimeoutHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        chain.addHandler(new GuiceActivityHandler());
        chain.addHandler(new AAAHandler());
        
        CoralServiceFactory.createWithChain(chain);
    }
}

public class BadCase12 {
    public void configureWithCustomOrder() {
        CoralService.Builder builder = CoralService.builder();
        builder.addHandler(new LoggingHandler());
        builder.addHandler(new ValidationHandler());
        // ruleid: java-authorizationhandlermisplacedrule
        builder.addHandler(new GuiceActivityHandler());
        builder.addHandler(new AuthHandler());
        
        CoralService service = builder.build();
    }
}

public class BadCase13 {
    public void setupWithDynamicHandlers() {
        List<Handler> preHandlers = getPreHandlers();
        List<Handler> postHandlers = getPostHandlers();
        
        CoralServiceBuilder builder = new CoralServiceBuilder();
        for (Handler h : preHandlers) {
            builder.withHandler(h);
        }
        
        // ruleid: java-authorizationhandlermisplacedrule
        builder.withHandler(new GuiceActivityHandler());
        builder.withHandler(new AuthorizationHandler());
        
        for (Handler h : postHandlers) {
            builder.withHandler(h);
        }
        
        CoralService service = builder.build();
    }
    
    private List<Handler> getPreHandlers() {
        return Arrays.asList(new MetricsHandler(), new LoggingHandler());
    }
    
    private List<Handler> getPostHandlers() {
        return Arrays.asList(new ExceptionHandler());
    }
}

public class BadCase14 {
    public void configureWithNamedHandlers() {
        Map<String, Handler> handlers = new HashMap<>();
        handlers.put("metrics", new MetricsHandler());
        handlers.put("logging", new LoggingHandler());
        handlers.put("activity", new GuiceActivityHandler());
        handlers.put("auth", new AuthorizationHandler());
        
        CoralServiceBuilder builder = new CoralServiceBuilder();
        builder.withHandler(handlers.get("metrics"));
        builder.withHandler(handlers.get("logging"));
        // ruleid: java-authorizationhandlermisplacedrule
        builder.withHandler(handlers.get("activity"));
        builder.withHandler(handlers.get("auth"));
        
        CoralService service = builder.build();
    }
}

public class BadCase15 {
    public void setupWithFactoryMethod() {
        CoralService service = CoralServiceFactory.create(
            new ValidationHandler(),
            new FilterHandler(),
            // ruleid: java-authorizationhandlermisplacedrule
            new GuiceActivityHandler(),
            new CloudAuthHandler()
        );
    }
}

// True Negative Examples (Safe/Secure Code)
public class GoodCase1 {
    public void configureService() {
        CoralService service = new CoralServiceBuilder()
            .withHandler(new MetricsHandler())
            .withHandler(new LoggingHandler())
            // ok: java-authorizationhandlermisplacedrule
            .withHandler(new AuthorizationHandler())
            .withHandler(new GuiceActivityHandler())
            .build();
    }
}

public class GoodCase2 {
    public void setupCoralEndpoint() {
        CoralEndpoint endpoint = CoralEndpoint.builder()
            .withHandler(new ValidationHandler())
            // ok: java-authorizationhandlermisplacedrule
            .withHandler(new AAAHandler())
            .withHandler(new GuiceActivityHandler())
            .build();
    }
}

public class GoodCase3 {
    public void initializeService() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ExceptionHandler());
        // ok: java-authorizationhandlermisplacedrule
        handlers.add(new CloudAuthHandler());
        handlers.add(new GuiceActivityHandler());
        
        CoralService service = CoralService.create(handlers);
    }
}

public class GoodCase4 {
    public void configureHandlerChain() {
        HandlerChain chain = new HandlerChain();
        chain.addHandler(new ThrottleHandler());
        // ok: java-authorizationhandlermisplacedrule
        chain.addHandler(new AuthHandler());
        chain.addHandler(new GuiceActivityHandler());
        
        CoralServiceFactory.create(chain);
    }
}

public class GoodCase5 {
    public void setupServiceWithRouter() {
        RouterHandler router = new RouterHandler();
        // ok: java-authorizationhandlermisplacedrule
        AuthorizationHandler authHandler = new AuthorizationHandler();
        GuiceActivityHandler activityHandler = new GuiceActivityHandler();
        
        CoralService service = new CoralServiceBuilder()
            .withHandler(router)
            .withHandler(authHandler)
            .withHandler(activityHandler)
            .build();
    }
}

public class GoodCase6 {
    public void configureWithCustomHandlers() {
        CoralService service = CoralService.builder()
            .withHandler(new FilterHandler())
            // ok: java-authorizationhandlermisplacedrule
            .withHandler(new AAAHandler(new AuthProvider()))
            .withHandler(new GuiceActivityHandler(new ActivityProvider()))
            .build();
    }
}

public class GoodCase7 {
    public void setupMultipleActivityHandlers() {
        HandlerRegistry registry = new HandlerRegistry();
        registry.register(new CacheHandler());
        // ok: java-authorizationhandlermisplacedrule
        registry.register(new AuthorizationHandler());
        registry.register(new TraceHandler());
        registry.register(new GuiceActivityHandler());
        
        CoralService.create(registry);
    }
}

public class GoodCase8 {
    public void configureWithConditionalHandlers() {
        boolean useMetrics = true;
        CoralServiceBuilder builder = new CoralServiceBuilder();
        
        if (useMetrics) {
            builder.withHandler(new MetricsHandler());
        }
        
        // ok: java-authorizationhandlermisplacedrule
        builder.withHandler(new AuthHandler());
        builder.withHandler(new GuiceActivityHandler());
        
        CoralService service = builder.build();
    }
}

public class GoodCase9 {
    public void setupWithEncryption() {
        List<Handler> handlers = Arrays.asList(
            new EncryptionHandler(),
            // ok: java-authorizationhandlermisplacedrule
            new CloudAuthHandler(),
            new GuiceActivityHandler()
        );
        
        CoralService service = CoralService.withHandlers(handlers);
    }
}

public class GoodCase10 {
    public void configureWithExceptionHandling() {
        CoralService service = new CoralServiceBuilder()
            .withHandler(new ExceptionHandler())
            .withHandler(new RetryHandler())
            // ok: java-authorizationhandlermisplacedrule
            .withHandler(new AuthorizationHandler())
            .withHandler(new GuiceActivityHandler())
            .build();
    }
}

public class GoodCase11 {
    public void setupWithTimeouts() {
        HandlerChain chain = new HandlerChain();
        chain.addHandler(new TimeoutHandler());
        // ok: java-authorizationhandlermisplacedrule
        chain.addHandler(new AAAHandler());
        chain.addHandler(new GuiceActivityHandler());
        
        CoralServiceFactory.createWithChain(chain);
    }
}

public class GoodCase12 {
    public void configureWithCustomOrder() {
        CoralService.Builder builder = CoralService.builder();
        builder.addHandler(new LoggingHandler());
        builder.addHandler(new ValidationHandler());
        // ok: java-authorizationhandlermisplacedrule
        builder.addHandler(new AuthHandler());
        builder.addHandler(new GuiceActivityHandler());
        
        CoralService service = builder.build();
    }
}

public class GoodCase13 {
    public void setupWithDynamicHandlers() {
        List<Handler> preHandlers = getPreHandlers();
        List<Handler> postHandlers = getPostHandlers();
        
        CoralServiceBuilder builder = new CoralServiceBuilder();
        for (Handler h : preHandlers) {
            builder.withHandler(h);
        }
        
        // ok: java-authorizationhandlermisplacedrule
        builder.withHandler(new AuthorizationHandler());
        builder.withHandler(new GuiceActivityHandler());
        
        for (Handler h : postHandlers) {
            builder.withHandler(h);
        }
        
        CoralService service = builder.build();
    }
    
    private List<Handler> getPreHandlers() {
        return Arrays.asList(new MetricsHandler(), new LoggingHandler());
    }
    
    private List<Handler> getPostHandlers() {
        return Arrays.asList(new ExceptionHandler());
    }
}

public class GoodCase14 {
    public void configureWithNamedHandlers() {
        Map<String, Handler> handlers = new HashMap<>();
        handlers.put("metrics", new MetricsHandler());
        handlers.put("logging", new LoggingHandler());
        handlers.put("activity", new GuiceActivityHandler());
        handlers.put("auth", new AuthorizationHandler());
        
        CoralServiceBuilder builder = new CoralServiceBuilder();
        builder.withHandler(handlers.get("metrics"));
        builder.withHandler(handlers.get("logging"));
        // ok: java-authorizationhandlermisplacedrule
        builder.withHandler(handlers.get("auth"));
        builder.withHandler(handlers.get("activity"));
        
        CoralService service = builder.build();
    }
}

public class GoodCase15 {
    public void setupWithFactoryMethod() {
        CoralService service = CoralServiceFactory.create(
            new ValidationHandler(),
            new FilterHandler(),
            // ok: java-authorizationhandlermisplacedrule
            new CloudAuthHandler(),
            new GuiceActivityHandler()
        );
    }
}