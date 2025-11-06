import com.amazonaws.coral.handler.ActivityHandler;
import com.amazonaws.coral.handler.ThrottlingHandler;
import com.amazonaws.coral.handler.HandlerChain;
import com.amazonaws.coral.service.AbstractCoralService;
import com.amazonaws.coral.service.CoralService;
import com.amazonaws.coral.handler.Handler;
import com.amazonaws.coral.handler.DefaultHandlerChain;
import com.amazonaws.coral.handler.LoggingHandler;
import com.amazonaws.coral.handler.MetricsHandler;
import com.amazonaws.coral.handler.ValidationHandler;
import com.amazonaws.coral.handler.AuthenticationHandler;
import com.amazonaws.coral.handler.AuthorizationHandler;
import com.amazonaws.coral.handler.CachingHandler;
import com.amazonaws.coral.handler.CircuitBreakerHandler;
import com.amazonaws.coral.handler.RetryHandler;
import com.amazonaws.coral.handler.RateLimitingHandler;
import com.amazonaws.coral.handler.RequestTracingHandler;
import com.amazonaws.coral.handler.TimeoutHandler;
import com.amazonaws.coral.handler.ErrorHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;

// Security Issue: Improper placement of ThrottlingHandler in relation to ActivityHandler in Coral Handler chain

// True Positive Examples (Vulnerable/Insecure Code)
public class ThrottlingHandlerOrderingExamples {

// {fact rule=improper-input-validation@v1.0 defects=1}
    public void bad_case_1() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new MetricsHandler());
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ThrottlingHandler());
    }

    public void bad_case_2() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ValidationHandler());
        // ruleid: java-throttling-handler-ordering
        handlers.add(new ActivityHandler());
        handlers.add(new ThrottlingHandler());
        
        HandlerChain chain = new DefaultHandlerChain();
        for (Handler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    public void bad_case_3() {
        class CustomCoralService extends AbstractCoralService {
            @Override
            protected void configureHandlerChain(HandlerChain chain) {
                chain.addHandler(new AuthenticationHandler());
                chain.addHandler(new AuthorizationHandler());
                // ruleid: java-throttling-handler-ordering
                chain.addHandler(new ActivityHandler());
                chain.addHandler(new ThrottlingHandler());
            }
        }
        
        CoralService service = new CustomCoralService();
    }

    public void bad_case_4() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new ValidationHandler());
        chain.addHandler(new CachingHandler());
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new MetricsHandler());
        chain.addHandler(new ThrottlingHandler());
    }

    public void bad_case_5() {
        Handler[] handlers = {
            new RequestTracingHandler(),
            new LoggingHandler(),
            // ruleid: java-throttling-handler-ordering
            new ActivityHandler(),
            new ThrottlingHandler()
        };
        
        HandlerChain chain = new DefaultHandlerChain();
        for (Handler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    public void bad_case_6() {
        HandlerChain chain = new DefaultHandlerChain();
        
        if (System.getProperty("enableLogging") != null) {
            chain.addHandler(new LoggingHandler());
        }
        
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        
        if (System.getProperty("enableThrottling") != null) {
            chain.addHandler(new ThrottlingHandler());
        }
    }

    public void bad_case_7() {
        class CustomHandlerChain implements HandlerChain {
            private List<Handler> handlers = new ArrayList<>();
            
            @Override
            public void addHandler(Handler handler) {
                handlers.add(handler);
            }
            
            public void initialize() {
                addHandler(new ValidationHandler());
                // ruleid: java-throttling-handler-ordering
                addHandler(new ActivityHandler());
                addHandler(new ThrottlingHandler());
            }
        }
        
        CustomHandlerChain chain = new CustomHandlerChain();
        chain.initialize();
    }

    public void bad_case_8() {
        HandlerChain primaryChain = new DefaultHandlerChain();
        primaryChain.addHandler(new LoggingHandler());
        
        HandlerChain secondaryChain = new DefaultHandlerChain();
        // ruleid: java-throttling-handler-ordering
        secondaryChain.addHandler(new ActivityHandler());
        secondaryChain.addHandler(new ThrottlingHandler());
        
        // Merge chains (conceptual)
        for (Handler handler : getHandlers(secondaryChain)) {
            primaryChain.addHandler(handler);
        }
    }
    
    private List<Handler> getHandlers(HandlerChain chain) {
        // This is just a placeholder method
        return new ArrayList<>();
    }

    public void bad_case_9() {
        HandlerChain chain = new DefaultHandlerChain();
        
        List<Handler> preHandlers = Arrays.asList(
            new LoggingHandler(),
            new ValidationHandler()
        );
        
        List<Handler> postHandlers = Arrays.asList(
            // ruleid: java-throttling-handler-ordering
            new ActivityHandler(),
            new ThrottlingHandler()
        );
        
        for (Handler handler : preHandlers) {
            chain.addHandler(handler);
        }
        
        for (Handler handler : postHandlers) {
            chain.addHandler(handler);
        }
    }

    public void bad_case_10() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new AuthenticationHandler());
        chain.addHandler(new AuthorizationHandler());
        
        // Adding core handlers
        addCoreHandlers(chain);
    }
    
    private void addCoreHandlers(HandlerChain chain) {
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ThrottlingHandler());
    }

    public void bad_case_11() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Conditional handler addition
        boolean useMetrics = true;
        boolean useLogging = true;
        
        if (useLogging) {
            chain.addHandler(new LoggingHandler());
        }
        
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        
        if (useMetrics) {
            chain.addHandler(new MetricsHandler());
        }
        
        chain.addHandler(new ThrottlingHandler());
    }

    public void bad_case_12() {
        class HandlerFactory {
            public Handler createActivityHandler() {
                return new ActivityHandler();
            }
            
            public Handler createThrottlingHandler() {
                return new ThrottlingHandler();
            }
        }
        
        HandlerFactory factory = new HandlerFactory();
        HandlerChain chain = new DefaultHandlerChain();
        
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(factory.createActivityHandler());
        chain.addHandler(factory.createThrottlingHandler());
    }

    public void bad_case_13() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Adding handlers in batches
        Handler[] firstBatch = {
            new LoggingHandler(),
            new ValidationHandler()
        };
        
        Handler[] secondBatch = {
            // ruleid: java-throttling-handler-ordering
            new ActivityHandler(),
            new ThrottlingHandler()
        };
        
        for (Handler h : firstBatch) chain.addHandler(h);
        for (Handler h : secondBatch) chain.addHandler(h);
    }

    public void bad_case_14() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Complex setup with multiple handlers
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new ValidationHandler());
        chain.addHandler(new AuthenticationHandler());
        chain.addHandler(new AuthorizationHandler());
        chain.addHandler(new CachingHandler());
        chain.addHandler(new CircuitBreakerHandler());
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new RetryHandler());
        chain.addHandler(new ThrottlingHandler());
    }

    public void bad_case_15() {
        class ServiceBuilder {
            private HandlerChain chain = new DefaultHandlerChain();
            
            public ServiceBuilder withLogging() {
                chain.addHandler(new LoggingHandler());
                return this;
            }
            
            public ServiceBuilder withActivity() {
                chain.addHandler(new ActivityHandler());
                return this;
            }
            
            public ServiceBuilder withThrottling() {
                chain.addHandler(new ThrottlingHandler());
                return this;
            }
            
            public HandlerChain build() {
                return chain;
            }
        }
        
        // ruleid: java-throttling-handler-ordering
        HandlerChain chain = new ServiceBuilder()
            .withLogging()
            .withActivity()
            .withThrottling()
            .build();
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new MetricsHandler());
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ActivityHandler());
    }

    public void good_case_2() {
        List<Handler> handlers = new ArrayList<>();
        handlers.add(new ValidationHandler());
        // ok: java-throttling-handler-ordering
        handlers.add(new ThrottlingHandler());
        handlers.add(new ActivityHandler());
        
        HandlerChain chain = new DefaultHandlerChain();
        for (Handler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    public void good_case_3() {
        class CustomCoralService extends AbstractCoralService {
            @Override
            protected void configureHandlerChain(HandlerChain chain) {
                chain.addHandler(new AuthenticationHandler());
                chain.addHandler(new AuthorizationHandler());
                // ok: java-throttling-handler-ordering
                chain.addHandler(new ThrottlingHandler());
                chain.addHandler(new ActivityHandler());
            }
        }
        
        CoralService service = new CustomCoralService();
    }

    public void good_case_4() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new ValidationHandler());
        chain.addHandler(new CachingHandler());
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new MetricsHandler());
        chain.addHandler(new ActivityHandler());
    }

    public void good_case_5() {
        Handler[] handlers = {
            new RequestTracingHandler(),
            new LoggingHandler(),
            // ok: java-throttling-handler-ordering
            new ThrottlingHandler(),
            new ActivityHandler()
        };
        
        HandlerChain chain = new DefaultHandlerChain();
        for (Handler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    public void good_case_6() {
        HandlerChain chain = new DefaultHandlerChain();
        
        if (System.getProperty("enableLogging") != null) {
            chain.addHandler(new LoggingHandler());
        }
        
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        
        if (System.getProperty("enableActivity") != null) {
            chain.addHandler(new ActivityHandler());
        }
    }

    public void good_case_7() {
        class CustomHandlerChain implements HandlerChain {
            private List<Handler> handlers = new ArrayList<>();
            
            @Override
            public void addHandler(Handler handler) {
                handlers.add(handler);
            }
            
            public void initialize() {
                addHandler(new ValidationHandler());
                // ok: java-throttling-handler-ordering
                addHandler(new ThrottlingHandler());
                addHandler(new ActivityHandler());
            }
        }
        
        CustomHandlerChain chain = new CustomHandlerChain();
        chain.initialize();
    }

    public void good_case_8() {
        HandlerChain primaryChain = new DefaultHandlerChain();
        primaryChain.addHandler(new LoggingHandler());
        
        HandlerChain secondaryChain = new DefaultHandlerChain();
        // ok: java-throttling-handler-ordering
        secondaryChain.addHandler(new ThrottlingHandler());
        secondaryChain.addHandler(new ActivityHandler());
        
        // Merge chains (conceptual)
        for (Handler handler : getHandlers(secondaryChain)) {
            primaryChain.addHandler(handler);
        }
    }

    public void good_case_9() {
        HandlerChain chain = new DefaultHandlerChain();
        
        List<Handler> preHandlers = Arrays.asList(
            new LoggingHandler(),
            new ValidationHandler(),
            // ok: java-throttling-handler-ordering
            new ThrottlingHandler()
        );
        
        List<Handler> postHandlers = Arrays.asList(
            new ActivityHandler(),
            new ErrorHandler()
        );
        
        for (Handler handler : preHandlers) {
            chain.addHandler(handler);
        }
        
        for (Handler handler : postHandlers) {
            chain.addHandler(handler);
        }
    }

    public void good_case_10() {
        HandlerChain chain = new DefaultHandlerChain();
        chain.addHandler(new AuthenticationHandler());
        chain.addHandler(new AuthorizationHandler());
        
        // Adding core handlers
        addCoreHandlers(chain);
    }
    
    private void addCoreHandlersCorrectly(HandlerChain chain) {
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ActivityHandler());
    }

    public void good_case_11() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Conditional handler addition
        boolean useMetrics = true;
        boolean useLogging = true;
        
        if (useLogging) {
            chain.addHandler(new LoggingHandler());
        }
        
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        
        if (useMetrics) {
            chain.addHandler(new MetricsHandler());
        }
        
        chain.addHandler(new ActivityHandler());
    }

    public void good_case_12() {
        class HandlerFactory {
            public Handler createActivityHandler() {
                return new ActivityHandler();
            }
            
            public Handler createThrottlingHandler() {
                return new ThrottlingHandler();
            }
        }
        
        HandlerFactory factory = new HandlerFactory();
        HandlerChain chain = new DefaultHandlerChain();
        
        // ok: java-throttling-handler-ordering
        chain.addHandler(factory.createThrottlingHandler());
        chain.addHandler(factory.createActivityHandler());
    }

    public void good_case_13() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Adding handlers in batches
        Handler[] firstBatch = {
            new LoggingHandler(),
            new ValidationHandler(),
            // ok: java-throttling-handler-ordering
            new ThrottlingHandler()
        };
        
        Handler[] secondBatch = {
            new ActivityHandler(),
            new ErrorHandler()
        };
        
        for (Handler h : firstBatch) chain.addHandler(h);
        for (Handler h : secondBatch) chain.addHandler(h);
    }

    public void good_case_14() {
        HandlerChain chain = new DefaultHandlerChain();
        
        // Complex setup with multiple handlers
        chain.addHandler(new LoggingHandler());
        chain.addHandler(new ValidationHandler());
        chain.addHandler(new AuthenticationHandler());
        chain.addHandler(new AuthorizationHandler());
        chain.addHandler(new CachingHandler());
        chain.addHandler(new CircuitBreakerHandler());
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new RetryHandler());
        chain.addHandler(new ActivityHandler());
    }

    public void good_case_15() {
        class ServiceBuilder {
            private HandlerChain chain = new DefaultHandlerChain();
            
            public ServiceBuilder withLogging() {
                chain.addHandler(new LoggingHandler());
                return this;
            }
            
            public ServiceBuilder withActivity() {
                chain.addHandler(new ActivityHandler());
                return this;
            }
            
            public ServiceBuilder withThrottling() {
                chain.addHandler(new ThrottlingHandler());
                return this;
            }
            
            public HandlerChain build() {
                return chain;
            }
        }
        
        // ok: java-throttling-handler-ordering
        HandlerChain chain = new ServiceBuilder()
            .withLogging()
            .withThrottling()
            .withActivity()
            .build();
    }
}
// {/fact}