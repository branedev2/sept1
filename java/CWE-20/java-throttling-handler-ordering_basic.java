import com.amazon.coral.handler.ActivityHandler;
import com.amazon.coral.handler.ThrottlingHandler;
import com.amazon.coral.handler.HandlerChain;
import com.amazon.coral.service.ServiceHandler;
import com.amazon.coral.service.ServiceHandlerChain;
import com.amazon.coral.service.ServiceHandlerChainFactory;
import com.amazon.coral.service.ServiceHandlerFactory;
import com.amazon.coral.service.ServiceHandlerContext;
import com.amazon.coral.service.ServiceRequest;
import com.amazon.coral.service.ServiceResponse;
import com.amazon.coral.service.ServiceResponseHandler;
import com.amazon.coral.throttle.ThrottledRequestException;
import java.util.ArrayList;
import java.util.List;

/**
 * Test cases for java-throttling-handler-ordering rule
 * This rule checks that ThrottlingHandler is placed before ActivityHandler
 * in the Coral Handler chain to prevent ThrottledExceptions
 */

// True positives (vulnerable code that should be detected)

public class ThrottlingHandlerOrderingTest {

    // Bad case 1: ActivityHandler added before ThrottlingHandler
// {fact rule=improper-input-validation@v1.0 defects=1}
    public void bad_case_1() {
        HandlerChain chain = new HandlerChain();
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ThrottlingHandler());
    }

    // Bad case 2: ActivityHandler added first in a service handler chain
    public void bad_case_2() {
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ServiceResponseHandler());
    }

    // Bad case 3: Adding handlers to a list and then using them in wrong order
    public void bad_case_3() {
        List<ServiceHandler> handlers = new ArrayList<>();
        handlers.add(new ActivityHandler());
        handlers.add(new ThrottlingHandler());
        
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ruleid: java-throttling-handler-ordering
        for (ServiceHandler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    // Bad case 4: Using a factory method but with wrong order
    public void bad_case_4() {
        ServiceHandlerChainFactory factory = new ServiceHandlerChainFactory();
        // ruleid: java-throttling-handler-ordering
        factory.addHandler(new ActivityHandler());
        factory.addHandler(new ThrottlingHandler());
        ServiceHandlerChain chain = factory.createHandlerChain();
    }

    // Bad case 5: Conditional addition of handlers but wrong order
    public void bad_case_5(boolean useThrottling) {
        HandlerChain chain = new HandlerChain();
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        
        if (useThrottling) {
            chain.addHandler(new ThrottlingHandler());
        }
    }

    // Bad case 6: Using array of handlers with wrong order
    public void bad_case_6() {
        ServiceHandler[] handlers = new ServiceHandler[2];
        handlers[0] = new ActivityHandler();
        handlers[1] = new ThrottlingHandler();
        
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ruleid: java-throttling-handler-ordering
        for (ServiceHandler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    // Bad case 7: Creating custom handler chain with wrong order
    public void bad_case_7() {
        class CustomHandlerChain extends HandlerChain {
            public CustomHandlerChain() {
                super();
                // ruleid: java-throttling-handler-ordering
                addHandler(new ActivityHandler());
                addHandler(new ThrottlingHandler());
            }
        }
        
        CustomHandlerChain chain = new CustomHandlerChain();
    }

    // Bad case 8: Using builder pattern but with wrong order
    public void bad_case_8() {
        HandlerChain chain = new HandlerChain()
            // ruleid: java-throttling-handler-ordering
            .addHandler(new ActivityHandler())
            .addHandler(new ThrottlingHandler());
    }

    // Bad case 9: Multiple ActivityHandlers before ThrottlingHandler
    public void bad_case_9() {
        HandlerChain chain = new HandlerChain();
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler("Logger"));
        chain.addHandler(new ActivityHandler("Metrics"));
        chain.addHandler(new ThrottlingHandler());
    }

    // Bad case 10: Using a map to configure handlers but with wrong order
    public void bad_case_10() {
        HandlerChain chain = new HandlerChain();
        
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        
        try {
            // Some operations
            chain.addHandler(new ThrottlingHandler());
        } catch (Exception e) {
            // Error handling
        }
    }

    // Bad case 11: Creating handlers dynamically but with wrong order
    public void bad_case_11() {
        HandlerChain chain = new HandlerChain();
        
        for (int i = 0; i < 2; i++) {
            if (i == 0) {
                // ruleid: java-throttling-handler-ordering
                chain.addHandler(new ActivityHandler());
            } else {
                chain.addHandler(new ThrottlingHandler());
            }
        }
    }

    // Bad case 12: Using reflection to add handlers but with wrong order
    public void bad_case_12() throws Exception {
        HandlerChain chain = new HandlerChain();
        
        Class<?> activityHandlerClass = Class.forName("com.amazon.coral.handler.ActivityHandler");
        Class<?> throttlingHandlerClass = Class.forName("com.amazon.coral.handler.ThrottlingHandler");
        
        // ruleid: java-throttling-handler-ordering
        chain.addHandler((ServiceHandler) activityHandlerClass.newInstance());
        chain.addHandler((ServiceHandler) throttlingHandlerClass.newInstance());
    }

    // Bad case 13: Using a switch statement but with wrong order
    public void bad_case_13(int option) {
        HandlerChain chain = new HandlerChain();
        
        switch (option) {
            case 1:
                // ruleid: java-throttling-handler-ordering
                chain.addHandler(new ActivityHandler());
                chain.addHandler(new ThrottlingHandler());
                break;
            case 2:
                // Different handlers
                break;
            default:
                // Default handlers
        }
    }

    // Bad case 14: Using a helper method but with wrong order
    public void bad_case_14() {
        HandlerChain chain = configureHandlers(new HandlerChain());
    }
    
    private HandlerChain configureHandlers(HandlerChain chain) {
        // ruleid: java-throttling-handler-ordering
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ThrottlingHandler());
        return chain;
    }

    // Bad case 15: Using a custom handler factory but with wrong order
    public void bad_case_15() {
        class HandlerFactory {
            public HandlerChain createChain() {
                HandlerChain chain = new HandlerChain();
                // ruleid: java-throttling-handler-ordering
                chain.addHandler(new ActivityHandler());
                chain.addHandler(new ThrottlingHandler());
                return chain;
            }
        }
        
        HandlerFactory factory = new HandlerFactory();
        HandlerChain chain = factory.createChain();
    }

    // True negatives (secure code that should not be detected)

    // Good case 1: ThrottlingHandler added before ActivityHandler
    public void good_case_1() {
        HandlerChain chain = new HandlerChain();
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ActivityHandler());
    }

    // Good case 2: ThrottlingHandler added first in a service handler chain
    public void good_case_2() {
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ActivityHandler());
        chain.addHandler(new ServiceResponseHandler());
    }

    // Good case 3: Adding handlers to a list and then using them in correct order
    public void good_case_3() {
        List<ServiceHandler> handlers = new ArrayList<>();
        handlers.add(new ThrottlingHandler());
        handlers.add(new ActivityHandler());
        
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ok: java-throttling-handler-ordering
        for (ServiceHandler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    // Good case 4: Using a factory method with correct order
    public void good_case_4() {
        ServiceHandlerChainFactory factory = new ServiceHandlerChainFactory();
        // ok: java-throttling-handler-ordering
        factory.addHandler(new ThrottlingHandler());
        factory.addHandler(new ActivityHandler());
        ServiceHandlerChain chain = factory.createHandlerChain();
    }

    // Good case 5: Conditional addition of handlers with correct order
    public void good_case_5(boolean useThrottling) {
        HandlerChain chain = new HandlerChain();
        
        if (useThrottling) {
            // ok: java-throttling-handler-ordering
            chain.addHandler(new ThrottlingHandler());
        }
        
        chain.addHandler(new ActivityHandler());
    }

    // Good case 6: Using array of handlers with correct order
    public void good_case_6() {
        ServiceHandler[] handlers = new ServiceHandler[2];
        handlers[0] = new ThrottlingHandler();
        handlers[1] = new ActivityHandler();
        
        ServiceHandlerChain chain = new ServiceHandlerChain();
        // ok: java-throttling-handler-ordering
        for (ServiceHandler handler : handlers) {
            chain.addHandler(handler);
        }
    }

    // Good case 7: Creating custom handler chain with correct order
    public void good_case_7() {
        class CustomHandlerChain extends HandlerChain {
            public CustomHandlerChain() {
                super();
                // ok: java-throttling-handler-ordering
                addHandler(new ThrottlingHandler());
                addHandler(new ActivityHandler());
            }
        }
        
        CustomHandlerChain chain = new CustomHandlerChain();
    }

    // Good case 8: Using builder pattern with correct order
    public void good_case_8() {
        HandlerChain chain = new HandlerChain()
            // ok: java-throttling-handler-ordering
            .addHandler(new ThrottlingHandler())
            .addHandler(new ActivityHandler());
    }

    // Good case 9: No ActivityHandler used at all
    public void good_case_9() {
        HandlerChain chain = new HandlerChain();
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ServiceResponseHandler());
    }

    // Good case 10: No ThrottlingHandler used at all
    public void good_case_10() {
        HandlerChain chain = new HandlerChain();
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ServiceResponseHandler());
        chain.addHandler(new ActivityHandler());
    }

    // Good case 11: Multiple ThrottlingHandlers before ActivityHandler
    public void good_case_11() {
        HandlerChain chain = new HandlerChain();
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler("API"));
        chain.addHandler(new ThrottlingHandler("Database"));
        chain.addHandler(new ActivityHandler());
    }

    // Good case 12: Using reflection to add handlers with correct order
    public void good_case_12() throws Exception {
        HandlerChain chain = new HandlerChain();
        
        Class<?> throttlingHandlerClass = Class.forName("com.amazon.coral.handler.ThrottlingHandler");
        Class<?> activityHandlerClass = Class.forName("com.amazon.coral.handler.ActivityHandler");
        
        // ok: java-throttling-handler-ordering
        chain.addHandler((ServiceHandler) throttlingHandlerClass.newInstance());
        chain.addHandler((ServiceHandler) activityHandlerClass.newInstance());
    }

    // Good case 13: Using a switch statement with correct order
    public void good_case_13(int option) {
        HandlerChain chain = new HandlerChain();
        
        switch (option) {
            case 1:
                // ok: java-throttling-handler-ordering
                chain.addHandler(new ThrottlingHandler());
                chain.addHandler(new ActivityHandler());
                break;
            case 2:
                // Different handlers
                break;
            default:
                // Default handlers
        }
    }

    // Good case 14: Using a helper method with correct order
    public void good_case_14() {
        HandlerChain chain = configureHandlersCorrectly(new HandlerChain());
    }
    
    private HandlerChain configureHandlersCorrectly(HandlerChain chain) {
        // ok: java-throttling-handler-ordering
        chain.addHandler(new ThrottlingHandler());
        chain.addHandler(new ActivityHandler());
        return chain;
    }

    // Good case 15: Using a custom handler factory with correct order
    public void good_case_15() {
        class HandlerFactory {
            public HandlerChain createChain() {
                HandlerChain chain = new HandlerChain();
                // ok: java-throttling-handler-ordering
                chain.addHandler(new ThrottlingHandler());
                chain.addHandler(new ActivityHandler());
                return chain;
            }
        }
        
        HandlerFactory factory = new HandlerFactory();
        HandlerChain chain = factory.createChain();
    }
}
// {/fact}