package com.example.metrics;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Examples for improper metrics instantiation vulnerability detection
 * Rule ID: java-coral-improper-metrics-instantiation
 */

// A basic MetricsFactory class for demonstration
class MetricsFactory {
    private Map<String, Object> metrics;
    
    public MetricsFactory() {
        this.metrics = new HashMap<>();
    }
    
    public void recordMetric(String name, Object value) {
        metrics.put(name, value);
    }
    
    public Map<String, Object> getMetrics() {
        return metrics;
    }
}

// Enhanced MetricsFactory with more realistic features
class EnhancedMetricsFactory {
    private Map<String, Object> metrics;
    private String environment;
    
    public EnhancedMetricsFactory(String environment) {
        this.metrics = new ConcurrentHashMap<>();
        this.environment = environment;
    }
    
    public void recordMetric(String name, Object value) {
        metrics.put(name + "_" + environment, value);
    }
    
    public Map<String, Object> getMetrics() {
        return metrics;
    }
}

@RestController
public class MetricsExamples {

    // BAD EXAMPLES - MetricsFactory not implemented as singleton

// {fact rule=resource-leak@v1.0 defects=1}
    public MetricsFactory bad_case_1() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new MetricsFactory();
    }
    
    @GetMapping("/metrics/bad2")
    public MetricsFactory bad_case_2(HttpServletRequest request) {
        String clientId = request.getParameter("clientId");
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        factory.recordMetric("client_access", clientId);
        return factory;
    }
    
    public EnhancedMetricsFactory bad_case_3() {
        String env = System.getProperty("app.environment", "production");
        // ruleid: java-coral-improper-metrics-instantiation
        return new EnhancedMetricsFactory(env);
    }
    
    @GetMapping("/metrics/bad4")
    public MetricsFactory bad_case_4(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-cache");
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory metricsFactory = new MetricsFactory();
        metricsFactory.recordMetric("api_call", System.currentTimeMillis());
        return metricsFactory;
    }
    
    public MetricsFactory bad_case_5(String appName) {
        if (appName == null || appName.isEmpty()) {
            appName = "default";
        }
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        factory.recordMetric("app_name", appName);
        return factory;
    }
    
    public MetricsFactory bad_case_6(boolean isDebug) {
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        if (isDebug) {
            factory.recordMetric("debug_mode", true);
        }
        return factory;
    }
    
    @GetMapping("/metrics/bad7")
    public EnhancedMetricsFactory bad_case_7(HttpServletRequest request) {
        String env = request.getParameter("env");
        if (env == null) {
            env = "production";
        }
        // ruleid: java-coral-improper-metrics-instantiation
        return new EnhancedMetricsFactory(env);
    }
    
    public MetricsFactory bad_case_8() {
        try {
            // Some operation that might fail
            int result = 10 / 0;
            return null;
        } catch (Exception e) {
            // ruleid: java-coral-improper-metrics-instantiation
            MetricsFactory errorMetrics = new MetricsFactory();
            errorMetrics.recordMetric("error", e.getMessage());
            return errorMetrics;
        }
    }
    
    public MetricsFactory bad_case_9(Map<String, String> config) {
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        for (Map.Entry<String, String> entry : config.entrySet()) {
            factory.recordMetric("config_" + entry.getKey(), entry.getValue());
        }
        return factory;
    }
    
    @GetMapping("/metrics/bad10")
    public MetricsFactory bad_case_10(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("userId");
        response.setHeader("X-User-ID", userId);
        
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory metrics = new MetricsFactory();
        metrics.recordMetric("user_access", userId);
        metrics.recordMetric("access_time", System.currentTimeMillis());
        return metrics;
    }
    
    public EnhancedMetricsFactory bad_case_11(String[] environments) {
        String env = environments.length > 0 ? environments[0] : "default";
        // ruleid: java-coral-improper-metrics-instantiation
        EnhancedMetricsFactory factory = new EnhancedMetricsFactory(env);
        factory.recordMetric("startup_time", System.currentTimeMillis());
        return factory;
    }
    
    public MetricsFactory bad_case_12() {
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        Thread metricUpdater = new Thread(() -> {
            while (true) {
                factory.recordMetric("heartbeat", System.currentTimeMillis());
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        metricUpdater.start();
        return factory;
    }
    
    @GetMapping("/metrics/bad13")
    public MetricsFactory bad_case_13(HttpServletRequest request) {
        String action = request.getParameter("action");
        switch (action) {
            case "start":
                // ruleid: java-coral-improper-metrics-instantiation
                MetricsFactory startMetrics = new MetricsFactory();
                startMetrics.recordMetric("start_time", System.currentTimeMillis());
                return startMetrics;
            case "stop":
                // ruleid: java-coral-improper-metrics-instantiation
                MetricsFactory stopMetrics = new MetricsFactory();
                stopMetrics.recordMetric("stop_time", System.currentTimeMillis());
                return stopMetrics;
            default:
                // ruleid: java-coral-improper-metrics-instantiation
                return new MetricsFactory();
        }
    }
    
    public MetricsFactory bad_case_14(int threshold) {
        // ruleid: java-coral-improper-metrics-instantiation
        MetricsFactory factory = new MetricsFactory();
        for (int i = 0; i < threshold; i++) {
            factory.recordMetric("iteration_" + i, i * i);
        }
        return factory;
    }
    
    public EnhancedMetricsFactory bad_case_15(String environment, boolean isProduction) {
        String env = isProduction ? "production" : environment;
        // ruleid: java-coral-improper-metrics-instantiation
        EnhancedMetricsFactory factory = new EnhancedMetricsFactory(env);
        factory.recordMetric("is_production", isProduction);
        return factory;
    }

    // GOOD EXAMPLES - MetricsFactory implemented as singleton

    // Singleton implementation with lazy initialization
    private static MetricsFactory instance = null;
    
    public MetricsFactory good_case_1() {
        // ok: java-coral-improper-metrics-instantiation
        if (instance == null) {
            instance = new MetricsFactory();
        }
        return instance;
    }
    
    // Singleton with double-checked locking
    private static volatile MetricsFactory factoryInstance;
    
    public MetricsFactory good_case_2() {
        if (factoryInstance == null) {
            synchronized (MetricsExamples.class) {
                // ok: java-coral-improper-metrics-instantiation
                if (factoryInstance == null) {
                    factoryInstance = new MetricsFactory();
                }
            }
        }
        return factoryInstance;
    }
    
    // Singleton using enum
    public enum MetricsFactorySingleton {
        INSTANCE;
        
        private final MetricsFactory factory;
        
        MetricsFactorySingleton() {
            factory = new MetricsFactory();
        }
        
        public MetricsFactory getFactory() {
            return factory;
        }
    }
    
    public MetricsFactory good_case_3() {
        // ok: java-coral-improper-metrics-instantiation
        return MetricsFactorySingleton.INSTANCE.getFactory();
    }
    
    // Singleton with static initialization
    private static final MetricsFactory METRICS_FAC_REDACTED_TWILIO_ID = new MetricsFactory();
    
    public MetricsFactory good_case_4() {
        // ok: java-coral-improper-metrics-instantiation
        return METRICS_FAC_REDACTED_TWILIO_ID;
    }
    
    // Singleton with holder pattern
    private static class MetricsFactoryHolder {
        private static final MetricsFactory INSTANCE = new MetricsFactory();
    }
    
    public MetricsFactory good_case_5() {
        // ok: java-coral-improper-metrics-instantiation
        return MetricsFactoryHolder.INSTANCE;
    }
    
    // Environment-specific singleton
    private static final Map<String, EnhancedMetricsFactory> ENV_FAC_REDACTED_TWILIO_ID = new HashMap<>();
    
    public EnhancedMetricsFactory good_case_6(String environment) {
        // ok: java-coral-improper-metrics-instantiation
        return ENV_FAC_REDACTED_TWILIO_ID.computeIfAbsent(environment, EnhancedMetricsFactory::new);
    }
    
    // Singleton with initialization in constructor
    private final MetricsFactory constructorInitializedFactory;
    
    public MetricsExamples() {
        this.constructorInitializedFactory = new MetricsFactory();
    }
    
    public MetricsFactory good_case_7() {
        // ok: java-coral-improper-metrics-instantiation
        return constructorInitializedFactory;
    }
    
    // Dependency injection approach
    private final MetricsFactory injectedFactory;
    
    public MetricsExamples(MetricsFactory factory) {
        this.injectedFactory = factory;
    }
    
    public MetricsFactory good_case_8() {
        // ok: java-coral-improper-metrics-instantiation
        return injectedFactory;
    }
    
    // Factory method pattern with singleton
    private static MetricsFactory createOrGetInstance() {
        if (instance == null) {
            instance = new MetricsFactory();
        }
        return instance;
    }
    
    public MetricsFactory good_case_9() {
        // ok: java-coral-improper-metrics-instantiation
        return createOrGetInstance();
    }
    
    // Thread-safe initialization with AtomicReference
    private static final java.util.concurrent.atomic.AtomicReference<MetricsFactory> atomicInstance = 
        new java.util.concurrent.atomic.AtomicReference<>();
    
    public MetricsFactory good_case_10() {
        // ok: java-coral-improper-metrics-instantiation
        if (atomicInstance.get() == null) {
            atomicInstance.compareAndSet(null, new MetricsFactory());
        }
        return atomicInstance.get();
    }
    
    // Spring-style bean singleton
    @org.springframework.context.annotation.Bean
    @org.springframework.context.annotation.Scope("singleton")
    public MetricsFactory good_case_11() {
        // ok: java-coral-improper-metrics-instantiation
        return new MetricsFactory();
    }
    
    // Using a registry for singletons
    private static final Map<Class<?>, Object> REGISTRY = new HashMap<>();
    
    @SuppressWarnings("unchecked")
    public <T> T getSingleton(Class<T> clazz) {
        if (!REGISTRY.containsKey(clazz)) {
            try {
                REGISTRY.put(clazz, clazz.getDeclaredConstructor().newInstance());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return (T) REGISTRY.get(clazz);
    }
    
    public MetricsFactory good_case_12() {
        // ok: java-coral-improper-metrics-instantiation
        return getSingleton(MetricsFactory.class);
    }
    
    // Singleton with lazy holder idiom
    private static class LazyHolder {
        static final MetricsFactory INSTANCE = new MetricsFactory();
    }
    
    public MetricsFactory good_case_13() {
        // ok: java-coral-improper-metrics-instantiation
        return LazyHolder.INSTANCE;
    }
    
    // Using a supplier for singleton
    private static java.util.function.Supplier<MetricsFactory> factorySupplier = new java.util.function.Supplier<MetricsFactory>() {
        private MetricsFactory instance;
        
        @Override
        public MetricsFactory get() {
            if (instance == null) {
                instance = new MetricsFactory();
            }
            return instance;
        }
    };
    
    public MetricsFactory good_case_14() {
        // ok: java-coral-improper-metrics-instantiation
        return factorySupplier.get();
    }
    
    // Using a service locator pattern
    public static class ServiceLocator {
        private static final Map<String, Object> services = new HashMap<>();
        
        static {
            services.put("metricsFactory", new MetricsFactory());
        }
        
        @SuppressWarnings("unchecked")
        public static <T> T getService(String name) {
            return (T) services.get(name);
        }
    }
    
    public MetricsFactory good_case_15() {
        // ok: java-coral-improper-metrics-instantiation
        return ServiceLocator.getService("metricsFactory");
    }
}
// {/fact}