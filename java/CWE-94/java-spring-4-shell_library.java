import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.context.annotation.*;
import org.springframework.stereotype.*;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.mvc.SimpleControllerHandlerAdapter;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.XmlWebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.view.freemarker.FreeMarkerViewResolver;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;
import org.springframework.web.servlet.view.tiles3.TilesConfigurer;
import org.springframework.web.servlet.view.tiles3.TilesViewResolver;
import org.springframework.web.servlet.view.groovy.GroovyMarkupConfigurer;
import org.springframework.web.servlet.view.groovy.GroovyMarkupViewResolver;
import org.springframework.web.servlet.view.script.ScriptTemplateConfigurer;
import org.springframework.web.servlet.view.script.ScriptTemplateViewResolver;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;
import org.springframework.web.servlet.view.xml.MarshallingView;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.web.servlet.view.document.AbstractPdfView;
import org.springframework.web.servlet.view.document.AbstractXlsView;
import org.springframework.web.servlet.view.feed.AbstractRssFeedView;
import org.springframework.web.servlet.view.feed.AbstractAtomFeedView;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

// Security Issue: Spring4Shell (CVE-2022-22965) - Remote Code Execution vulnerability in Spring Framework

// True Positive Examples (Vulnerable/Insecure Code)

public class Spring4ShellExamples {

    // Example 1: Basic Spring Boot application with vulnerable Spring Framework version
// {fact rule=autoescape-disabled@v1.0 defects=1}
    public static void bad_case_1() {
        // ruleid: java-spring-4-shell
        @SpringBootApplication
        public class VulnerableSpringBootApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.17 which is vulnerable to Spring4Shell
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.17");
                SpringApplication app = new SpringApplication(VulnerableSpringBootApp.class);
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 2: Spring MVC application with vulnerable version in web.xml
    public static void bad_case_2() {
        // ruleid: java-spring-4-shell
        public class VulnerableSpringMvcApp extends SpringBootServletInitializer {
            @Override
            protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
                // Using Spring Framework 5.3.0 which is vulnerable
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.0");
                application.properties(props);
                return application.sources(VulnerableSpringMvcApp.class);
            }
        }
    }

    // Example 3: Spring WebFlux application with vulnerable Spring Core version
    public static void bad_case_3() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableWebFluxConfig {
            @Bean
            public RouterFunction<?> routes() {
                // Using Spring Framework 5.2.19.RELEASE which is vulnerable
                System.setProperty("spring.framework.version", "5.2.19.RELEASE");
                return RouterFunctions.route()
                        .GET("/api", request -> ServerResponse.ok().body("Hello"))
                        .build();
            }
        }
    }

    // Example 4: Spring Data REST application with vulnerable version
    public static void bad_case_4() {
        // ruleid: java-spring-4-shell
        @SpringBootApplication
        public class VulnerableDataRestApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.16 which is vulnerable
                SpringApplication app = new SpringApplication(VulnerableDataRestApp.class);
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.16");
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 5: Spring Security application with vulnerable Spring Core
    public static void bad_case_5() {
        // ruleid: java-spring-4-shell
        @Configuration
        @EnableWebSecurity
        public class VulnerableSecurityConfig {
            @Bean
            public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                // Using Spring Framework 5.2.20.RELEASE which is vulnerable
                System.setProperty("spring.framework.version", "5.2.20.RELEASE");
                return http.authorizeRequests()
                        .anyRequest().authenticated()
                        .and().formLogin()
                        .and().build();
            }
        }
    }

    // Example 6: Spring Cloud application with vulnerable Spring Framework
    public static void bad_case_6() {
        // ruleid: java-spring-4-shell
        @SpringBootApplication
        @EnableDiscoveryClient
        public class VulnerableCloudApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.15 which is vulnerable
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.15");
                SpringApplication app = new SpringApplication(VulnerableCloudApp.class);
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 7: Spring Batch application with vulnerable version
    public static void bad_case_7() {
        // ruleid: java-spring-4-shell
        @Configuration
        @EnableBatchProcessing
        public class VulnerableBatchConfig {
            @Bean
            public Job importUserJob(JobBuilderFactory jobBuilderFactory) {
                // Using Spring Framework 5.3.14 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.14");
                return jobBuilderFactory.get("importUserJob")
                        .incrementer(new RunIdIncrementer())
                        .flow(step1())
                        .end()
                        .build();
            }
        }
    }

    // Example 8: Spring Integration application with vulnerable Spring Core
    public static void bad_case_8() {
        // ruleid: java-spring-4-shell
        @Configuration
        @EnableIntegration
        public class VulnerableIntegrationConfig {
            @Bean
            public IntegrationFlow integrationFlow() {
                // Using Spring Framework 5.3.13 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.13");
                return IntegrationFlows.from("inputChannel")
                        .handle(System.out::println)
                        .get();
            }
        }
    }

    // Example 9: Spring AMQP application with vulnerable version
    public static void bad_case_9() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableRabbitConfig {
            @Bean
            public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory() {
                // Using Spring Framework 5.3.12 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.12");
                SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
                factory.setConcurrentConsumers(3);
                factory.setMaxConcurrentConsumers(10);
                return factory;
            }
        }
    }

    // Example 10: Spring Kafka application with vulnerable Spring Core
    public static void bad_case_10() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableKafkaConfig {
            @Bean
            public ConsumerFactory<String, String> consumerFactory() {
                // Using Spring Framework 5.3.11 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.11");
                Map<String, Object> props = new HashMap<>();
                props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
                props.put(ConsumerConfig.GROUP_ID_CONFIG, "group");
                return new DefaultKafkaConsumerFactory<>(props);
            }
        }
    }

    // Example 11: Spring WebSocket application with vulnerable version
    public static void bad_case_11() {
        // ruleid: java-spring-4-shell
        @Configuration
        @EnableWebSocket
        public class VulnerableWebSocketConfig implements WebSocketConfigurer {
            @Override
            public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
                // Using Spring Framework 5.3.10 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.10");
                registry.addHandler(myHandler(), "/myHandler");
            }
        }
    }

    // Example 12: Spring JDBC application with vulnerable Spring Core
    public static void bad_case_12() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableJdbcConfig {
            @Bean
            public JdbcTemplate jdbcTemplate(DataSource dataSource) {
                // Using Spring Framework 5.3.9 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.9");
                return new JdbcTemplate(dataSource);
            }
        }
    }

    // Example 13: Spring JMS application with vulnerable version
    public static void bad_case_13() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableJmsConfig {
            @Bean
            public JmsTemplate jmsTemplate() {
                // Using Spring Framework 5.3.8 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.8");
                JmsTemplate template = new JmsTemplate();
                template.setConnectionFactory(connectionFactory());
                return template;
            }
        }
    }

    // Example 14: Spring OXM application with vulnerable Spring Core
    public static void bad_case_14() {
        // ruleid: java-spring-4-shell
        @Configuration
        public class VulnerableOxmConfig {
            @Bean
            public Jaxb2Marshaller marshaller() {
                // Using Spring Framework 5.3.7 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.7");
                Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
                marshaller.setPackagesToScan("com.example");
                return marshaller;
            }
        }
    }

    // Example 15: Spring Transaction application with vulnerable version
    public static void bad_case_15() {
        // ruleid: java-spring-4-shell
        @Configuration
        @EnableTransactionManagement
        public class VulnerableTransactionConfig {
            @Bean
            public PlatformTransactionManager transactionManager() {
                // Using Spring Framework 5.3.6 which is vulnerable
                System.setProperty("spring.framework.version", "5.3.6");
                return new DataSourceTransactionManager(dataSource());
            }
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Example 1: Spring Boot application with patched Spring Framework version
    public static void good_case_1() {
        // ok: java-spring-4-shell
        @SpringBootApplication
        public class SecureSpringBootApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.18 which is patched against Spring4Shell
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.18");
                SpringApplication app = new SpringApplication(SecureSpringBootApp.class);
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 2: Spring MVC application with patched version
    public static void good_case_2() {
        // ok: java-spring-4-shell
        public class SecureSpringMvcApp extends SpringBootServletInitializer {
            @Override
            protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
                // Using Spring Framework 5.3.20 which is patched
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.20");
                application.properties(props);
                return application.sources(SecureSpringMvcApp.class);
            }
        }
    }

    // Example 3: Spring WebFlux application with patched Spring Core version
    public static void good_case_3() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureWebFluxConfig {
            @Bean
            public RouterFunction<?> routes() {
                // Using Spring Framework 5.2.21.RELEASE which is patched
                System.setProperty("spring.framework.version", "5.2.21.RELEASE");
                return RouterFunctions.route()
                        .GET("/api", request -> ServerResponse.ok().body("Hello"))
                        .build();
            }
        }
    }

    // Example 4: Spring Data REST application with patched version
    public static void good_case_4() {
        // ok: java-spring-4-shell
        @SpringBootApplication
        public class SecureDataRestApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.19 which is patched
                SpringApplication app = new SpringApplication(SecureDataRestApp.class);
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.19");
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 5: Spring Security application with patched Spring Core
    public static void good_case_5() {
        // ok: java-spring-4-shell
        @Configuration
        @EnableWebSecurity
        public class SecureSecurityConfig {
            @Bean
            public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                // Using Spring Framework 5.2.22.RELEASE which is patched
                System.setProperty("spring.framework.version", "5.2.22.RELEASE");
                return http.authorizeRequests()
                        .anyRequest().authenticated()
                        .and().formLogin()
                        .and().build();
            }
        }
    }

    // Example 6: Spring Cloud application with patched Spring Framework
    public static void good_case_6() {
        // ok: java-spring-4-shell
        @SpringBootApplication
        @EnableDiscoveryClient
        public class SecureCloudApp {
            public static void main(String[] args) {
                // Using Spring Framework 5.3.21 which is patched
                Properties props = new Properties();
                props.setProperty("spring.framework.version", "5.3.21");
                SpringApplication app = new SpringApplication(SecureCloudApp.class);
                app.setDefaultProperties(props);
                app.run(args);
            }
        }
    }

    // Example 7: Spring Batch application with patched version
    public static void good_case_7() {
        // ok: java-spring-4-shell
        @Configuration
        @EnableBatchProcessing
        public class SecureBatchConfig {
            @Bean
            public Job importUserJob(JobBuilderFactory jobBuilderFactory) {
                // Using Spring Framework 5.3.22 which is patched
                System.setProperty("spring.framework.version", "5.3.22");
                return jobBuilderFactory.get("importUserJob")
                        .incrementer(new RunIdIncrementer())
                        .flow(step1())
                        .end()
                        .build();
            }
        }
    }

    // Example 8: Spring Integration application with patched Spring Core
    public static void good_case_8() {
        // ok: java-spring-4-shell
        @Configuration
        @EnableIntegration
        public class SecureIntegrationConfig {
            @Bean
            public IntegrationFlow integrationFlow() {
                // Using Spring Framework 5.3.23 which is patched
                System.setProperty("spring.framework.version", "5.3.23");
                return IntegrationFlows.from("inputChannel")
                        .handle(System.out::println)
                        .get();
            }
        }
    }

    // Example 9: Spring AMQP application with patched version
    public static void good_case_9() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureRabbitConfig {
            @Bean
            public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory() {
                // Using Spring Framework 5.3.24 which is patched
                System.setProperty("spring.framework.version", "5.3.24");
                SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
                factory.setConcurrentConsumers(3);
                factory.setMaxConcurrentConsumers(10);
                return factory;
            }
        }
    }

    // Example 10: Spring Kafka application with patched Spring Core
    public static void good_case_10() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureKafkaConfig {
            @Bean
            public ConsumerFactory<String, String> consumerFactory() {
                // Using Spring Framework 6.0.0 which is patched
                System.setProperty("spring.framework.version", "6.0.0");
                Map<String, Object> props = new HashMap<>();
                props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
                props.put(ConsumerConfig.GROUP_ID_CONFIG, "group");
                return new DefaultKafkaConsumerFactory<>(props);
            }
        }
    }

    // Example 11: Spring WebSocket application with patched version
    public static void good_case_11() {
        // ok: java-spring-4-shell
        @Configuration
        @EnableWebSocket
        public class SecureWebSocketConfig implements WebSocketConfigurer {
            @Override
            public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
                // Using Spring Framework 6.0.1 which is patched
                System.setProperty("spring.framework.version", "6.0.1");
                registry.addHandler(myHandler(), "/myHandler");
            }
        }
    }

    // Example 12: Spring JDBC application with patched Spring Core
    public static void good_case_12() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureJdbcConfig {
            @Bean
            public JdbcTemplate jdbcTemplate(DataSource dataSource) {
                // Using Spring Framework 6.0.2 which is patched
                System.setProperty("spring.framework.version", "6.0.2");
                return new JdbcTemplate(dataSource);
            }
        }
    }

    // Example 13: Spring JMS application with patched version
    public static void good_case_13() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureJmsConfig {
            @Bean
            public JmsTemplate jmsTemplate() {
                // Using Spring Framework 6.0.3 which is patched
                System.setProperty("spring.framework.version", "6.0.3");
                JmsTemplate template = new JmsTemplate();
                template.setConnectionFactory(connectionFactory());
                return template;
            }
        }
    }

    // Example 14: Spring OXM application with patched Spring Core
    public static void good_case_14() {
        // ok: java-spring-4-shell
        @Configuration
        public class SecureOxmConfig {
            @Bean
            public Jaxb2Marshaller marshaller() {
                // Using Spring Framework 6.0.4 which is patched
                System.setProperty("spring.framework.version", "6.0.4");
                Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
                marshaller.setPackagesToScan("com.example");
                return marshaller;
            }
        }
    }

    // Example 15: Spring Transaction application with patched version
    public static void good_case_15() {
        // ok: java-spring-4-shell
        @Configuration
        @EnableTransactionManagement
        public class SecureTransactionConfig {
            @Bean
            public PlatformTransactionManager transactionManager() {
                // Using Spring Framework 6.0.5 which is patched
                System.setProperty("spring.framework.version", "6.0.5");
                return new DataSourceTransactionManager(dataSource());
            }
        }
    }
}
// {/fact}