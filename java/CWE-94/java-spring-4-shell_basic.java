package com.example.spring4shell;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;

import java.util.Properties;
import java.io.File;

// TRUE POSITIVES - Vulnerable code examples

/**
 * Example 1: Vulnerable Spring Boot application using Spring Framework 5.3.17
 * which is vulnerable to Spring4Shell
 */
@SpringBootApplication
public class bad_case_1 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties properties = new Properties();
        properties.setProperty("spring.version", "5.3.17");
        SpringApplication app = new SpringApplication(bad_case_1.class);
        app.setDefaultProperties(properties);
        app.run(args);
    }
}

/**
 * Example 2: Vulnerable Spring MVC application using Spring Framework 5.3.0
 */
@Configuration
@EnableWebMvc
public class bad_case_2 implements WebMvcConfigurer {
    // ruleid: java-spring-4-shell
    @Bean
    public InternalResourceViewResolver viewResolver() {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/WEB-INF/views/");
        resolver.setSuffix(".jsp");
        // Using vulnerable Spring version
        System.setProperty("spring.version", "5.3.0");
        return resolver;
    }
}

/**
 * Example 3: Vulnerable Spring Boot application with explicit dependency on Spring Framework 5.2.20
 */
@SpringBootApplication
public class bad_case_3 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(bad_case_3.class);
        Properties props = new Properties();
        props.setProperty("spring.framework.version", "5.2.20.RELEASE");
        app.setDefaultProperties(props);
        app.run(args);
    }
}

/**
 * Example 4: Vulnerable controller with Spring Framework 5.3.16
 */
@Controller
public class bad_case_4 {
    // ruleid: java-spring-4-shell
    @GetMapping("/users")
    public String getUsers() {
        System.setProperty("spring.version", "5.3.16");
        return "users";
    }
    
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
    }
}

/**
 * Example 5: Vulnerable Spring Boot application with pom.xml properties
 */
@SpringBootApplication
public class bad_case_5 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties properties = new Properties();
        properties.setProperty("spring.framework.version", "5.3.15");
        properties.setProperty("spring.boot.version", "2.6.3");
        SpringApplication app = new SpringApplication(bad_case_5.class);
        app.setDefaultProperties(properties);
        app.run(args);
    }
}

/**
 * Example 6: Vulnerable Spring MVC configuration with Spring 5.2.19
 */
@Configuration
@EnableWebMvc
public class bad_case_6 implements WebMvcConfigurer {
    // ruleid: java-spring-4-shell
    @Bean
    public InternalResourceViewResolver setupViewResolver() {
        System.setProperty("spring.version", "5.2.19.RELEASE");
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/WEB-INF/views/");
        resolver.setSuffix(".jsp");
        return resolver;
    }
}

/**
 * Example 7: Vulnerable Spring Boot application with explicit dependency version in build.gradle
 */
@SpringBootApplication
public class bad_case_7 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties props = new Properties();
        props.setProperty("spring.version", "5.3.10");
        props.setProperty("implementation", "org.springframework:spring-webmvc:5.3.10");
        SpringApplication.run(bad_case_7.class, args);
    }
}

/**
 * Example 8: Vulnerable Spring MVC controller with Spring 5.3.14
 */
@RestController
public class bad_case_8 {
    // ruleid: java-spring-4-shell
    @GetMapping("/api/data")
    public String getData() {
        System.setProperty("spring.framework.version", "5.3.14");
        return "Data from vulnerable Spring version";
    }
}

/**
 * Example 9: Vulnerable Spring Boot application with Maven dependency properties
 */
@SpringBootApplication
public class bad_case_9 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties mavenProps = new Properties();
        mavenProps.setProperty("spring-framework.version", "5.2.18.RELEASE");
        SpringApplication app = new SpringApplication(bad_case_9.class);
        app.setDefaultProperties(mavenProps);
        app.run(args);
    }
}

/**
 * Example 10: Vulnerable Spring WebFlux application
 */
@Configuration
public class bad_case_10 {
    // ruleid: java-spring-4-shell
    @Bean
    public String webFluxSetup() {
        System.setProperty("spring.version", "5.3.13");
        System.setProperty("spring.webflux.version", "5.3.13");
        return "webflux-setup";
    }
}

/**
 * Example 11: Vulnerable Spring Boot application with explicit version in application.properties
 */
@SpringBootApplication
public class bad_case_11 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties appProps = new Properties();
        appProps.setProperty("spring.version", "5.3.12");
        appProps.setProperty("spring.boot.version", "2.6.0");
        SpringApplication app = new SpringApplication(bad_case_11.class);
        app.setDefaultProperties(appProps);
        app.run(args);
    }
}

/**
 * Example 12: Vulnerable Spring MVC application with explicit dependency
 */
@Configuration
@EnableWebMvc
public class bad_case_12 {
    // ruleid: java-spring-4-shell
    @Bean
    public String mvcConfig() {
        System.setProperty("spring.framework.version", "5.3.11");
        System.setProperty("dependency.spring-webmvc", "5.3.11");
        return "mvc-config";
    }
}

/**
 * Example 13: Vulnerable Spring Boot application with Gradle dependency
 */
@SpringBootApplication
public class bad_case_13 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties gradleProps = new Properties();
        gradleProps.setProperty("springVersion", "5.3.9");
        gradleProps.setProperty("implementation", "org.springframework:spring-core:5.3.9");
        SpringApplication app = new SpringApplication(bad_case_13.class);
        app.setDefaultProperties(gradleProps);
        app.run(args);
    }
}

/**
 * Example 14: Vulnerable Spring MVC controller with explicit version
 */
@Controller
public class bad_case_14 {
    // ruleid: java-spring-4-shell
    @PostMapping("/submit")
    public String submitForm() {
        System.setProperty("spring.version", "5.3.8");
        return "success";
    }
    
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // Even with this mitigation, the version is still vulnerable
        binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
    }
}

/**
 * Example 15: Vulnerable Spring Boot application with explicit dependency in build file
 */
@SpringBootApplication
public class bad_case_15 {
    // ruleid: java-spring-4-shell
    public static void main(String[] args) {
        Properties buildProps = new Properties();
        buildProps.setProperty("spring-framework.version", "5.3.7");
        buildProps.setProperty("spring-boot.version", "2.5.12");
        SpringApplication app = new SpringApplication(bad_case_15.class);
        app.setDefaultProperties(buildProps);
        app.run(args);
    }
}

// TRUE NEGATIVES - Safe code examples

/**
 * Example 1: Safe Spring Boot application using patched Spring Framework 5.3.18
 */
@SpringBootApplication
public class good_case_1 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties properties = new Properties();
        properties.setProperty("spring.version", "5.3.18");
        SpringApplication app = new SpringApplication(good_case_1.class);
        app.setDefaultProperties(properties);
        app.run(args);
    }
}

/**
 * Example 2: Safe Spring MVC application using patched Spring Framework 5.3.20
 */
@Configuration
@EnableWebMvc
public class good_case_2 implements WebMvcConfigurer {
    // ok: java-spring-4-shell
    @Bean
    public InternalResourceViewResolver viewResolver() {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/WEB-INF/views/");
        resolver.setSuffix(".jsp");
        // Using patched Spring version
        System.setProperty("spring.version", "5.3.20");
        return resolver;
    }
}

/**
 * Example 3: Safe Spring Boot application with explicit dependency on patched Spring Framework 5.2.21
 */
@SpringBootApplication
public class good_case_3 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(good_case_3.class);
        Properties props = new Properties();
        props.setProperty("spring.framework.version", "5.2.21.RELEASE");
        app.setDefaultProperties(props);
        app.run(args);
    }
}

/**
 * Example 4: Safe controller with patched Spring Framework 5.3.19
 */
@Controller
public class good_case_4 {
    // ok: java-spring-4-shell
    @GetMapping("/users")
    public String getUsers() {
        System.setProperty("spring.version", "5.3.19");
        return "users";
    }
    
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
    }
}

/**
 * Example 5: Safe Spring Boot application with patched version in pom.xml properties
 */
@SpringBootApplication
public class good_case_5 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties properties = new Properties();
        properties.setProperty("spring.framework.version", "5.3.22");
        properties.setProperty("spring.boot.version", "2.7.0");
        SpringApplication app = new SpringApplication(good_case_5.class);
        app.setDefaultProperties(properties);
        app.run(args);
    }
}

/**
 * Example 6: Safe Spring MVC configuration with Spring 5.2.22
 */
@Configuration
@EnableWebMvc
public class good_case_6 implements WebMvcConfigurer {
    // ok: java-spring-4-shell
    @Bean
    public InternalResourceViewResolver setupViewResolver() {
        System.setProperty("spring.version", "5.2.22.RELEASE");
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/WEB-INF/views/");
        resolver.setSuffix(".jsp");
        return resolver;
    }
}

/**
 * Example 7: Safe Spring Boot application with explicit dependency version in build.gradle
 */
@SpringBootApplication
public class good_case_7 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties props = new Properties();
        props.setProperty("spring.version", "5.3.24");
        props.setProperty("implementation", "org.springframework:spring-webmvc:5.3.24");
        SpringApplication.run(good_case_7.class, args);
    }
}

/**
 * Example 8: Safe Spring MVC controller with Spring 6.0.0
 */
@RestController
public class good_case_8 {
    // ok: java-spring-4-shell
    @GetMapping("/api/data")
    public String getData() {
        System.setProperty("spring.framework.version", "6.0.0");
        return "Data from safe Spring version";
    }
}

/**
 * Example 9: Safe Spring Boot application with Maven dependency properties
 */
@SpringBootApplication
public class good_case_9 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties mavenProps = new Properties();
        mavenProps.setProperty("spring-framework.version", "5.2.23.RELEASE");
        SpringApplication app = new SpringApplication(good_case_9.class);
        app.setDefaultProperties(mavenProps);
        app.run(args);
    }
}

/**
 * Example 10: Safe Spring WebFlux application
 */
@Configuration
public class good_case_10 {
    // ok: java-spring-4-shell
    @Bean
    public String webFluxSetup() {
        System.setProperty("spring.version", "5.3.23");
        System.setProperty("spring.webflux.version", "5.3.23");
        return "webflux-setup";
    }
}

/**
 * Example 11: Safe Spring Boot application with explicit version in application.properties
 */
@SpringBootApplication
public class good_case_11 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties appProps = new Properties();
        appProps.setProperty("spring.version", "5.3.25");
        appProps.setProperty("spring.boot.version", "2.7.5");
        SpringApplication app = new SpringApplication(good_case_11.class);
        app.setDefaultProperties(appProps);
        app.run(args);
    }
}

/**
 * Example 12: Safe Spring MVC application with explicit dependency
 */
@Configuration
@EnableWebMvc
public class good_case_12 {
    // ok: java-spring-4-shell
    @Bean
    public String mvcConfig() {
        System.setProperty("spring.framework.version", "6.0.3");
        System.setProperty("dependency.spring-webmvc", "6.0.3");
        return "mvc-config";
    }
}

/**
 * Example 13: Safe Spring Boot application with Gradle dependency
 */
@SpringBootApplication
public class good_case_13 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties gradleProps = new Properties();
        gradleProps.setProperty("springVersion", "5.3.26");
        gradleProps.setProperty("implementation", "org.springframework:spring-core:5.3.26");
        SpringApplication app = new SpringApplication(good_case_13.class);
        app.setDefaultProperties(gradleProps);
        app.run(args);
    }
}

/**
 * Example 14: Safe Spring MVC controller with explicit version and mitigation
 */
@Controller
public class good_case_14 {
    // ok: java-spring-4-shell
    @PostMapping("/submit")
    public String submitForm() {
        System.setProperty("spring.version", "5.3.21");
        return "success";
    }
    
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // Additional mitigation with patched version
        binder.setDisallowedFields("class.*", "Class.*", "*.class.*", "*.Class.*");
    }
}

/**
 * Example 15: Safe Spring Boot application with explicit dependency in build file
 */
@SpringBootApplication
public class good_case_15 {
    // ok: java-spring-4-shell
    public static void main(String[] args) {
        Properties buildProps = new Properties();
        buildProps.setProperty("spring-framework.version", "6.0.5");
        buildProps.setProperty("spring-boot.version", "3.0.3");
        SpringApplication app = new SpringApplication(good_case_15.class);
        app.setDefaultProperties(buildProps);
        app.run(args);
    }
}