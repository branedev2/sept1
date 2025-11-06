package com.example.corsconfig;

import org.springframework.web.bind.annotation.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;

public class CorsConfigurationExamples {

    // True Positive Examples (Vulnerable Code)

    @Configuration
    public static class bad_case_1 {
        @Bean
        public WebMvcConfigurer corsConfigurer() {
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    // ruleid: java-permissive-cors-configuration
                    registry.addMapping("/**")
                           .allowedOrigins("*")
                           .allowedMethods("GET", "POST", "PUT", "DELETE");
                }
            };
        }
    }

    @Configuration
    public static class bad_case_2 {
        @Bean
        public CorsFilter corsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            config.setAllowedOrigins(Collections.singletonList("*"));
            config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            source.registerCorsConfiguration("/**", config);
            return new CorsFilter(source);
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class bad_case_3 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ruleid: java-permissive-cors-configuration
            http.cors().configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.addAllowedOrigin("*");
                config.addAllowedHeader("*");
                config.addAllowedMethod("*");
                return config;
            });
        }
    }

    @RestController
    public static class bad_case_4 {
        @CrossOrigin(origins = "*")  // ruleid: java-permissive-cors-configuration
        @GetMapping("/api/users")
        public String getUsers() {
            return "User data";
        }
    }

    @Configuration
    public static class bad_case_5 {
        @Bean
        public FilterRegistrationBean<CorsFilter> simpleCorsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            config.addAllowedOrigin("*");
            config.setAllowCredentials(true);
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            source.registerCorsConfiguration("/**", config);
            FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
            bean.setOrder(0);
            return bean;
        }
    }

    @RestController
    public static class bad_case_6 {
        @RequestMapping("/api/data")
        public ResponseEntity<String> getData(HttpServletResponse response) {
            // ruleid: java-permissive-cors-configuration
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            return ResponseEntity.ok("Data");
        }
    }

    @Configuration
    @EnableWebMvc
    public static class bad_case_7 implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ruleid: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                   .allowedOrigins("*")
                   .allowedMethods("*")
                   .allowedHeaders("*")
                   .allowCredentials(true);
        }
    }

    @Configuration
    public static class bad_case_8 {
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            configuration.addAllowedOriginPattern("*");
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }
    }

    @RestController
    public static class bad_case_9 {
        @RequestMapping("/api/products")
        public String getProducts(HttpServletResponse response) {
            // ruleid: java-permissive-cors-configuration
            response.addHeader("Access-Control-Allow-Origin", "*");
            response.addHeader("Access-Control-Allow-Headers", "Content-Type");
            return "Product data";
        }
    }

    @Configuration
    public static class bad_case_10 extends WebMvcConfigurerAdapter {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ruleid: java-permissive-cors-configuration
            registry.addMapping("/**").allowedOriginPatterns("*");
        }
    }

    @RestController
    public static class bad_case_11 {
        @GetMapping("/api/orders")
        public ResponseEntity<String> getOrders() {
            HttpHeaders headers = new HttpHeaders();
            // ruleid: java-permissive-cors-configuration
            headers.add("Access-Control-Allow-Origin", "*");
            headers.add("Access-Control-Allow-Methods", "GET, POST");
            return ResponseEntity.ok().headers(headers).body("Order data");
        }
    }

    @Configuration
    public static class bad_case_12 {
        @Bean
        public WebMvcConfigurer corsConfig() {
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    // ruleid: java-permissive-cors-configuration
                    registry.addMapping("/api/v1/**")
                           .allowedOrigins("*")
                           .allowedMethods("GET", "POST", "PUT")
                           .maxAge(3600);
                }
            };
        }
    }

    @RestController
    public static class bad_case_13 {
        @CrossOrigin  // Default is "*" for origins
        // ruleid: java-permissive-cors-configuration
        @GetMapping("/api/customers")
        public String getCustomers() {
            return "Customer data";
        }
    }

    @Configuration
    public static class bad_case_14 {
        @Bean
        public CorsFilter customCorsFilter() {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            corsConfiguration.setAllowedOriginPatterns(Collections.singletonList("*"));
            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "HEAD"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", corsConfiguration);
            return new CorsFilter(source);
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class bad_case_15 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            corsConfiguration.addAllowedOrigin("*");
            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            
            http.cors().configurationSource(request -> corsConfiguration);
        }
    }

    // True Negative Examples (Secure Code)

    @Configuration
    public static class good_case_1 {
        @Bean
        public WebMvcConfigurer corsConfigurer() {
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    // ok: java-permissive-cors-configuration
                    registry.addMapping("/**")
                           .allowedOrigins("https://example.com", "https://subdomain.example.com")
                           .allowedMethods("GET", "POST", "PUT", "DELETE");
                }
            };
        }
    }

    @Configuration
    public static class good_case_2 {
        @Bean
        public CorsFilter corsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            config.setAllowedOrigins(Arrays.asList("https://example.com", "https://api.example.com"));
            config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            source.registerCorsConfiguration("/**", config);
            return new CorsFilter(source);
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class good_case_3 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ok: java-permissive-cors-configuration
            http.cors().configurationSource(request -> {
                CorsConfiguration config = new CorsConfiguration();
                config.addAllowedOrigin("https://trusted-site.com");
                config.addAllowedHeader("Content-Type");
                config.addAllowedMethod("GET");
                return config;
            });
        }
    }

    @RestController
    public static class good_case_4 {
        @CrossOrigin(origins = "https://example.com")  // ok: java-permissive-cors-configuration
        @GetMapping("/api/users")
        public String getUsers() {
            return "User data";
        }
    }

    @Configuration
    public static class good_case_5 {
        @Bean
        public FilterRegistrationBean<CorsFilter> simpleCorsFilter() {
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            CorsConfiguration config = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            config.addAllowedOrigin("https://example.org");
            config.setAllowCredentials(true);
            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            source.registerCorsConfiguration("/**", config);
            FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
            bean.setOrder(0);
            return bean;
        }
    }

    @RestController
    public static class good_case_6 {
        @RequestMapping("/api/data")
        public ResponseEntity<String> getData(HttpServletResponse response) {
            // ok: java-permissive-cors-configuration
            response.setHeader("Access-Control-Allow-Origin", "https://trusted-domain.com");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST");
            return ResponseEntity.ok("Data");
        }
    }

    @Configuration
    @EnableWebMvc
    public static class good_case_7 implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ok: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                   .allowedOrigins("https://app.example.com", "https://admin.example.com")
                   .allowedMethods("GET", "POST")
                   .allowedHeaders("Authorization")
                   .allowCredentials(true);
        }
    }

    @Configuration
    public static class good_case_8 {
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            configuration.setAllowedOrigins(Arrays.asList("https://example.com", "https://api.example.com"));
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }
    }

    @RestController
    public static class good_case_9 {
        @RequestMapping("/api/products")
        public String getProducts(HttpServletResponse response) {
            // ok: java-permissive-cors-configuration
            response.addHeader("Access-Control-Allow-Origin", "https://shop.example.com");
            response.addHeader("Access-Control-Allow-Headers", "Content-Type");
            return "Product data";
        }
    }

    @Configuration
    public static class good_case_10 extends WebMvcConfigurerAdapter {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ok: java-permissive-cors-configuration
            registry.addMapping("/**")
                   .allowedOriginPatterns("https://*.example.com")
                   .allowedMethods("GET");
        }
    }

    @RestController
    public static class good_case_11 {
        @GetMapping("/api/orders")
        public ResponseEntity<String> getOrders() {
            HttpHeaders headers = new HttpHeaders();
            // ok: java-permissive-cors-configuration
            headers.add("Access-Control-Allow-Origin", "https://orders.example.com");
            headers.add("Access-Control-Allow-Methods", "GET");
            return ResponseEntity.ok().headers(headers).body("Order data");
        }
    }

    @Configuration
    public static class good_case_12 {
        @Bean
        public WebMvcConfigurer corsConfig() {
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    // ok: java-permissive-cors-configuration
                    registry.addMapping("/api/v1/**")
                           .allowedOrigins("https://client.example.com")
                           .allowedMethods("GET", "POST")
                           .maxAge(3600);
                }
            };
        }
    }

    @RestController
    public static class good_case_13 {
        @CrossOrigin(origins = {"https://app1.example.com", "https://app2.example.com"})  // ok: java-permissive-cors-configuration
        @GetMapping("/api/customers")
        public String getCustomers() {
            return "Customer data";
        }
    }

    @Configuration
    public static class good_case_14 {
        @Bean
        public CorsFilter customCorsFilter() {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            corsConfiguration.setAllowedOrigins(Collections.singletonList("https://dashboard.example.com"));
            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "HEAD"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", corsConfiguration);
            return new CorsFilter(source);
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class good_case_15 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            corsConfiguration.setAllowedOrigins(Arrays.asList("https://admin.example.com", "https://staff.example.com"));
            corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST"));
            
            http.cors().configurationSource(request -> corsConfiguration);
        }
    }
}