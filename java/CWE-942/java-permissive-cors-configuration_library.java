import org.springframework.web.bind.annotation.*;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;
import org.springframework.web.cors.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import com.google.common.net.HttpHeaders;
import org.apache.catalina.filters.CorsFilter as CatalinaFilter;
import org.eclipse.jetty.servlets.CrossOriginFilter;
import org.jboss.resteasy.plugins.interceptors.CorsFilter as ResteasyCorsFilter;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.core.Vertx;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import ratpack.handling.Handler;
import ratpack.handling.Context;
import spark.Spark;
import play.mvc.Result;
import play.mvc.Controller as PlayController;
import play.mvc.Http.Request;
import play.mvc.Http.Response;
import play.filters.cors.CORSFilter;
import play.filters.cors.CORSConfig;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

// Security Issue: Cross-Origin Resource Sharing (CORS) misconfiguration with wildcard origins

// True Positive Examples (Vulnerable/Insecure Code)

// Spring Web MVC CORS Configuration
public class bad_case_1 {
    @Configuration
    public class WebConfig implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ruleid: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*");
        }
    }
}

// Spring Security CORS Configuration
public class bad_case_2 {
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ruleid: java-permissive-cors-configuration
            http.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and().csrf().disable();
        }
        
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            // ruleid: java-permissive-cors-configuration
            configuration.setAllowedOrigins(Arrays.asList("*"));
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            configuration.setAllowedHeaders(Arrays.asList("*"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }
    }
}

// Spring Boot CorsFilter Registration
public class bad_case_3 {
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // ruleid: java-permissive-cors-configuration
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }
}

// Servlet Filter CORS Implementation
public class bad_case_4 {
    @WebFilter(urlPatterns = "/*")
    public class MyCorsFilter implements Filter {
        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) 
                throws IOException, ServletException {
            HttpServletResponse response = (HttpServletResponse) res;
            // ruleid: java-permissive-cors-configuration
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            response.setHeader("Access-Control-Allow-Headers", "*");
            response.setHeader("Access-Control-Max-Age", "3600");
            chain.doFilter(req, res);
        }
    }
}

// Apache Tomcat Catalina CORS Filter
public class bad_case_5 {
    @Bean
    public FilterRegistrationBean<CatalinaFilter> corsFilterRegistration() {
        FilterRegistrationBean<CatalinaFilter> registrationBean = new FilterRegistrationBean<>();
        CatalinaFilter corsFilter = new CatalinaFilter();
        // ruleid: java-permissive-cors-configuration
        corsFilter.setInitParameter("cors.allowed.origins", "*");
        corsFilter.setInitParameter("cors.allowed.methods", "GET,POST,PUT,DELETE,OPTIONS");
        corsFilter.setInitParameter("cors.allowed.headers", "*");
        registrationBean.setFilter(corsFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}

// Jetty CrossOriginFilter Configuration
public class bad_case_6 {
    @Bean
    public FilterRegistrationBean<CrossOriginFilter> corsFilterRegistration() {
        FilterRegistrationBean<CrossOriginFilter> registrationBean = new FilterRegistrationBean<>();
        CrossOriginFilter corsFilter = new CrossOriginFilter();
        // ruleid: java-permissive-cors-configuration
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, "*");
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, "GET,POST,PUT,DELETE,OPTIONS");
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, "*");
        registrationBean.setFilter(corsFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}

// RESTEasy CORS Filter Configuration
public class bad_case_7 {
    @Bean
    public ResteasyCorsFilter corsFilter() {
        ResteasyCorsFilter corsFilter = new ResteasyCorsFilter();
        // ruleid: java-permissive-cors-configuration
        corsFilter.getAllowedOrigins().add("*");
        corsFilter.setAllowedMethods("GET, POST, PUT, DELETE, OPTIONS");
        corsFilter.setAllowedHeaders("*");
        return corsFilter;
    }
}

// Vert.x CORS Handler Configuration
public class bad_case_8 {
    public void configureRouter(Vertx vertx) {
        Router router = Router.router(vertx);
        
        // ruleid: java-permissive-cors-configuration
        router.route().handler(CorsHandler.create("*")
            .allowedMethods(new HashSet<>(Arrays.asList(
                HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE)))
            .allowedHeaders(new HashSet<>(Arrays.asList(
                "Content-Type", "Authorization")))
            .allowCredentials(true));
        
        // Rest of the router configuration
    }
}

// Micronaut CORS Response Headers
public class bad_case_9 {
    @Controller("/api")
    public class ApiController {
        @Get("/data")
        public HttpResponse<String> getData() {
            MutableHttpResponse<String> response = HttpResponse.ok("Data");
            // ruleid: java-permissive-cors-configuration
            response.header("Access-Control-Allow-Origin", "*");
            response.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            response.header("Access-Control-Allow-Headers", "*");
            return response;
        }
    }
}

// Ratpack CORS Handler
public class bad_case_10 {
    public Handler corsHandler() {
        return ctx -> {
            Context context = ctx;
            // ruleid: java-permissive-cors-configuration
            context.getResponse().getHeaders().add("Access-Control-Allow-Origin", "*");
            context.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            context.getResponse().getHeaders().add("Access-Control-Allow-Headers", "*");
            context.next();
        };
    }
}

// Spark Framework CORS Configuration
public class bad_case_11 {
    public void configureCors() {
        // ruleid: java-permissive-cors-configuration
        Spark.options("/*", (request, response) -> {
            String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                response.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
            }
            
            String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                response.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }
            
            response.header("Access-Control-Allow-Origin", "*");
            return "OK";
        });
        
        Spark.before((request, response) -> {
            // ruleid: java-permissive-cors-configuration
            response.header("Access-Control-Allow-Origin", "*");
        });
    }
}

// Play Framework CORS Filter Configuration
public class bad_case_12 {
    @Bean
    public CORSFilter corsFilter() {
        CORSConfig corsConfig = new CORSConfig();
        // ruleid: java-permissive-cors-configuration
        corsConfig.setAllowedOrigins(Collections.singletonList("*"));
        corsConfig.setAllowedHttpMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        corsConfig.setAllowedHttpHeaders(Collections.singletonList("*"));
        return new CORSFilter(corsConfig);
    }
}

// HttpServlet CORS Implementation
public class bad_case_13 {
    @WebServlet("/api/*")
    public class ApiServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
                throws ServletException, IOException {
            // ruleid: java-permissive-cors-configuration
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            resp.setHeader("Access-Control-Allow-Headers", "*");
            
            // Process the request
            resp.getWriter().write("API response");
        }
        
        @Override
        protected void doOptions(HttpServletRequest req, HttpServletResponse resp) 
                throws ServletException, IOException {
            // ruleid: java-permissive-cors-configuration
            resp.setHeader("Access-Control-Allow-Origin", "*");
            resp.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
            resp.setHeader("Access-Control-Allow-Headers", "*");
            resp.setStatus(HttpServletResponse.SC_OK);
        }
    }
}

// JAX-RS ContainerResponseFilter for CORS
public class bad_case_14 {
    @Provider
    public class CorsFilter implements ContainerResponseFilter {
        @Override
        public void filter(ContainerRequestContext requestContext, 
                          ContainerResponseContext responseContext) throws IOException {
            // ruleid: java-permissive-cors-configuration
            responseContext.getHeaders().add("Access-Control-Allow-Origin", "*");
            responseContext.getHeaders().add("Access-Control-Allow-Methods", 
                "GET, POST, PUT, DELETE, OPTIONS");
            responseContext.getHeaders().add("Access-Control-Allow-Headers", "*");
        }
    }
}

// Spring WebFlux CORS Configuration
public class bad_case_15 {
    @Configuration
    public class WebFluxConfig implements WebFluxConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ruleid: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*");
        }
    }
}

// True Negative Examples (Safe/Secure Code)

// Spring Web MVC CORS Configuration - Secure
public class good_case_1 {
    @Configuration
    public class WebConfig implements WebMvcConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ok: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                .allowedOrigins("https://trusted-domain.com", "https://another-trusted.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("Authorization", "Content-Type");
        }
    }
}

// Spring Security CORS Configuration - Secure
public class good_case_2 {
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration configuration = new CorsConfiguration();
            // ok: java-permissive-cors-configuration
            configuration.setAllowedOrigins(Arrays.asList(
                "https://trusted-domain.com", 
                "https://another-trusted.com"
            ));
            configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
            configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration("/**", configuration);
            return source;
        }
    }
}

// Spring Boot CorsFilter Registration - Secure
public class good_case_3 {
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // ok: java-permissive-cors-configuration
        config.setAllowedOrigins(Arrays.asList("https://trusted-domain.com"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }
}

// Servlet Filter CORS Implementation - Secure
public class good_case_4 {
    @WebFilter(urlPatterns = "/*")
    public class MyCorsFilter implements Filter {
        @Override
        public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) 
                throws IOException, ServletException {
            HttpServletResponse response = (HttpServletResponse) res;
            HttpServletRequest request = (HttpServletRequest) req;
            
            String origin = request.getHeader("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                response.setHeader("Access-Control-Allow-Origin", origin);
                response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            chain.doFilter(req, res);
        }
    }
}

// Apache Tomcat Catalina CORS Filter - Secure
public class good_case_5 {
    @Bean
    public FilterRegistrationBean<CatalinaFilter> corsFilterRegistration() {
        FilterRegistrationBean<CatalinaFilter> registrationBean = new FilterRegistrationBean<>();
        CatalinaFilter corsFilter = new CatalinaFilter();
        // ok: java-permissive-cors-configuration
        corsFilter.setInitParameter("cors.allowed.origins", "https://trusted-domain.com,https://another-trusted.com");
        corsFilter.setInitParameter("cors.allowed.methods", "GET,POST,PUT,DELETE");
        corsFilter.setInitParameter("cors.allowed.headers", "Authorization,Content-Type");
        registrationBean.setFilter(corsFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}

// Jetty CrossOriginFilter Configuration - Secure
public class good_case_6 {
    @Bean
    public FilterRegistrationBean<CrossOriginFilter> corsFilterRegistration() {
        FilterRegistrationBean<CrossOriginFilter> registrationBean = new FilterRegistrationBean<>();
        CrossOriginFilter corsFilter = new CrossOriginFilter();
        // ok: java-permissive-cors-configuration
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, 
                                   "https://trusted-domain.com,https://another-trusted.com");
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, "GET,POST,PUT,DELETE");
        corsFilter.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, "Authorization,Content-Type");
        registrationBean.setFilter(corsFilter);
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}

// RESTEasy CORS Filter Configuration - Secure
public class good_case_7 {
    @Bean
    public ResteasyCorsFilter corsFilter() {
        ResteasyCorsFilter corsFilter = new ResteasyCorsFilter();
        // ok: java-permissive-cors-configuration
        corsFilter.getAllowedOrigins().add("https://trusted-domain.com");
        corsFilter.getAllowedOrigins().add("https://another-trusted.com");
        corsFilter.setAllowedMethods("GET, POST, PUT, DELETE");
        corsFilter.setAllowedHeaders("Authorization, Content-Type");
        return corsFilter;
    }
}

// Vert.x CORS Handler Configuration - Secure
public class good_case_8 {
    public void configureRouter(Vertx vertx) {
        Router router = Router.router(vertx);
        
        // ok: java-permissive-cors-configuration
        router.route().handler(CorsHandler.create()
            .addOrigin("https://trusted-domain.com")
            .addOrigin("https://another-trusted.com")
            .allowedMethods(new HashSet<>(Arrays.asList(
                HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.DELETE)))
            .allowedHeaders(new HashSet<>(Arrays.asList(
                "Content-Type", "Authorization")))
            .allowCredentials(true));
        
        // Rest of the router configuration
    }
}

// Micronaut CORS Response Headers - Secure
public class good_case_9 {
    @Controller("/api")
    public class ApiController {
        @Get("/data")
        public HttpResponse<String> getData(HttpServletRequest request) {
            MutableHttpResponse<String> response = HttpResponse.ok("Data");
            String origin = request.getHeader("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                response.header("Access-Control-Allow-Origin", origin);
                response.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                response.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            return response;
        }
    }
}

// Ratpack CORS Handler - Secure
public class good_case_10 {
    public Handler corsHandler() {
        return ctx -> {
            Context context = ctx;
            String origin = context.getRequest().getHeaders().get("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                context.getResponse().getHeaders().add("Access-Control-Allow-Origin", origin);
                context.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                context.getResponse().getHeaders().add("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            context.next();
        };
    }
}

// Spark Framework CORS Configuration - Secure
public class good_case_11 {
    public void configureCors() {
        Spark.options("/*", (request, response) -> {
            String origin = request.headers("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                response.header("Access-Control-Allow-Origin", origin);
                
                String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
                if (accessControlRequestHeaders != null) {
                    response.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
                }
                
                String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
                if (accessControlRequestMethod != null) {
                    response.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                }
            }
            return "OK";
        });
    }
}

// Play Framework CORS Filter Configuration - Secure
public class good_case_12 {
    @Bean
    public CORSFilter corsFilter() {
        CORSConfig corsConfig = new CORSConfig();
        // ok: java-permissive-cors-configuration
        corsConfig.setAllowedOrigins(Arrays.asList(
            "https://trusted-domain.com", 
            "https://another-trusted.com"
        ));
        corsConfig.setAllowedHttpMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        corsConfig.setAllowedHttpHeaders(Arrays.asList("Authorization", "Content-Type"));
        return new CORSFilter(corsConfig);
    }
}

// HttpServlet CORS Implementation - Secure
public class good_case_13 {
    @WebServlet("/api/*")
    public class ApiServlet extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
                throws ServletException, IOException {
            String origin = req.getHeader("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                resp.setHeader("Access-Control-Allow-Origin", origin);
                resp.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                resp.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
            }
            
            // Process the request
            resp.getWriter().write("API response");
        }
    }
}

// JAX-RS ContainerResponseFilter for CORS - Secure
public class good_case_14 {
    @Provider
    public class CorsFilter implements ContainerResponseFilter {
        @Override
        public void filter(ContainerRequestContext requestContext, 
                          ContainerResponseContext responseContext) throws IOException {
            String origin = requestContext.getHeaderString("Origin");
            if (origin != null && (origin.equals("https://trusted-domain.com") || 
                                  origin.equals("https://another-trusted.com"))) {
                // ok: java-permissive-cors-configuration
                responseContext.getHeaders().add("Access-Control-Allow-Origin", origin);
                responseContext.getHeaders().add("Access-Control-Allow-Methods", 
                    "GET, POST, PUT, DELETE, OPTIONS");
                responseContext.getHeaders().add("Access-Control-Allow-Headers", 
                    "Authorization, Content-Type");
            }
        }
    }
}

// Spring WebFlux CORS Configuration - Secure
public class good_case_15 {
    @Configuration
    public class WebFluxConfig implements WebFluxConfigurer {
        @Override
        public void addCorsMappings(CorsRegistry registry) {
            // ok: java-permissive-cors-configuration
            registry.addMapping("/api/**")
                .allowedOrigins("https://trusted-domain.com", "https://another-trusted.com")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("Authorization", "Content-Type");
        }
    }
}