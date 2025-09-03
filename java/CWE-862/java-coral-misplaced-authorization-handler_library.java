import java.util.*;
import javax.servlet.http.*;
import org.springframework.web.bind.*;
import org.springframework.stereotype.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.access.*;
import org.springframework.security.access.*;
import org.springframework.security.core.*;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.*;
import org.apache.shiro.web.filter.*;
import org.apache.shiro.web.filter.authz.*;
import org.apache.shiro.web.filter.mgt.*;
import org.apache.struts2.dispatcher.filter.*;
import org.apache.struts2.dispatcher.*;
import com.netflix.zuul.context.*;
import com.netflix.zuul.filters.*;
import com.netflix.zuul.*;
import io.micronaut.http.filter.*;
import io.micronaut.http.*;
import io.micronaut.http.annotation.*;
import io.micronaut.security.filters.*;
import io.micronaut.security.*;
import io.javalin.*;
import io.javalin.http.*;
import io.javalin.http.Handler;
import ratpack.handling.*;
import ratpack.handling.Handler;
import ratpack.server.*;
import spark.*;
import spark.Filter;
import com.amazonaws.services.lambda.runtime.events.*;
import com.amazonaws.services.lambda.runtime.*;
import com.google.cloud.functions.*;
import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.*;
import org.glassfish.jersey.server.*;
import org.glassfish.jersey.server.filter.*;
import javax.ws.rs.container.*;
import javax.ws.rs.core.*;
import javax.ws.rs.ext.*;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.*;
import org.eclipse.jetty.servlet.*;
import org.eclipse.jetty.util.component.*;
import org.eclipse.jetty.util.component.LifeCycle.*;
import play.mvc.*;
import play.mvc.Http.*;
import play.libs.F.*;
import play.api.mvc.*;
import akka.actor.*;
import akka.http.javadsl.server.*;
import akka.http.javadsl.model.*;
import akka.http.javadsl.*;
import com.typesafe.config.*;
import io.vertx.core.*;
import io.vertx.core.http.*;
import io.vertx.ext.web.*;
import io.vertx.ext.web.handler.*;
import io.vertx.ext.auth.*;
import io.quarkus.security.*;
import io.quarkus.security.identity.*;
import io.quarkus.vertx.http.*;

// Security Issue: Missing AuthorizationHandler before ActivityHandler

// True Positive Examples (Vulnerable/Insecure Code)

public class MisplacedAuthorizationHandlerExamples {

    // Spring Security Filter Chain Example
// {fact rule=missing-authorization@v1.0 defects=1}
    public void bad_case_1() {
        class CustomSecurityConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // ruleid: java-coral-misplaced-authorization-handler
                http.addFilterBefore(new CustomActivityHandler(), UsernamePasswordAuthenticationFilter.class);
            }
        }
        
        class CustomActivityHandler extends OncePerRequestFilter {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                    FilterChain filterChain) throws ServletException, IOException {
                // Activity handling without prior authorization
                filterChain.doFilter(request, response);
            }
        }
    }

    // Apache Shiro Filter Chain Example
    public void bad_case_2() {
        class ShiroFilterConfiguration {
            public void configureShiroFilters() {
                DefaultFilterChainManager filterChainManager = new DefaultFilterChainManager();
                
                // Add activity filter without authorization filter
                // ruleid: java-coral-misplaced-authorization-handler
                filterChainManager.addFilter("activityFilter", new CustomActivityFilter());
                
                // Create chain without authorization
                filterChainManager.createChain("/api/**", "activityFilter");
            }
        }
        
        class CustomActivityFilter extends AccessControlFilter {
            @Override
            protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
                return true; // Always allow access
            }
            
            @Override
            protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
                return false;
            }
        }
    }

    // Struts 2 Filter Chain Example
    public void bad_case_3() {
        class StrutsFilterConfig {
            public void configureFilters() {
                FilterConfig filterConfig = new FilterConfig();
                
                // ruleid: java-coral-misplaced-authorization-handler
                filterConfig.addFilter(new CustomActivityActionFilter());
            }
        }
        
        class CustomActivityActionFilter implements Filter {
            @Override
            public void init(javax.servlet.FilterConfig filterConfig) {}
            
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
                    throws IOException, ServletException {
                // Process activities without authorization
                chain.doFilter(request, response);
            }
            
            @Override
            public void destroy() {}
        }
    }

    // Netflix Zuul API Gateway Example
    public void bad_case_4() {
        class ZuulConfiguration {
            public void configureFilters() {
                // ruleid: java-coral-misplaced-authorization-handler
                new CustomActivityZuulFilter().filterType();
            }
        }
        
        class CustomActivityZuulFilter extends ZuulFilter {
            @Override
            public String filterType() {
                return "route"; // Activity handling filter
            }
            
            @Override
            public int filterOrder() {
                return 1;
            }
            
            @Override
            public boolean shouldFilter() {
                return true;
            }
            
            @Override
            public Object run() {
                RequestContext ctx = RequestContext.getCurrentContext();
                // Process activity without prior authorization
                return null;
            }
        }
    }

    // Micronaut HTTP Filter Example
    public void bad_case_5() {
        @Filter("/**")
        class CustomActivityFilter implements HttpFilter {
            // ruleid: java-coral-misplaced-authorization-handler
            @Override
            public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
                // Process activity without authorization
                return chain.proceed(request);
            }
        }
    }

    // Javalin Web Framework Example
    public void bad_case_6() {
        class JavalinApp {
            public void configureRoutes() {
                Javalin app = Javalin.create();
                
                // ruleid: java-coral-misplaced-authorization-handler
                app.before(ctx -> {
                    // Activity processing without authorization
                    ctx.attribute("processed", true);
                });
                
                app.get("/api/data", ctx -> {
                    ctx.json(new HashMap<String, Object>());
                });
            }
        }
    }

    // Ratpack Web Framework Example
    public void bad_case_7() {
        class RatpackApp {
            public void configureHandlers() {
                RatpackServer.start(server -> server
                    .handlers(chain -> {
                        // ruleid: java-coral-misplaced-authorization-handler
                        chain.all(ctx -> {
                            // Activity handling without authorization
                            ctx.next();
                        });
                    })
                );
            }
        }
    }

    // Spark Java Web Framework Example
    public void bad_case_8() {
        class SparkApp {
            public void configureRoutes() {
                // ruleid: java-coral-misplaced-authorization-handler
                Spark.before((request, response) -> {
                    // Activity processing without authorization check
                    request.attribute("processed", true);
                });
                
                Spark.get("/api/data", (request, response) -> {
                    return "Data";
                });
            }
        }
    }

    // AWS Lambda API Gateway Handler Example
    public void bad_case_9() {
        class ApiGatewayHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
            // ruleid: java-coral-misplaced-authorization-handler
            @Override
            public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
                // Process activity without authorization check
                APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
                response.setStatusCode(200);
                response.setBody("Success");
                return response;
            }
        }
    }

    // Google Cloud Functions Example
    public void bad_case_10() {
        class HttpFunction implements HttpFunction {
            // ruleid: java-coral-misplaced-authorization-handler
            @Override
            public void service(HttpRequest request, HttpResponse response) throws Exception {
                // Process activity without authorization
                response.getWriter().write("Processed");
            }
        }
    }

    // Azure Functions Example
    public void bad_case_11() {
        class AzureHttpTrigger {
            // ruleid: java-coral-misplaced-authorization-handler
            @FunctionName("HttpTrigger")
            public HttpResponseMessage run(
                    @HttpTrigger(name = "req", methods = {"get", "post"}, authLevel = AuthorizationLevel.ANONYMOUS) 
                    HttpRequestMessage<Optional<String>> request,
                    final ExecutionContext context) {
                // Process activity without authorization check
                return request.createResponseBuilder(HttpStatus.OK).body("Processed").build();
            }
        }
    }

    // JAX-RS / Jersey Filter Example
    public void bad_case_12() {
        @Provider
        class CustomActivityFilter implements ContainerRequestFilter {
            // ruleid: java-coral-misplaced-authorization-handler
            @Override
            public void filter(ContainerRequestContext requestContext) throws IOException {
                // Process activity without authorization check
                requestContext.setProperty("processed", true);
            }
        }
    }

    // Jetty Handler Example
    public void bad_case_13() {
        class JettyHandlerConfig {
            public void configureHandlers() {
                Server server = new Server(8080);
                
                // ruleid: java-coral-misplaced-authorization-handler
                HandlerCollection handlers = new HandlerCollection();
                handlers.addHandler(new CustomActivityHandler());
                server.setHandler(handlers);
            }
        }
        
        class CustomActivityHandler extends AbstractHandler {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, 
                    HttpServletResponse response) throws IOException, ServletException {
                // Process activity without authorization
                response.setStatus(HttpServletResponse.SC_OK);
                baseRequest.setHandled(true);
            }
        }
    }

    // Play Framework Example
    public void bad_case_14() {
        class CustomController extends Controller {
            // ruleid: java-coral-misplaced-authorization-handler
            public Result processActivity(Http.Request request) {
                // Process activity without authorization check
                return ok("Processed");
            }
        }
    }

    // Vert.x Web Example
    public void bad_case_15() {
        class VertxWebApp {
            public void configureRoutes() {
                Vertx vertx = Vertx.vertx();
                Router router = Router.router(vertx);
                
                // ruleid: java-coral-misplaced-authorization-handler
                router.route().handler(routingContext -> {
                    // Process activity without authorization
                    routingContext.next();
                });
                
                vertx.createHttpServer()
                    .requestHandler(router)
                    .listen(8080);
            }
        }
    }

    // True Negative Examples (Safe/Secure Code)

    // Spring Security Filter Chain Example - Secure
    public void good_case_1() {
        class SecureSpringSecurityConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(HttpSecurity http) throws Exception {
                // ok: java-coral-misplaced-authorization-handler
                http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .addFilterAfter(new CustomActivityHandler(), CustomAuthorizationFilter.class);
            }
        }
        
        class CustomAuthorizationFilter extends OncePerRequestFilter {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                    FilterChain filterChain) throws ServletException, IOException {
                // Authorization check
                if (isAuthorized(request)) {
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
            
            private boolean isAuthorized(HttpServletRequest request) {
                // Authorization logic
                return true;
            }
        }
        
        class CustomActivityHandler extends OncePerRequestFilter {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                    FilterChain filterChain) throws ServletException, IOException {
                // Activity handling after authorization
                filterChain.doFilter(request, response);
            }
        }
    }

    // Apache Shiro Filter Chain Example - Secure
    public void good_case_2() {
        class SecureShiroFilterConfiguration {
            public void configureShiroFilters() {
                DefaultFilterChainManager filterChainManager = new DefaultFilterChainManager();
                
                // Add authorization filter
                filterChainManager.addFilter("authcFilter", new FormAuthenticationFilter());
                filterChainManager.addFilter("authzFilter", new RolesAuthorizationFilter());
                filterChainManager.addFilter("activityFilter", new CustomActivityFilter());
                
                // ok: java-coral-misplaced-authorization-handler
                filterChainManager.createChain("/api/**", "authcFilter, authzFilter, activityFilter");
            }
        }
        
        class CustomActivityFilter extends AccessControlFilter {
            @Override
            protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
                // Activity processing after authorization
                return true;
            }
            
            @Override
            protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
                return false;
            }
        }
    }

    // Struts 2 Filter Chain Example - Secure
    public void good_case_3() {
        class SecureStrutsFilterConfig {
            public void configureFilters() {
                FilterConfig filterConfig = new FilterConfig();
                
                // ok: java-coral-misplaced-authorization-handler
                filterConfig.addFilter(new CustomAuthorizationFilter());
                filterConfig.addFilter(new CustomActivityActionFilter());
            }
        }
        
        class CustomAuthorizationFilter implements Filter {
            @Override
            public void init(javax.servlet.FilterConfig filterConfig) {}
            
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
                    throws IOException, ServletException {
                // Authorization check
                if (isAuthorized(request)) {
                    chain.doFilter(request, response);
                } else {
                    ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
            
            private boolean isAuthorized(ServletRequest request) {
                // Authorization logic
                return true;
            }
            
            @Override
            public void destroy() {}
        }
        
        class CustomActivityActionFilter implements Filter {
            @Override
            public void init(javax.servlet.FilterConfig filterConfig) {}
            
            @Override
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
                    throws IOException, ServletException {
                // Process activities after authorization
                chain.doFilter(request, response);
            }
            
            @Override
            public void destroy() {}
        }
    }

    // Netflix Zuul API Gateway Example - Secure
    public void good_case_4() {
        class SecureZuulConfiguration {
            public void configureFilters() {
                // ok: java-coral-misplaced-authorization-handler
                new CustomAuthorizationZuulFilter().filterType();
                new CustomActivityZuulFilter().filterType();
            }
        }
        
        class CustomAuthorizationZuulFilter extends ZuulFilter {
            @Override
            public String filterType() {
                return "pre"; // Authorization filter runs before routing
            }
            
            @Override
            public int filterOrder() {
                return 0; // Runs before activity filter
            }
            
            @Override
            public boolean shouldFilter() {
                return true;
            }
            
            @Override
            public Object run() {
                RequestContext ctx = RequestContext.getCurrentContext();
                // Authorization check
                if (!isAuthorized(ctx)) {
                    ctx.setSendZuulResponse(false);
                    ctx.setResponseStatusCode(403);
                }
                return null;
            }
            
            private boolean isAuthorized(RequestContext ctx) {
                // Authorization logic
                return true;
            }
        }
        
        class CustomActivityZuulFilter extends ZuulFilter {
            @Override
            public String filterType() {
                return "route"; // Activity handling filter
            }
            
            @Override
            public int filterOrder() {
                return 1; // Runs after authorization filter
            }
            
            @Override
            public boolean shouldFilter() {
                return true;
            }
            
            @Override
            public Object run() {
                // Process activity after authorization
                return null;
            }
        }
    }

    // Micronaut HTTP Filter Example - Secure
    public void good_case_5() {
        @Filter("/**")
        class CustomAuthorizationFilter implements HttpFilter {
            @Override
            public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
                // Authorization check
                if (isAuthorized(request)) {
                    return chain.proceed(request);
                } else {
                    return Publishers.just(HttpResponse.status(HttpStatus.FORBIDDEN));
                }
            }
            
            private boolean isAuthorized(HttpRequest<?> request) {
                // Authorization logic
                return true;
            }
        }
        
        @Filter("/**")
        @Order(10) // Runs after authorization filter
        class CustomActivityFilter implements HttpFilter {
            // ok: java-coral-misplaced-authorization-handler
            @Override
            public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
                // Process activity after authorization
                return chain.proceed(request);
            }
        }
    }

    // Javalin Web Framework Example - Secure
    public void good_case_6() {
        class SecureJavalinApp {
            public void configureRoutes() {
                Javalin app = Javalin.create();
                
                // ok: java-coral-misplaced-authorization-handler
                app.before(ctx -> {
                    // Authorization check
                    if (!isAuthorized(ctx)) {
                        ctx.status(403).result("Unauthorized");
                        ctx.halt();
                    }
                });
                
                app.before(ctx -> {
                    // Activity processing after authorization
                    ctx.attribute("processed", true);
                });
                
                app.get("/api/data", ctx -> {
                    ctx.json(new HashMap<String, Object>());
                });
            }
            
            private boolean isAuthorized(Context ctx) {
                // Authorization logic
                return true;
            }
        }
    }

    // Ratpack Web Framework Example - Secure
    public void good_case_7() {
        class SecureRatpackApp {
            public void configureHandlers() {
                RatpackServer.start(server -> server
                    .handlers(chain -> {
                        // ok: java-coral-misplaced-authorization-handler
                        chain.all(ctx -> {
                            // Authorization check
                            if (isAuthorized(ctx)) {
                                ctx.next();
                            } else {
                                ctx.getResponse().status(403).send("Unauthorized");
                            }
                        });
                        
                        chain.all(ctx -> {
                            // Activity handling after authorization
                            ctx.next();
                        });
                    })
                );
            }
            
            private boolean isAuthorized(Context ctx) {
                // Authorization logic
                return true;
            }
        }
    }

    // Spark Java Web Framework Example - Secure
    public void good_case_8() {
        class SecureSparkApp {
            public void configureRoutes() {
                // ok: java-coral-misplaced-authorization-handler
                Spark.before((request, response) -> {
                    // Authorization check
                    if (!isAuthorized(request)) {
                        response.status(403);
                        response.body("Unauthorized");
                        Spark.halt(403);
                    }
                });
                
                Spark.before((request, response) -> {
                    // Activity processing after authorization
                    request.attribute("processed", true);
                });
                
                Spark.get("/api/data", (request, response) -> {
                    return "Data";
                });
            }
            
            private boolean isAuthorized(Request request) {
                // Authorization logic
                return true;
            }
        }
    }

    // AWS Lambda API Gateway Handler Example - Secure
    public void good_case_9() {
        class SecureApiGatewayHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
            // ok: java-coral-misplaced-authorization-handler
            @Override
            public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
                // Authorization check
                if (!isAuthorized(input)) {
                    APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
                    response.setStatusCode(403);
                    response.setBody("Unauthorized");
                    return response;
                }
                
                // Process activity after authorization
                APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
                response.setStatusCode(200);
                response.setBody("Success");
                return response;
            }
            
            private boolean isAuthorized(APIGatewayProxyRequestEvent input) {
                // Authorization logic
                return true;
            }
        }
    }

    // Google Cloud Functions Example - Secure
    public void good_case_10() {
        class SecureHttpFunction implements HttpFunction {
            // ok: java-coral-misplaced-authorization-handler
            @Override
            public void service(HttpRequest request, HttpResponse response) throws Exception {
                // Authorization check
                if (!isAuthorized(request)) {
                    response.setStatusCode(403);
                    response.getWriter().write("Unauthorized");
                    return;
                }
                
                // Process activity after authorization
                response.getWriter().write("Processed");
            }
            
            private boolean isAuthorized(HttpRequest request) {
                // Authorization logic
                return true;
            }
        }
    }

    // Azure Functions Example - Secure
    public void good_case_11() {
        class SecureAzureHttpTrigger {
            // ok: java-coral-misplaced-authorization-handler
            @FunctionName("HttpTrigger")
            public HttpResponseMessage run(
                    @HttpTrigger(name = "req", methods = {"get", "post"}, authLevel = AuthorizationLevel.FUNCTION) 
                    HttpRequestMessage<Optional<String>> request,
                    final ExecutionContext context) {
                
                // Authorization check
                if (!isAuthorized(request)) {
                    return request.createResponseBuilder(HttpStatus.FORBIDDEN).body("Unauthorized").build();
                }
                
                // Process activity after authorization
                return request.createResponseBuilder(HttpStatus.OK).body("Processed").build();
            }
            
            private boolean isAuthorized(HttpRequestMessage<Optional<String>> request) {
                // Authorization logic
                return true;
            }
        }
    }

    // JAX-RS / Jersey Filter Example - Secure
    public void good_case_12() {
        @Provider
        @Priority(Priorities.AUTHENTICATION)
        class CustomAuthorizationFilter implements ContainerRequestFilter {
            @Override
            public void filter(ContainerRequestContext requestContext) throws IOException {
                // Authorization check
                if (!isAuthorized(requestContext)) {
                    requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN).entity("Unauthorized").build()
                    );
                }
            }
            
            private boolean isAuthorized(ContainerRequestContext requestContext) {
                // Authorization logic
                return true;
            }
        }
        
        @Provider
        @Priority(Priorities.USER)
        class CustomActivityFilter implements ContainerRequestFilter {
            // ok: java-coral-misplaced-authorization-handler
            @Override
            public void filter(ContainerRequestContext requestContext) throws IOException {
                // Process activity after authorization
                requestContext.setProperty("processed", true);
            }
        }
    }

    // Jetty Handler Example - Secure
    public void good_case_13() {
        class SecureJettyHandlerConfig {
            public void configureHandlers() {
                Server server = new Server(8080);
                
                // ok: java-coral-misplaced-authorization-handler
                HandlerCollection handlers = new HandlerCollection();
                handlers.addHandler(new CustomAuthorizationHandler());
                handlers.addHandler(new CustomActivityHandler());
                server.setHandler(handlers);
            }
        }
        
        class CustomAuthorizationHandler extends AbstractHandler {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, 
                    HttpServletResponse response) throws IOException, ServletException {
                // Authorization check
                if (!isAuthorized(request)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    baseRequest.setHandled(true);
                    return;
                }
                
                // Continue to next handler if authorized
            }
            
            private boolean isAuthorized(HttpServletRequest request) {
                // Authorization logic
                return true;
            }
        }
        
        class CustomActivityHandler extends AbstractHandler {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, 
                    HttpServletResponse response) throws IOException, ServletException {
                // Process activity after authorization
                if (!baseRequest.isHandled()) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    baseRequest.setHandled(true);
                }
            }
        }
    }

    // Play Framework Example - Secure
    public void good_case_14() {
        class SecureController extends Controller {
            private final AuthorizationService authService;
            
            public SecureController(AuthorizationService authService) {
                this.authService = authService;
            }
            
            // ok: java-coral-misplaced-authorization-handler
            public Result processActivity(Http.Request request) {
                // Authorization check
                if (!authService.isAuthorized(request)) {
                    return forbidden("Unauthorized");
                }
                
                // Process activity after authorization
                return ok("Processed");
            }
        }
        
        class AuthorizationService {
            public boolean isAuthorized(Http.Request request) {
                // Authorization logic
                return true;
            }
        }
    }

    // Vert.x Web Example - Secure
    public void good_case_15() {
        class SecureVertxWebApp {
            public void configureRoutes() {
                Vertx vertx = Vertx.vertx();
                Router router = Router.router(vertx);
                
                // ok: java-coral-misplaced-authorization-handler
                router.route().handler(AuthHandler.create(null));
                
                router.route().handler(routingContext -> {
                    // Process activity after authorization
                    routingContext.next();
                });
                
                vertx.createHttpServer()
                    .requestHandler(router)
                    .listen(8080);
            }
        }
    }
}
// {/fact}