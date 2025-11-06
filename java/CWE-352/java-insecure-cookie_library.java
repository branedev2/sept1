import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpCookie;
import jakarta.servlet.http.Cookie as JakartaCookie;
import jakarta.servlet.http.HttpServletResponse as JakartaResponse;
import play.mvc.Http.Cookie.SameSite;
import play.mvc.Http.CookieBuilder;
import play.mvc.Http;
import io.undertow.server.handlers.CookieHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.CookieHandler.CookieSameSiteMode;
import io.micronaut.http.cookie.CookieConfiguration;
import io.micronaut.http.cookie.SameSite as MicronautSameSite;
import io.javalin.http.Context;
import io.vertx.core.http.Cookie as VertxCookie;
import io.vertx.ext.web.RoutingContext;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.wicket.util.cookies.CookieUtils;
import org.apache.wicket.request.http.WebResponse;
import com.vaadin.flow.server.VaadinResponse;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.glassfish.grizzly.http.server.Response as GrizzlyResponse;
import org.apache.tapestry5.services.Cookies;
import ratpack.http.Response;
import spark.Request as SparkRequest;
import spark.Response as SparkResponse;
import com.google.common.net.HttpHeaders;

// Security Issue: Insecure Cookie Configuration (CWE-614, CWE-319, CWE-352)
// This file demonstrates various ways cookies can be set insecurely (without the Secure flag)
// and securely (with the Secure flag) across different Java web frameworks and libraries.

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
    // Standard Java Servlet API - Creating an insecure cookie
    Cookie sessionCookie = new Cookie("sessionId", generateSessionId());
    sessionCookie.setMaxAge(3600);
    sessionCookie.setPath("/");
    // ruleid: java-insecure-cookie
    response.addCookie(sessionCookie); // Insecure: No secure flag set
}

public void bad_case_2(HttpServletResponse response) {
    // Jakarta Servlet API - Creating an insecure cookie
    JakartaCookie userCookie = new JakartaCookie("userId", "12345");
    userCookie.setMaxAge(86400);
    userCookie.setPath("/account");
    userCookie.setHttpOnly(true); // HttpOnly is set but Secure is missing
    // ruleid: java-insecure-cookie
    response.addCookie(userCookie); // Insecure: No secure flag set
}

@RestController
public void bad_case_3(HttpServletResponse response) {
    // Spring Framework - Creating an insecure ResponseCookie
    ResponseCookie authCookie = ResponseCookie.from("authToken", generateAuthToken())
            .maxAge(7200)
            .path("/api")
            .httpOnly(true)
            .build();
    // ruleid: java-insecure-cookie
    response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString()); // Insecure: No secure flag set
}

public void bad_case_4(Http.Response response) {
    // Play Framework - Creating an insecure cookie
    // ruleid: java-insecure-cookie
    response.setCookie(
        Http.Cookie.builder("rememberMe", "true")
            .withMaxAge(java.time.Duration.ofDays(30))
            .withPath("/")
            .withHttpOnly(true)
            .build()
    ); // Insecure: No secure flag set
}

public void bad_case_5(HttpServerExchange exchange) {
    // Undertow - Creating an insecure cookie
    CookieHandler cookieHandler = new CookieHandler();
    // ruleid: java-insecure-cookie
    cookieHandler.addCookie(exchange, "preferenceId", "theme-dark", "/", null, -1, false, false);
    // Insecure: Last parameter is secure flag, set to false
}

public void bad_case_6(io.micronaut.http.HttpResponse<?> response) {
    // Micronaut - Creating an insecure cookie
    // ruleid: java-insecure-cookie
    response.cookie(
        io.micronaut.http.cookie.Cookie.of("analyticsId", "visitor-123")
            .path("/")
            .maxAge(60 * 60 * 24 * 30)
            .httpOnly(true)
    ); // Insecure: No secure flag set
}

public void bad_case_7(Context context) {
    // Javalin - Creating an insecure cookie
    // ruleid: java-insecure-cookie
    context.cookie("cartId", "cart-456", 3600, false, false);
    // Insecure: 4th parameter is httpOnly, 5th parameter is secure flag, set to false
}

public void bad_case_8(RoutingContext routingContext) {
    // Vert.x - Creating an insecure cookie
    VertxCookie cookie = routingContext.response().cookies().add(
        io.vertx.core.http.Cookie.cookie("visitorId", "visitor-789")
            .setPath("/")
            .setMaxAge(3600)
            .setHttpOnly(true)
    );
    // ruleid: java-insecure-cookie
    routingContext.response().end(); // Insecure: No secure flag set on cookie
}

public void bad_case_9(HttpServletResponse response) {
    // Apache Shiro - Creating an insecure cookie
    SimpleCookie rememberMeCookie = new SimpleCookie("rememberMe");
    rememberMeCookie.setValue("true");
    rememberMeCookie.setMaxAge(3600);
    rememberMeCookie.setPath("/");
    rememberMeCookie.setHttpOnly(true);
    // ruleid: java-insecure-cookie
    rememberMeCookie.saveTo(null, response); // Insecure: No secure flag set
}

public void bad_case_10(WebResponse response) {
    // Apache Wicket - Creating an insecure cookie
    CookieUtils cookieUtils = new CookieUtils();
    Cookie preferenceCookie = cookieUtils.createCookie("preference", "compact-view");
    preferenceCookie.setMaxAge(60 * 60 * 24 * 7);
    preferenceCookie.setPath("/");
    // ruleid: java-insecure-cookie
    response.addCookie(preferenceCookie); // Insecure: No secure flag set
}

public void bad_case_11(VaadinResponse response) {
    // Vaadin - Creating an insecure cookie
    Cookie themeCookie = new Cookie("theme", "dark-mode");
    themeCookie.setMaxAge(60 * 60 * 24 * 30);
    themeCookie.setPath("/");
    // ruleid: java-insecure-cookie
    response.addCookie(themeCookie); // Insecure: No secure flag set
}

public void bad_case_12(Response jettyResponse) {
    // Jetty - Creating an insecure cookie
    Cookie langCookie = new Cookie("language", "en-US");
    langCookie.setMaxAge(60 * 60 * 24 * 365);
    langCookie.setPath("/");
    langCookie.setHttpOnly(true);
    // ruleid: java-insecure-cookie
    jettyResponse.addCookie(langCookie); // Insecure: No secure flag set
}

public void bad_case_13(GrizzlyResponse response) {
    // Grizzly - Creating an insecure cookie
    Cookie fontCookie = new Cookie("fontsize", "medium");
    fontCookie.setMaxAge(60 * 60 * 24);
    fontCookie.setPath("/");
    // ruleid: java-insecure-cookie
    response.addCookie(fontCookie); // Insecure: No secure flag set
}

public void bad_case_14(Cookies cookies) {
    // Apache Tapestry - Creating an insecure cookie
    // ruleid: java-insecure-cookie
    cookies.writeCookieValue("userSettings", "contrast-high", 60 * 60 * 24 * 7);
    // Insecure: No secure flag set in this simplified API
}

public void bad_case_15(SparkResponse response) {
    // Spark Framework - Creating an insecure cookie
    // ruleid: java-insecure-cookie
    response.cookie("accessLevel", "standard", 3600, false, "/");
    // Insecure: 4th parameter is httpOnly, no secure flag parameter provided
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
    // Standard Java Servlet API - Creating a secure cookie
    Cookie sessionCookie = new Cookie("sessionId", generateSessionId());
    sessionCookie.setMaxAge(3600);
    sessionCookie.setPath("/");
    // ok: java-insecure-cookie
    sessionCookie.setSecure(true);
    response.addCookie(sessionCookie); // Secure: Secure flag set to true
}

public void good_case_2(JakartaResponse response) {
    // Jakarta Servlet API - Creating a secure cookie
    JakartaCookie userCookie = new JakartaCookie("userId", "12345");
    userCookie.setMaxAge(86400);
    userCookie.setPath("/account");
    userCookie.setHttpOnly(true);
    // ok: java-insecure-cookie
    userCookie.setSecure(true);
    response.addCookie(userCookie); // Secure: Secure flag set to true
}

@RestController
public void good_case_3(HttpServletResponse response) {
    // Spring Framework - Creating a secure ResponseCookie
    // ok: java-insecure-cookie
    ResponseCookie authCookie = ResponseCookie.from("authToken", generateAuthToken())
            .maxAge(7200)
            .path("/api")
            .httpOnly(true)
            .secure(true)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString()); // Secure: Secure flag set to true
}

public void good_case_4(Http.Response response) {
    // Play Framework - Creating a secure cookie
    // ok: java-insecure-cookie
    response.setCookie(
        Http.Cookie.builder("rememberMe", "true")
            .withMaxAge(java.time.Duration.ofDays(30))
            .withPath("/")
            .withHttpOnly(true)
            .withSecure(true)
            .build()
    ); // Secure: Secure flag set to true
}

public void good_case_5(HttpServerExchange exchange) {
    // Undertow - Creating a secure cookie
    CookieHandler cookieHandler = new CookieHandler();
    // ok: java-insecure-cookie
    cookieHandler.addCookie(exchange, "preferenceId", "theme-dark", "/", null, -1, false, true);
    // Secure: Last parameter is secure flag, set to true
}

public void good_case_6(io.micronaut.http.HttpResponse<?> response) {
    // Micronaut - Creating a secure cookie
    // ok: java-insecure-cookie
    response.cookie(
        io.micronaut.http.cookie.Cookie.of("analyticsId", "visitor-123")
            .path("/")
            .maxAge(60 * 60 * 24 * 30)
            .httpOnly(true)
            .secure(true)
    ); // Secure: Secure flag set to true
}

public void good_case_7(Context context) {
    // Javalin - Creating a secure cookie
    // ok: java-insecure-cookie
    context.cookie("cartId", "cart-456", 3600, false, true);
    // Secure: 5th parameter is secure flag, set to true
}

public void good_case_8(RoutingContext routingContext) {
    // Vert.x - Creating a secure cookie
    // ok: java-insecure-cookie
    VertxCookie cookie = routingContext.response().cookies().add(
        io.vertx.core.http.Cookie.cookie("visitorId", "visitor-789")
            .setPath("/")
            .setMaxAge(3600)
            .setHttpOnly(true)
            .setSecure(true)
    );
    routingContext.response().end(); // Secure: Secure flag set to true on cookie
}

public void good_case_9(HttpServletResponse response) {
    // Apache Shiro - Creating a secure cookie
    SimpleCookie rememberMeCookie = new SimpleCookie("rememberMe");
    rememberMeCookie.setValue("true");
    rememberMeCookie.setMaxAge(3600);
    rememberMeCookie.setPath("/");
    rememberMeCookie.setHttpOnly(true);
    // ok: java-insecure-cookie
    rememberMeCookie.setSecure(true);
    rememberMeCookie.saveTo(null, response); // Secure: Secure flag set to true
}

public void good_case_10(WebResponse response) {
    // Apache Wicket - Creating a secure cookie
    CookieUtils cookieUtils = new CookieUtils();
    Cookie preferenceCookie = cookieUtils.createCookie("preference", "compact-view");
    preferenceCookie.setMaxAge(60 * 60 * 24 * 7);
    preferenceCookie.setPath("/");
    // ok: java-insecure-cookie
    preferenceCookie.setSecure(true);
    response.addCookie(preferenceCookie); // Secure: Secure flag set to true
}

public void good_case_11(VaadinResponse response) {
    // Vaadin - Creating a secure cookie
    Cookie themeCookie = new Cookie("theme", "dark-mode");
    themeCookie.setMaxAge(60 * 60 * 24 * 30);
    themeCookie.setPath("/");
    // ok: java-insecure-cookie
    themeCookie.setSecure(true);
    response.addCookie(themeCookie); // Secure: Secure flag set to true
}

public void good_case_12(Response jettyResponse) {
    // Jetty - Creating a secure cookie
    Cookie langCookie = new Cookie("language", "en-US");
    langCookie.setMaxAge(60 * 60 * 24 * 365);
    langCookie.setPath("/");
    langCookie.setHttpOnly(true);
    // ok: java-insecure-cookie
    langCookie.setSecure(true);
    jettyResponse.addCookie(langCookie); // Secure: Secure flag set to true
}

public void good_case_13(GrizzlyResponse response) {
    // Grizzly - Creating a secure cookie
    Cookie fontCookie = new Cookie("fontsize", "medium");
    fontCookie.setMaxAge(60 * 60 * 24);
    fontCookie.setPath("/");
    // ok: java-insecure-cookie
    fontCookie.setSecure(true);
    response.addCookie(fontCookie); // Secure: Secure flag set to true
}

public void good_case_14(ratpack.http.Response response) {
    // Ratpack - Creating a secure cookie
    // ok: java-insecure-cookie
    response.cookie(
        ratpack.http.Cookie.builder("userSettings", "contrast-high")
            .maxAge(java.time.Duration.ofDays(7))
            .path("/")
            .httpOnly(true)
            .secure(true)
            .build()
    ); // Secure: Secure flag set to true
}

public void good_case_15(SparkResponse response) {
    // Spark Framework - Creating a secure cookie using a different approach
    Cookie secureCookie = new Cookie("accessLevel", "standard");
    secureCookie.setMaxAge(3600);
    secureCookie.setPath("/");
    secureCookie.setHttpOnly(true);
    // ok: java-insecure-cookie
    secureCookie.setSecure(true);
    response.raw().addCookie(secureCookie); // Secure: Secure flag set to true
}

// Helper methods
private String generateSessionId() {
    return java.util.UUID.randomUUID().toString();
}

private String generateAuthToken() {
    return java.util.UUID.randomUUID().toString();
}