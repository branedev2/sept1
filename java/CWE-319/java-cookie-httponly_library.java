import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import jakarta.servlet.http.Cookie as JakartaCookie;
import jakarta.servlet.http.HttpServletResponse as JakartaResponse;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.apache.catalina.connector.Response;
import io.undertow.server.handlers.CookieHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.CookieHandler.CookieSameSiteMode;
import io.undertow.server.handlers.Cookie as UndertowCookie;
import io.undertow.util.Headers;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.http.cookie.CookieConfiguration;
import io.javalin.http.Context;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Cookie as VertxCookie;
import play.mvc.Http;
import play.mvc.Result;
import play.mvc.Results;
import ratpack.http.Response;
import ratpack.http.Headers;
import ratpack.exec.Promise;
import spark.Request;
import spark.Response as SparkResponse;
import org.eclipse.jetty.server.Request as JettyRequest;
import org.eclipse.jetty.server.Response as JettyResponse;
import com.google.common.net.HttpHeaders;
import java.net.HttpCookie;
import java.util.Map;
import java.util.HashMap;
import org.glassfish.grizzly.http.server.Response as GrizzlyResponse;
import org.glassfish.grizzly.http.server.Request as GrizzlyRequest;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ContainerResponse;

// Security Issue: Missing HttpOnly and SameSite attributes in cookies, which can lead to XSS attacks (CWE-614, CWE-319, CWE-352)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request, HttpServletResponse response) {
    String username = request.getParameter("username");
    // ruleid: java-cookie-httponly
    Cookie cookie = new Cookie("sessionId", generateSessionId());
    cookie.setMaxAge(3600);
    response.addCookie(cookie);
}

public void bad_case_2(HttpServletRequest request, HttpServletResponse response) {
    // Using javax.servlet.http.Cookie with partial security
    String userId = request.getParameter("userId");
    // ruleid: java-cookie-httponly
    Cookie cookie = new Cookie("authToken", generateToken(userId));
    cookie.setSecure(true); // Only using secure but missing HttpOnly
    response.addCookie(cookie);
}

public void bad_case_3(JakartaResponse response) {
    // Using Jakarta EE Cookie API
    // ruleid: java-cookie-httponly
    JakartaCookie cookie = new JakartaCookie("userPrefs", "theme=dark");
    cookie.setPath("/");
    cookie.setMaxAge(86400);
    response.addCookie(cookie);
}

public void bad_case_4() {
    // Using Spring ResponseCookie
    // ruleid: java-cookie-httponly
    ResponseCookie cookie = ResponseCookie.from("trackingId", "abc123")
            .maxAge(365 * 24 * 60 * 60)
            .path("/")
            .secure(true)
            .build();
    
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.SET_COOKIE, cookie.toString());
    return ResponseEntity.ok().headers(headers).body("Cookie set");
}

public void bad_case_5(Response tomcatResponse) {
    // Using Apache Tomcat's cookie processor
    Rfc6265CookieProcessor cookieProcessor = new Rfc6265CookieProcessor();
    // ruleid: java-cookie-httponly
    Cookie cookie = new Cookie("sessionData", "sensitive-data");
    cookie.setPath("/app");
    cookie.setMaxAge(3600);
    tomcatResponse.addCookie(cookie);
}

public void bad_case_6(HttpServerExchange exchange) {
    // Using Undertow server
    // ruleid: java-cookie-httponly
    UndertowCookie cookie = CookieHandler.getRequestCookie(exchange, "rememberMe");
    if (cookie == null) {
        cookie = new io.undertow.server.handlers.Cookie("rememberMe", "true");
        cookie.setPath("/");
        cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
        exchange.setResponseCookie(cookie);
    }
}

public void bad_case_7(MutableHttpResponse<?> response) {
    // Using Micronaut framework
    // ruleid: java-cookie-httponly
    response.cookie(
        io.micronaut.http.cookie.Cookie.of("analyticsId", "visitor12345")
            .maxAge(30 * 24 * 60 * 60)
            .path("/")
            .secure(true)
    );
}

public void bad_case_8(Context ctx) {
    // Using Javalin framework
    // ruleid: java-cookie-httponly
    ctx.cookie("cart", "item1,item2,item3", 3600);
}

public void bad_case_9(HttpServerResponse response) {
    // Using Vert.x framework
    // ruleid: java-cookie-httponly
    VertxCookie cookie = VertxCookie.cookie("lastVisit", System.currentTimeMillis() + "");
    cookie.setPath("/");
    cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
    response.addCookie(cookie);
}

public void bad_case_10(Http.Request request) {
    // Using Play framework
    // ruleid: java-cookie-httponly
    Http.Cookie cookie = Http.Cookie.builder("visitorId", "12345")
        .withMaxAge(java.time.Duration.ofDays(30))
        .withPath("/")
        .withSecure(true)
        .build();
    
    return Results.ok("Cookie set").withCookies(cookie);
}

public void bad_case_11(ratpack.http.Response response) {
    // Using Ratpack framework
    // ruleid: java-cookie-httponly
    response.getHeaders().add("Set-Cookie", "userId=12345; Path=/; Max-Age=3600; Secure");
}

public void bad_case_12(SparkResponse response) {
    // Using Spark framework
    // ruleid: java-cookie-httponly
    response.cookie("sessionToken", "abc123", 3600, false, false);
}

public void bad_case_13(JettyResponse response) {
    // Using Jetty server
    // ruleid: java-cookie-httponly
    response.addCookie(new Cookie("preferredLanguage", "en-US"));
}

public void bad_case_14() {
    // Using java.net.HttpCookie
    // ruleid: java-cookie-httponly
    HttpCookie cookie = new HttpCookie("accountId", "user12345");
    cookie.setPath("/");
    cookie.setMaxAge(3600);
    cookie.setSecure(true);
    
    Map<String, String> headers = new HashMap<>();
    headers.put("Set-Cookie", cookie.toString());
}

public void bad_case_15(GrizzlyResponse response) {
    // Using Grizzly server
    // ruleid: java-cookie-httponly
    Cookie cookie = new Cookie("authState", "authenticated");
    cookie.setMaxAge(1800);
    cookie.setPath("/");
    response.addCookie(cookie);
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request, HttpServletResponse response) {
    String username = request.getParameter("username");
    // ok: java-cookie-httponly
    Cookie cookie = new Cookie("sessionId", generateSessionId());
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setAttribute("SameSite", "Strict");
    cookie.setMaxAge(3600);
    response.addCookie(cookie);
}

public void good_case_2(HttpServletRequest request, HttpServletResponse response) {
    // Using javax.servlet.http.Cookie with proper security
    String userId = request.getParameter("userId");
    // ok: java-cookie-httponly
    Cookie cookie = new Cookie("authToken", generateToken(userId));
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
}

public void good_case_3(JakartaResponse response) {
    // Using Jakarta EE Cookie API with proper security
    // ok: java-cookie-httponly
    JakartaCookie cookie = new JakartaCookie("userPrefs", "theme=dark");
    cookie.setPath("/");
    cookie.setMaxAge(86400);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setAttribute("SameSite", "Strict");
    response.addCookie(cookie);
}

public void good_case_4() {
    // Using Spring ResponseCookie with proper security
    // ok: java-cookie-httponly
    ResponseCookie cookie = ResponseCookie.from("trackingId", "abc123")
            .maxAge(365 * 24 * 60 * 60)
            .path("/")
            .secure(true)
            .httpOnly(true)
            .sameSite("Strict")
            .build();
    
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.SET_COOKIE, cookie.toString());
    return ResponseEntity.ok().headers(headers).body("Cookie set");
}

public void good_case_5(Response tomcatResponse) {
    // Using Apache Tomcat's cookie processor with proper security
    Rfc6265CookieProcessor cookieProcessor = new Rfc6265CookieProcessor();
    cookieProcessor.setSameSiteCookies("strict");
    
    // ok: java-cookie-httponly
    Cookie cookie = new Cookie("sessionData", "sensitive-data");
    cookie.setPath("/app");
    cookie.setMaxAge(3600);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    tomcatResponse.addCookie(cookie);
}

public void good_case_6(HttpServerExchange exchange) {
    // Using Undertow server with proper security
    // ok: java-cookie-httponly
    UndertowCookie cookie = new io.undertow.server.handlers.Cookie("rememberMe", "true");
    cookie.setPath("/");
    cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setSameSiteMode(CookieSameSiteMode.STRICT);
    exchange.setResponseCookie(cookie);
}

public void good_case_7(MutableHttpResponse<?> response) {
    // Using Micronaut framework with proper security
    // ok: java-cookie-httponly
    response.cookie(
        io.micronaut.http.cookie.Cookie.of("analyticsId", "visitor12345")
            .maxAge(30 * 24 * 60 * 60)
            .path("/")
            .secure(true)
            .httpOnly(true)
            .sameSite(SameSite.STRICT)
    );
}

public void good_case_8(Context ctx) {
    // Using Javalin framework with proper security
    // ok: java-cookie-httponly
    ctx.cookieStore().set("cart", "item1,item2,item3");
    // Javalin's cookieStore automatically sets HttpOnly and Secure flags
    // For SameSite, we need to configure it at the app level
    // Javalin.create(config -> {
    //     config.cookieStore.sameSite = SameSite.STRICT;
    // });
}

public void good_case_9(HttpServerResponse response) {
    // Using Vert.x framework with proper security
    // ok: java-cookie-httponly
    VertxCookie cookie = VertxCookie.cookie("lastVisit", System.currentTimeMillis() + "");
    cookie.setPath("/");
    cookie.setMaxAge(30 * 24 * 60 * 60); // 30 days
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setSameSite(io.vertx.core.http.CookieSameSite.STRICT);
    response.addCookie(cookie);
}

public void good_case_10(Http.Request request) {
    // Using Play framework with proper security
    // ok: java-cookie-httponly
    Http.Cookie cookie = Http.Cookie.builder("visitorId", "12345")
        .withMaxAge(java.time.Duration.ofDays(30))
        .withPath("/")
        .withSecure(true)
        .withHttpOnly(true)
        .withSameSite(Http.Cookie.SameSite.STRICT)
        .build();
    
    return Results.ok("Cookie set").withCookies(cookie);
}

public void good_case_11(ratpack.http.Response response) {
    // Using Ratpack framework with proper security
    // ok: java-cookie-httponly
    response.getHeaders().add("Set-Cookie", "userId=12345; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict");
}

public void good_case_12(SparkResponse response) {
    // Using Spark framework with proper security
    // ok: java-cookie-httponly
    response.cookie("sessionToken", "abc123", 3600, true, true);
    // For SameSite, we need to use a custom header
    response.header("Set-Cookie", "sessionToken=abc123; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Strict");
}

public void good_case_13(JettyResponse response) {
    // Using Jetty server with proper security
    // ok: java-cookie-httponly
    Cookie cookie = new Cookie("preferredLanguage", "en-US");
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    // Jetty doesn't have direct SameSite support in older versions
    // We need to manually set it in the header
    response.addHeader("Set-Cookie", cookie.toString() + "; SameSite=Strict");
}

public void good_case_14() {
    // Using java.net.HttpCookie with proper security
    // ok: java-cookie-httponly
    HttpCookie cookie = new HttpCookie("accountId", "user12345");
    cookie.setPath("/");
    cookie.setMaxAge(3600);
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    
    Map<String, String> headers = new HashMap<>();
    headers.put("Set-Cookie", cookie.toString() + "; SameSite=Strict");
}

public void good_case_15(ContainerResponse response) {
    // Using Jersey with proper security
    // ok: java-cookie-httponly
    NewCookie cookie = new NewCookie.Builder("authState")
        .value("authenticated")
        .path("/")
        .maxAge(1800)
        .secure(true)
        .httpOnly(true)
        .sameSite(SameSite.STRICT)
        .build();
    
    response.getHeaders().add("Set-Cookie", cookie.toString());
}

// Helper methods
private String generateSessionId() {
    return "session-" + System.currentTimeMillis();
}

private String generateToken(String userId) {
    return "token-" + userId + "-" + System.currentTimeMillis();
}