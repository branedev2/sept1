import org.springframework.util.Base64; // Deprecated Spring Base64
import org.springframework.util.Base64Utils; // Non-deprecated replacement
import java.util.Base64 as JavaBase64; // Java's built-in Base64
import org.apache.commons.codec.binary.Base64 as CommonsBase64; // Apache Commons Base64
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import javax.servlet.http.*;
import java.io.IOException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.client.RestTemplate;
import org.springframework.security.crypto.codec.Base64 as SecurityBase64; // Another deprecated Spring Base64
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.springframework.integration.http.inbound.HttpRequestHandlingMessagingGateway;
import org.springframework.integration.http.outbound.HttpRequestExecutingMessageHandler;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.batch.item.ItemReader;
import org.springframework.batch.item.ItemWriter;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;

// Security Issue: Using deprecated Base64 class in the Spring framework (CWE-477)

// True Positive Examples (Vulnerable/Insecure Code)

public class DeprecatedSpringBase64Examples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring MVC web controller using deprecated Base64
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length());
            // ruleid: java-deprecatedspringbase64
            byte[] decodedBytes = Base64.decode(base64Credentials.getBytes());
            String credentials = new String(decodedBytes);
            // Process credentials
        }
    }
    
    public void bad_case_2(HttpServletRequest request) {
        // Spring Security authentication using deprecated Base64
        String token = request.getParameter("token");
        if (token != null) {
            // ruleid: java-deprecatedspringbase64
            byte[] decodedToken = org.springframework.security.crypto.codec.Base64.decode(token.getBytes());
            String tokenData = new String(decodedToken);
            // Process token data
        }
    }
    
    @RestController
    public class bad_case_3 {
        // Spring REST API controller using deprecated Base64 for file upload
        @PostMapping("/upload")
        public ResponseEntity<String> uploadFile(@RequestBody String base64File) {
            // ruleid: java-deprecatedspringbase64
            byte[] fileContent = Base64.decode(base64File.getBytes());
            // Save file content
            return ResponseEntity.ok("File uploaded successfully");
        }
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Spring Integration HTTP gateway using deprecated Base64
        String imageData = request.getParameter("image");
        if (imageData != null) {
            // ruleid: java-deprecatedspringbase64
            byte[] imageBytes = Base64.decode(imageData.getBytes());
            response.setContentType("image/jpeg");
            response.getOutputStream().write(imageBytes);
        }
    }
    
    @Controller
    public class bad_case_5 {
        // Spring MVC Thymeleaf template with deprecated Base64
        @GetMapping("/profile")
        public String getProfile(HttpServletRequest request, Model model) {
            String profileImage = request.getParameter("avatar");
            if (profileImage != null) {
                // ruleid: java-deprecatedspringbase64
                byte[] imageData = Base64.decode(profileImage.getBytes());
                model.addAttribute("profileImageData", imageData);
            }
            return "profile";
        }
    }
    
    public void bad_case_6() {
        // Spring WebClient with deprecated Base64
        WebClient webClient = WebClient.create("https://api.example.com");
        webClient.get()
                .uri("/data")
                .retrieve()
                .bodyToMono(String.class)
                .subscribe(response -> {
                    // ruleid: java-deprecatedspringbase64
                    byte[] decodedData = Base64.decode(response.getBytes());
                    // Process decoded data
                });
    }
    
    public class bad_case_7 extends TextWebSocketHandler {
        // Spring WebSocket handler with deprecated Base64
        @Override
        public void handleTextMessage(WebSocketSession session, TextMessage message) {
            String payload = message.getPayload();
            // ruleid: java-deprecatedspringbase64
            byte[] decodedPayload = Base64.decode(payload.getBytes());
            // Process decoded payload
        }
    }
    
    public void bad_case_8(HttpServletRequest request) {
        // Spring Batch job with deprecated Base64
        String batchData = request.getParameter("batchData");
        ItemProcessor<String, byte[]> processor = item -> {
            // ruleid: java-deprecatedspringbase64
            return Base64.decode(item.getBytes());
        };
        // Use processor in batch job
    }
    
    public void bad_case_9(HttpServletRequest request) {
        // Spring Redis template with deprecated Base64
        RedisTemplate<String, byte[]> redisTemplate = new RedisTemplate<>();
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        // ruleid: java-deprecatedspringbase64
        byte[] encodedValue = Base64.encode(value.getBytes());
        redisTemplate.opsForValue().set(key, encodedValue);
    }
    
    public void bad_case_10(HttpServletRequest request) {
        // Spring Kafka producer with deprecated Base64
        KafkaTemplate<String, byte[]> kafkaTemplate = new KafkaTemplate<>(null);
        String message = request.getParameter("message");
        // ruleid: java-deprecatedspringbase64
        byte[] encodedMessage = Base64.encode(message.getBytes());
        kafkaTemplate.send("topic", encodedMessage);
    }
    
    public void bad_case_11(HttpServletRequest request) {
        // Spring RabbitMQ template with deprecated Base64
        RabbitTemplate rabbitTemplate = new RabbitTemplate();
        String message = request.getParameter("message");
        // ruleid: java-deprecatedspringbase64
        byte[] encodedMessage = Base64.encode(message.getBytes());
        rabbitTemplate.convertAndSend("exchange", "routingKey", encodedMessage);
    }
    
    public void bad_case_12(HttpServletRequest request) throws Exception {
        // Spring Mail sender with deprecated Base64
        JavaMailSender mailSender = null;
        javax.mail.internet.MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        
        String attachment = request.getParameter("attachment");
        // ruleid: java-deprecatedspringbase64
        byte[] decodedAttachment = Base64.decode(attachment.getBytes());
        
        helper.addAttachment("document.pdf", new javax.activation.DataSource() {
            @Override
            public java.io.InputStream getInputStream() {
                return new java.io.ByteArrayInputStream(decodedAttachment);
            }
            @Override
            public java.io.OutputStream getOutputStream() { return null; }
            @Override
            public String getContentType() { return "application/pdf"; }
            @Override
            public String getName() { return "document.pdf"; }
        });
    }
    
    public class bad_case_13 extends AbstractGatewayFilterFactory<Object> {
        // Spring Cloud Gateway filter with deprecated Base64
        @Override
        public GatewayFilter apply(Object config) {
            return (exchange, chain) -> {
                String token = exchange.getRequest().getHeaders().getFirst("Authorization");
                if (token != null && token.startsWith("Basic ")) {
                    String base64Credentials = token.substring("Basic ".length());
                    // ruleid: java-deprecatedspringbase64
                    byte[] decodedBytes = Base64.decode(base64Credentials.getBytes());
                    String credentials = new String(decodedBytes);
                    // Process credentials
                }
                return chain.filter(exchange);
            };
        }
    }
    
    public void bad_case_14(ServerRequest request) {
        // Spring WebFlux functional endpoint with deprecated Base64
        request.bodyToMono(String.class)
                .map(body -> {
                    // ruleid: java-deprecatedspringbase64
                    return Base64.decode(body.getBytes());
                })
                .subscribe(decodedData -> {
                    // Process decoded data
                });
    }
    
    public void bad_case_15(HttpServletRequest request, SseEmitter emitter) {
        // Spring Server-Sent Events with deprecated Base64
        String eventData = request.getParameter("data");
        // ruleid: java-deprecatedspringbase64
        byte[] decodedData = Base64.decode(eventData.getBytes());
        emitter.send(decodedData);
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1(HttpServletRequest request) {
        // Spring MVC web controller using non-deprecated Base64Utils
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length());
            // ok: java-deprecatedspringbase64
            byte[] decodedBytes = Base64Utils.decodeFromString(base64Credentials);
            String credentials = new String(decodedBytes);
            // Process credentials
        }
    }
    
    public void good_case_2(HttpServletRequest request) {
        // Spring Security authentication using Java's built-in Base64
        String token = request.getParameter("token");
        if (token != null) {
            // ok: java-deprecatedspringbase64
            byte[] decodedToken = java.util.Base64.getDecoder().decode(token);
            String tokenData = new String(decodedToken);
            // Process token data
        }
    }
    
    @RestController
    public class good_case_3 {
        // Spring REST API controller using Java's built-in Base64 for file upload
        @PostMapping("/upload")
        public ResponseEntity<String> uploadFile(@RequestBody String base64File) {
            // ok: java-deprecatedspringbase64
            byte[] fileContent = java.util.Base64.getDecoder().decode(base64File);
            // Save file content
            return ResponseEntity.ok("File uploaded successfully");
        }
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Spring Integration HTTP gateway using Base64Utils
        String imageData = request.getParameter("image");
        if (imageData != null) {
            // ok: java-deprecatedspringbase64
            byte[] imageBytes = Base64Utils.decodeFromString(imageData);
            response.setContentType("image/jpeg");
            response.getOutputStream().write(imageBytes);
        }
    }
    
    @Controller
    public class good_case_5 {
        // Spring MVC Thymeleaf template with Java's built-in Base64
        @GetMapping("/profile")
        public String getProfile(HttpServletRequest request, Model model) {
            String profileImage = request.getParameter("avatar");
            if (profileImage != null) {
                // ok: java-deprecatedspringbase64
                byte[] imageData = java.util.Base64.getDecoder().decode(profileImage);
                model.addAttribute("profileImageData", imageData);
            }
            return "profile";
        }
    }
    
    public void good_case_6() {
        // Spring WebClient with Base64Utils
        WebClient webClient = WebClient.create("https://api.example.com");
        webClient.get()
                .uri("/data")
                .retrieve()
                .bodyToMono(String.class)
                .subscribe(response -> {
                    // ok: java-deprecatedspringbase64
                    byte[] decodedData = Base64Utils.decodeFromString(response);
                    // Process decoded data
                });
    }
    
    public class good_case_7 extends TextWebSocketHandler {
        // Spring WebSocket handler with Java's built-in Base64
        @Override
        public void handleTextMessage(WebSocketSession session, TextMessage message) {
            String payload = message.getPayload();
            // ok: java-deprecatedspringbase64
            byte[] decodedPayload = java.util.Base64.getDecoder().decode(payload);
            // Process decoded payload
        }
    }
    
    public void good_case_8(HttpServletRequest request) {
        // Spring Batch job with Base64Utils
        String batchData = request.getParameter("batchData");
        ItemProcessor<String, byte[]> processor = item -> {
            // ok: java-deprecatedspringbase64
            return Base64Utils.decodeFromString(item);
        };
        // Use processor in batch job
    }
    
    public void good_case_9(HttpServletRequest request) {
        // Spring Redis template with Java's built-in Base64
        RedisTemplate<String, byte[]> redisTemplate = new RedisTemplate<>();
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        // ok: java-deprecatedspringbase64
        byte[] encodedValue = java.util.Base64.getEncoder().encode(value.getBytes());
        redisTemplate.opsForValue().set(key, encodedValue);
    }
    
    public void good_case_10(HttpServletRequest request) {
        // Spring Kafka producer with Base64Utils
        KafkaTemplate<String, byte[]> kafkaTemplate = new KafkaTemplate<>(null);
        String message = request.getParameter("message");
        // ok: java-deprecatedspringbase64
        byte[] encodedMessage = Base64Utils.encode(message.getBytes());
        kafkaTemplate.send("topic", encodedMessage);
    }
    
    public void good_case_11(HttpServletRequest request) {
        // Spring RabbitMQ template with Java's built-in Base64
        RabbitTemplate rabbitTemplate = new RabbitTemplate();
        String message = request.getParameter("message");
        // ok: java-deprecatedspringbase64
        byte[] encodedMessage = java.util.Base64.getEncoder().encode(message.getBytes());
        rabbitTemplate.convertAndSend("exchange", "routingKey", encodedMessage);
    }
    
    public void good_case_12(HttpServletRequest request) throws Exception {
        // Spring Mail sender with Base64Utils
        JavaMailSender mailSender = null;
        javax.mail.internet.MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        
        String attachment = request.getParameter("attachment");
        // ok: java-deprecatedspringbase64
        byte[] decodedAttachment = Base64Utils.decodeFromString(attachment);
        
        helper.addAttachment("document.pdf", new javax.activation.DataSource() {
            @Override
            public java.io.InputStream getInputStream() {
                return new java.io.ByteArrayInputStream(decodedAttachment);
            }
            @Override
            public java.io.OutputStream getOutputStream() { return null; }
            @Override
            public String getContentType() { return "application/pdf"; }
            @Override
            public String getName() { return "document.pdf"; }
        });
    }
    
    public class good_case_13 extends AbstractGatewayFilterFactory<Object> {
        // Spring Cloud Gateway filter with Java's built-in Base64
        @Override
        public GatewayFilter apply(Object config) {
            return (exchange, chain) -> {
                String token = exchange.getRequest().getHeaders().getFirst("Authorization");
                if (token != null && token.startsWith("Basic ")) {
                    String base64Credentials = token.substring("Basic ".length());
                    // ok: java-deprecatedspringbase64
                    byte[] decodedBytes = java.util.Base64.getDecoder().decode(base64Credentials);
                    String credentials = new String(decodedBytes);
                    // Process credentials
                }
                return chain.filter(exchange);
            };
        }
    }
    
    public void good_case_14(ServerRequest request) {
        // Spring WebFlux functional endpoint with Base64Utils
        request.bodyToMono(String.class)
                .map(body -> {
                    // ok: java-deprecatedspringbase64
                    return Base64Utils.decodeFromString(body);
                })
                .subscribe(decodedData -> {
                    // Process decoded data
                });
    }
    
    public void good_case_15(HttpServletRequest request, SseEmitter emitter) {
        // Spring Server-Sent Events with Java's built-in Base64
        String eventData = request.getParameter("data");
        // ok: java-deprecatedspringbase64
        byte[] decodedData = java.util.Base64.getDecoder().decode(eventData);
        emitter.send(decodedData);
    }
}
// {/fact}