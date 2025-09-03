import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import org.jboss.resteasy.annotations.providers.jaxb.Wrapped;
import org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider;
import org.jboss.resteasy.plugins.providers.jaxb.JAXBXmlRootElementProvider;
import org.jboss.resteasy.plugins.providers.SerializableProvider;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.plugins.server.servlet.HttpServletDispatcher;
import org.jboss.resteasy.plugins.server.netty.NettyJaxrsServer;
import org.jboss.resteasy.plugins.server.undertow.UndertowJaxrsServer;
import org.jboss.resteasy.plugins.server.vertx.VertxJaxrsServer;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.jboss.resteasy.plugins.providers.atom.Feed;
import org.jboss.resteasy.plugins.providers.jaxb.JAXBElement;
import org.jboss.resteasy.plugins.providers.jaxb.JAXBXmlTypeProvider;
import org.jboss.resteasy.plugins.providers.jaxb.XmlJAXBContextFinder;
import org.jboss.resteasy.plugins.providers.yaml.YamlProvider;
import org.jboss.resteasy.plugins.interceptors.CacheControlFeature;
import org.jboss.resteasy.plugins.validation.ValidatorContextResolver;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.jboss.resteasy.plugins.providers.RegisterBuiltin;
import org.jboss.resteasy.spi.ResteasyDeployment;
import org.jboss.resteasy.plugins.server.servlet.ResteasyContextParameters;
import org.jboss.resteasy.plugins.server.resourcefactory.SingletonResource;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// Security Issue: Insecure deserialization in RESTEasy endpoints using wildcard media types

// True Positive Examples (Vulnerable/Insecure Code)

// Example 1: Basic RESTEasy endpoint with wildcard media type
public class bad_case_1 {
    @Path("/api/data")
    public static class DataResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("*/*")
        @Produces(MediaType.APPLICATION_JSON)
        public String processData(Object data) {
            // Process the deserialized object
            return "Processed: " + data.toString();
        }
    }
}

// Example 2: RESTEasy endpoint explicitly accepting serialized Java objects
public class bad_case_2 {
    @Path("/api/objects")
    public static class ObjectResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("application/x-java-serialized-object")
        public String processSerializedObject(Serializable obj) {
            // Process the deserialized object
            return "Received serialized object: " + obj.getClass().getName();
        }
    }
}

// Example 3: RESTEasy endpoint using MediaType.WILDCARD_TYPE constant
public class bad_case_3 {
    @Path("/api/generic")
    public static class GenericResource {
        // ruleid: java-rest-easy-deserialization
        @PUT
        @Consumes(MediaType.WILDCARD_TYPE)
        public void storeObject(Object obj) {
            // Store the deserialized object
            System.out.println("Stored object: " + obj);
        }
    }
}

// Example 4: RESTEasy resource with multiple media types including wildcard
public class bad_case_4 {
    @Path("/api/multi")
    public static class MultiFormatResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML, "*/*"})
        public String handleMultipleFormats(Object data) {
            // Process data in multiple formats
            return "Processed multi-format data";
        }
    }
}

// Example 5: RESTEasy endpoint with wildcard subtype
public class bad_case_5 {
    @Path("/api/documents")
    public static class DocumentResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("application/*")
        public String processDocument(Object doc) {
            // Process document
            return "Document processed";
        }
    }
}

// Example 6: RESTEasy JAX-RS application with wildcard media type
public class bad_case_6 {
    @Path("/api/users")
    public static class UserResource {
        // ruleid: java-rest-easy-deserialization
        @PUT
        @Path("/{id}")
        @Consumes({"application/json", "application/x-java-serialized-object"})
        public void updateUser(@PathParam("id") String id, Serializable userData) {
            // Update user with serialized data
            System.out.println("Updated user: " + id);
        }
    }
}

// Example 7: RESTEasy endpoint with custom provider and wildcard
public class bad_case_7 {
    @Path("/api/custom")
    public static class CustomResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.WILDCARD_TYPE)
        @Wrapped
        public String processCustomData(Object data) {
            // Process with custom provider
            return "Processed with custom provider";
        }
    }
}

// Example 8: RESTEasy multipart form with wildcard
public class bad_case_8 {
    @Path("/api/upload")
    public static class UploadResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("multipart/*")
        public String handleUpload(MultipartFormDataInput input) {
            // Process multipart form data
            return "Upload processed";
        }
    }
}

// Example 9: RESTEasy endpoint with wildcard for atom feeds
public class bad_case_9 {
    @Path("/api/feeds")
    public static class FeedResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("*/*")
        public String processFeed(Feed feed) {
            // Process atom feed
            return "Feed processed: " + feed.getTitle();
        }
    }
}

// Example 10: RESTEasy client with wildcard media type
public class bad_case_10 {
    public void createClientWithWildcard() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        // ruleid: java-rest-easy-deserialization
        client.target("http://example.com/api")
              .request()
              .accept("*/*")
              .post(javax.ws.rs.client.Entity.entity(new Object(), "application/x-java-serialized-object"));
    }
}

// Example 11: RESTEasy server configuration with wildcard provider
public class bad_case_11 {
    public void configureServer() {
        ResteasyDeployment deployment = new ResteasyDeployment();
        // ruleid: java-rest-easy-deserialization
        deployment.setMediaTypeMapping("*:application/x-java-serialized-object");
        
        NettyJaxrsServer server = new NettyJaxrsServer();
        server.setDeployment(deployment);
        server.start();
    }
}

// Example 12: RESTEasy endpoint with YAML provider and wildcard
public class bad_case_12 {
    @Path("/api/config")
    public static class ConfigResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes({"application/yaml", "*/*"})
        public String updateConfig(Map<String, Object> config) {
            // Update configuration
            return "Configuration updated";
        }
    }
}

// Example 13: RESTEasy endpoint with JAXBElement and wildcard
public class bad_case_13 {
    @Path("/api/xml")
    public static class XmlResource {
        // ruleid: java-rest-easy-deserialization
        @PUT
        @Consumes(MediaType.WILDCARD_TYPE)
        public String processXml(JAXBElement<?> element) {
            // Process XML element
            return "XML processed";
        }
    }
}

// Example 14: RESTEasy endpoint with validator and wildcard
public class bad_case_14 {
    @Path("/api/validate")
    public static class ValidationResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("*/*")
        public String validateData(Object data) {
            // Validate data
            return "Data validated";
        }
    }
}

// Example 15: RESTEasy endpoint with singleton resource and wildcard
public class bad_case_15 {
    @Path("/api/singleton")
    public static class SingletonResource {
        // ruleid: java-rest-easy-deserialization
        @POST
        @Consumes("application/x-java-serialized-object")
        public String processSingleton(Serializable obj) {
            // Process singleton
            return "Singleton processed";
        }
    }
}

// True Negative Examples (Safe/Secure Code)

// Example 1: RESTEasy endpoint with specific safe media type
public class good_case_1 {
    @Path("/api/data")
    public static class DataResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.APPLICATION_JSON)
        @Produces(MediaType.APPLICATION_JSON)
        public String processData(Map<String, Object> data) {
            // Process the JSON data safely
            return "Processed: " + data.toString();
        }
    }
}

// Example 2: RESTEasy endpoint with multiple safe media types
public class good_case_2 {
    @Path("/api/objects")
    public static class ObjectResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
        public String processObject(Object obj) {
            // Process the object safely
            return "Received object: " + obj.getClass().getName();
        }
    }
}

// Example 3: RESTEasy endpoint with form data
public class good_case_3 {
    @Path("/api/forms")
    public static class FormResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        public String processForm(@FormParam("name") String name, @FormParam("age") int age) {
            // Process form data safely
            return "Form processed for: " + name;
        }
    }
}

// Example 4: RESTEasy endpoint with multipart form data
public class good_case_4 {
    @Path("/api/upload")
    public static class UploadResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.MULTIPART_FORM_DATA)
        public String handleUpload(MultipartFormDataInput input) {
            // Process multipart form data safely
            return "Upload processed safely";
        }
    }
}

// Example 5: RESTEasy endpoint with text plain
public class good_case_5 {
    @Path("/api/text")
    public static class TextResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.TEXT_PLAIN)
        public String processText(String text) {
            // Process text safely
            return "Text processed: " + text;
        }
    }
}

// Example 6: RESTEasy endpoint with specific XML format
public class good_case_6 {
    @Path("/api/xml")
    public static class XmlResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.APPLICATION_XML)
        public String processXml(JAXBElement<?> element) {
            // Process XML safely
            return "XML processed safely";
        }
    }
}

// Example 7: RESTEasy endpoint with HTML form
public class good_case_7 {
    @Path("/api/html")
    public static class HtmlResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes(MediaType.TEXT_HTML)
        public String processHtml(String html) {
            // Process HTML safely
            return "HTML processed";
        }
    }
}

// Example 8: RESTEasy endpoint with CSV data
public class good_case_8 {
    @Path("/api/csv")
    public static class CsvResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("text/csv")
        public String processCsv(String csv) {
            // Process CSV safely
            return "CSV processed";
        }
    }
}

// Example 9: RESTEasy endpoint with YAML data
public class good_case_9 {
    @Path("/api/yaml")
    public static class YamlResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("application/yaml")
        public String processYaml(Map<String, Object> yaml) {
            // Process YAML safely
            return "YAML processed";
        }
    }
}

// Example 10: RESTEasy client with safe media type
public class good_case_10 {
    public void createClientWithSafeMediaType() {
        ResteasyClient client = new ResteasyClientBuilder().build();
        // ok: java-rest-easy-deserialization
        client.target("http://example.com/api")
              .request()
              .accept(MediaType.APPLICATION_JSON)
              .post(javax.ws.rs.client.Entity.entity("{\"name\":\"test\"}", MediaType.APPLICATION_JSON));
    }
}

// Example 11: RESTEasy server configuration with safe provider
public class good_case_11 {
    public void configureServerSafely() {
        ResteasyDeployment deployment = new ResteasyDeployment();
        // ok: java-rest-easy-deserialization
        deployment.setMediaTypeMapping("json:application/json");
        
        NettyJaxrsServer server = new NettyJaxrsServer();
        server.setDeployment(deployment);
        server.start();
    }
}

// Example 12: RESTEasy endpoint with specific image format
public class good_case_12 {
    @Path("/api/images")
    public static class ImageResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("image/jpeg")
        public String processImage(byte[] imageData) {
            // Process image safely
            return "Image processed, size: " + imageData.length;
        }
    }
}

// Example 13: RESTEasy endpoint with PDF format
public class good_case_13 {
    @Path("/api/documents")
    public static class DocumentResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("application/pdf")
        public String processPdf(byte[] pdfData) {
            // Process PDF safely
            return "PDF processed, size: " + pdfData.length;
        }
    }
}

// Example 14: RESTEasy endpoint with specific audio format
public class good_case_14 {
    @Path("/api/audio")
    public static class AudioResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("audio/mpeg")
        public String processAudio(byte[] audioData) {
            // Process audio safely
            return "Audio processed, size: " + audioData.length;
        }
    }
}

// Example 15: RESTEasy endpoint with specific video format
public class good_case_15 {
    @Path("/api/video")
    public static class VideoResource {
        // ok: java-rest-easy-deserialization
        @POST
        @Consumes("video/mp4")
        public String processVideo(byte[] videoData) {
            // Process video safely
            return "Video processed, size: " + videoData.length;
        }
    }
}