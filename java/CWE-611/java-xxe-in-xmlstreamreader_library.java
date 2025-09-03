import javax.xml.stream.*;
import java.io.*;
import javax.servlet.http.*;
import org.apache.commons.io.IOUtils;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import javax.xml.parsers.*;
import javax.xml.XMLConstants;
import org.springframework.web.bind.annotation.*;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.struts2.dispatcher.multipart.JakartaMultiPartRequest;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.Context;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import com.sun.jersey.multipart.FormDataParam;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.MultipartBody;
import spark.Request;
import spark.Response;
import ratpack.handling.Context;
import ratpack.http.Request;
import play.mvc.Http;
import io.vertx.ext.web.RoutingContext;
import io.micronaut.http.HttpRequest;
import io.javalin.http.Context;
import com.google.api.client.http.HttpRequest;
import org.eclipse.jetty.server.Request;

// Security Issue: XML External Entity (XXE) injection in XMLStreamReader

// True Positive Examples (Vulnerable/Insecure Code)
public class XXEVulnerabilities {

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLInputFactory with default settings (vulnerable to XXE)
        String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
        XMLInputFactory factory = XMLInputFactory.newInstance();
        StringReader reader = new StringReader(xmlData);
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(reader);
        
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_2(org.springframework.web.bind.annotation.RequestBody String xmlData) throws Exception {
        // Spring MVC controller with vulnerable XMLStreamReader
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process the XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_3(CloseableHttpClient httpClient) throws Exception {
        // Apache HttpClient with vulnerable XMLStreamReader
        HttpPost httpPost = new HttpPost("https://example.com/api");
        CloseableHttpResponse response = httpClient.execute(httpPost);
        HttpEntity entity = response.getEntity();
        String xmlData = IOUtils.toString(entity.getContent(), "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_4(JakartaMultiPartRequest multiPartRequest) throws Exception {
        // Apache Struts 2 multipart request with vulnerable XMLStreamReader
        String xmlData = new String(multiPartRequest.getFileContents("xmlFile"));
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public String bad_case_5(APIGatewayProxyRequestEvent event, Context context) throws Exception {
        // AWS Lambda function with vulnerable XMLStreamReader
        String xmlData = event.getBody();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        StringBuilder result = new StringBuilder();
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
            if (xmlStreamReader.isStartElement()) {
                result.append(xmlStreamReader.getLocalName());
            }
        }
        return result.toString();
    }

    public void bad_case_6(MultipartFormDataInput input) throws Exception {
        // RESTEasy multipart input with vulnerable XMLStreamReader
        InputStream xmlStream = input.getFormDataPart("xmlFile", InputStream.class, null);
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_7(@FormDataParam("xmlFile") InputStream xmlStream) throws Exception {
        // Jersey multipart with vulnerable XMLStreamReader
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_8(MultipartBody multipartBody) throws Exception {
        // Apache CXF multipart with vulnerable XMLStreamReader
        Attachment attachment = multipartBody.getAttachment("xmlFile");
        InputStream xmlStream = attachment.getDataHandler().getInputStream();
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public String bad_case_9(spark.Request request) throws Exception {
        // Spark framework with vulnerable XMLStreamReader
        String xmlData = request.body();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        StringBuilder result = new StringBuilder();
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
            if (xmlStreamReader.isStartElement()) {
                result.append(xmlStreamReader.getLocalName());
            }
        }
        return result.toString();
    }

    public void bad_case_10(ratpack.handling.Context ctx) throws Exception {
        // Ratpack framework with vulnerable XMLStreamReader
        Request request = ctx.getRequest();
        String xmlData = request.getBody().getText();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_11(play.mvc.Http.Request request) throws Exception {
        // Play framework with vulnerable XMLStreamReader
        String xmlData = request.body().asText();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_12(io.vertx.ext.web.RoutingContext routingContext) throws Exception {
        // Vert.x framework with vulnerable XMLStreamReader
        String xmlData = routingContext.getBodyAsString();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_13(io.micronaut.http.HttpRequest<?> request) throws Exception {
        // Micronaut framework with vulnerable XMLStreamReader
        String xmlData = request.getBody().map(body -> body.toString()).orElse("");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_14(io.javalin.http.Context ctx) throws Exception {
        // Javalin framework with vulnerable XMLStreamReader
        String xmlData = ctx.body();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void bad_case_15(org.eclipse.jetty.server.Request request) throws Exception {
        // Jetty server with vulnerable XMLStreamReader
        String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xxe-in-xmlstreamreader
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Using XMLInputFactory with secure settings
        String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
        XMLInputFactory factory = XMLInputFactory.newInstance();
        
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_2(org.springframework.web.bind.annotation.RequestBody String xmlData) throws Exception {
        // Spring MVC controller with secure XMLStreamReader
        XMLInputFactory factory = XMLInputFactory.newInstance();
        
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process the XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_3(CloseableHttpClient httpClient) throws Exception {
        // Apache HttpClient with secure XMLStreamReader
        HttpPost httpPost = new HttpPost("https://example.com/api");
        CloseableHttpResponse response = httpClient.execute(httpPost);
        HttpEntity entity = response.getEntity();
        String xmlData = IOUtils.toString(entity.getContent(), "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_4(JakartaMultiPartRequest multiPartRequest) throws Exception {
        // Apache Struts 2 multipart request with secure XMLStreamReader
        String xmlData = new String(multiPartRequest.getFileContents("xmlFile"));
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public String good_case_5(APIGatewayProxyRequestEvent event, Context context) throws Exception {
        // AWS Lambda function with secure XMLStreamReader
        String xmlData = event.getBody();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        StringBuilder result = new StringBuilder();
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
            if (xmlStreamReader.isStartElement()) {
                result.append(xmlStreamReader.getLocalName());
            }
        }
        return result.toString();
    }

    public void good_case_6(MultipartFormDataInput input) throws Exception {
        // RESTEasy multipart input with secure XMLStreamReader
        InputStream xmlStream = input.getFormDataPart("xmlFile", InputStream.class, null);
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_7(@com.sun.jersey.multipart.FormDataParam("xmlFile") InputStream xmlStream) throws Exception {
        // Jersey multipart with secure XMLStreamReader
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_8(MultipartBody multipartBody) throws Exception {
        // Apache CXF multipart with secure XMLStreamReader
        Attachment attachment = multipartBody.getAttachment("xmlFile");
        InputStream xmlStream = attachment.getDataHandler().getInputStream();
        String xmlData = IOUtils.toString(xmlStream, "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public String good_case_9(spark.Request request) throws Exception {
        // Spark framework with secure XMLStreamReader
        String xmlData = request.body();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        StringBuilder result = new StringBuilder();
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
            if (xmlStreamReader.isStartElement()) {
                result.append(xmlStreamReader.getLocalName());
            }
        }
        return result.toString();
    }

    public void good_case_10(ratpack.handling.Context ctx) throws Exception {
        // Ratpack framework with secure XMLStreamReader
        Request request = ctx.getRequest();
        String xmlData = request.getBody().getText();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_11(play.mvc.Http.Request request) throws Exception {
        // Play framework with secure XMLStreamReader
        String xmlData = request.body().asText();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_12(io.vertx.ext.web.RoutingContext routingContext) throws Exception {
        // Vert.x framework with secure XMLStreamReader
        String xmlData = routingContext.getBodyAsString();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_13(io.micronaut.http.HttpRequest<?> request) throws Exception {
        // Micronaut framework with secure XMLStreamReader
        String xmlData = request.getBody().map(body -> body.toString()).orElse("");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_14(io.javalin.http.Context ctx) throws Exception {
        // Javalin framework with secure XMLStreamReader
        String xmlData = ctx.body();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }

    public void good_case_15(org.eclipse.jetty.server.Request request) throws Exception {
        // Jetty server with secure XMLStreamReader
        String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xxe-in-xmlstreamreader
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader xmlStreamReader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        // Process XML data
        while (xmlStreamReader.hasNext()) {
            xmlStreamReader.next();
        }
    }
}
// {/fact}