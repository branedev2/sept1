import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.sax.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import java.io.*;
import javax.servlet.http.*;
import org.apache.commons.io.IOUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.apache.struts2.util.ServletContextAware;
import javax.servlet.*;
import org.w3c.dom.*;
import javax.xml.XMLConstants;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.MultipartBody;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.servlet.CamelHttpTransportServlet;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.springframework.integration.xml.transformer.XsltPayloadTransformer;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;
import java.util.Map;

// Security Issue: XML External Entity (XXE) vulnerability in TransformerFactory

// True Positive Examples (Vulnerable/Insecure Code)

@Controller
public class XXEVulnerableExamples {

    // Example 1: Basic TransformerFactory vulnerability with Spring MVC
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad1")
    public String bad_case_1(@RequestParam("xmlFile") String xmlContent) {
        try {
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            
            StringReader reader = new StringReader(xmlContent);
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error processing XML: " + e.getMessage();
        }
    }
    
    // Example 2: Using TransformerFactory with SAX in Servlet API
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory factory = TransformerFactory.newInstance();
            Templates templates = factory.newTemplates(new StreamSource(new File("transform.xsl")));
            Transformer transformer = templates.newTransformer();
            
            Source xmlSource = new StreamSource(new StringReader(xmlData));
            StreamResult result = new StreamResult(response.getOutputStream());
            transformer.transform(xmlSource, result);
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    // Example 3: Using TransformerFactory with JAX-RS
    @Path("/transform")
    public class bad_case_3 {
        @POST
        @Consumes("application/xml")
        @Produces("application/xml")
        public String transformXml(String xmlInput) {
            try {
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory tf = TransformerFactory.newInstance();
                Source xslt = new StreamSource(new File("stylesheet.xsl"));
                Transformer transformer = tf.newTransformer(xslt);
                
                Source source = new StreamSource(new StringReader(xmlInput));
                StringWriter output = new StringWriter();
                transformer.transform(source, new StreamResult(output));
                
                return output.toString();
            } catch (Exception e) {
                return "<error>" + e.getMessage() + "</error>";
            }
        }
    }
    
    // Example 4: Using TransformerFactory with Apache CXF multipart
    @Path("/multipart")
    public class bad_case_4 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processMultipartXml(MultipartBody body) {
            try {
                Attachment attachment = body.getAttachment("xmlFile");
                InputStream is = attachment.getDataHandler().getInputStream();
                String xmlContent = IOUtils.toString(is, "UTF-8");
                
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 5: Using TransformerFactory with RESTEasy multipart
    @Path("/resteasy")
    public class bad_case_5 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processXmlWithResteasy(MultipartFormDataInput input) {
            try {
                Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
                List<InputPart> inputParts = uploadForm.get("xmlFile");
                
                String xmlContent = inputParts.get(0).getBodyAsString();
                
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 6: Using TransformerFactory with Jersey multipart
    @Path("/jersey")
    public class bad_case_6 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processXmlWithJersey(@FormDataParam("xmlFile") String xmlContent) {
            try {
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 7: Using TransformerFactory with Apache Camel
    public class bad_case_7 implements Processor {
        public void process(Exchange exchange) throws Exception {
            String xmlContent = exchange.getIn().getBody(String.class);
            
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            exchange.getOut().setBody(writer.toString());
        }
    }
    
    // Example 8: Using TransformerFactory with Apache Commons FileUpload
    public void bad_case_8(HttpServletRequest request) throws Exception {
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        List<FileItem> items = upload.parseRequest(request);
        
        for (FileItem item : items) {
            if (item.getFieldName().equals("xmlFile")) {
                String xmlContent = IOUtils.toString(item.getInputStream(), "UTF-8");
                
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                // Process the transformed XML
                System.out.println(writer.toString());
            }
        }
    }
    
    // Example 9: Using TransformerFactory with Spring Integration
    @Autowired
    private ResourceLoader resourceLoader;
    
    @PostMapping("/spring-integration")
    public String bad_case_9(@RequestBody String xmlContent) {
        try {
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Resource xsltResource = resourceLoader.getResource("classpath:transform.xsl");
            Transformer transformer = transformerFactory.newTransformer(new StreamSource(xsltResource.getInputStream()));
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 10: Using TransformerFactory with DOM
    @PostMapping("/dom-transform")
    public String bad_case_10(@RequestBody String xmlContent) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            
            DOMSource source = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 11: Using TransformerFactory with SAX
    @PostMapping("/sax-transform")
    public String bad_case_11(@RequestBody String xmlContent) {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            SAXParser parser = spf.newSAXParser();
            XMLReader reader = parser.getXMLReader();
            
            SAXSource source = new SAXSource(reader, new InputSource(new StringReader(xmlContent)));
            
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 12: Using TransformerFactory with Spring MVC MultipartFile
    @PostMapping("/upload-xml")
    public ResponseEntity<String> bad_case_12(@RequestParam("file") MultipartFile file) {
        try {
            String xmlContent = new String(file.getBytes(), "UTF-8");
            
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return new ResponseEntity<>(writer.toString(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    // Example 13: Using TransformerFactory with custom properties
    @PostMapping("/custom-properties")
    public String bad_case_13(@RequestBody String xmlContent) {
        try {
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute("indent-number", 2);
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 14: Using TransformerFactory with Struts 2
    public class bad_case_14 implements ServletRequestAware {
        private HttpServletRequest request;
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String processXml() {
            try {
                String xmlContent = IOUtils.toString(request.getInputStream(), "UTF-8");
                
                // ruleid: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 15: Using TransformerFactory with custom error handler
    @PostMapping("/custom-error-handler")
    public String bad_case_15(@RequestBody String xmlContent) {
        try {
            // ruleid: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            
            transformer.setErrorListener(new ErrorListener() {
                public void warning(TransformerException e) { System.out.println("Warning: " + e.getMessage()); }
                public void error(TransformerException e) { System.out.println("Error: " + e.getMessage()); }
                public void fatalError(TransformerException e) { System.out.println("Fatal: " + e.getMessage()); }
            });
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: Secure TransformerFactory with Spring MVC
    @PostMapping("/good1")
    public String good_case_1(@RequestParam("xmlFile") String xmlContent) {
        try {
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = transformerFactory.newTransformer();
            
            StringReader reader = new StringReader(xmlContent);
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error processing XML: " + e.getMessage();
        }
    }
    
    // Example 2: Secure TransformerFactory with Servlet API
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String xmlData = IOUtils.toString(request.getInputStream(), "UTF-8");
            
            // ok: java-xxe-in-transformerfactory
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Templates templates = factory.newTemplates(new StreamSource(new File("transform.xsl")));
            Transformer transformer = templates.newTransformer();
            
            Source xmlSource = new StreamSource(new StringReader(xmlData));
            StreamResult result = new StreamResult(response.getOutputStream());
            transformer.transform(xmlSource, result);
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    // Example 3: Secure TransformerFactory with JAX-RS
    @Path("/transform-secure")
    public class good_case_3 {
        @POST
        @Consumes("application/xml")
        @Produces("application/xml")
        public String transformXml(String xmlInput) {
            try {
                // ok: java-xxe-in-transformerfactory
                TransformerFactory tf = TransformerFactory.newInstance();
                tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Source xslt = new StreamSource(new File("stylesheet.xsl"));
                Transformer transformer = tf.newTransformer(xslt);
                
                Source source = new StreamSource(new StringReader(xmlInput));
                StringWriter output = new StringWriter();
                transformer.transform(source, new StreamResult(output));
                
                return output.toString();
            } catch (Exception e) {
                return "<error>" + e.getMessage() + "</error>";
            }
        }
    }
    
    // Example 4: Secure TransformerFactory with Apache CXF multipart
    @Path("/multipart-secure")
    public class good_case_4 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processMultipartXml(MultipartBody body) {
            try {
                Attachment attachment = body.getAttachment("xmlFile");
                InputStream is = attachment.getDataHandler().getInputStream();
                String xmlContent = IOUtils.toString(is, "UTF-8");
                
                // ok: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 5: Secure TransformerFactory with RESTEasy multipart
    @Path("/resteasy-secure")
    public class good_case_5 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processXmlWithResteasy(MultipartFormDataInput input) {
            try {
                Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
                List<InputPart> inputParts = uploadForm.get("xmlFile");
                
                String xmlContent = inputParts.get(0).getBodyAsString();
                
                // ok: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 6: Secure TransformerFactory with Jersey multipart
    @Path("/jersey-secure")
    public class good_case_6 {
        @POST
        @Consumes("multipart/form-data")
        @Produces("text/html")
        public String processXmlWithJersey(@FormDataParam("xmlFile") String xmlContent) {
            try {
                // ok: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 7: Secure TransformerFactory with Apache Camel
    public class good_case_7 implements Processor {
        public void process(Exchange exchange) throws Exception {
            String xmlContent = exchange.getIn().getBody(String.class);
            
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = transformerFactory.newTransformer();
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            exchange.getOut().setBody(writer.toString());
        }
    }
    
    // Example 8: Secure TransformerFactory with Apache Commons FileUpload
    public void good_case_8(HttpServletRequest request) throws Exception {
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        List<FileItem> items = upload.parseRequest(request);
        
        for (FileItem item : items) {
            if (item.getFieldName().equals("xmlFile")) {
                String xmlContent = IOUtils.toString(item.getInputStream(), "UTF-8");
                
                // ok: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                // Process the transformed XML
                System.out.println(writer.toString());
            }
        }
    }
    
    // Example 9: Secure TransformerFactory with Spring Integration
    @Autowired
    private ResourceLoader resourceLoader;
    
    @PostMapping("/spring-integration-secure")
    public String good_case_9(@RequestBody String xmlContent) {
        try {
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Resource xsltResource = resourceLoader.getResource("classpath:transform.xsl");
            Transformer transformer = transformerFactory.newTransformer(new StreamSource(xsltResource.getInputStream()));
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 10: Secure TransformerFactory with DOM
    @PostMapping("/dom-transform-secure")
    public String good_case_10(@RequestBody String xmlContent) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(new InputSource(new StringReader(xmlContent)));
            
            // ok: java-xxe-in-transformerfactory
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = tf.newTransformer();
            
            DOMSource source = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 11: Secure TransformerFactory with SAX
    @PostMapping("/sax-transform-secure")
    public String good_case_11(@RequestBody String xmlContent) {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            SAXParser parser = spf.newSAXParser();
            XMLReader reader = parser.getXMLReader();
            
            SAXSource source = new SAXSource(reader, new InputSource(new StringReader(xmlContent)));
            
            // ok: java-xxe-in-transformerfactory
            TransformerFactory tf = TransformerFactory.newInstance();
            tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = tf.newTransformer();
            
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 12: Secure TransformerFactory with Spring MVC MultipartFile
    @PostMapping("/upload-xml-secure")
    public ResponseEntity<String> good_case_12(@RequestParam("file") MultipartFile file) {
        try {
            String xmlContent = new String(file.getBytes(), "UTF-8");
            
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = transformerFactory.newTransformer();
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return new ResponseEntity<>(writer.toString(), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    
    // Example 13: Secure TransformerFactory with custom properties
    @PostMapping("/custom-properties-secure")
    public String good_case_13(@RequestBody String xmlContent) {
        try {
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            transformerFactory.setAttribute("indent-number", 2);
            
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // Example 14: Secure TransformerFactory with Struts 2
    public class good_case_14 implements ServletRequestAware {
        private HttpServletRequest request;
        
        public void setServletRequest(HttpServletRequest request) {
            this.request = request;
        }
        
        public String processXml() {
            try {
                String xmlContent = IOUtils.toString(request.getInputStream(), "UTF-8");
                
                // ok: java-xxe-in-transformerfactory
                TransformerFactory transformerFactory = TransformerFactory.newInstance();
                transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
                transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
                
                Transformer transformer = transformerFactory.newTransformer();
                
                Source source = new StreamSource(new StringReader(xmlContent));
                StringWriter writer = new StringWriter();
                transformer.transform(source, new StreamResult(writer));
                
                return writer.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
    
    // Example 15: Secure TransformerFactory with custom error handler
    @PostMapping("/custom-error-handler-secure")
    public String good_case_15(@RequestBody String xmlContent) {
        try {
            // ok: java-xxe-in-transformerfactory
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = transformerFactory.newTransformer();
            
            transformer.setErrorListener(new ErrorListener() {
                public void warning(TransformerException e) { System.out.println("Warning: " + e.getMessage()); }
                public void error(TransformerException e) { System.out.println("Error: " + e.getMessage()); }
                public void fatalError(TransformerException e) { System.out.println("Fatal: " + e.getMessage()); }
            });
            
            Source source = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            transformer.transform(source, new StreamResult(writer));
            
            return writer.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
// {/fact}