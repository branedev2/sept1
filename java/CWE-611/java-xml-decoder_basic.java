import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.BufferedReader;

public class XMLDecoderVulnerabilityExamples {

    // True positives (vulnerable code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("xml");
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlData.getBytes()));
        Object result = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("Processed: " + result);
    }
    
    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        BufferedReader reader = request.getReader();
        StringBuilder xmlBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            xmlBuilder.append(line);
        }
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlBuilder.toString().getBytes()));
        Map<String, Object> result = (Map<String, Object>) decoder.readObject();
        decoder.close();
        
        response.getWriter().println("User: " + result.get("username"));
    }
    
    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String xmlFile = request.getParameter("config");
        if (xmlFile == null || xmlFile.isEmpty()) {
            throw new ServletException("Missing config parameter");
        }
        
        try (FileInputStream fis = new FileInputStream(xmlFile)) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(fis);
            Object config = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Config loaded: " + config);
        }
    }
    
    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        URL xmlUrl = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) xmlUrl.openConnection();
        
        try (InputStream inputStream = connection.getInputStream()) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(inputStream);
            Object data = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Remote data: " + data);
        }
    }
    
    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String header = request.getHeader("X-Custom-XML");
        if (header != null && !header.isEmpty()) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(header.getBytes()));
            Object result = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Header processed: " + result);
        }
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookie = request.getHeader("Cookie");
        String xmlData = extractXmlFromCookie(cookie);
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new StringReader(xmlData));
        Object userData = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("User data: " + userData);
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String[]> parameterMap = request.getParameterMap();
        String[] xmlValues = parameterMap.get("xmlData");
        
        if (xmlValues != null && xmlValues.length > 0) {
            String xml = xmlValues[0];
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xml.getBytes()));
            Object result = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Result: " + result);
        }
    }
    
    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String base64Xml = request.getParameter("data");
        byte[] decodedXml = java.util.Base64.getDecoder().decode(base64Xml);
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(decodedXml));
        Object result = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("Decoded result: " + result);
    }
    
    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String part = request.getPart("xmlFile").getSubmittedFileName();
        InputStream inputStream = request.getPart("xmlFile").getInputStream();
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(inputStream);
        Object uploadedData = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("Uploaded: " + uploadedData);
    }
    
    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = "";
        for (String paramName : request.getParameterMap().keySet()) {
            if (paramName.startsWith("xml_")) {
                xmlData = request.getParameter(paramName);
                break;
            }
        }
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlData.getBytes()));
        Object result = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("Dynamic param result: " + result);
    }
    
    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String xmlData = request.getParameter("xml");
        ByteArrayInputStream bais = new ByteArrayInputStream(xmlData.getBytes());
        
        try {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(bais);
            while (true) {
                Object obj = decoder.readObject();
                if (obj == null) break;
                response.getWriter().println(obj);
            }
            decoder.close();
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
    
    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String xmlData = request.getParameter("data");
        
        if ("process".equals(action)) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(
                new ByteArrayInputStream(xmlData.getBytes("UTF-8"))
            );
            Object result = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Processed with action: " + result);
        }
    }
    
    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String sessionId = request.getSession().getId();
        String xmlCache = getXmlFromCache(sessionId); // Assume this gets XML from some cache
        
        if (xmlCache != null) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlCache.getBytes()));
            Object sessionData = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Session data: " + sessionData);
        }
    }
    
    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String referer = request.getHeader("Referer");
        String encodedXml = extractEncodedXmlFromUrl(referer); // Assume this extracts XML from URL
        
        if (encodedXml != null) {
            // ruleid: java-xml-decoder
            XMLDecoder decoder = new XMLDecoder(
                new ByteArrayInputStream(java.net.URLDecoder.decode(encodedXml, "UTF-8").getBytes())
            );
            Object result = decoder.readObject();
            decoder.close();
            
            response.getWriter().println("Referer data: " + result);
        }
    }
    
    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String jsonData = request.getParameter("json");
        // Assume convertJsonToXml transforms JSON to XML format
        String xmlData = convertJsonToXml(jsonData);
        
        // ruleid: java-xml-decoder
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xmlData.getBytes()));
        Object result = decoder.readObject();
        decoder.close();
        
        response.getWriter().println("Converted result: " + result);
    }
    
    // True negatives (secure code)
    
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-decoder
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("Processed safely: " + doc.getDocumentElement().getNodeName());
    }
    
    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Instead of using XMLDecoder, use a safer alternative like JSON
        String jsonData = request.getParameter("data");
        
        // ok: java-xml-decoder
        java.util.Map<String, Object> result = new com.google.gson.Gson().fromJson(
            jsonData, java.util.Map.class);
        
        response.getWriter().println("Safely processed: " + result);
    }
    
    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlFile = request.getParameter("config");
        
        // ok: java-xml-decoder
        // Using JAXB instead of XMLDecoder
        javax.xml.bind.JAXBContext context = javax.xml.bind.JAXBContext.newInstance(ConfigClass.class);
        javax.xml.bind.Unmarshaller unmarshaller = context.createUnmarshaller();
        ConfigClass config = (ConfigClass) unmarshaller.unmarshal(new java.io.File(xmlFile));
        
        response.getWriter().println("Config loaded safely: " + config);
    }
    
    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        URL xmlUrl = new URL(url);
        
        // ok: java-xml-decoder
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xmlUrl.openStream());
        
        response.getWriter().println("Remote data loaded safely: " + doc.getDocumentElement().getNodeName());
    }
    
    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String header = request.getHeader("X-Custom-Data");
        
        // ok: java-xml-decoder
        // Using a safer format like JSON instead of XML
        if (header != null && !header.isEmpty()) {
            Map<String, Object> result = new com.google.gson.Gson().fromJson(
                header, Map.class);
            response.getWriter().println("Header processed safely: " + result);
        }
    }
    
    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Validate XML against a schema before processing
        javax.xml.validation.SchemaFactory schemaFactory = 
            javax.xml.validation.SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
        javax.xml.validation.Schema schema = schemaFactory.newSchema(new java.io.File("schema.xsd"));
        
        // ok: java-xml-decoder
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setSchema(schema);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        response.getWriter().println("Validated and processed safely: " + doc.getDocumentElement().getNodeName());
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-decoder
        // Using SAX parser with security features enabled
        javax.xml.parsers.SAXParserFactory spf = javax.xml.parsers.SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        javax.xml.parsers.SAXParser parser = spf.newSAXParser();
        
        MySaxHandler handler = new MySaxHandler();
        parser.parse(new InputSource(new StringReader(xmlData)), handler);
        
        response.getWriter().println("SAX parsed safely: " + handler.getResult());
    }
    
    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String base64Xml = request.getParameter("data");
        byte[] decodedXml = java.util.Base64.getDecoder().decode(base64Xml);
        
        // ok: java-xml-decoder
        // Using StAX parser with security features
        javax.xml.stream.XMLInputFactory xif = javax.xml.stream.XMLInputFactory.newInstance();
        xif.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);
        xif.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        
        javax.xml.stream.XMLStreamReader xsr = xif.createXMLStreamReader(
            new ByteArrayInputStream(decodedXml));
        
        StringBuilder result = new StringBuilder();
        while (xsr.hasNext()) {
            xsr.next();
            if (xsr.isStartElement()) {
                result.append(xsr.getLocalName()).append(" ");
            }
        }
        
        response.getWriter().println("StAX parsed safely: " + result.toString());
    }
    
    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InputStream inputStream = request.getPart("xmlFile").getInputStream();
        
        // ok: java-xml-decoder
        // Using DOM4J with security features
        org.dom4j.io.SAXReader reader = new org.dom4j.io.SAXReader();
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        org.dom4j.Document document = reader.read(inputStream);
        response.getWriter().println("DOM4J parsed safely: " + document.getRootElement().getName());
    }
    
    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-decoder
        // Using XStream with security enhancements
        com.thoughtworks.xstream.XStream xstream = new com.thoughtworks.xstream.XStream();
        xstream.allowTypesByWildcard(new String[] {"com.example.model.*"});
        xstream.addPermission(com.thoughtworks.xstream.security.NoTypePermission.NONE);
        xstream.addPermission(com.thoughtworks.xstream.security.AnyTypePermission.ANY);
        
        Object result = xstream.fromXML(xmlData);
        response.getWriter().println("XStream parsed safely: " + result);
    }
    
    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-decoder
        // Using JDOM2 with security features
        org.jdom2.input.SAXBuilder builder = new org.jdom2.input.SAXBuilder();
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        org.jdom2.Document document = builder.build(new StringReader(xmlData));
        response.getWriter().println("JDOM2 parsed safely: " + document.getRootElement().getName());
    }
    
    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String action = request.getParameter("action");
        String xmlData = request.getParameter("data");
        
        if ("process".equals(action)) {
            // ok: java-xml-decoder
            // Using Jackson XML instead of XMLDecoder
            com.fasterxml.jackson.dataformat.xml.XmlMapper xmlMapper = new com.fasterxml.jackson.dataformat.xml.XmlMapper();
            Map<String, Object> result = xmlMapper.readValue(xmlData, Map.class);
            
            response.getWriter().println("Jackson processed safely: " + result);
        }
    }
    
    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // ok: java-xml-decoder
        // Using a custom XML parser with validation
        MySecureXmlParser parser = new MySecureXmlParser();
        parser.setDisallowDoctypeDecl(true);
        parser.setDisallowExternalEntities(true);
        
        Object result = parser.parse(xmlData);
        response.getWriter().println("Custom parsed safely: " + result);
    }
    
    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // ok: java-xml-decoder
        // Using a completely different approach - properties file instead of XML
        String propsData = request.getParameter("config");
        
        java.util.Properties props = new java.util.Properties();
        props.load(new StringReader(propsData));
        
        response.getWriter().println("Properties loaded safely: " + props.getProperty("name"));
    }
    
    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String jsonData = request.getParameter("json");
        
        // ok: java-xml-decoder
        // Using JSON instead of XML for configuration
        org.json.JSONObject json = new org.json.JSONObject(jsonData);
        String name = json.getString("name");
        int value = json.getInt("value");
        
        response.getWriter().println("JSON processed safely: " + name + "=" + value);
    }
    
    // Helper methods
    private String extractXmlFromCookie(String cookie) {
        // Implementation to extract XML from cookie
        return cookie != null ? cookie.replaceAll("^xml=", "") : "";
    }
    
    private String getXmlFromCache(String sessionId) {
        // Implementation to get XML from cache
        return "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\"><object class=\"java.util.HashMap\"/></java>";
    }
    
    private String extractEncodedXmlFromUrl(String url) {
        // Implementation to extract encoded XML from URL
        return url != null && url.contains("xml=") ? url.substring(url.indexOf("xml=") + 4) : null;
    }
    
    private String convertJsonToXml(String json) {
        // Implementation to convert JSON to XML
        return "<java version=\"1.8.0\" class=\"java.beans.XMLDecoder\"><object class=\"java.util.HashMap\"/></java>";
    }
    
    // Mock classes for examples
    private static class ConfigClass {
        private String name;
        private int value;
        
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getValue() { return value; }
        public void setValue(int value) { this.value = value; }
        
        @Override
        public String toString() {
            return "Config[name=" + name + ", value=" + value + "]";
        }
    }
    
    private static class MySaxHandler extends org.xml.sax.helpers.DefaultHandler {
        private StringBuilder result = new StringBuilder();
        
        @Override
        public void startElement(String uri, String localName, String qName, org.xml.sax.Attributes attributes) {
            result.append(qName).append(" ");
        }
        
        public String getResult() {
            return result.toString();
        }
    }
    
    private static class MySecureXmlParser {
        private boolean disallowDoctypeDecl;
        private boolean disallowExternalEntities;
        
        public void setDisallowDoctypeDecl(boolean value) {
            this.disallowDoctypeDecl = value;
        }
        
        public void setDisallowExternalEntities(boolean value) {
            this.disallowExternalEntities = value;
        }
        
        public Object parse(String xml) throws Exception {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", disallowDoctypeDecl);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", !disallowExternalEntities);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xml)));
            
            // Custom processing logic here
            return doc.getDocumentElement().getNodeName();
        }
    }
}
// {/fact}