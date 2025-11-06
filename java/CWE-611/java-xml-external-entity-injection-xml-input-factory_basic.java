import java.io.*;
import javax.xml.stream.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.xml.sax.InputSource;
import javax.xml.parsers.*;
import java.util.Properties;

public class XMLInputFactoryXXEExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Creating XMLInputFactory without security settings
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InputStream inputStream = request.getInputStream();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Explicitly enabling external entities, which is dangerous
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        processXML(reader);
    }

    public void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        InputStream inputStream = new URL(url).openStream();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Only setting DTD support but not disabling external entities
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLEventReader eventReader = factory.createXMLEventReader(inputStream);
        
        while(eventReader.hasNext()) {
            eventReader.nextEvent();
        }
    }

    public void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlFile = request.getParameter("file");
        Reader fileReader = new FileReader(xmlFile);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // No security properties set at all
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(fileReader);
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlContent = request.getHeader("X-XML-Data");
        
        XMLInputFactory inputFactory = XMLInputFactory.newFactory();
        // Setting some properties but missing critical security settings
        inputFactory.setProperty(XMLInputFactory.IS_NAMESPAC_REDACTED_TWILIO_ID_AWARE, true);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLEventReader eventReader = inputFactory.createXMLEventReader(new StringReader(xmlContent));
        
        while(eventReader.hasNext()) {
            eventReader.nextEvent();
        }
    }

    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Part filePart = request.getPart("xmlFile");
        InputStream fileContent = filePart.getInputStream();
        
        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // Setting IS_VALIDATING but not disabling external entities
            factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLStreamReader reader = factory.createXMLStreamReader(fileContent);
            
            processXMLStream(reader);
        } catch (XMLStreamException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes());
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Setting irrelevant property but not security properties
        factory.setProperty(XMLInputFactory.IS_COALESCING, true);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlPath = request.getParameter("path");
        InputStream is = Files.newInputStream(Paths.get(xmlPath));
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Setting DTD to false but not disabling external entities
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLEventReader reader = factory.createXMLEventReader(is);
        
        while(reader.hasNext()) {
            reader.nextEvent();
        }
    }

    public void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Cookie[] cookies = request.getCookies();
        String xmlData = "";
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("xmlData")) {
                xmlData = cookie.getValue();
                break;
            }
        }
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Setting property with wrong value type (should be Boolean)
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, "false");
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processXMLContent(reader);
    }

    public void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        if (xml == null || xml.isEmpty()) {
            xml = "<default>empty</default>";
        }
        
        XMLInputFactory factory = XMLInputFactory.newFactory();
        // Using a custom resolver but not disabling external entities
        factory.setXMLResolver(new CustomResolver());
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xml));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Setting reporter but not security properties
        factory.setProperty(XMLInputFactory.REPORTER, new CustomReporter());
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processDocument(reader);
    }

    public void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("fileName");
        InputStream inputStream = getClass().getResourceAsStream("/" + fileName);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Setting allocator but not security properties
        factory.setProperty(XMLInputFactory.ALLOCATOR, new CustomAllocator());
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLEventReader reader = factory.createXMLEventReader(inputStream);
        
        while(reader.hasNext()) {
            reader.nextEvent();
        }
    }

    public void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlContent = request.getParameter("content");
        
        // Creating factory through a different method but still insecure
        XMLInputFactory factory = XMLInputFactory.newFactory();
        // Only setting one security property but missing others
        factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("data");
        
        // Using a factory from a method but still insecure
        XMLInputFactory factory = getConfiguredFactory();
        // ruleid: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processXMLData(reader);
    }

    private XMLInputFactory getConfiguredFactory() {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // Missing security properties
        return factory;
    }

    public void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Using conditional logic but still insecure in some paths
        XMLInputFactory factory = XMLInputFactory.newInstance();
        boolean secureMode = Boolean.parseBoolean(request.getParameter("secure"));
        
        if (secureMode) {
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        } else {
            // This path is insecure
            // ruleid: java-xml-external-entity-injection-xml-input-factory
            XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
            processXML(reader);
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        InputStream inputStream = request.getInputStream();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        processXML(reader);
    }

    public void good_case_3(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String url = request.getParameter("url");
        InputStream inputStream = new URL(url).openStream();
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLEventReader eventReader = factory.createXMLEventReader(inputStream);
        
        while(eventReader.hasNext()) {
            eventReader.nextEvent();
        }
    }

    public void good_case_4(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlFile = request.getParameter("file");
        Reader fileReader = new FileReader(xmlFile);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        XMLStreamReader reader = factory.createXMLStreamReader(fileReader);
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_5(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlContent = request.getHeader("X-XML-Data");
        
        XMLInputFactory inputFactory = XMLInputFactory.newFactory();
        // ok: java-xml-external-entity-injection-xml-input-factory
        inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        inputFactory.setProperty(XMLInputFactory.IS_VALIDATING, false);
        inputFactory.setProperty(XMLInputFactory.IS_NAMESPAC_REDACTED_TWILIO_ID_AWARE, true);
        XMLEventReader eventReader = inputFactory.createXMLEventReader(new StringReader(xmlContent));
        
        while(eventReader.hasNext()) {
            eventReader.nextEvent();
        }
    }

    public void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Part filePart = request.getPart("xmlFile");
        InputStream fileContent = filePart.getInputStream();
        
        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            // ok: java-xml-external-entity-injection-xml-input-factory
            factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
            XMLStreamReader reader = factory.createXMLStreamReader(fileContent);
            
            processXMLStream(reader);
        } catch (XMLStreamException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("data");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlData.getBytes());
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_COALESCING, true);
        XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_8(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlPath = request.getParameter("path");
        InputStream is = Files.newInputStream(Paths.get(xmlPath));
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        XMLEventReader reader = factory.createXMLEventReader(is);
        
        while(reader.hasNext()) {
            reader.nextEvent();
        }
    }

    public void good_case_9(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Cookie[] cookies = request.getCookies();
        String xmlData = "";
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("xmlData")) {
                xmlData = cookie.getValue();
                break;
            }
        }
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processXMLContent(reader);
    }

    public void good_case_10(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xml = request.getParameter("xml");
        if (xml == null || xml.isEmpty()) {
            xml = "<default>empty</default>";
        }
        
        XMLInputFactory factory = XMLInputFactory.newFactory();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setXMLResolver(new CustomResolver());
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xml));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getReader().lines().reduce("", (accumulator, actual) -> accumulator + actual);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.REPORTER, new CustomReporter());
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processDocument(reader);
    }

    public void good_case_12(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String fileName = request.getParameter("fileName");
        InputStream inputStream = getClass().getResourceAsStream("/" + fileName);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.ALLOCATOR, new CustomAllocator());
        XMLEventReader reader = factory.createXMLEventReader(inputStream);
        
        while(reader.hasNext()) {
            reader.nextEvent();
        }
    }

    public void good_case_13(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlContent = request.getParameter("content");
        
        // Using a secure factory from a helper method
        XMLInputFactory factory = getSecureXMLInputFactory();
        // ok: java-xml-external-entity-injection-xml-input-factory
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlContent));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    private XMLInputFactory getSecureXMLInputFactory() {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        return factory;
    }

    public void good_case_14(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("data");
        
        // Using a properties-based configuration approach
        Properties securityProperties = new Properties();
        securityProperties.put(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        securityProperties.put(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        for (Object key : securityProperties.keySet()) {
            factory.setProperty((String)key, securityProperties.get(key));
        }
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        processXMLData(reader);
    }

    public void good_case_15(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String xmlData = request.getParameter("xml");
        
        // Using a secure factory with additional configuration
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ok: java-xml-external-entity-injection-xml-input-factory
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_VALIDATING, false);
        factory.setProperty(XMLInputFactory.IS_NAMESPAC_REDACTED_TWILIO_ID_AWARE, true);
        factory.setProperty(XMLInputFactory.IS_COALESCING, true);
        factory.setProperty(XMLInputFactory.IS_REPLAC_REDACTED_TWILIO_ID_ENTITY_REFERENCES, false);
        XMLStreamReader reader = factory.createXMLStreamReader(new StringReader(xmlData));
        
        while(reader.hasNext()) {
            reader.next();
        }
    }

    // Helper methods to make the examples work
    private void processXML(XMLStreamReader reader) throws XMLStreamException {
        while(reader.hasNext()) {
            reader.next();
        }
    }
    
    private void processXMLStream(XMLStreamReader reader) throws XMLStreamException {
        while(reader.hasNext()) {
            reader.next();
        }
    }
    
    private void processXMLContent(XMLStreamReader reader) throws XMLStreamException {
        while(reader.hasNext()) {
            reader.next();
        }
    }
    
    private void processDocument(XMLStreamReader reader) throws XMLStreamException {
        while(reader.hasNext()) {
            reader.next();
        }
    }
    
    private void processXMLData(XMLStreamReader reader) throws XMLStreamException {
        while(reader.hasNext()) {
            reader.next();
        }
    }
    
    // Custom classes for examples
    private class CustomResolver implements XMLResolver {
        @Override
        public Object resolveEntity(String publicID, String systemID, String baseURI, String namespace) {
            return null;
        }
    }
    
    private class CustomReporter implements XMLReporter {
        @Override
        public void report(String message, String errorType, Object relatedInformation, Location location) {
            // Do nothing
        }
    }
    
    private class CustomAllocator implements XMLEventAllocator {
        @Override
        public XMLEventAllocator newInstance() {
            return this;
        }
        
        @Override
        public XMLEvent allocate(XMLStreamReader reader) throws XMLStreamException {
            return null;
        }
        
        @Override
        public void allocate(XMLStreamReader reader, XMLEventConsumer consumer) throws XMLStreamException {
            // Do nothing
        }
    }
}
// {/fact}