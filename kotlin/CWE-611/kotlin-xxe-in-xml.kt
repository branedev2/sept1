import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import org.xml.sax.InputSource
import org.xml.sax.helpers.DefaultHandler
import java.io.StringReader
import javax.xml.stream.XMLInputFactory
import org.dom4j.io.SAXReader
import org.jdom2.input.SAXBuilder
import nu.xom.Builder
import org.apache.commons.digester3.Digester
import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletRequest
import java.io.ByteArrayInputStream
import org.apache.http.HttpEntity
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.HttpClients
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.w3c.dom.Document
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import java.io.StringWriter
import java.net.URL
import javax.xml.XMLConstants

// True Positives (Vulnerable Code)

@RestController
class VulnerableXMLController {
    
    // Case 1: Vulnerable DocumentBuilder without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad1")
    fun bad_case_1(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        // ruleid: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 2: Vulnerable SAXParser without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad2")
    fun bad_case_2(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        // ruleid: kotlin-xxe-in-xml
        val saxParser = factory.newSAXParser()
        val handler = DefaultHandler()
        saxParser.parse(InputSource(StringReader(xmlData)), handler)
        return "XML Processed"
    }
// {/fact}
    
    // Case 3: Vulnerable XMLInputFactory with external entities enabled
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad3")
    fun bad_case_3(@RequestBody xmlData: String): String {
        val factory = XMLInputFactory.newInstance()
        // ruleid: kotlin-xxe-in-xml
        val xmlReader = factory.createXMLStreamReader(StringReader(xmlData))
        while (xmlReader.hasNext()) {
            xmlReader.next()
        }
        return "XML Processed"
    }
// {/fact}
    
    // Case 4: Vulnerable SAXReader without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad4")
    fun bad_case_4(@RequestBody xmlData: String): String {
        val reader = SAXReader()
        // ruleid: kotlin-xxe-in-xml
        val document = reader.read(StringReader(xmlData))
        return document.rootElement.textContent
    }
// {/fact}
    
    // Case 5: Vulnerable SAXBuilder without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad5")
    fun bad_case_5(@RequestBody xmlData: String): String {
        val builder = SAXBuilder()
        // ruleid: kotlin-xxe-in-xml
        val document = builder.build(StringReader(xmlData))
        return document.rootElement.textContent
    }
// {/fact}
    
    // Case 6: Vulnerable XOM Builder without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad6")
    fun bad_case_6(@RequestBody xmlData: String): String {
        val builder = Builder()
        // ruleid: kotlin-xxe-in-xml
        val document = builder.build(StringReader(xmlData))
        return document.rootElement.value
    }
// {/fact}
    
    // Case 7: Vulnerable Digester without secure processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad7")
    fun bad_case_7(@RequestBody xmlData: String): String {
        val digester = Digester()
        // ruleid: kotlin-xxe-in-xml
        digester.parse(StringReader(xmlData))
        return "XML Processed"
    }
// {/fact}
    
    // Case 8: Vulnerable DocumentBuilder with explicit feature setting allowing DTD
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad8")
    fun bad_case_8(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false)
        // ruleid: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 9: Vulnerable DocumentBuilder with explicit external entity processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad9")
    fun bad_case_9(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true)
        // ruleid: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 10: Vulnerable SAXParser with explicit external entity processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad10")
    fun bad_case_10(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        factory.setFeature("http://xml.org/sax/features/external-general-entities", true)
        // ruleid: kotlin-xxe-in-xml
        val saxParser = factory.newSAXParser()
        val handler = DefaultHandler()
        saxParser.parse(InputSource(StringReader(xmlData)), handler)
        return "XML Processed"
    }
// {/fact}
    
    // Case 11: Vulnerable XMLInputFactory with explicit setting allowing DTD
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad11")
    fun bad_case_11(@RequestBody xmlData: String): String {
        val factory = XMLInputFactory.newInstance()
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, true)
        // ruleid: kotlin-xxe-in-xml
        val xmlReader = factory.createXMLStreamReader(StringReader(xmlData))
        while (xmlReader.hasNext()) {
            xmlReader.next()
        }
        return "XML Processed"
    }
// {/fact}
    
    // Case 12: Vulnerable XMLInputFactory with explicit external entity processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad12")
    fun bad_case_12(@RequestBody xmlData: String): String {
        val factory = XMLInputFactory.newInstance()
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true)
        // ruleid: kotlin-xxe-in-xml
        val xmlReader = factory.createXMLStreamReader(StringReader(xmlData))
        while (xmlReader.hasNext()) {
            xmlReader.next()
        }
        return "XML Processed"
    }
// {/fact}
    
    // Case 13: Vulnerable SAXReader with explicit external entity processing
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad13")
    fun bad_case_13(@RequestBody xmlData: String): String {
        val reader = SAXReader()
        reader.setFeature("http://xml.org/sax/features/external-general-entities", true)
        // ruleid: kotlin-xxe-in-xml
        val document = reader.read(StringReader(xmlData))
        return document.rootElement.textContent
    }
// {/fact}
    
    // Case 14: Vulnerable DocumentBuilder with ByteArrayInputStream
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad14")
    fun bad_case_14(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        // ruleid: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(ByteArrayInputStream(xmlData.toByteArray()))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 15: Vulnerable DocumentBuilder with URL
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/bad15")
    fun bad_case_15(request: HttpServletRequest): String {
        val xmlUrl = request.getParameter("xmlUrl")
        val dbf = DocumentBuilderFactory.newInstance()
        // ruleid: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(URL(xmlUrl).openStream())
        return doc.documentElement.textContent
    }
// {/fact}
    
    // True Negatives (Secure Code)
    
    // Case 1: Secure DocumentBuilder with DTD disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good1")
    fun good_case_1(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 2: Secure SAXParser with DTD disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good2")
    fun good_case_2(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // ok: kotlin-xxe-in-xml
        val saxParser = factory.newSAXParser()
        val handler = DefaultHandler()
        saxParser.parse(InputSource(StringReader(xmlData)), handler)
        return "XML Processed"
    }
// {/fact}
    
    // Case 3: Secure XMLInputFactory with external entities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good3")
    fun good_case_3(@RequestBody xmlData: String): String {
        val factory = XMLInputFactory.newInstance()
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
        // ok: kotlin-xxe-in-xml
        val xmlReader = factory.createXMLStreamReader(StringReader(xmlData))
        while (xmlReader.hasNext()) {
            xmlReader.next()
        }
        return "XML Processed"
    }
// {/fact}
    
    // Case 4: Secure SAXReader with external entities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good4")
    fun good_case_4(@RequestBody xmlData: String): String {
        val reader = SAXReader()
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false)
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        // ok: kotlin-xxe-in-xml
        val document = reader.read(StringReader(xmlData))
        return document.rootElement.textContent
    }
// {/fact}
    
    // Case 5: Secure SAXBuilder with external entities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good5")
    fun good_case_5(@RequestBody xmlData: String): String {
        val builder = SAXBuilder()
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // ok: kotlin-xxe-in-xml
        val document = builder.build(StringReader(xmlData))
        return document.rootElement.textContent
    }
// {/fact}
    
    // Case 6: Secure XOM Builder with external entities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good6")
    fun good_case_6(@RequestBody xmlData: String): String {
        val builder = Builder(false)  // false means non-validating, which disables DTD
        // ok: kotlin-xxe-in-xml
        val document = builder.build(StringReader(xmlData))
        return document.rootElement.value
    }
// {/fact}
    
    // Case 7: Secure Digester with external entities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good7")
    fun good_case_7(@RequestBody xmlData: String): String {
        val digester = Digester()
        digester.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // ok: kotlin-xxe-in-xml
        digester.parse(StringReader(xmlData))
        return "XML Processed"
    }
// {/fact}
    
    // Case 8: Secure DocumentBuilder with multiple security features
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good8")
    fun good_case_8(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 9: Secure DocumentBuilder using XMLConstants
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good9")
    fun good_case_9(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 10: Secure SAXParser using XMLConstants
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good10")
    fun good_case_10(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        // ok: kotlin-xxe-in-xml
        val saxParser = factory.newSAXParser()
        val handler = DefaultHandler()
        saxParser.parse(InputSource(StringReader(xmlData)), handler)
        return "XML Processed"
    }
// {/fact}
    
    // Case 11: Secure XMLInputFactory with multiple security settings
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good11")
    fun good_case_11(@RequestBody xmlData: String): String {
        val factory = XMLInputFactory.newInstance()
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
        // ok: kotlin-xxe-in-xml
        val xmlReader = factory.createXMLStreamReader(StringReader(xmlData))
        while (xmlReader.hasNext()) {
            xmlReader.next()
        }
        return "XML Processed"
    }
// {/fact}
    
    // Case 12: Secure TransformerFactory with XMLConstants
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good12")
    fun good_case_12(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        
        val transformerFactory = TransformerFactory.newInstance()
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
        // ok: kotlin-xxe-in-xml
        val transformer = transformerFactory.newTransformer()
        val source = DOMSource(doc)
        val writer = StringWriter()
        val result = StreamResult(writer)
        transformer.transform(source, result)
        
        return writer.toString()
    }
// {/fact}
    
    // Case 13: Secure DocumentBuilder with ByteArrayInputStream
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good13")
    fun good_case_13(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(ByteArrayInputStream(xmlData.toByteArray()))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 14: Secure DocumentBuilder with comprehensive protections
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good14")
    fun good_case_14(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        dbf.setXIncludeAware(false)
        dbf.setExpandEntityReferences(false)
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
    
    // Case 15: Secure XML processing with validation and custom error handling
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/good15")
    fun good_case_15(@RequestBody xmlData: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        dbf.setValidating(true)
        // ok: kotlin-xxe-in-xml
        val db = dbf.newDocumentBuilder()
        db.setErrorHandler(object : org.xml.sax.ErrorHandler {
            override fun warning(exception: org.xml.sax.SAXParseException) {
                println("Warning: ${exception.message}")
            }
            
            override fun error(exception: org.xml.sax.SAXParseException) {
                println("Error: ${exception.message}")
            }
            
            override fun fatalError(exception: org.xml.sax.SAXParseException) {
                throw exception
            }
        })
        
        val doc = db.parse(InputSource(StringReader(xmlData)))
        return doc.documentElement.textContent
    }
// {/fact}
}