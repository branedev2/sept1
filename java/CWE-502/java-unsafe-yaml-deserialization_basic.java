import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;

import java.io.InputStream;
import java.io.FileInputStream;
import java.io.StringReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

public class YamlDeserializationExamples {

    // True Positives (Vulnerable Code)

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml();
        String yamlContent = "key: value";
        Map<String, Object> data = yaml.load(yamlContent);
        System.out.println(data);
    }

    public void bad_case_2(HttpServletRequest request) throws IOException {
        String yamlInput = request.getParameter("yamlData");
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml();
        Object obj = yaml.load(yamlInput);
        System.out.println("Loaded YAML: " + obj);
    }

    public void bad_case_3() throws IOException {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor());
        try (InputStream inputStream = new FileInputStream("config.yml")) {
            Map<String, Object> data = yaml.load(inputStream);
            System.out.println("Config loaded: " + data);
        }
    }

    @WebServlet("/yaml-processor")
    public static class bad_case_4 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String yamlData = request.getParameter("data");
            // ruleid: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new Constructor(), new Representer());
            Object parsed = yaml.load(yamlData);
            response.getWriter().println("Processed: " + parsed);
        }
    }

    public void bad_case_5() {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(options);
        String result = yaml.dump(new HashMap<String, Object>() {{
            put("key", "value");
        }});
        System.out.println(result);
    }

    public void bad_case_6() throws IOException {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions());
        try (FileReader reader = new FileReader("data.yml")) {
            Object data = yaml.load(reader);
            System.out.println("Loaded: " + data);
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        String yamlStr = request.getParameter("config");
        LoaderOptions loaderOptions = new LoaderOptions();
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions(), loaderOptions);
        Map<String, Object> config = yaml.load(yamlStr);
        System.out.println("Config: " + config);
    }

    public void bad_case_8() {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor(), new Representer(), new DumperOptions(), new LoaderOptions(), new Resolver());
        String yamlStr = "key: value\nlist:\n  - item1\n  - item2";
        Object obj = yaml.load(yamlStr);
        System.out.println(obj);
    }

    public void bad_case_9(HttpServletRequest request) {
        String yamlContent = request.getParameter("template");
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml();
        for (Object data : yaml.loadAll(yamlContent)) {
            System.out.println("Document: " + data);
        }
    }

    public void bad_case_10() throws IOException {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor());
        try (FileReader reader = new FileReader("multi-doc.yml")) {
            Iterable<Object> documents = yaml.loadAll(reader);
            for (Object doc : documents) {
                System.out.println(doc);
            }
        }
    }

    public void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String yamlInput = request.getParameter("data");
        DumperOptions options = new DumperOptions();
        options.setPrettyFlow(true);
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(options);
        Object result = yaml.load(yamlInput);
        response.getWriter().write(yaml.dump(result));
    }

    public void bad_case_12() {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml();
        String multiDoc = "---\nname: doc1\n---\nname: doc2";
        List<Object> documents = (List<Object>) yaml.loadAll(multiDoc);
        System.out.println("Loaded " + documents.size() + " documents");
    }

    public void bad_case_13(HttpServletRequest request) {
        String yamlStr = request.getParameter("yamlData");
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor());
        if (yamlStr != null && !yamlStr.isEmpty()) {
            try {
                Object obj = yaml.load(yamlStr);
                System.out.println("Parsed YAML: " + obj);
            } catch (Exception e) {
                System.err.println("Error parsing YAML: " + e.getMessage());
            }
        }
    }

    public void bad_case_14() throws IOException {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml();
        try (InputStream is = YamlDeserializationExamples.class.getClassLoader().getResourceAsStream("config.yml")) {
            if (is != null) {
                Map<String, Object> config = yaml.load(is);
                System.out.println("Loaded configuration: " + config);
            }
        }
    }

    public void bad_case_15() {
        // ruleid: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new Constructor(), new Representer());
        String yamlString = "!!java.util.Date 2022-01-01";
        Object date = yaml.load(yamlString);
        System.out.println("Parsed date: " + date);
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        String yamlContent = "key: value";
        Map<String, Object> data = yaml.load(yamlContent);
        System.out.println(data);
    }

    public void good_case_2(HttpServletRequest request) throws IOException {
        String yamlInput = request.getParameter("yamlData");
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        Object obj = yaml.load(yamlInput);
        System.out.println("Loaded YAML: " + obj);
    }

    public void good_case_3() throws IOException {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        try (InputStream inputStream = new FileInputStream("config.yml")) {
            Map<String, Object> data = yaml.load(inputStream);
            System.out.println("Config loaded: " + data);
        }
    }

    @WebServlet("/yaml-processor-safe")
    public static class good_case_4 extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) 
                throws ServletException, IOException {
            String yamlData = request.getParameter("data");
            // ok: java-unsafe-yaml-deserialization
            Yaml yaml = new Yaml(new SafeConstructor(), new Representer());
            Object parsed = yaml.load(yamlData);
            response.getWriter().println("Processed: " + parsed);
        }
    }

    public void good_case_5() {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), options);
        String result = yaml.dump(new HashMap<String, Object>() {{
            put("key", "value");
        }});
        System.out.println(result);
    }

    public void good_case_6() throws IOException {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        try (FileReader reader = new FileReader("data.yml")) {
            Object data = yaml.load(reader);
            System.out.println("Loaded: " + data);
        }
    }

    public void good_case_7(HttpServletRequest request) {
        String yamlStr = request.getParameter("config");
        LoaderOptions loaderOptions = new LoaderOptions();
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), loaderOptions);
        Map<String, Object> config = yaml.load(yamlStr);
        System.out.println("Config: " + config);
    }

    public void good_case_8() {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), new DumperOptions(), new LoaderOptions(), new Resolver());
        String yamlStr = "key: value\nlist:\n  - item1\n  - item2";
        Object obj = yaml.load(yamlStr);
        System.out.println(obj);
    }

    public void good_case_9(HttpServletRequest request) {
        String yamlContent = request.getParameter("template");
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        for (Object data : yaml.loadAll(yamlContent)) {
            System.out.println("Document: " + data);
        }
    }

    public void good_case_10() throws IOException {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        try (FileReader reader = new FileReader("multi-doc.yml")) {
            Iterable<Object> documents = yaml.loadAll(reader);
            for (Object doc : documents) {
                System.out.println(doc);
            }
        }
    }

    public void good_case_11(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String yamlInput = request.getParameter("data");
        DumperOptions options = new DumperOptions();
        options.setPrettyFlow(true);
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor(), new Representer(), options);
        Object result = yaml.load(yamlInput);
        response.getWriter().write(yaml.dump(result));
    }

    public void good_case_12() {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        String multiDoc = "---\nname: doc1\n---\nname: doc2";
        List<Object> documents = (List<Object>) yaml.loadAll(multiDoc);
        System.out.println("Loaded " + documents.size() + " documents");
    }

    public void good_case_13(HttpServletRequest request) {
        String yamlStr = request.getParameter("yamlData");
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        if (yamlStr != null && !yamlStr.isEmpty()) {
            try {
                Object obj = yaml.load(yamlStr);
                System.out.println("Parsed YAML: " + obj);
            } catch (Exception e) {
                System.err.println("Error parsing YAML: " + e.getMessage());
            }
        }
    }

    public void good_case_14() throws IOException {
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor());
        try (InputStream is = YamlDeserializationExamples.class.getClassLoader().getResourceAsStream("config.yml")) {
            if (is != null) {
                Map<String, Object> config = yaml.load(is);
                System.out.println("Loaded configuration: " + config);
            }
        }
    }

    public void good_case_15() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(false);
        // ok: java-unsafe-yaml-deserialization
        Yaml yaml = new Yaml(new SafeConstructor(loaderOptions));
        String yamlString = "key: value\nlist:\n  - item1\n  - item2";
        Object obj = yaml.load(yamlString);
        System.out.println(obj);
    }
}
// {/fact}