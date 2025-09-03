import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;

public class SystemLoadLibraryVulnerabilities {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=assembly-path-injection@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-fortify-process-control
        System.loadLibrary("mylib");
    }
    
    public void bad_case_2(String libraryName) {
        // ruleid: java-fortify-process-control
        System.loadLibrary(libraryName);
    }
    
    public void bad_case_3() {
        String libName = "crypto";
        // ruleid: java-fortify-process-control
        System.loadLibrary(libName);
    }
    
    public void bad_case_4(HttpServletRequest request) {
        String libraryParam = request.getParameter("lib");
        String defaultLib = "default";
        String libToLoad = (libraryParam != null) ? libraryParam : defaultLib;
        // ruleid: java-fortify-process-control
        System.loadLibrary(libToLoad);
    }
    
    public void bad_case_5() {
        try {
            Properties props = new Properties();
            props.load(getClass().getResourceAsStream("/config.properties"));
            String libName = props.getProperty("library.name");
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("load".equals(action)) {
                // ruleid: java-fortify-process-control
                System.loadLibrary("dynamiclib");
                response.getWriter().println("Library loaded successfully");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        String osName = System.getProperty("os.name").toLowerCase();
        String libName;
        
        if (osName.contains("win")) {
            libName = "winutils";
        } else if (osName.contains("mac")) {
            libName = "macutils";
        } else {
            libName = "linuxutils";
        }
        
        // ruleid: java-fortify-process-control
        System.loadLibrary(libName);
    }
    
    public void bad_case_8(String[] args) {
        if (args.length > 0) {
            for (String lib : args) {
                // ruleid: java-fortify-process-control
                System.loadLibrary(lib);
            }
        } else {
            // ruleid: java-fortify-process-control
            System.loadLibrary("defaultlib");
        }
    }
    
    public void bad_case_9() {
        String[] libraries = {"math", "crypto", "network"};
        for (String lib : libraries) {
            // ruleid: java-fortify-process-control
            System.loadLibrary(lib);
        }
    }
    
    public void bad_case_10(HttpServletRequest request) {
        String mode = request.getParameter("mode");
        if ("secure".equals(mode)) {
            // Even in "secure" mode, this is still vulnerable
            // ruleid: java-fortify-process-control
            System.loadLibrary("securelib");
        } else {
            // ruleid: java-fortify-process-control
            System.loadLibrary("standardlib");
        }
    }
    
    public void bad_case_11() {
        try {
            InputStream is = getClass().getResourceAsStream("/libs.txt");
            byte[] bytes = new byte[is.available()];
            is.read(bytes);
            String libName = new String(bytes).trim();
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        class LibraryLoader {
            public void load(String name) {
                // ruleid: java-fortify-process-control
                System.loadLibrary(name);
            }
        }
        
        new LibraryLoader().load("helperlib");
    }
    
    public void bad_case_13(HttpServletRequest request) {
        try {
            String configPath = request.getParameter("config");
            if (configPath == null) configPath = "/default-config.txt";
            
            Path path = Paths.get(configPath);
            String libName = Files.readAllLines(path).get(0);
            
            // ruleid: java-fortify-process-control
            System.loadLibrary(libName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        String version = "1.0";
        String libName = "mylib-" + version;
        // ruleid: java-fortify-process-control
        System.loadLibrary(libName);
    }
    
    public void bad_case_15() {
        try {
            // Even with validation, using loadLibrary is still vulnerable
            String libName = "validatedlib";
            if (libName.matches("[a-zA-Z0-9_-]+")) {
                // ruleid: java-fortify-process-control
                System.loadLibrary(libName);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() {
        String absolutePath = "/usr/lib/libmylib.so";
        // ok: java-fortify-process-control
        System.load(absolutePath);
    }
    
    public void good_case_2() {
        File libFile = new File("/usr/local/lib/libcrypto.so");
        // ok: java-fortify-process-control
        System.load(libFile.getAbsolutePath());
    }
    
    public void good_case_3(HttpServletRequest request) {
        String libraryName = request.getParameter("lib");
        // Using a fixed absolute path instead of user input for the path
        File libDir = new File("/opt/secure/libs/");
        File libFile = new File(libDir, "lib" + libraryName + ".so");
        
        if (libFile.getParentFile().equals(libDir) && libFile.exists() && !libFile.isDirectory()) {
            // ok: java-fortify-process-control
            System.load(libFile.getAbsolutePath());
        }
    }
    
    public void good_case_4() {
        try {
            Properties props = new Properties();
            props.load(getClass().getResourceAsStream("/config.properties"));
            String libPath = props.getProperty("library.path");
            
            // ok: java-fortify-process-control
            System.load(libPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_5() {
        String osName = System.getProperty("os.name").toLowerCase();
        String libPath;
        
        if (osName.contains("win")) {
            libPath = "C:\\Program Files\\MyApp\\winutils.dll";
        } else if (osName.contains("mac")) {
            libPath = "/Applications/MyApp/libmacutils.dylib";
        } else {
            libPath = "/usr/lib/liblinuxutils.so";
        }
        
        // ok: java-fortify-process-control
        System.load(libPath);
    }
    
    public void good_case_6() {
        // Using a library path from a trusted source
        String libPath = System.getProperty("java.library.path") + File.separator + "libsecure.so";
        File libFile = new File(libPath);
        
        // ok: java-fortify-process-control
        System.load(libFile.getAbsolutePath());
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) {
        try {
            String action = request.getParameter("action");
            if ("load".equals(action)) {
                // Using a fixed absolute path
                String libPath = "/opt/app/libs/libdynamic.so";
                // ok: java-fortify-process-control
                System.load(libPath);
                response.getWriter().println("Library loaded successfully");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        // Using a library bundled with the application
        String appHome = System.getProperty("app.home");
        String libPath = appHome + File.separator + "lib" + File.separator + "libapp.so";
        
        // ok: java-fortify-process-control
        System.load(libPath);
    }
    
    public void good_case_9(String[] args) {
        // Even with user input, we're using absolute paths
        if (args.length > 0) {
            String baseDir = "/opt/secure/libs/";
            for (String lib : args) {
                if (lib.matches("[a-zA-Z0-9_-]+")) {
                    File libFile = new File(baseDir, "lib" + lib + ".so");
                    if (libFile.exists() && libFile.getParentFile().getAbsolutePath().equals(new File(baseDir).getAbsolutePath())) {
                        // ok: java-fortify-process-control
                        System.load(libFile.getAbsolutePath());
                    }
                }
            }
        }
    }
    
    public void good_case_10() {
        // Using JNI with absolute paths
        String[] libraries = {
            "/usr/lib/libmath.so", 
            "/usr/lib/libcrypto.so", 
            "/usr/lib/libnetwork.so"
        };
        
        for (String lib : libraries) {
            File libFile = new File(lib);
            if (libFile.exists()) {
                // ok: java-fortify-process-control
                System.load(libFile.getAbsolutePath());
            }
        }
    }
    
    public void good_case_11() {
        try {
            // Reading library path from a configuration file
            InputStream is = getClass().getResourceAsStream("/libpaths.txt");
            byte[] bytes = new byte[is.available()];
            is.read(bytes);
            String libPath = new String(bytes).trim();
            
            File libFile = new File(libPath);
            if (libFile.exists() && libFile.isAbsolute()) {
                // ok: java-fortify-process-control
                System.load(libFile.getAbsolutePath());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        class SecureLibraryLoader {
            public void load(String absolutePath) {
                // ok: java-fortify-process-control
                System.load(absolutePath);
            }
        }
        
        new SecureLibraryLoader().load("/usr/local/lib/libhelper.so");
    }
    
    public void good_case_13() {
        // Using a library from a trusted location with version
        String version = "1.0";
        String libPath = "/opt/myapp/libs/libmyapp-" + version + ".so";
        
        // ok: java-fortify-process-control
        System.load(libPath);
    }
    
    public void good_case_14(HttpServletRequest request) {
        try {
            // Even with user input, we're using a whitelist and absolute paths
            String libName = request.getParameter("lib");
            
            // Whitelist of allowed libraries with their absolute paths
            java.util.Map<String, String> allowedLibs = new java.util.HashMap<>();
            allowedLibs.put("math", "/usr/lib/libmath.so");
            allowedLibs.put("crypto", "/usr/lib/libcrypto.so");
            
            if (allowedLibs.containsKey(libName)) {
                // ok: java-fortify-process-control
                System.load(allowedLibs.get(libName));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_15() {
        // Using a library from the Java home directory
        String javaHome = System.getProperty("java.home");
        String libPath = javaHome + File.separator + "lib" + File.separator + "libsystem.so";
        File libFile = new File(libPath);
        
        if (libFile.exists()) {
            // ok: java-fortify-process-control
            System.load(libFile.getAbsolutePath());
        }
    }
}
// {/fact}