import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Example classes for serialization
class User {
    private String name;
    private int age;
    
    public User() {}
    
    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }
}

class Address {
    private String street;
    private String city;
    
    public Address() {}
    
    public Address(String street, String city) {
        this.street = street;
        this.city = city;
    }
}

class Product {
    private String name;
    private double price;
    
    public Product() {}
    
    public Product(String name, double price) {
        this.name = name;
        this.price = price;
    }
}

class Order {
    private int id;
    private List<Product> products;
    
    public Order() {}
    
    public Order(int id, List<Product> products) {
        this.id = id;
        this.products = products;
    }
}

class Customer {
    private User user;
    private Address address;
    
    public Customer() {}
    
    public Customer(User user, Address address) {
        this.user = user;
        this.address = address;
    }
}

public class KryoRegistrationExamples {

    // True Positive Examples (Vulnerable)
    
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Address.class, 3); // Skipping ID 2 can cause issues
        kryo.register(Product.class, 4);
    }
    
    public void bad_case_2() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 10);
        kryo.register(Address.class, 5); // Non-ascending order
        kryo.register(Product.class, 7);
    }
    
    public void bad_case_3() {
        Kryo kryo = new Kryo();
        kryo.register(User.class, 1);
        kryo.register(Address.class, 2);
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 3); // Re-registering the same class with different ID
    }
    
    public void bad_case_4() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 100);
        kryo.register(Address.class, 200); // Large gaps between IDs
        kryo.register(Product.class, 300);
    }
    
    public void bad_case_5() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class);      // Auto-assigned ID
        kryo.register(Address.class, 5); // Mixing auto-assigned and explicit IDs
        kryo.register(Product.class);   // Auto-assigned ID
    }
    
    public void bad_case_6() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        if (System.currentTimeMillis() % 2 == 0) {
            kryo.register(Address.class, 2);
        } else {
            kryo.register(Product.class, 2); // Conditional registration with same ID
        }
    }
    
    public void bad_case_7() {
        Kryo kryo = new Kryo();
        Map<Class<?>, Integer> registrationMap = new HashMap<>();
        registrationMap.put(User.class, 1);
        registrationMap.put(Address.class, 3); // Skipping ID 2
        
        for (Map.Entry<Class<?>, Integer> entry : registrationMap.entrySet()) {
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(entry.getKey(), entry.getValue());
        }
    }
    
    public void bad_case_8() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, -1);    // Negative ID
        kryo.register(Address.class, 0);
        kryo.register(Product.class, 1);
    }
    
    public void bad_case_9() {
        Kryo kryo = new Kryo();
        int startId = 5;
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, startId);
        kryo.register(Address.class, startId + 2); // Skipping ID 6
        kryo.register(Product.class, startId + 3);
    }
    
    public void bad_case_10() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        try {
            // Some operation that might fail
            int x = 1 / 0;
            kryo.register(Address.class, 2);
        } catch (Exception e) {
            // Register a different class with ID 2 in exception handler
            kryo.register(Product.class, 2);
        }
    }
    
    public void bad_case_11() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        for (int i = 0; i < 5; i++) {
            if (i == 0) kryo.register(User.class, 10);
            else if (i == 1) kryo.register(Address.class, 20);
            else if (i == 2) kryo.register(Product.class, 30);
            // Non-continuous IDs in a loop
        }
    }
    
    public void bad_case_12() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Address.class, 2);
        
        // Adding a new class with an ID that's between existing IDs
        kryo.register(Customer.class, 1); // Conflicting with existing ID
    }
    
    public void bad_case_13() {
        Kryo kryo = new Kryo();
        List<Class<?>> classes = new ArrayList<>();
        classes.add(User.class);
        classes.add(Address.class);
        classes.add(Product.class);
        
        // ruleid: java-kryo-library-registered-class-id
        int id = 0;
        for (Class<?> clazz : classes) {
            id += 2; // Incrementing by 2 creates gaps
            kryo.register(clazz, id);
        }
    }
    
    public void bad_case_14() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, Integer.MAX_VALUE - 2);
        kryo.register(Address.class, Integer.MAX_VALUE - 1);
        kryo.register(Product.class, Integer.MAX_VALUE); // Risk of overflow if more classes are added
    }
    
    public void bad_case_15() {
        Kryo kryo = new Kryo();
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        
        // Dynamically determining class to register, but with fixed ID
        String className = System.getProperty("class.to.register", "Address");
        try {
            Class<?> dynamicClass = Class.forName(className);
            kryo.register(dynamicClass, 1); // Same ID used for different classes
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure)
    
    public void good_case_1() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Address.class, 2);
        kryo.register(Product.class, 3);
    }
    
    public void good_case_2() {
        Kryo kryo = new Kryo();
        int nextId = 1;
        // ok: java-kryo-library-registered-class-id
        kryo.register(User.class, nextId++);
        kryo.register(Address.class, nextId++);
        kryo.register(Product.class, nextId++);
    }
    
    public void good_case_3() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using auto-registration consistently (no explicit IDs)
        kryo.register(User.class);
        kryo.register(Address.class);
        kryo.register(Product.class);
    }
    
    public void good_case_4() {
        Kryo kryo = new Kryo();
        List<Class<?>> classes = new ArrayList<>();
        classes.add(User.class);
        classes.add(Address.class);
        classes.add(Product.class);
        
        // ok: java-kryo-library-registered-class-id
        int id = 1;
        for (Class<?> clazz : classes) {
            kryo.register(clazz, id++);
        }
    }
    
    public void good_case_5() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Address.class, 2);
        
        // Conditional registration but maintaining ID sequence
        boolean includeProduct = true;
        if (includeProduct) {
            kryo.register(Product.class, 3);
        }
    }
    
    public void good_case_6() {
        Kryo kryo = new Kryo();
        Map<Class<?>, Integer> registrationMap = new HashMap<>();
        registrationMap.put(User.class, 1);
        registrationMap.put(Address.class, 2);
        registrationMap.put(Product.class, 3);
        
        // ok: java-kryo-library-registered-class-id
        for (Map.Entry<Class<?>, Integer> entry : registrationMap.entrySet()) {
            kryo.register(entry.getKey(), entry.getValue());
        }
    }
    
    public void good_case_7() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        int baseId = 100;
        kryo.register(User.class, baseId);
        kryo.register(Address.class, baseId + 1);
        kryo.register(Product.class, baseId + 2);
    }
    
    public void good_case_8() {
        // ok: java-kryo-library-registered-class-id
        // Using a registration helper method to ensure sequential IDs
        Kryo kryo = new Kryo();
        int nextId = 1;
        registerSequentially(kryo, nextId, User.class, Address.class, Product.class);
    }
    
    private void registerSequentially(Kryo kryo, int startId, Class<?>... classes) {
        int id = startId;
        for (Class<?> clazz : classes) {
            kryo.register(clazz, id++);
        }
    }
    
    public void good_case_9() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using enum to maintain registration order
        for (ClassRegistry classReg : ClassRegistry.values()) {
            kryo.register(classReg.getClazz(), classReg.getId());
        }
    }
    
    enum ClassRegistry {
        USER(User.class, 1),
        ADDRESS(Address.class, 2),
        PRODUCT(Product.class, 3);
        
        private final Class<?> clazz;
        private final int id;
        
        ClassRegistry(Class<?> clazz, int id) {
            this.clazz = clazz;
            this.id = id;
        }
        
        public Class<?> getClazz() {
            return clazz;
        }
        
        public int getId() {
            return id;
        }
    }
    
    public void good_case_10() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using a configuration class to maintain registration order
        KryoConfig config = new KryoConfig();
        config.configureKryo(kryo);
    }
    
    static class KryoConfig {
        public void configureKryo(Kryo kryo) {
            kryo.register(User.class, 1);
            kryo.register(Address.class, 2);
            kryo.register(Product.class, 3);
        }
    }
    
    public void good_case_11() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        try {
            // Even in exception handling, maintain proper ID sequence
            kryo.register(User.class, 1);
            try {
                // Some operation that might fail
                int x = 1 / 0;
            } catch (Exception e) {
                // Still register in proper sequence
                kryo.register(Address.class, 2);
            }
            kryo.register(Product.class, 3);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_12() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using a properties file or similar to maintain registration order
        Map<String, Integer> classRegistry = loadClassRegistry();
        for (Map.Entry<String, Integer> entry : classRegistry.entrySet()) {
            try {
                Class<?> clazz = Class.forName(entry.getKey());
                kryo.register(clazz, entry.getValue());
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }
    
    private Map<String, Integer> loadClassRegistry() {
        // Simulating loading from a properties file
        Map<String, Integer> registry = new HashMap<>();
        registry.put(User.class.getName(), 1);
        registry.put(Address.class.getName(), 2);
        registry.put(Product.class.getName(), 3);
        return registry;
    }
    
    public void good_case_13() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using a builder pattern to ensure proper registration
        KryoBuilder builder = new KryoBuilder(kryo);
        builder.register(User.class)
               .register(Address.class)
               .register(Product.class);
    }
    
    static class KryoBuilder {
        private final Kryo kryo;
        private int nextId = 1;
        
        public KryoBuilder(Kryo kryo) {
            this.kryo = kryo;
        }
        
        public KryoBuilder register(Class<?> clazz) {
            kryo.register(clazz, nextId++);
            return this;
        }
    }
    
    public void good_case_14() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using a version-aware registration strategy
        int version = 1; // Could be loaded from configuration
        registerForVersion(kryo, version);
    }
    
    private void registerForVersion(Kryo kryo, int version) {
        // Base classes registered with same IDs across all versions
        kryo.register(User.class, 1);
        kryo.register(Address.class, 2);
        
        // Version-specific registrations, still maintaining sequential IDs
        if (version >= 1) {
            kryo.register(Product.class, 3);
        }
        if (version >= 2) {
            kryo.register(Order.class, 4);
        }
    }
    
    public void good_case_15() {
        Kryo kryo = new Kryo();
        // ok: java-kryo-library-registered-class-id
        // Using a dedicated registry class with proper ID management
        ClassRegistryManager registryManager = new ClassRegistryManager();
        registryManager.registerClasses(kryo);
    }
    
    static class ClassRegistryManager {
        private final List<Class<?>> classes = new ArrayList<>();
        
        public ClassRegistryManager() {
            // Define classes in the order they should be registered
            classes.add(User.class);
            classes.add(Address.class);
            classes.add(Product.class);
            classes.add(Order.class);
            classes.add(Customer.class);
        }
        
        public void registerClasses(Kryo kryo) {
            int id = 1;
            for (Class<?> clazz : classes) {
                kryo.register(clazz, id++);
            }
        }
    }
}
// {/fact}