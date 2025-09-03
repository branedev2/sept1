import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class User {
    private String username;
    private String email;
    
    public User() {}
    
    public User(String username, String email) {
        this.username = username;
        this.email = email;
    }
    
    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

class Product {
    private String name;
    private double price;
    
    public Product() {}
    
    public Product(String name, double price) {
        this.name = name;
        this.price = price;
    }
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public double getPrice() { return price; }
    public void setPrice(double price) { this.price = price; }
}

class Order {
    private int id;
    private List<Product> products;
    
    public Order() {}
    
    public Order(int id, List<Product> products) {
        this.id = id;
        this.products = products;
    }
    
    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public List<Product> getProducts() { return products; }
    public void setProducts(List<Product> products) { this.products = products; }
}

class Address {
    private String street;
    private String city;
    
    public Address() {}
    
    public Address(String street, String city) {
        this.street = street;
        this.city = city;
    }
    
    // Getters and setters
    public String getStreet() { return street; }
    public void setStreet(String street) { this.street = street; }
    public String getCity() { return city; }
    public void setCity(String city) { this.city = city; }
}

class Customer {
    private String name;
    private Address address;
    
    public Customer() {}
    
    public Customer(String name, Address address) {
        this.name = name;
        this.address = address;
    }
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Address getAddress() { return address; }
    public void setAddress(Address address) { this.address = address; }
}

public class KryoExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
    public void bad_case_1() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Product.class, 3); // Skipping ID 2, creating a gap
        kryo.register(Order.class, 4);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("john", "john@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 10);
        kryo.register(Product.class, 20); // Non-continuous IDs with large gaps
        kryo.register(Order.class, 30);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(1, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_3() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 5);
        kryo.register(Product.class, 4); // Descending order instead of ascending
        kryo.register(Order.class, 3);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Laptop", 999.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        Kryo kryo = new Kryo();
        
        // First registration
        kryo.register(User.class, 1);
        kryo.register(Product.class, 2);
        
        // Later in the code, re-registering with different IDs
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 3); // Re-registering with different ID
        kryo.register(Product.class, 4);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("alice", "alice@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Product.class, 2);
        kryo.register(Order.class, 2); // Duplicate ID
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(1, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_6() {
        Kryo kryo = new Kryo();
        Map<Class<?>, Integer> registrationMap = new HashMap<>();
        
        registrationMap.put(User.class, 1);
        registrationMap.put(Product.class, 3); // Gap in IDs
        
        // ruleid: java-kryo-library-registered-class-id
        for (Map.Entry<Class<?>, Integer> entry : registrationMap.entrySet()) {
            kryo.register(entry.getKey(), entry.getValue());
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("bob", "bob@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        for (int i = 10; i >= 1; i--) {
            if (i == 10) kryo.register(User.class, i);
            else if (i == 8) kryo.register(Product.class, i); // Skipping 9
            else if (i == 5) kryo.register(Order.class, i);   // Skipping 6, 7
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Phone", 599.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_8() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        if (System.currentTimeMillis() % 2 == 0) {
            kryo.register(User.class, 1);
            kryo.register(Product.class, 2);
        } else {
            kryo.register(User.class, 3); // Inconsistent IDs based on condition
            kryo.register(Product.class, 4);
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("charlie", "charlie@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        Kryo kryo = new Kryo();
        int startId = 100;
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, startId);
        kryo.register(Product.class, startId + 5); // Non-continuous increment
        kryo.register(Order.class, startId + 10);  // Non-continuous increment
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(2, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class);      // Auto-assigned ID
        kryo.register(Product.class, 5); // Manual ID after auto-assignment
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Tablet", 299.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Product.class, 2);
        
        // Simulating a code update where a new class is inserted between existing registrations
        kryo.register(Address.class, 3);
        kryo.register(Order.class, 4);
        
        // Later, trying to insert a class with ID between existing ones
        kryo.register(Customer.class, 2); // Conflict with Product class ID
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Customer customer = new Customer("Dave", new Address("123 Main St", "Anytown"));
            kryo.writeObject(output, customer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        int[] ids = {1, 3, 5, 7}; // Non-continuous IDs
        Class<?>[] classes = {User.class, Product.class, Order.class, Address.class};
        
        for (int i = 0; i < classes.length; i++) {
            kryo.register(classes[i], ids[i]);
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Address address = new Address("456 Oak St", "Somewhere");
            kryo.writeObject(output, address);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_13() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        
        // Simulating adding classes in different development iterations
        // with non-continuous IDs
        kryo.register(Product.class, 10);
        kryo.register(Order.class, 20);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("eve", "eve@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_14() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, getNextId()); // Using a method that might return non-continuous IDs
        kryo.register(Product.class, getNextId());
        kryo.register(Order.class, getNextId());
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(3, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private int nextId = 0;
    private int getNextId() {
        // This method returns non-continuous IDs
        nextId += 2; // Incrementing by 2 creates gaps
        return nextId;
    }
    
    public void bad_case_15() {
        Kryo kryo = new Kryo();
        
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(User.class, 100);
        
        // Later in the application lifecycle, registering more classes
        // but starting from a different ID range
        kryo.register(Product.class, 200);
        kryo.register(Order.class, 300);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("frank", "frank@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Secure Code)
    
    public void good_case_1() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        kryo.register(User.class, 1);
        kryo.register(Product.class, 2); // Continuous IDs in ascending order
        kryo.register(Order.class, 3);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("john", "john@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_2() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        int nextId = 1;
        kryo.register(User.class, nextId++);
        kryo.register(Product.class, nextId++); // Using incremental IDs
        kryo.register(Order.class, nextId++);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(1, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_3() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using auto-registration for all classes (no explicit IDs)
        kryo.register(User.class);
        kryo.register(Product.class);
        kryo.register(Order.class);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Laptop", 999.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using an enum to maintain consistent IDs
        for (ClassRegistry classReg : ClassRegistry.values()) {
            kryo.register(classReg.getClazz(), classReg.getId());
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("alice", "alice@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    enum ClassRegistry {
        USER(User.class, 1),
        PRODUCT(Product.class, 2),
        ORDER(Order.class, 3),
        ADDRESS(Address.class, 4),
        CUSTOMER(Customer.class, 5);
        
        private final Class<?> clazz;
        private final int id;
        
        ClassRegistry(Class<?> clazz, int id) {
            this.clazz = clazz;
            this.id = id;
        }
        
        public Class<?> getClazz() { return clazz; }
        public int getId() { return id; }
    }
    
    public void good_case_5() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        List<Class<?>> classes = new ArrayList<>();
        classes.add(User.class);
        classes.add(Product.class);
        classes.add(Order.class);
        
        int id = 1;
        for (Class<?> clazz : classes) {
            kryo.register(clazz, id++); // Sequential registration with continuous IDs
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(1, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_6() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        Map<Class<?>, Integer> registrationMap = new HashMap<>();
        registrationMap.put(User.class, 1);
        registrationMap.put(Product.class, 2);
        registrationMap.put(Order.class, 3);
        
        for (Map.Entry<Class<?>, Integer> entry : registrationMap.entrySet()) {
            kryo.register(entry.getKey(), entry.getValue());
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("bob", "bob@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_7() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Consistent registration across different conditions
        boolean condition = System.currentTimeMillis() % 2 == 0;
        
        if (condition) {
            kryo.register(User.class, 1);
            kryo.register(Product.class, 2);
        } else {
            kryo.register(User.class, 1);  // Same IDs regardless of condition
            kryo.register(Product.class, 2);
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("charlie", "charlie@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_8() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a configuration class to maintain registration order
        KryoRegistrar registrar = new KryoRegistrar();
        registrar.registerClasses(kryo);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Phone", 599.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class KryoRegistrar {
        public void registerClasses(Kryo kryo) {
            int id = 1;
            kryo.register(User.class, id++);
            kryo.register(Product.class, id++);
            kryo.register(Order.class, id++);
            kryo.register(Address.class, id++);
            kryo.register(Customer.class, id++);
        }
    }
    
    public void good_case_9() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a constant class to define IDs
        kryo.register(User.class, ClassIds.USER_ID);
        kryo.register(Product.class, ClassIds.PRODUCT_ID);
        kryo.register(Order.class, ClassIds.ORDER_ID);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(2, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class ClassIds {
        public static final int USER_ID = 1;
        public static final int PRODUCT_ID = 2;
        public static final int ORDER_ID = 3;
        public static final int ADDRESS_ID = 4;
        public static final int CUSTOMER_ID = 5;
    }
    
    public void good_case_10() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Reading registration info from a configuration
        KryoConfig config = new KryoConfig();
        Map<Class<?>, Integer> registrations = config.getRegistrations();
        
        for (Map.Entry<Class<?>, Integer> entry : registrations.entrySet()) {
            kryo.register(entry.getKey(), entry.getValue());
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Product product = new Product("Tablet", 299.99);
            kryo.writeObject(output, product);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class KryoConfig {
        public Map<Class<?>, Integer> getRegistrations() {
            Map<Class<?>, Integer> map = new HashMap<>();
            map.put(User.class, 1);
            map.put(Product.class, 2);
            map.put(Order.class, 3);
            return map;
        }
    }
    
    public void good_case_11() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a dedicated registration method
        registerInOrder(kryo, 
            User.class, 
            Product.class, 
            Order.class, 
            Address.class, 
            Customer.class
        );
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Customer customer = new Customer("Dave", new Address("123 Main St", "Anytown"));
            kryo.writeObject(output, customer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private void registerInOrder(Kryo kryo, Class<?>... classes) {
        int id = 1;
        for (Class<?> clazz : classes) {
            kryo.register(clazz, id++);
        }
    }
    
    public void good_case_12() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Versioned registration to maintain backward compatibility
        int version = 2; // Current version
        
        // Base registrations (version 1)
        kryo.register(User.class, 1);
        kryo.register(Product.class, 2);
        
        // Additional registrations for version 2
        if (version >= 2) {
            kryo.register(Order.class, 3);
            kryo.register(Address.class, 4);
        }
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Address address = new Address("456 Oak St", "Somewhere");
            kryo.writeObject(output, address);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_13() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a registration factory
        KryoRegistrationFactory factory = new KryoRegistrationFactory();
        factory.configureKryo(kryo);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("eve", "eve@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class KryoRegistrationFactory {
        public void configureKryo(Kryo kryo) {
            int id = 1;
            kryo.register(User.class, id++);
            kryo.register(Product.class, id++);
            kryo.register(Order.class, id++);
            // Additional registrations can be added here in sequence
        }
    }
    
    public void good_case_14() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a builder pattern for registration
        new KryoBuilder()
            .register(User.class, 1)
            .register(Product.class, 2)
            .register(Order.class, 3)
            .build(kryo);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            Order order = new Order(3, new ArrayList<>());
            kryo.writeObject(output, order);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class KryoBuilder {
        private final Map<Class<?>, Integer> registrations = new HashMap<>();
        
        public KryoBuilder register(Class<?> type, int id) {
            registrations.put(type, id);
            return this;
        }
        
        public void build(Kryo kryo) {
            for (Map.Entry<Class<?>, Integer> entry : registrations.entrySet()) {
                kryo.register(entry.getKey(), entry.getValue());
            }
        }
    }
    
    public void good_case_15() {
        Kryo kryo = new Kryo();
        
        // ok: java-kryo-library-registered-class-id
        // Using a centralized registry with sequential IDs
        ClassRegistryManager registryManager = ClassRegistryManager.getInstance();
        registryManager.registerClassesWithKryo(kryo);
        
        try (Output output = new Output(new FileOutputStream("data.bin"))) {
            User user = new User("frank", "frank@example.com");
            kryo.writeObject(output, user);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    static class ClassRegistryManager {
        private static final ClassRegistryManager INSTANCE = new ClassRegistryManager();
        private final Map<Class<?>, Integer> registrations = new HashMap<>();
        
        private ClassRegistryManager() {
            int id = 1;
            registrations.put(User.class, id++);
            registrations.put(Product.class, id++);
            registrations.put(Order.class, id++);
            registrations.put(Address.class, id++);
            registrations.put(Customer.class, id++);
        }
        
        public static ClassRegistryManager getInstance() {
            return INSTANCE;
        }
        
        public void registerClassesWithKryo(Kryo kryo) {
            for (Map.Entry<Class<?>, Integer> entry : registrations.entrySet()) {
                kryo.register(entry.getKey(), entry.getValue());
            }
        }
    }
}
// {/fact}