import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.esotericsoftware.kryo.serializers.CompatibleFieldSerializer;
import com.esotericsoftware.kryo.serializers.VersionFieldSerializer;
import com.esotericsoftware.kryo.util.DefaultInstantiatorStrategy;
import com.esotericsoftware.kryo.util.Pool;
import org.objenesis.strategy.StdInstantiatorStrategy;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Security Issue: Improper registration of class IDs in Kryo serialization can lead to deserialization issues,
// data corruption, or potential security vulnerabilities (CWE-502). Classes should be registered with continuous
// IDs in ascending order, and existing registrations should not be changed.

// True Positive Examples (Vulnerable/Insecure Code)

class User {
    String name;
    int age;
}

class Product {
    String name;
    double price;
}

class Order {
    String id;
    List<Product> products;
}

class Customer {
    String id;
    String name;
}

class Address {
    String street;
    String city;
}

class Payment {
    String method;
    double amount;
}

class ShippingInfo {
    Address address;
    String carrier;
}

class Invoice {
    String id;
    double total;
}

class Discount {
    String code;
    double percentage;
}

class Category {
    String name;
    List<Product> products;
}

class Review {
    String text;
    int rating;
}

class Notification {
    String message;
    String recipient;
}

class Inventory {
    Product product;
    int quantity;
}

class Supplier {
    String name;
    List<Product> products;
}

class Warehouse {
    String location;
    List<Inventory> inventory;
}

// Example 1: Basic Kryo with non-sequential IDs
public void bad_case_1() {
    Kryo kryo = new Kryo();
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Product.class, 3); // Skipping ID 2
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "John";
    user.age = 30;
    
    kryo.writeObject(output, user);
    output.close();
}

// Example 2: Kryo with duplicate IDs
public void bad_case_2() {
    Kryo kryo = new Kryo();
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Product.class, 1); // Same ID used twice
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Product product = new Product();
    product.name = "Laptop";
    product.price = 999.99;
    
    kryo.writeObject(output, product);
    output.close();
}

// Example 3: Kryo with Pool and inconsistent registration order
public void bad_case_3() {
    Pool<Kryo> kryoPool = new Pool<Kryo>(true, false, 8) {
        protected Kryo create() {
            Kryo kryo = new Kryo();
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(User.class, 1);
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(Product.class, 2);
            return kryo;
        }
    };
    
    Kryo kryo1 = kryoPool.obtain();
    // ruleid: java-kryo-library-registered-class-id
    kryo1.register(Order.class, 5); // Skipping IDs 3 and 4
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Order order = new Order();
    order.id = "ORD-001";
    order.products = new ArrayList<>();
    
    kryo1.writeObject(output, order);
    output.close();
    kryoPool.free(kryo1);
}

// Example 4: Kryo with CompatibleFieldSerializer and inconsistent IDs
public void bad_case_4() {
    Kryo kryo = new Kryo();
    kryo.setDefaultSerializer(CompatibleFieldSerializer.class);
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Customer.class, 10);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Address.class, 20); // Large gap in IDs
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Customer customer = new Customer();
    customer.id = "CUST-001";
    customer.name = "Jane Doe";
    
    kryo.writeObject(output, customer);
    output.close();
}

// Example 5: Kryo with VersionFieldSerializer and inconsistent IDs
public void bad_case_5() {
    Kryo kryo = new Kryo();
    kryo.setDefaultSerializer(VersionFieldSerializer.class);
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Payment.class, 1);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(ShippingInfo.class, 3); // Skipping ID 2
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Payment payment = new Payment();
    payment.method = "Credit Card";
    payment.amount = 150.00;
    
    kryo.writeObject(output, payment);
    output.close();
}

// Example 6: Kryo with custom instantiator strategy and non-sequential IDs
public void bad_case_6() {
    Kryo kryo = new Kryo();
    kryo.setInstantiatorStrategy(new DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Invoice.class, 5);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Discount.class, 10); // Non-sequential IDs
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Invoice invoice = new Invoice();
    invoice.id = "INV-001";
    invoice.total = 299.99;
    
    kryo.writeObject(output, invoice);
    output.close();
}

// Example 7: Kryo with file output and inconsistent IDs
public void bad_case_7() {
    Kryo kryo = new Kryo();
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Category.class, 100);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Product.class, 200); // Large gap in IDs
    
    try {
        Output output = new Output(new FileOutputStream("category.bin"));
        
        Category category = new Category();
        category.name = "Electronics";
        category.products = new ArrayList<>();
        
        kryo.writeObject(output, category);
        output.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Example 8: Kryo with re-registration of classes
public void bad_case_8() {
    Kryo kryo = new Kryo();
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Product.class, 2);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 3); // Re-registering User class with different ID
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "Alice";
    user.age = 25;
    
    kryo.writeObject(output, user);
    output.close();
}

// Example 9: Kryo with dynamic registration and inconsistent IDs
public void bad_case_9() {
    Kryo kryo = new Kryo();
    Map<String, Integer> classIds = new HashMap<>();
    classIds.put(Review.class.getName(), 1);
    classIds.put(Product.class.getName(), 3); // Skipping ID 2
    
    for (Map.Entry<String, Integer> entry : classIds.entrySet()) {
        try {
            Class<?> clazz = Class.forName(entry.getKey());
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(clazz, entry.getValue());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Review review = new Review();
    review.text = "Great product!";
    review.rating = 5;
    
    kryo.writeObject(output, review);
    output.close();
}

// Example 10: Kryo with conditional registration and inconsistent IDs
public void bad_case_10() {
    Kryo kryo = new Kryo();
    boolean includeNotifications = true;
    
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    
    if (includeNotifications) {
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(Notification.class, 3); // Skipping ID 2
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Notification notification = new Notification();
    notification.message = "New message received";
    notification.recipient = "user@example.com";
    
    kryo.writeObject(output, notification);
    output.close();
}

// Example 11: Kryo with registration based on configuration and inconsistent IDs
public void bad_case_11() {
    Kryo kryo = new Kryo();
    String[] classesToRegister = {"User", "Product", "Order"};
    int id = 1;
    
    for (String className : classesToRegister) {
        try {
            if (className.equals("Product")) {
                id += 2; // Creating a gap in IDs
            }
            Class<?> clazz = Class.forName("com.example." + className);
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(clazz, id++);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    try {
        Object user = Class.forName("com.example.User").newInstance();
        kryo.writeObject(output, user);
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    output.close();
}

// Example 12: Kryo with registration in separate methods and inconsistent IDs
public void bad_case_12() {
    Kryo kryo = new Kryo();
    
    registerUserClasses(kryo);
    registerProductClasses(kryo);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Inventory inventory = new Inventory();
    inventory.product = new Product();
    inventory.quantity = 100;
    
    kryo.writeObject(output, inventory);
    output.close();
}

private void registerUserClasses(Kryo kryo) {
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Customer.class, 2);
}

private void registerProductClasses(Kryo kryo) {
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Product.class, 5); // Gap in IDs
    // ruleid: java-kryo-library-registered-class-id
    kryo.register(Inventory.class, 6);
}

// Example 13: Kryo with registration from external configuration and inconsistent IDs
public void bad_case_13() {
    Kryo kryo = new Kryo();
    Map<String, Integer> externalConfig = new HashMap<>();
    externalConfig.put("Supplier", 10);
    externalConfig.put("Product", 20); // Non-sequential IDs
    
    for (Map.Entry<String, Integer> entry : externalConfig.entrySet()) {
        try {
            Class<?> clazz = Class.forName(entry.getKey());
            // ruleid: java-kryo-library-registered-class-id
            kryo.register(clazz, entry.getValue());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Supplier supplier = new Supplier();
    supplier.name = "ABC Suppliers";
    supplier.products = new ArrayList<>();
    
    kryo.writeObject(output, supplier);
    output.close();
}

// Example 14: Kryo with registration in try-catch blocks and inconsistent IDs
public void bad_case_14() {
    Kryo kryo = new Kryo();
    
    try {
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(Warehouse.class, 1);
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    try {
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(Inventory.class, 3); // Skipping ID 2
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Warehouse warehouse = new Warehouse();
    warehouse.location = "Central";
    warehouse.inventory = new ArrayList<>();
    
    kryo.writeObject(output, warehouse);
    output.close();
}

// Example 15: Kryo with registration in a loop and inconsistent IDs
public void bad_case_15() {
    Kryo kryo = new Kryo();
    Class<?>[] classes = {User.class, Product.class, Order.class, Customer.class};
    
    int id = 1;
    for (Class<?> clazz : classes) {
        if (clazz == Order.class) {
            id += 2; // Creating a gap in IDs
        }
        // ruleid: java-kryo-library-registered-class-id
        kryo.register(clazz, id++);
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "Bob";
    user.age = 40;
    
    kryo.writeObject(output, user);
    output.close();
}

// True Negative Examples (Safe/Secure Code)

// Example 1: Basic Kryo with sequential IDs
public void good_case_1() {
    Kryo kryo = new Kryo();
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Product.class, 2);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "John";
    user.age = 30;
    
    kryo.writeObject(output, user);
    output.close();
}

// Example 2: Kryo with Pool and consistent registration order
public void good_case_2() {
    Pool<Kryo> kryoPool = new Pool<Kryo>(true, false, 8) {
        protected Kryo create() {
            Kryo kryo = new Kryo();
            // ok: java-kryo-library-registered-class-id
            kryo.register(User.class, 1);
            // ok: java-kryo-library-registered-class-id
            kryo.register(Product.class, 2);
            // ok: java-kryo-library-registered-class-id
            kryo.register(Order.class, 3);
            return kryo;
        }
    };
    
    Kryo kryo = kryoPool.obtain();
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Order order = new Order();
    order.id = "ORD-001";
    order.products = new ArrayList<>();
    
    kryo.writeObject(output, order);
    output.close();
    kryoPool.free(kryo);
}

// Example 3: Kryo with CompatibleFieldSerializer and sequential IDs
public void good_case_3() {
    Kryo kryo = new Kryo();
    kryo.setDefaultSerializer(CompatibleFieldSerializer.class);
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(Customer.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Address.class, 2);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Customer customer = new Customer();
    customer.id = "CUST-001";
    customer.name = "Jane Doe";
    
    kryo.writeObject(output, customer);
    output.close();
}

// Example 4: Kryo with VersionFieldSerializer and sequential IDs
public void good_case_4() {
    Kryo kryo = new Kryo();
    kryo.setDefaultSerializer(VersionFieldSerializer.class);
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(Payment.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(ShippingInfo.class, 2);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Payment payment = new Payment();
    payment.method = "Credit Card";
    payment.amount = 150.00;
    
    kryo.writeObject(output, payment);
    output.close();
}

// Example 5: Kryo with custom instantiator strategy and sequential IDs
public void good_case_5() {
    Kryo kryo = new Kryo();
    kryo.setInstantiatorStrategy(new DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(Invoice.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Discount.class, 2);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Invoice invoice = new Invoice();
    invoice.id = "INV-001";
    invoice.total = 299.99;
    
    kryo.writeObject(output, invoice);
    output.close();
}

// Example 6: Kryo with file output and sequential IDs
public void good_case_6() {
    Kryo kryo = new Kryo();
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(Category.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Product.class, 2);
    
    try {
        Output output = new Output(new FileOutputStream("category.bin"));
        
        Category category = new Category();
        category.name = "Electronics";
        category.products = new ArrayList<>();
        
        kryo.writeObject(output, category);
        output.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}

// Example 7: Kryo with consistent registration of classes
public void good_case_7() {
    Kryo kryo = new Kryo();
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Product.class, 2);
    // Using the same class with the same ID is fine
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "Alice";
    user.age = 25;
    
    kryo.writeObject(output, user);
    output.close();
}

// Example 8: Kryo with dynamic registration and sequential IDs
public void good_case_8() {
    Kryo kryo = new Kryo();
    Map<String, Integer> classIds = new HashMap<>();
    classIds.put(Review.class.getName(), 1);
    classIds.put(Product.class.getName(), 2);
    
    for (Map.Entry<String, Integer> entry : classIds.entrySet()) {
        try {
            Class<?> clazz = Class.forName(entry.getKey());
            // ok: java-kryo-library-registered-class-id
            kryo.register(clazz, entry.getValue());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Review review = new Review();
    review.text = "Great product!";
    review.rating = 5;
    
    kryo.writeObject(output, review);
    output.close();
}

// Example 9: Kryo with conditional registration and sequential IDs
public void good_case_9() {
    Kryo kryo = new Kryo();
    boolean includeNotifications = true;
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    
    if (includeNotifications) {
        // ok: java-kryo-library-registered-class-id
        kryo.register(Notification.class, 2);
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Notification notification = new Notification();
    notification.message = "New message received";
    notification.recipient = "user@example.com";
    
    kryo.writeObject(output, notification);
    output.close();
}

// Example 10: Kryo with registration based on configuration and sequential IDs
public void good_case_10() {
    Kryo kryo = new Kryo();
    String[] classesToRegister = {"User", "Product", "Order"};
    int id = 1;
    
    for (String className : classesToRegister) {
        try {
            Class<?> clazz = Class.forName("com.example." + className);
            // ok: java-kryo-library-registered-class-id
            kryo.register(clazz, id++);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    try {
        Object user = Class.forName("com.example.User").newInstance();
        kryo.writeObject(output, user);
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    output.close();
}

// Example 11: Kryo with registration in separate methods and sequential IDs
public void good_case_11() {
    Kryo kryo = new Kryo();
    
    int nextId = registerUserClasses(kryo, 1);
    registerProductClasses(kryo, nextId);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Inventory inventory = new Inventory();
    inventory.product = new Product();
    inventory.quantity = 100;
    
    kryo.writeObject(output, inventory);
    output.close();
}

private int registerUserClasses(Kryo kryo, int startId) {
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, startId++);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Customer.class, startId++);
    return startId;
}

private void registerProductClasses(Kryo kryo, int startId) {
    // ok: java-kryo-library-registered-class-id
    kryo.register(Product.class, startId++);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Inventory.class, startId++);
}

// Example 12: Kryo with registration from external configuration and sequential IDs
public void good_case_12() {
    Kryo kryo = new Kryo();
    Map<String, Integer> externalConfig = new HashMap<>();
    externalConfig.put("Supplier", 1);
    externalConfig.put("Product", 2);
    
    for (Map.Entry<String, Integer> entry : externalConfig.entrySet()) {
        try {
            Class<?> clazz = Class.forName(entry.getKey());
            // ok: java-kryo-library-registered-class-id
            kryo.register(clazz, entry.getValue());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Supplier supplier = new Supplier();
    supplier.name = "ABC Suppliers";
    supplier.products = new ArrayList<>();
    
    kryo.writeObject(output, supplier);
    output.close();
}

// Example 13: Kryo with registration in try-catch blocks and sequential IDs
public void good_case_13() {
    Kryo kryo = new Kryo();
    
    try {
        // ok: java-kryo-library-registered-class-id
        kryo.register(Warehouse.class, 1);
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    try {
        // ok: java-kryo-library-registered-class-id
        kryo.register(Inventory.class, 2);
    } catch (Exception e) {
        e.printStackTrace();
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    Warehouse warehouse = new Warehouse();
    warehouse.location = "Central";
    warehouse.inventory = new ArrayList<>();
    
    kryo.writeObject(output, warehouse);
    output.close();
}

// Example 14: Kryo with registration in a loop and sequential IDs
public void good_case_14() {
    Kryo kryo = new Kryo();
    Class<?>[] classes = {User.class, Product.class, Order.class, Customer.class};
    
    int id = 1;
    for (Class<?> clazz : classes) {
        // ok: java-kryo-library-registered-class-id
        kryo.register(clazz, id++);
    }
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    Output output = new Output(outputStream);
    
    User user = new User();
    user.name = "Bob";
    user.age = 40;
    
    kryo.writeObject(output, user);
    output.close();
}

// Example 15: Kryo with file input/output and sequential IDs
public void good_case_15() {
    Kryo kryo = new Kryo();
    
    // ok: java-kryo-library-registered-class-id
    kryo.register(User.class, 1);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Product.class, 2);
    // ok: java-kryo-library-registered-class-id
    kryo.register(Order.class, 3);
    
    try {
        // Write object
        Output output = new Output(new FileOutputStream("data.bin"));
        User user = new User();
        user.name = "Charlie";
        user.age = 35;
        kryo.writeObject(output, user);
        output.close();
        
        // Read object
        Input input = new Input(new FileInputStream("data.bin"));
        User readUser = kryo.readObject(input, User.class);
        input.close();
    } catch (Exception e) {
        e.printStackTrace();
    }
}