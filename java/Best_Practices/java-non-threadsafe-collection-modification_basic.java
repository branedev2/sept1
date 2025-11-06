import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import java.util.function.*;
import java.util.concurrent.atomic.*;

public class NonThreadSafeCollectionModification {

    // True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            numbers.add(i);
        }
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(number -> {
            if (number % 2 == 0) {
                numbers.add(number * 2); // Modifying the same collection being streamed
            }
        });
    }

    public void bad_case_2() {
        Map<String, Integer> wordCounts = new HashMap<>();
        List<String> words = Arrays.asList("hello", "world", "java", "stream", "parallel");
        
        // ruleid: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            wordCounts.put(word, word.length()); // Modifying HashMap in parallel stream
        });
    }

    public void bad_case_3() {
        Set<Integer> uniqueNumbers = new HashSet<>();
        List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(n -> {
            uniqueNumbers.add(n * n); // Modifying HashSet in parallel stream
        });
    }

    public void bad_case_4() {
        List<String> results = new ArrayList<>();
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().map(n -> n * 2).forEach(n -> {
            results.add(n.toString()); // Modifying ArrayList in parallel stream
        });
    }

    public void bad_case_5() {
        Map<Integer, String> dataMap = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        IntStream.range(0, 1000).parallel().forEach(i -> {
            dataMap.put(i, "Value-" + i); // Modifying HashMap in parallel IntStream
        });
    }

    public void bad_case_6() {
        List<String> sharedList = new ArrayList<>();
        List<Integer> values = Arrays.asList(1, 2, 3, 4, 5);
        
        // ruleid: java-non-threadsafe-collection-modification
        values.parallelStream().forEach(v -> {
            if (v % 2 == 0) {
                sharedList.add("Even: " + v);
            } else {
                sharedList.add("Odd: " + v);
            }
        });
    }

    public void bad_case_7() {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            numbers.add(i);
        }
        
        List<Integer> evenNumbers = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().filter(n -> n % 2 == 0).forEach(n -> {
            evenNumbers.add(n);
            numbers.remove(Integer.valueOf(n)); // Removing from the source collection
        });
    }

    public void bad_case_8() {
        Map<String, List<Integer>> groupedData = new HashMap<>();
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(n -> {
            String key = n % 10 == 0 ? "divisible" : "not-divisible";
            if (!groupedData.containsKey(key)) {
                groupedData.put(key, new ArrayList<>());
            }
            groupedData.get(key).add(n);
        });
    }

    public void bad_case_9() {
        Set<String> processedItems = new HashSet<>();
        List<String> items = Arrays.asList("item1", "item2", "item3", "item4", "item5");
        
        // ruleid: java-non-threadsafe-collection-modification
        items.parallelStream().forEach(item -> {
            String processed = item.toUpperCase();
            processedItems.add(processed);
            if (processed.contains("3")) {
                processedItems.remove(item); // Removing while processing in parallel
            }
        });
    }

    public void bad_case_10() {
        LinkedList<Integer> linkedList = new LinkedList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        IntStream.range(0, 1000).parallel().forEach(i -> {
            linkedList.add(i); // LinkedList is not thread-safe
        });
    }

    public void bad_case_11() {
        TreeMap<Integer, String> treeMap = new TreeMap<>();
        List<Integer> keys = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ruleid: java-non-threadsafe-collection-modification
        keys.parallelStream().forEach(key -> {
            treeMap.put(key, "Value-" + key); // TreeMap is not thread-safe
        });
    }

    public void bad_case_12() {
        List<Integer> sourceList = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        List<Integer> targetList = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        sourceList.parallelStream().filter(n -> n % 3 == 0).forEach(n -> {
            targetList.add(n);
            if (n > 50) {
                targetList.add(n * 2);
            }
        });
    }

    public void bad_case_13() {
        Queue<String> messageQueue = new LinkedList<>();
        List<String> messages = Arrays.asList("msg1", "msg2", "msg3", "msg4", "msg5");
        
        // ruleid: java-non-threadsafe-collection-modification
        messages.parallelStream().forEach(msg -> {
            messageQueue.offer(msg); // Queue is not thread-safe
            if (messageQueue.size() > 3) {
                messageQueue.poll(); // Removing from queue in parallel
            }
        });
    }

    public void bad_case_14() {
        Map<String, Integer> counters = new HashMap<>();
        List<String> words = Arrays.asList("apple", "banana", "apple", "orange", "banana", "apple");
        
        // ruleid: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            counters.compute(word, (k, v) -> (v == null) ? 1 : v + 1); // Modifying map with compute
        });
    }

    public void bad_case_15() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        List<Integer> processedNumbers = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(n -> {
            if (n % 2 == 0) {
                processedNumbers.add(n);
            } else {
                processedNumbers.add(0, n); // Adding at specific index is not thread-safe
            }
        });
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < 1000; i++) {
            numbers.add(i);
        }
        
        // Using CopyOnWriteArrayList which is thread-safe
        List<Integer> threadSafeList = new CopyOnWriteArrayList<>();
        
        // ok: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(number -> {
            if (number % 2 == 0) {
                threadSafeList.add(number * 2); // Modifying a thread-safe collection
            }
        });
    }

    public void good_case_2() {
        List<String> words = Arrays.asList("hello", "world", "java", "stream", "parallel");
        
        // Using ConcurrentHashMap which is thread-safe
        Map<String, Integer> wordCounts = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            wordCounts.put(word, word.length()); // ConcurrentHashMap is thread-safe
        });
    }

    public void good_case_3() {
        List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        
        // Using ConcurrentSkipListSet which is thread-safe
        Set<Integer> uniqueNumbers = new ConcurrentSkipListSet<>();
        
        // ok: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(n -> {
            uniqueNumbers.add(n * n); // ConcurrentSkipListSet is thread-safe
        });
    }

    public void good_case_4() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // Using collect to aggregate results instead of modifying a collection
        // ok: java-non-threadsafe-collection-modification
        List<String> results = numbers.parallelStream()
                .map(n -> n * 2)
                .map(Object::toString)
                .collect(Collectors.toList()); // Collect is thread-safe
    }

    public void good_case_5() {
        // Using collect to create a map instead of modifying one
        // ok: java-non-threadsafe-collection-modification
        Map<Integer, String> dataMap = IntStream.range(0, 1000)
                .parallel()
                .boxed()
                .collect(Collectors.toConcurrentMap(
                        i -> i,
                        i -> "Value-" + i
                ));
    }

    public void good_case_6() {
        List<Integer> values = Arrays.asList(1, 2, 3, 4, 5);
        
        // Using synchronizedList which provides thread-safety
        List<String> sharedList = Collections.synchronizedList(new ArrayList<>());
        
        // ok: java-non-threadsafe-collection-modification
        values.parallelStream().forEach(v -> {
            synchronized (sharedList) {
                if (v % 2 == 0) {
                    sharedList.add("Even: " + v);
                } else {
                    sharedList.add("Odd: " + v);
                }
            }
        });
    }

    public void good_case_7() {
        List<Integer> numbers = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            numbers.add(i);
        }
        
        // Using sequential stream for operations that modify collections
        // ok: java-non-threadsafe-collection-modification
        List<Integer> evenNumbers = numbers.stream() // Not parallel
                .filter(n -> n % 2 == 0)
                .collect(Collectors.toList());
    }

    public void good_case_8() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // Using groupingByConcurrent for thread-safe grouping
        // ok: java-non-threadsafe-collection-modification
        Map<String, List<Integer>> groupedData = numbers.parallelStream()
                .collect(Collectors.groupingByConcurrent(
                        n -> n % 10 == 0 ? "divisible" : "not-divisible"
                ));
    }

    public void good_case_9() {
        List<String> items = Arrays.asList("item1", "item2", "item3", "item4", "item5");
        
        // Using ConcurrentHashMap's newKeySet for a thread-safe set
        Set<String> processedItems = ConcurrentHashMap.newKeySet();
        
        // ok: java-non-threadsafe-collection-modification
        items.parallelStream().forEach(item -> {
            String processed = item.toUpperCase();
            processedItems.add(processed);
        });
    }

    public void good_case_10() {
        // Using concurrent queue for thread-safety
        ConcurrentLinkedQueue<Integer> concurrentQueue = new ConcurrentLinkedQueue<>();
        
        // ok: java-non-threadsafe-collection-modification
        IntStream.range(0, 1000).parallel().forEach(i -> {
            concurrentQueue.add(i); // ConcurrentLinkedQueue is thread-safe
        });
    }

    public void good_case_11() {
        List<Integer> keys = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // Using ConcurrentSkipListMap which is thread-safe
        ConcurrentNavigableMap<Integer, String> concurrentMap = new ConcurrentSkipListMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        keys.parallelStream().forEach(key -> {
            concurrentMap.put(key, "Value-" + key); // ConcurrentSkipListMap is thread-safe
        });
    }

    public void good_case_12() {
        List<Integer> sourceList = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // Using collect to create a new list instead of modifying one
        // ok: java-non-threadsafe-collection-modification
        List<Integer> targetList = sourceList.parallelStream()
                .filter(n -> n % 3 == 0)
                .flatMap(n -> n > 50 ? Stream.of(n, n * 2) : Stream.of(n))
                .collect(Collectors.toList());
    }

    public void good_case_13() {
        List<String> messages = Arrays.asList("msg1", "msg2", "msg3", "msg4", "msg5");
        
        // Using BlockingQueue which is thread-safe
        BlockingQueue<String> messageQueue = new LinkedBlockingQueue<>();
        
        // ok: java-non-threadsafe-collection-modification
        messages.parallelStream().forEach(msg -> {
            messageQueue.offer(msg); // LinkedBlockingQueue is thread-safe
        });
    }

    public void good_case_14() {
        List<String> words = Arrays.asList("apple", "banana", "apple", "orange", "banana", "apple");
        
        // Using atomic operations with ConcurrentHashMap
        ConcurrentHashMap<String, AtomicInteger> counters = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            counters.computeIfAbsent(word, k -> new AtomicInteger(0)).incrementAndGet();
        });
    }

    public void good_case_15() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        
        // Using partitioningBy to separate even and odd numbers
        // ok: java-non-threadsafe-collection-modification
        Map<Boolean, List<Integer>> partitioned = numbers.parallelStream()
                .collect(Collectors.partitioningBy(n -> n % 2 == 0));
        
        List<Integer> evenNumbers = partitioned.get(true);
        List<Integer> oddNumbers = partitioned.get(false);
    }
}
// {/fact}