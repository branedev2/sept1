import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import java.util.function.*;

public class NonThreadSafeCollectionModification {

    // True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        List<Integer> numbers = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
        Map<Integer, String> results = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(num -> {
            results.put(num, "Result-" + num); // Modifying non-thread-safe HashMap in parallel stream
        });
        
        System.out.println("Results: " + results);
    }
    
    public void bad_case_2() {
        List<String> words = new ArrayList<>(Arrays.asList("apple", "banana", "cherry", "date"));
        Set<String> uniqueChars = new HashSet<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            for (char c : word.toCharArray()) {
                uniqueChars.add(String.valueOf(c)); // Modifying non-thread-safe HashSet in parallel stream
            }
        });
        
        System.out.println("Unique characters: " + uniqueChars);
    }
    
    public void bad_case_3() {
        int[] array = {1, 2, 3, 4, 5};
        List<Integer> results = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        Arrays.stream(array).parallel().forEach(num -> {
            results.add(num * 2); // Modifying non-thread-safe ArrayList in parallel stream
        });
        
        System.out.println("Results: " + results);
    }
    
    public void bad_case_4() {
        Map<String, Integer> wordCount = new HashMap<>();
        List<String> sentences = Arrays.asList(
            "Hello world",
            "Java programming",
            "Parallel streams",
            "Concurrent modification"
        );
        
        // ruleid: java-non-threadsafe-collection-modification
        sentences.parallelStream().forEach(sentence -> {
            String[] words = sentence.split(" ");
            for (String word : words) {
                wordCount.merge(word, 1, Integer::sum); // Modifying non-thread-safe HashMap in parallel stream
            }
        });
        
        System.out.println("Word count: " + wordCount);
    }
    
    public void bad_case_5() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        List<Integer> evenNumbers = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream()
               .filter(n -> n % 2 == 0)
               .forEach(evenNumbers::add); // Modifying non-thread-safe ArrayList using method reference
        
        System.out.println("Even numbers count: " + evenNumbers.size());
    }
    
    public void bad_case_6() {
        Map<String, List<Integer>> groupedData = new HashMap<>();
        List<Integer> data = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ruleid: java-non-threadsafe-collection-modification
        data.parallelStream().forEach(num -> {
            String key = num % 2 == 0 ? "even" : "odd";
            if (!groupedData.containsKey(key)) {
                groupedData.put(key, new ArrayList<>()); // Creating and adding new list to map
            }
            groupedData.get(key).add(num); // Modifying list inside map
        });
        
        System.out.println("Grouped data: " + groupedData);
    }
    
    public void bad_case_7() {
        List<String> words = Arrays.asList("hello", "world", "java", "parallel", "stream");
        Map<Character, Integer> charFrequency = new TreeMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            for (char c : word.toCharArray()) {
                charFrequency.compute(c, (k, v) -> (v == null) ? 1 : v + 1); // Modifying non-thread-safe TreeMap
            }
        });
        
        System.out.println("Character frequency: " + charFrequency);
    }
    
    public void bad_case_8() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        LinkedList<Integer> processedNumbers = new LinkedList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(num -> {
            if (num % 10 == 0) {
                processedNumbers.addFirst(num); // Modifying non-thread-safe LinkedList from head
            } else {
                processedNumbers.addLast(num); // Modifying non-thread-safe LinkedList from tail
            }
        });
        
        System.out.println("Processed numbers size: " + processedNumbers.size());
    }
    
    public void bad_case_9() {
        List<String> urls = Arrays.asList(
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3"
        );
        
        Map<String, String> cache = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        urls.parallelStream().forEach(url -> {
            if (!cache.containsKey(url)) {
                // Simulate fetching content
                String content = "Content for " + url;
                cache.put(url, content); // Modifying non-thread-safe HashMap
            }
        });
        
        System.out.println("Cache size: " + cache.size());
    }
    
    public void bad_case_10() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        Set<Integer> uniqueFactors = new HashSet<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(num -> {
            for (int i = 1; i <= num; i++) {
                if (num % i == 0) {
                    uniqueFactors.add(i); // Modifying non-thread-safe HashSet
                }
            }
        });
        
        System.out.println("Unique factors count: " + uniqueFactors.size());
    }
    
    public void bad_case_11() {
        List<String> words = Arrays.asList("apple", "banana", "cherry", "date", "elderberry");
        Map<Integer, List<String>> wordsByLength = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        words.parallelStream().forEach(word -> {
            int length = word.length();
            wordsByLength.computeIfAbsent(length, k -> new ArrayList<>()).add(word); // Modifying map and inner list
        });
        
        System.out.println("Words by length: " + wordsByLength);
    }
    
    public void bad_case_12() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        Queue<Integer> queue = new LinkedList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(num -> {
            if (num % 2 == 0) {
                queue.offer(num); // Modifying non-thread-safe Queue
            }
        });
        
        System.out.println("Queue size: " + queue.size());
    }
    
    public void bad_case_13() {
        List<String> sentences = Arrays.asList(
            "The quick brown fox",
            "jumps over the lazy dog",
            "Java parallel streams"
        );
        
        List<String> allWords = new ArrayList<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        sentences.parallelStream().forEach(sentence -> {
            String[] words = sentence.split(" ");
            for (String word : words) {
                allWords.add(word); // Modifying non-thread-safe ArrayList
            }
        });
        
        System.out.println("All words count: " + allWords.size());
    }
    
    public void bad_case_14() {
        Map<String, Integer> initialScores = new HashMap<>();
        initialScores.put("Alice", 85);
        initialScores.put("Bob", 92);
        initialScores.put("Charlie", 78);
        
        Map<String, String> grades = new HashMap<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        initialScores.entrySet().parallelStream().forEach(entry -> {
            String name = entry.getKey();
            int score = entry.getValue();
            
            String grade;
            if (score >= 90) grade = "A";
            else if (score >= 80) grade = "B";
            else if (score >= 70) grade = "C";
            else grade = "D";
            
            grades.put(name, grade); // Modifying non-thread-safe HashMap
        });
        
        System.out.println("Grades: " + grades);
    }
    
    public void bad_case_15() {
        List<List<Integer>> nestedLists = Arrays.asList(
            Arrays.asList(1, 2, 3),
            Arrays.asList(4, 5, 6),
            Arrays.asList(7, 8, 9)
        );
        
        Set<Integer> uniqueNumbers = new HashSet<>();
        
        // ruleid: java-non-threadsafe-collection-modification
        nestedLists.parallelStream().forEach(list -> {
            for (Integer num : list) {
                uniqueNumbers.add(num * num); // Modifying non-thread-safe HashSet
            }
        });
        
        System.out.println("Unique squared numbers: " + uniqueNumbers);
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        List<Integer> numbers = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
        
        // ok: java-non-threadsafe-collection-modification
        Map<Integer, String> results = numbers.parallelStream()
                .collect(Collectors.toConcurrentMap(
                        num -> num,
                        num -> "Result-" + num
                ));
        
        System.out.println("Results: " + results);
    }
    
    public void good_case_2() {
        List<String> words = new ArrayList<>(Arrays.asList("apple", "banana", "cherry", "date"));
        
        // ok: java-non-threadsafe-collection-modification
        Set<String> uniqueChars = words.parallelStream()
                .flatMap(word -> word.chars().mapToObj(c -> String.valueOf((char) c)))
                .collect(Collectors.toSet());
        
        System.out.println("Unique characters: " + uniqueChars);
    }
    
    public void good_case_3() {
        int[] array = {1, 2, 3, 4, 5};
        
        // ok: java-non-threadsafe-collection-modification
        List<Integer> results = Arrays.stream(array)
                .parallel()
                .map(num -> num * 2)
                .boxed()
                .collect(Collectors.toList());
        
        System.out.println("Results: " + results);
    }
    
    public void good_case_4() {
        List<String> sentences = Arrays.asList(
            "Hello world",
            "Java programming",
            "Parallel streams",
            "Concurrent modification"
        );
        
        // ok: java-non-threadsafe-collection-modification
        Map<String, Long> wordCount = sentences.parallelStream()
                .flatMap(sentence -> Arrays.stream(sentence.split(" ")))
                .collect(Collectors.groupingByConcurrent(
                        word -> word,
                        Collectors.counting()
                ));
        
        System.out.println("Word count: " + wordCount);
    }
    
    public void good_case_5() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        
        // ok: java-non-threadsafe-collection-modification
        List<Integer> evenNumbers = numbers.parallelStream()
                .filter(n -> n % 2 == 0)
                .collect(Collectors.toList());
        
        System.out.println("Even numbers count: " + evenNumbers.size());
    }
    
    public void good_case_6() {
        List<Integer> data = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ok: java-non-threadsafe-collection-modification
        Map<String, List<Integer>> groupedData = data.parallelStream()
                .collect(Collectors.groupingByConcurrent(
                        num -> num % 2 == 0 ? "even" : "odd"
                ));
        
        System.out.println("Grouped data: " + groupedData);
    }
    
    public void good_case_7() {
        List<String> words = Arrays.asList("hello", "world", "java", "parallel", "stream");
        
        // ok: java-non-threadsafe-collection-modification
        Map<Character, Integer> charFrequency = words.parallelStream()
                .flatMapToInt(String::chars)
                .mapToObj(c -> (char) c)
                .collect(Collectors.toConcurrentMap(
                        c -> c,
                        c -> 1,
                        Integer::sum
                ));
        
        System.out.println("Character frequency: " + charFrequency);
    }
    
    public void good_case_8() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        ConcurrentLinkedQueue<Integer> processedNumbers = new ConcurrentLinkedQueue<>();
        
        // ok: java-non-threadsafe-collection-modification
        numbers.parallelStream().forEach(num -> {
            processedNumbers.add(num); // Using thread-safe ConcurrentLinkedQueue
        });
        
        System.out.println("Processed numbers size: " + processedNumbers.size());
    }
    
    public void good_case_9() {
        List<String> urls = Arrays.asList(
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3"
        );
        
        ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();
        
        // ok: java-non-threadsafe-collection-modification
        urls.parallelStream().forEach(url -> {
            if (!cache.containsKey(url)) {
                // Simulate fetching content
                String content = "Content for " + url;
                cache.put(url, content); // Using thread-safe ConcurrentHashMap
            }
        });
        
        System.out.println("Cache size: " + cache.size());
    }
    
    public void good_case_10() {
        List<Integer> numbers = IntStream.range(0, 1000).boxed().collect(Collectors.toList());
        
        // ok: java-non-threadsafe-collection-modification
        Set<Integer> uniqueFactors = numbers.parallelStream()
                .flatMap(num -> IntStream.rangeClosed(1, num)
                        .filter(i -> num % i == 0)
                        .boxed())
                .collect(Collectors.toSet());
        
        System.out.println("Unique factors count: " + uniqueFactors.size());
    }
    
    public void good_case_11() {
        List<String> words = Arrays.asList("apple", "banana", "cherry", "date", "elderberry");
        
        // ok: java-non-threadsafe-collection-modification
        ConcurrentMap<Integer, List<String>> wordsByLength = new ConcurrentHashMap<>();
        
        words.forEach(word -> {
            int length = word.length();
            wordsByLength.computeIfAbsent(length, k -> new CopyOnWriteArrayList<>()).add(word);
        });
        
        // Now we can use parallel stream safely
        words.parallelStream().forEach(word -> {
            int length = word.length();
            // Using thread-safe collections
            wordsByLength.computeIfAbsent(length, k -> new CopyOnWriteArrayList<>()).add(word + "-copy");
        });
        
        System.out.println("Words by length: " + wordsByLength);
    }
    
    public void good_case_12() {
        List<Integer> numbers = IntStream.range(0, 100).boxed().collect(Collectors.toList());
        
        // ok: java-non-threadsafe-collection-modification
        List<Integer> evenNumbers = Collections.synchronizedList(new ArrayList<>());
        
        numbers.parallelStream().forEach(num -> {
            if (num % 2 == 0) {
                synchronized (evenNumbers) {
                    evenNumbers.add(num); // Using synchronized list with explicit synchronization
                }
            }
        });
        
        System.out.println("Even numbers count: " + evenNumbers.size());
    }
    
    public void good_case_13() {
        List<String> sentences = Arrays.asList(
            "The quick brown fox",
            "jumps over the lazy dog",
            "Java parallel streams"
        );
        
        // ok: java-non-threadsafe-collection-modification
        List<String> allWords = sentences.parallelStream()
                .flatMap(sentence -> Arrays.stream(sentence.split(" ")))
                .collect(Collectors.toList());
        
        System.out.println("All words count: " + allWords.size());
    }
    
    public void good_case_14() {
        Map<String, Integer> initialScores = new HashMap<>();
        initialScores.put("Alice", 85);
        initialScores.put("Bob", 92);
        initialScores.put("Charlie", 78);
        
        // ok: java-non-threadsafe-collection-modification
        Map<String, String> grades = initialScores.entrySet().parallelStream()
                .collect(Collectors.toConcurrentMap(
                        Map.Entry::getKey,
                        entry -> {
                            int score = entry.getValue();
                            if (score >= 90) return "A";
                            else if (score >= 80) return "B";
                            else if (score >= 70) return "C";
                            else return "D";
                        }
                ));
        
        System.out.println("Grades: " + grades);
    }
    
    public void good_case_15() {
        List<List<Integer>> nestedLists = Arrays.asList(
            Arrays.asList(1, 2, 3),
            Arrays.asList(4, 5, 6),
            Arrays.asList(7, 8, 9)
        );
        
        // ok: java-non-threadsafe-collection-modification
        Set<Integer> uniqueNumbers = nestedLists.parallelStream()
                .flatMap(Collection::stream)
                .map(num -> num * num)
                .collect(Collectors.toSet());
        
        System.out.println("Unique squared numbers: " + uniqueNumbers);
    }
}
// {/fact}