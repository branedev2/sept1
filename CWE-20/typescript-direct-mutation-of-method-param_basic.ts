// True Positives (Vulnerable Code)

// Function that directly mutates an array parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(items: string[]): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  items.push("new item");
  console.log("Modified array:", items);
}
// {/fact}

// Function that directly mutates an object parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(user: { name: string; age: number }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  user.age += 1;
  console.log(`User ${user.name} is now ${user.age} years old`);
}

// Function that directly mutates a Map parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(dataMap: Map<string, number>): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  dataMap.set("newKey", 100);
  console.log("Map updated:", dataMap);
}
// {/fact}

// Function that directly mutates a Set parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(uniqueIds: Set<number>): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  uniqueIds.add(42);
  console.log("Set updated:", uniqueIds);
}
// {/fact}

// Function that directly mutates an object parameter's nested property
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(config: { settings: { darkMode: boolean } }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  config.settings.darkMode = !config.settings.darkMode;
  console.log("Config updated:", config);
}

// Function that directly mutates an array parameter by sorting it
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(numbers: number[]): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  numbers.sort((a, b) => a - b);
  console.log("Sorted numbers:", numbers);
}
// {/fact}

// Function that directly mutates an object parameter by deleting a property
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(data: { [key: string]: any }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  delete data.temporary;
  console.log("Cleaned data:", data);
}

// Function that directly mutates a Date parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(date: Date): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  date.setFullYear(date.getFullYear() + 1);
  console.log("Updated date:", date);
}
// {/fact}

// Function that directly mutates an array parameter by splicing
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(tasks: string[]): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  tasks.splice(0, 1);
  console.log("Remaining tasks:", tasks);
}
// {/fact}

// Function that directly mutates multiple parameters
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(user: { name: string }, roles: string[]): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  user.name = user.name.toUpperCase();
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  roles.push("user");
  console.log(`User ${user.name} has roles:`, roles);
}

// Function that directly mutates an object parameter in a loop
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(counters: { [key: string]: number }): void {
// {/fact}

  const keys = Object.keys(counters);
  for (const key of keys) {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    counters[key] += 1;
  }
  console.log("Updated counters:", counters);
}

// Function that directly mutates a parameter conditionally
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(config: { debug: boolean; logLevel: string }): void {
// {/fact}

  if (config.debug) {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    config.logLevel = "verbose";
  }
  console.log("Config:", config);
}

// Function that directly mutates an array parameter using array methods
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(queue: number[]): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  queue.shift();
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  queue.unshift(0);
  console.log("Modified queue:", queue);
}
// {/fact}

// Function that directly mutates a complex object parameter
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(product: { 
  id: number; 
  details: { 
    price: number; 
    stock: number 
  } 
}): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  product.details.stock -= 1;
  console.log("Updated product:", product);
}

// Function that directly mutates a parameter in a try-catch block
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(apiConfig: { retries: number; timeout: number }): void {
// {/fact}

  try {
    // Some API call that might fail
    throw new Error("API failed");
  } catch (error) {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    apiConfig.retries -= 1;
    console.log("Retries left:", apiConfig.retries);
  }
}

// True Negatives (Safe Code)

// Function that clones an array parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(items: string[]): string[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const itemsCopy = [...items];
  itemsCopy.push("new item");
  console.log("Original array:", items);
  console.log("Modified copy:", itemsCopy);
  return itemsCopy;
}
// {/fact}

// Function that clones an object parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(user: { name: string; age: number }): { name: string; age: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const userCopy = { ...user };
  userCopy.age += 1;
  console.log("Original user:", user);
  console.log("Modified user:", userCopy);
  return userCopy;
}

// Function that creates a new Map from a parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(dataMap: Map<string, number>): Map<string, number> {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const dataMapCopy = new Map(dataMap);
  dataMapCopy.set("newKey", 100);
  console.log("Original map:", dataMap);
  console.log("Modified map:", dataMapCopy);
  return dataMapCopy;
}
// {/fact}

// Function that creates a new Set from a parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(uniqueIds: Set<number>): Set<number> {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const uniqueIdsCopy = new Set(uniqueIds);
  uniqueIdsCopy.add(42);
  console.log("Original set:", uniqueIds);
  console.log("Modified set:", uniqueIdsCopy);
  return uniqueIdsCopy;
}
// {/fact}

// Function that deep clones an object parameter before modifying nested properties
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(config: { settings: { darkMode: boolean } }): { settings: { darkMode: boolean } } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const configCopy = JSON.parse(JSON.stringify(config));
  configCopy.settings.darkMode = !configCopy.settings.darkMode;
  console.log("Original config:", config);
  console.log("Modified config:", configCopy);
  return configCopy;
}

// Function that creates a sorted copy of an array parameter
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(numbers: number[]): number[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const sortedNumbers = [...numbers].sort((a, b) => a - b);
  console.log("Original numbers:", numbers);
  console.log("Sorted numbers:", sortedNumbers);
  return sortedNumbers;
}
// {/fact}

// Function that creates a copy of an object parameter before deleting a property
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(data: { [key: string]: any }): { [key: string]: any } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const dataCopy = { ...data };
  delete dataCopy.temporary;
  console.log("Original data:", data);
  console.log("Cleaned data:", dataCopy);
  return dataCopy;
}

// Function that creates a new Date from a parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(date: Date): Date {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const newDate = new Date(date);
  newDate.setFullYear(newDate.getFullYear() + 1);
  console.log("Original date:", date);
  console.log("Updated date:", newDate);
  return newDate;
}
// {/fact}

// Function that creates a copy of an array parameter before splicing
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(tasks: string[]): string[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const tasksCopy = [...tasks];
  tasksCopy.splice(0, 1);
  console.log("Original tasks:", tasks);
  console.log("Remaining tasks:", tasksCopy);
  return tasksCopy;
}
// {/fact}

// Function that creates copies of multiple parameters before modifying them
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(user: { name: string }, roles: string[]): [{ name: string }, string[]] {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const userCopy = { ...user };
  const rolesCopy = [...roles];
  
  userCopy.name = userCopy.name.toUpperCase();
  rolesCopy.push("user");
  
  console.log("Original user:", user);
  console.log("Original roles:", roles);
  console.log("Modified user:", userCopy);
  console.log("Modified roles:", rolesCopy);
  
  return [userCopy, rolesCopy];
}

// Function that creates a copy of an object parameter before modifying it in a loop
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(counters: { [key: string]: number }): { [key: string]: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const countersCopy = { ...counters };
  const keys = Object.keys(countersCopy);
  
  for (const key of keys) {
    countersCopy[key] += 1;
  }
  
  console.log("Original counters:", counters);
  console.log("Updated counters:", countersCopy);
  return countersCopy;
}

// Function that creates a copy of a parameter before conditionally modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(config: { debug: boolean; logLevel: string }): { debug: boolean; logLevel: string } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const configCopy = { ...config };
  
  if (configCopy.debug) {
    configCopy.logLevel = "verbose";
  }
  
  console.log("Original config:", config);
  console.log("Modified config:", configCopy);
  return configCopy;
}

// Function that creates a copy of an array parameter before using array methods
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(queue: number[]): number[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const queueCopy = [...queue];
  queueCopy.shift();
  queueCopy.unshift(0);
  
  console.log("Original queue:", queue);
  console.log("Modified queue:", queueCopy);
  return queueCopy;
}
// {/fact}

// Function that deep clones a complex object parameter before modifying it
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(product: { 
  id: number; 
  details: { 
    price: number; 
    stock: number 
  } 
}): { id: number; details: { price: number; stock: number } } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const productCopy = {
    id: product.id,
    details: {
      price: product.details.price,
      stock: product.details.stock
    }
  };
  
  productCopy.details.stock -= 1;
  
  console.log("Original product:", product);
  console.log("Updated product:", productCopy);
  return productCopy;
}

// Function that creates a copy of a parameter before modifying it in a try-catch block
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(apiConfig: { retries: number; timeout: number }): { retries: number; timeout: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const apiConfigCopy = { ...apiConfig };
  
  try {
    // Some API call that might fail
    throw new Error("API failed");
  } catch (error) {
    apiConfigCopy.retries -= 1;
    console.log("Original config:", apiConfig);
    console.log("Retries left:", apiConfigCopy.retries);
  }
  
  return apiConfigCopy;
}