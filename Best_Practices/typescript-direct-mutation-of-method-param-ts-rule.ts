// True Positives (Vulnerable Code)

// Example 1: Direct mutation of an object parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(user: { name: string, age: number }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  user.name = "Modified Name";
  user.age += 1;
  console.log(`User is now ${user.name}, ${user.age} years old`);
}

// Example 2: Direct mutation of an array parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(numbers: number[]): number[] {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  numbers.push(100);
  numbers.sort((a, b) => a - b);
  return numbers;
}
// {/fact}

// Example 3: Direct mutation of a map parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(userMap: Map<string, number>): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  userMap.set("newUser", 25);
  userMap.delete("oldUser");
  console.log("User map updated");
}
// {/fact}

// Example 4: Direct mutation of a set parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(allowedRoles: Set<string>): Set<string> {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  allowedRoles.add("admin");
  allowedRoles.delete("guest");
  return allowedRoles;
}
// {/fact}

// Example 5: Direct mutation of a nested object parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(config: { server: { host: string, port: number } }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  config.server.host = "new-host.com";
  config.server.port = 8080;
  console.log(`Server configured at ${config.server.host}:${config.server.port}`);
}

// Example 6: Direct mutation of an array parameter with splice
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(items: string[]): string[] {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  items.splice(0, 1);
  items.unshift("New Item");
  return items;
}
// {/fact}

// Example 7: Direct mutation of object parameter properties in a loop
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(users: { id: number, active: boolean }[]): void {
// {/fact}

  for (const user of users) {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    user.active = false;
  }
  console.log("All users deactivated");
}

// Example 8: Direct mutation of parameter in a conditional block
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(settings: { debug: boolean, timeout: number }): void {
// {/fact}

  if (process.env.NODE_ENV === 'development') {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    settings.debug = true;
    settings.timeout = 30000;
  }
  console.log(`Debug: ${settings.debug}, Timeout: ${settings.timeout}`);
}

// Example 9: Direct mutation of parameter using destructuring assignment
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(product: { name: string, price: number }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  product.price *= 1.1; // Apply 10% price increase
  console.log(`${product.name} now costs ${product.price}`);
}

// Example 10: Direct mutation of date parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(eventDate: Date): void {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  eventDate.setDate(eventDate.getDate() + 7); // Add one week
  console.log(`Event rescheduled to ${eventDate.toISOString()}`);
}
// {/fact}

// Example 11: Direct mutation of parameter in a callback
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(options: { retries: number, timeout: number }): void {
// {/fact}

  setTimeout(() => {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    options.retries -= 1;
    if (options.retries > 0) {
      console.log(`Retrying... ${options.retries} attempts left`);
    }
  }, options.timeout);
}

// Example 12: Direct mutation of parameter in a try-catch block
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(connection: { isOpen: boolean, retries: number }): void {
// {/fact}

  try {
    if (!connection.isOpen) {
      throw new Error("Connection closed");
    }
  } catch (error) {
    // ruleid: typescript-direct-mutation-of-method-param-ts-rule
    connection.retries -= 1;
    console.log(`Connection error, ${connection.retries} retries left`);
  }
}

// Example 13: Direct mutation of parameter in a switch statement
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(task: { status: string, priority: number }): void {
// {/fact}

  switch (task.status) {
    case 'pending':
      // ruleid: typescript-direct-mutation-of-method-param-ts-rule
      task.priority += 1;
      break;
    case 'in-progress':
      // ruleid: typescript-direct-mutation-of-method-param-ts-rule
      task.priority += 2;
      break;
    default:
      // ruleid: typescript-direct-mutation-of-method-param-ts-rule
      task.priority = 0;
  }
  console.log(`Task priority set to ${task.priority}`);
}

// Example 14: Direct mutation of parameter with array methods
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(data: number[]): number {
  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  data.reverse();
  const sum = data.reduce((acc, val) => acc + val, 0);
  return sum;
}
// {/fact}

// Example 15: Direct mutation of parameter with object assign
// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(config: { [key: string]: any }): void {
// {/fact}

  // ruleid: typescript-direct-mutation-of-method-param-ts-rule
  Object.assign(config, { 
    debug: true,
    logLevel: 'verbose',
    timeout: 5000
  });
  console.log("Configuration updated:", config);
}

// True Negatives (Safe Code)

// Example 1: Creating a copy of an object parameter before modifying
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(user: { name: string, age: number }): void {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const userCopy = { ...user };
  userCopy.name = "Modified Name";
  userCopy.age += 1;
  console.log(`User is now ${userCopy.name}, ${userCopy.age} years old`);
}

// Example 2: Creating a copy of an array parameter before modifying
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(numbers: number[]): number[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const numbersCopy = [...numbers];
  numbersCopy.push(100);
  numbersCopy.sort((a, b) => a - b);
  return numbersCopy;
}
// {/fact}

// Example 3: Creating a copy of a map parameter before modifying
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(userMap: Map<string, number>): Map<string, number> {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const userMapCopy = new Map(userMap);
  userMapCopy.set("newUser", 25);
  userMapCopy.delete("oldUser");
  console.log("User map updated");
  return userMapCopy;
}
// {/fact}

// Example 4: Creating a copy of a set parameter before modifying
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(allowedRoles: Set<string>): Set<string> {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const rolesCopy = new Set(allowedRoles);
  rolesCopy.add("admin");
  rolesCopy.delete("guest");
  return rolesCopy;
}
// {/fact}

// Example 5: Deep cloning a nested object parameter before modifying
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(config: { server: { host: string, port: number } }): { server: { host: string, port: number } } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const configCopy = JSON.parse(JSON.stringify(config));
  configCopy.server.host = "new-host.com";
  configCopy.server.port = 8080;
  console.log(`Server configured at ${configCopy.server.host}:${configCopy.server.port}`);
  return configCopy;
}

// Example 6: Using array methods that return new arrays instead of modifying the original
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(items: string[]): string[] {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  return ["New Item", ...items.slice(1)];
}
// {/fact}

// Example 7: Creating new objects instead of modifying objects in an array
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(users: { id: number, active: boolean }[]): { id: number, active: boolean }[] {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  return users.map(user => ({ ...user, active: false }));
}

// Example 8: Creating a new object with modified properties in a conditional block
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(settings: { debug: boolean, timeout: number }): { debug: boolean, timeout: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  let updatedSettings = { ...settings };
  
  if (process.env.NODE_ENV === 'development') {
    updatedSettings = { ...updatedSettings, debug: true, timeout: 30000 };
  }
  
  console.log(`Debug: ${updatedSettings.debug}, Timeout: ${updatedSettings.timeout}`);
  return updatedSettings;
}

// Example 9: Creating a new object with calculated properties
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(product: { name: string, price: number }): { name: string, price: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const updatedProduct = { 
    ...product, 
    price: product.price * 1.1 // Apply 10% price increase
  };
  console.log(`${updatedProduct.name} now costs ${updatedProduct.price}`);
  return updatedProduct;
}

// Example 10: Creating a new date object instead of modifying the original
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(eventDate: Date): Date {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const newDate = new Date(eventDate);
  newDate.setDate(newDate.getDate() + 7); // Add one week
  console.log(`Event rescheduled to ${newDate.toISOString()}`);
  return newDate;
}
// {/fact}

// Example 11: Using a local variable in a callback instead of modifying the parameter
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(options: { retries: number, timeout: number }): void {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  let localRetries = options.retries;
  
  setTimeout(() => {
    localRetries -= 1;
    if (localRetries > 0) {
      console.log(`Retrying... ${localRetries} attempts left`);
    }
  }, options.timeout);
}

// Example 12: Creating a copy of the parameter in a try-catch block
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(connection: { isOpen: boolean, retries: number }): { isOpen: boolean, retries: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const connectionCopy = { ...connection };
  
  try {
    if (!connectionCopy.isOpen) {
      throw new Error("Connection closed");
    }
  } catch (error) {
    connectionCopy.retries -= 1;
    console.log(`Connection error, ${connectionCopy.retries} retries left`);
  }
  
  return connectionCopy;
}

// Example 13: Creating a new object in a switch statement
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(task: { status: string, priority: number }): { status: string, priority: number } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  let updatedTask = { ...task };
  
  switch (task.status) {
    case 'pending':
      updatedTask.priority += 1;
      break;
    case 'in-progress':
      updatedTask.priority += 2;
      break;
    default:
      updatedTask.priority = 0;
  }
  
  console.log(`Task priority set to ${updatedTask.priority}`);
  return updatedTask;
}

// Example 14: Using array methods that return new arrays
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(data: number[]): number {
  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const reversedData = [...data].reverse();
  const sum = reversedData.reduce((acc, val) => acc + val, 0);
  return sum;
}
// {/fact}

// Example 15: Creating a new object instead of using Object.assign on the parameter
// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(config: { [key: string]: any }): { [key: string]: any } {
// {/fact}

  // ok: typescript-direct-mutation-of-method-param-ts-rule
  const updatedConfig = { 
    ...config,
    debug: true,
    logLevel: 'verbose',
    timeout: 5000
  };
  
  console.log("Configuration updated:", updatedConfig);
  return updatedConfig;
}