// File: object_reference_mutation_examples.ts

// True Positive Examples (Vulnerable Code)

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_1() {
  const originalUser = { name: "John", settings: { theme: "dark", notifications: true } };
  const userCopy = originalUser; // Direct reference assignment
  
  // ruleid: typescript-avoid-reference-mutation
  userCopy.settings.theme = "light"; // This also modifies originalUser.settings.theme
  
  console.log("Original user theme:", originalUser.settings.theme); // Will output "light"
  console.log("User copy theme:", userCopy.settings.theme); // Will output "light"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_2() {
  const originalConfig = { server: { port: 3000, host: "localhost" } };
  const configBackup = originalConfig;
  
  // ruleid: typescript-avoid-reference-mutation
  configBackup.server.port = 8080; // This also changes originalConfig.server.port
  
  return { original: originalConfig, backup: configBackup };
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_3() {
  const products = [
    { id: 1, name: "Laptop", price: 999 },
    { id: 2, name: "Phone", price: 699 }
  ];
  
  const productsCopy = products;
  
  // ruleid: typescript-avoid-reference-mutation
  productsCopy[0].price = 899; // This also changes products[0].price
  
  return { original: products, copy: productsCopy };
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_4() {
  interface UserProfile {
    id: number;
    preferences: {
      language: string;
      timezone: string;
    };
  }
  
  const profile: UserProfile = {
    id: 123,
    preferences: {
      language: "en",
      timezone: "UTC"
    }
  };
  
  function updateLanguage(userProfile: UserProfile, newLanguage: string) {
    // ruleid: typescript-avoid-reference-mutation
    userProfile.preferences.language = newLanguage; // Directly modifies the original object
    return userProfile;
  }
  
  const updatedProfile = updateLanguage(profile, "es");
  console.log(profile.preferences.language); // Will output "es"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_5() {
  const appState = {
    user: {
      loggedIn: false,
      lastLogin: null
    },
    data: []
  };
  
  function login(state: typeof appState) {
    // ruleid: typescript-avoid-reference-mutation
    state.user.loggedIn = true;
    state.user.lastLogin = new Date();
    return state;
  }
  
  const newState = login(appState);
  console.log(appState === newState); // Will output true
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_6() {
  const serverConfig = {
    database: {
      host: "localhost",
      port: 5432,
      credentials: {
        username: "admin",
        password: "password123"
      }
    }
  };
  
  function updateCredentials(config: typeof serverConfig) {
    // ruleid: typescript-avoid-reference-mutation
    config.database.credentials.username = "newadmin";
    config.database.credentials.password = "newpassword";
    return config;
  }
  
  const updatedConfig = updateCredentials(serverConfig);
  console.log(serverConfig.database.credentials.username); // Will output "newadmin"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_7() {
  class ShoppingCart {
    items: { id: number; quantity: number }[];
    
    constructor() {
      this.items = [];
    }
    
    updateQuantity(cart: ShoppingCart, itemId: number, newQuantity: number) {
      const item = cart.items.find(i => i.id === itemId);
      if (item) {
        // ruleid: typescript-avoid-reference-mutation
        item.quantity = newQuantity; // Directly modifies the original object
      }
      return cart;
    }
  }
  
  const cart = new ShoppingCart();
  cart.items.push({ id: 1, quantity: 2 });
  
  const updatedCart = cart.updateQuantity(cart, 1, 5);
  console.log(cart.items[0].quantity); // Will output 5
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_8() {
  const teamMembers = [
    { id: 1, name: "Alice", roles: ["developer", "tester"] },
    { id: 2, name: "Bob", roles: ["designer"] }
  ];
  
  function addRole(members: typeof teamMembers, memberId: number, newRole: string) {
    const member = members.find(m => m.id === memberId);
    if (member) {
      // ruleid: typescript-avoid-reference-mutation
      member.roles.push(newRole); // Directly modifies the original array
    }
    return members;
  }
  
  const updatedMembers = addRole(teamMembers, 2, "manager");
  console.log(teamMembers[1].roles); // Will output ["designer", "manager"]
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_9() {
  interface TreeNode {
    value: number;
    children: TreeNode[];
  }
  
  const tree: TreeNode = {
    value: 1,
    children: [
      { value: 2, children: [] },
      { value: 3, children: [] }
    ]
  };
  
  function addChild(node: TreeNode, parentValue: number, childValue: number) {
    if (node.value === parentValue) {
      // ruleid: typescript-avoid-reference-mutation
      node.children.push({ value: childValue, children: [] });
      return true;
    }
    
    for (const child of node.children) {
      if (addChild(child, parentValue, childValue)) {
        return true;
      }
    }
    
    return false;
  }
  
  addChild(tree, 2, 4);
  console.log(tree.children[0].children); // Will contain the new node
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_10() {
  const apiResponse = {
    data: {
      items: [
        { id: "a1", status: "pending" },
        { id: "a2", status: "completed" }
      ],
      metadata: {
        total: 2,
        page: 1
      }
    }
  };
  
  function processResponse(response: typeof apiResponse) {
    // ruleid: typescript-avoid-reference-mutation
    response.data.items.forEach(item => {
      if (item.status === "pending") {
        item.status = "processing"; // Directly modifies objects in the original array
      }
    });
    
    return response;
  }
  
  const processed = processResponse(apiResponse);
  console.log(apiResponse.data.items[0].status); // Will output "processing"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_11() {
  const formData = {
    personal: {
      name: "",
      email: "",
      phone: ""
    },
    address: {
      street: "",
      city: "",
      zipCode: ""
    }
  };
  
  function handleNameChange(data: typeof formData, newName: string) {
    // ruleid: typescript-avoid-reference-mutation
    data.personal.name = newName; // Directly modifies the original object
    return data;
  }
  
  const updatedForm = handleNameChange(formData, "John Doe");
  console.log(formData.personal.name); // Will output "John Doe"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_12() {
  interface MenuItem {
    id: string;
    name: string;
    price: number;
    options?: {
      size?: string;
      extras?: string[];
    };
  }
  
  const menu: MenuItem[] = [
    { id: "item1", name: "Coffee", price: 2.5, options: { size: "medium" } },
    { id: "item2", name: "Tea", price: 2.0 }
  ];
  
  function addExtraToItem(items: MenuItem[], itemId: string, extra: string) {
    const item = items.find(i => i.id === itemId);
    if (item && item.options) {
      if (!item.options.extras) {
        // ruleid: typescript-avoid-reference-mutation
        item.options.extras = []; // Creates a new property on the original object
      }
      // ruleid: typescript-avoid-reference-mutation
      item.options.extras.push(extra); // Modifies the original object
    }
    return items;
  }
  
  const updatedMenu = addExtraToItem(menu, "item1", "sugar");
  console.log(menu[0].options?.extras); // Will output ["sugar"]
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_13() {
  const gameState = {
    player: {
      position: { x: 0, y: 0 },
      health: 100,
      inventory: ["sword", "potion"]
    },
    enemies: [
      { id: "e1", position: { x: 10, y: 10 }, health: 50 }
    ]
  };
  
  function movePlayer(state: typeof gameState, dx: number, dy: number) {
    // ruleid: typescript-avoid-reference-mutation
    state.player.position.x += dx;
    // ruleid: typescript-avoid-reference-mutation
    state.player.position.y += dy;
    return state;
  }
  
  const newState = movePlayer(gameState, 5, 3);
  console.log(gameState.player.position); // Will output { x: 5, y: 3 }
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_14() {
  interface Document {
    id: string;
    content: string;
    metadata: {
      author: string;
      tags: string[];
      lastModified: Date;
    };
  }
  
  const document: Document = {
    id: "doc1",
    content: "Hello world",
    metadata: {
      author: "Alice",
      tags: ["draft"],
      lastModified: new Date("2023-01-01")
    }
  };
  
  function updateDocument(doc: Document, newContent: string) {
    // ruleid: typescript-avoid-reference-mutation
    doc.content = newContent;
    // ruleid: typescript-avoid-reference-mutation
    doc.metadata.lastModified = new Date();
    return doc;
  }
  
  const updatedDoc = updateDocument(document, "Updated content");
  console.log(document.content); // Will output "Updated content"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_15() {
  const permissions = {
    roles: {
      admin: {
        canCreate: true,
        canEdit: true,
        canDelete: true
      },
      user: {
        canCreate: true,
        canEdit: false,
        canDelete: false
      }
    }
  };
  
  function updateRolePermissions(perms: typeof permissions, role: string, permission: string, value: boolean) {
    if (role in perms.roles && permission in perms.roles[role as keyof typeof perms.roles]) {
      // ruleid: typescript-avoid-reference-mutation
      (perms.roles[role as keyof typeof perms.roles] as any)[permission] = value;
    }
    return perms;
  }
  
  const updatedPermissions = updateRolePermissions(permissions, "user", "canEdit", true);
  console.log(permissions.roles.user.canEdit); // Will output true
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_1() {
  const originalUser = { name: "John", settings: { theme: "dark", notifications: true } };
  
  // ok: typescript-avoid-reference-mutation
  const userCopy = { 
    ...originalUser, 
    settings: { ...originalUser.settings } 
  };
  
  userCopy.settings.theme = "light"; // This only modifies userCopy, not originalUser
  
  console.log("Original user theme:", originalUser.settings.theme); // Will output "dark"
  console.log("User copy theme:", userCopy.settings.theme); // Will output "light"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_2() {
  const originalConfig = { server: { port: 3000, host: "localhost" } };
  
  // ok: typescript-avoid-reference-mutation
  const configBackup = JSON.parse(JSON.stringify(originalConfig)); // Deep copy
  
  configBackup.server.port = 8080; // This only changes configBackup, not originalConfig
  
  return { original: originalConfig, backup: configBackup };
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_3() {
  const products = [
    { id: 1, name: "Laptop", price: 999 },
    { id: 2, name: "Phone", price: 699 }
  ];
  
  // ok: typescript-avoid-reference-mutation
  const productsCopy = products.map(product => ({ ...product }));
  
  productsCopy[0].price = 899; // This only changes productsCopy, not products
  
  return { original: products, copy: productsCopy };
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_4() {
  interface UserProfile {
    id: number;
    preferences: {
      language: string;
      timezone: string;
    };
  }
  
  const profile: UserProfile = {
    id: 123,
    preferences: {
      language: "en",
      timezone: "UTC"
    }
  };
  
  function updateLanguage(userProfile: UserProfile, newLanguage: string): UserProfile {
    // ok: typescript-avoid-reference-mutation
    return {
      ...userProfile,
      preferences: {
        ...userProfile.preferences,
        language: newLanguage
      }
    };
  }
  
  const updatedProfile = updateLanguage(profile, "es");
  console.log(profile.preferences.language); // Will output "en"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_5() {
  const appState = {
    user: {
      loggedIn: false,
      lastLogin: null as Date | null
    },
    data: []
  };
  
  function login(state: typeof appState) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...state,
      user: {
        ...state.user,
        loggedIn: true,
        lastLogin: new Date()
      }
    };
  }
  
  const newState = login(appState);
  console.log(appState === newState); // Will output false
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_6() {
  const serverConfig = {
    database: {
      host: "localhost",
      port: 5432,
      credentials: {
        username: "admin",
        password: "password123"
      }
    }
  };
  
  function updateCredentials(config: typeof serverConfig) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...config,
      database: {
        ...config.database,
        credentials: {
          username: "newadmin",
          password: "newpassword"
        }
      }
    };
  }
  
  const updatedConfig = updateCredentials(serverConfig);
  console.log(serverConfig.database.credentials.username); // Will still output "admin"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_7() {
  class ShoppingCart {
    items: { id: number; quantity: number }[];
    
    constructor() {
      this.items = [];
    }
    
    updateQuantity(cart: ShoppingCart, itemId: number, newQuantity: number) {
      // ok: typescript-avoid-reference-mutation
      const newCart = new ShoppingCart();
      newCart.items = cart.items.map(item => 
        item.id === itemId 
          ? { ...item, quantity: newQuantity }
          : { ...item }
      );
      return newCart;
    }
  }
  
  const cart = new ShoppingCart();
  cart.items.push({ id: 1, quantity: 2 });
  
  const updatedCart = cart.updateQuantity(cart, 1, 5);
  console.log(cart.items[0].quantity); // Will still output 2
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_8() {
  const teamMembers = [
    { id: 1, name: "Alice", roles: ["developer", "tester"] },
    { id: 2, name: "Bob", roles: ["designer"] }
  ];
  
  function addRole(members: typeof teamMembers, memberId: number, newRole: string) {
    // ok: typescript-avoid-reference-mutation
    return members.map(member => {
      if (member.id === memberId) {
        return {
          ...member,
          roles: [...member.roles, newRole]
        };
      }
      return { ...member };
    });
  }
  
  const updatedMembers = addRole(teamMembers, 2, "manager");
  console.log(teamMembers[1].roles); // Will still output ["designer"]
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_9() {
  interface TreeNode {
    value: number;
    children: TreeNode[];
  }
  
  const tree: TreeNode = {
    value: 1,
    children: [
      { value: 2, children: [] },
      { value: 3, children: [] }
    ]
  };
  
  function addChild(node: TreeNode, parentValue: number, childValue: number): TreeNode {
    if (node.value === parentValue) {
      // ok: typescript-avoid-reference-mutation
      return {
        ...node,
        children: [...node.children, { value: childValue, children: [] }]
      };
    }
    
    // ok: typescript-avoid-reference-mutation
    return {
      ...node,
      children: node.children.map(child => addChild(child, parentValue, childValue))
    };
  }
  
  const newTree = addChild(tree, 2, 4);
  console.log(tree.children[0].children.length); // Will still be 0
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_10() {
  const apiResponse = {
    data: {
      items: [
        { id: "a1", status: "pending" },
        { id: "a2", status: "completed" }
      ],
      metadata: {
        total: 2,
        page: 1
      }
    }
  };
  
  function processResponse(response: typeof apiResponse) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...response,
      data: {
        ...response.data,
        items: response.data.items.map(item => {
          if (item.status === "pending") {
            return { ...item, status: "processing" };
          }
          return { ...item };
        })
      }
    };
  }
  
  const processed = processResponse(apiResponse);
  console.log(apiResponse.data.items[0].status); // Will still output "pending"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_11() {
  const formData = {
    personal: {
      name: "",
      email: "",
      phone: ""
    },
    address: {
      street: "",
      city: "",
      zipCode: ""
    }
  };
  
  function handleNameChange(data: typeof formData, newName: string) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...data,
      personal: {
        ...data.personal,
        name: newName
      }
    };
  }
  
  const updatedForm = handleNameChange(formData, "John Doe");
  console.log(formData.personal.name); // Will still output ""
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_12() {
  interface MenuItem {
    id: string;
    name: string;
    price: number;
    options?: {
      size?: string;
      extras?: string[];
    };
  }
  
  const menu: MenuItem[] = [
    { id: "item1", name: "Coffee", price: 2.5, options: { size: "medium" } },
    { id: "item2", name: "Tea", price: 2.0 }
  ];
  
  function addExtraToItem(items: MenuItem[], itemId: string, extra: string) {
    // ok: typescript-avoid-reference-mutation
    return items.map(item => {
      if (item.id === itemId && item.options) {
        return {
          ...item,
          options: {
            ...item.options,
            extras: item.options.extras ? [...item.options.extras, extra] : [extra]
          }
        };
      }
      return { ...item };
    });
  }
  
  const updatedMenu = addExtraToItem(menu, "item1", "sugar");
  console.log(menu[0].options?.extras); // Will output undefined
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_13() {
  const gameState = {
    player: {
      position: { x: 0, y: 0 },
      health: 100,
      inventory: ["sword", "potion"]
    },
    enemies: [
      { id: "e1", position: { x: 10, y: 10 }, health: 50 }
    ]
  };
  
  function movePlayer(state: typeof gameState, dx: number, dy: number) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...state,
      player: {
        ...state.player,
        position: {
          x: state.player.position.x + dx,
          y: state.player.position.y + dy
        }
      }
    };
  }
  
  const newState = movePlayer(gameState, 5, 3);
  console.log(gameState.player.position); // Will still output { x: 0, y: 0 }
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_14() {
  interface Document {
    id: string;
    content: string;
    metadata: {
      author: string;
      tags: string[];
      lastModified: Date;
    };
  }
  
  const document: Document = {
    id: "doc1",
    content: "Hello world",
    metadata: {
      author: "Alice",
      tags: ["draft"],
      lastModified: new Date("2023-01-01")
    }
  };
  
  function updateDocument(doc: Document, newContent: string) {
    // ok: typescript-avoid-reference-mutation
    return {
      ...doc,
      content: newContent,
      metadata: {
        ...doc.metadata,
        lastModified: new Date()
      }
    };
  }
  
  const updatedDoc = updateDocument(document, "Updated content");
  console.log(document.content); // Will still output "Hello world"
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_15() {
  const permissions = {
    roles: {
      admin: {
        canCreate: true,
        canEdit: true,
        canDelete: true
      },
      user: {
        canCreate: true,
        canEdit: false,
        canDelete: false
      }
    }
  };
  
  function updateRolePermissions(perms: typeof permissions, role: string, permission: string, value: boolean) {
    // ok: typescript-avoid-reference-mutation
    if (role === "admin" || role === "user") {
      return {
        ...perms,
        roles: {
          ...perms.roles,
          [role]: {
            ...perms.roles[role as keyof typeof perms.roles],
            [permission]: value
          }
        }
      };
    }
    return { ...perms };
  }
  
  const updatedPermissions = updateRolePermissions(permissions, "user", "canEdit", true);
  console.log(permissions.roles.user.canEdit); // Will still output false
}
// {/fact}