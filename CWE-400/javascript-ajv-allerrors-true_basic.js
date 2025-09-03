// Test cases for javascript-ajv-allerrors-true rule
const Ajv = require('ajv');
const express = require('express');
const bodyParser = require('body-parser');

// BAD CASES - Setting allErrors to true

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  // Simple case with allErrors explicitly set to true
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string", minLength: 2 },
      age: { type: "number", minimum: 18 }
    },
    required: ["name", "age"]
  };
  
  const validate = ajv.compile(schema);
  return validate;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  // Using allErrors: true in an Express API endpoint
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/validate-user', (req, res) => {
    // ruleid: javascript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    
    const userSchema = {
      type: "object",
      properties: {
        username: { type: "string", pattern: "^[a-zA-Z0-9]{3,20}$" },
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 }
      },
      required: ["username", "email", "password"]
    };
    
    const validate = ajv.compile(userSchema);
    const valid = validate(req.body);
    
    if (!valid) {
      return res.status(400).json({ errors: validate.errors });
    }
    
    return res.status(200).json({ message: "User data is valid" });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
  // Using allErrors with other options
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: true,
    removeAdditional: true,
    useDefaults: true,
    coerceTypes: true
  });
  
  const schema = {
    type: "object",
    properties: {
      items: {
        type: "array",
        items: { type: "string" },
        minItems: 1
      }
    },
    required: ["items"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  // Using allErrors with variable but still set to true
  const options = {
    allErrors: true,
    verbose: true
  };
  
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      data: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string" }
          },
          required: ["id", "name"]
        }
      }
    },
    required: ["data"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  // Using allErrors in a function that processes form data
  function processForm(formData) {
    // ruleid: javascript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    
    const formSchema = {
      type: "object",
      properties: {
        firstName: { type: "string" },
        lastName: { type: "string" },
        email: { type: "string", format: "email" },
        age: { type: "number", minimum: 18 }
      },
      required: ["firstName", "lastName", "email", "age"]
    };
    
    const validate = ajv.compile(formSchema);
    return validate(formData);
  }
  
  return processForm;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  // Using allErrors in a class constructor
  class SchemaValidator {
    constructor() {
      // ruleid: javascript-ajv-allerrors-true
      this.ajv = new Ajv({ allErrors: true });
      
      this.schema = {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          createdAt: { type: "string", format: "date-time" },
          data: { type: "object" }
        },
        required: ["id", "createdAt", "data"]
      };
      
      this.validate = this.ajv.compile(this.schema);
    }
    
    isValid(data) {
      return this.validate(data);
    }
  }
  
  return new SchemaValidator();
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  // Using allErrors with async validation
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const schema = {
    type: "object",
    properties: {
      id: { type: "string" },
      email: { type: "string", format: "email" }
    },
    required: ["id", "email"]
  };
  
  async function validateData(data) {
    const validate = ajv.compile(schema);
    const valid = validate(data);
    if (!valid) {
      throw new Error("Validation failed: " + JSON.stringify(validate.errors));
    }
    return data;
  }
  
  return validateData;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  // Using allErrors with conditional logic but still set to true
  const enableAllErrors = true;
  
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: enableAllErrors,
    strict: false
  });
  
  const schema = {
    type: "object",
    properties: {
      username: { type: "string", minLength: 3 },
      password: { type: "string", minLength: 8 }
    },
    required: ["username", "password"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  // Using allErrors in a factory function
  function createValidator(schema) {
    // ruleid: javascript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    return ajv.compile(schema);
  }
  
  const userSchema = {
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" }
    },
    required: ["name", "age"]
  };
  
  return createValidator(userSchema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  // Using allErrors with a complex nested schema
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const schema = {
    type: "object",
    properties: {
      user: {
        type: "object",
        properties: {
          profile: {
            type: "object",
            properties: {
              name: { type: "string" },
              address: {
                type: "object",
                properties: {
                  street: { type: "string" },
                  city: { type: "string" },
                  zipCode: { type: "string", pattern: "^\\d{5}$" }
                },
                required: ["street", "city", "zipCode"]
              }
            },
            required: ["name", "address"]
          }
        },
        required: ["profile"]
      }
    },
    required: ["user"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  // Using allErrors with custom error messages
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: true,
    messages: true
  });
  
  // Add custom error messages
  ajv.addFormat("email", {
    validate: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
    compare: () => 0
  });
  
  const schema = {
    type: "object",
    properties: {
      email: { type: "string", format: "email" }
    },
    required: ["email"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  // Using allErrors with a schema that has many potential validation points
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const schema = {
    type: "object",
    properties: {
      items: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string", minLength: 3 },
            price: { type: "number", minimum: 0 },
            tags: {
              type: "array",
              items: { type: "string" },
              minItems: 1
            }
          },
          required: ["id", "name", "price", "tags"]
        },
        minItems: 1
      },
      customer: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          email: { type: "string", format: "email" }
        },
        required: ["id", "name", "email"]
      }
    },
    required: ["items", "customer"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  // Using allErrors with dynamic schema generation
  function generateSchema(fields) {
    const properties = {};
    const required = [];
    
    fields.forEach(field => {
      properties[field.name] = { type: field.type };
      if (field.required) {
        required.push(field.name);
      }
    });
    
    return {
      type: "object",
      properties,
      required
    };
  }
  
  const fields = [
    { name: "username", type: "string", required: true },
    { name: "email", type: "string", required: true },
    { name: "age", type: "number", required: false }
  ];
  
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  const schema = generateSchema(fields);
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  // Using allErrors with schema references
  // ruleid: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const addressSchema = {
    $id: "http://example.com/schemas/address",
    type: "object",
    properties: {
      street: { type: "string" },
      city: { type: "string" },
      state: { type: "string", pattern: "^[A-Z]{2}$" },
      zipCode: { type: "string", pattern: "^\\d{5}$" }
    },
    required: ["street", "city", "state", "zipCode"]
  };
  
  const userSchema = {
    $id: "http://example.com/schemas/user",
    type: "object",
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      address: { $ref: "http://example.com/schemas/address" }
    },
    required: ["name", "email", "address"]
  };
  
  ajv.addSchema(addressSchema);
  return ajv.compile(userSchema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  // Using allErrors in an Express middleware
  function validationMiddleware(schema) {
    // ruleid: javascript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    const validate = ajv.compile(schema);
    
    return (req, res, next) => {
      const valid = validate(req.body);
      if (!valid) {
        return res.status(400).json({ errors: validate.errors });
      }
      next();
    };
  }
  
  const app = express();
  app.use(bodyParser.json());
  
  const userSchema = {
    type: "object",
    properties: {
      username: { type: "string", minLength: 3 },
      password: { type: "string", minLength: 8 }
    },
    required: ["username", "password"]
  };
  
  app.post('/register', validationMiddleware(userSchema), (req, res) => {
    res.status(201).json({ message: "User registered successfully" });
  });
  
  return app;
}
// {/fact}

// GOOD CASES - Setting allErrors to false or not setting it at all

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  // Simple case with allErrors explicitly set to false
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: false });
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string", minLength: 2 },
      age: { type: "number", minimum: 18 }
    },
    required: ["name", "age"]
  };
  
  const validate = ajv.compile(schema);
  return validate;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
  // Using default settings (allErrors is false by default)
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv();
  
  const schema = {
    type: "object",
    properties: {
      username: { type: "string", pattern: "^[a-zA-Z0-9]{3,20}$" },
      email: { type: "string", format: "email" },
      password: { type: "string", minLength: 8 }
    },
    required: ["username", "email", "password"]
  };
  
  const validate = ajv.compile(schema);
  return validate;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  // Using other options but not allErrors
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    removeAdditional: true,
    useDefaults: true,
    coerceTypes: true
  });
  
  const schema = {
    type: "object",
    properties: {
      items: {
        type: "array",
        items: { type: "string" },
        minItems: 1
      }
    },
    required: ["items"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  // Using allErrors with variable set to false
  const options = {
    allErrors: false,
    verbose: true
  };
  
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      data: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string" }
          },
          required: ["id", "name"]
        }
      }
    },
    required: ["data"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  // Using a safe approach in a function that processes form data
  function processForm(formData) {
    // ok: javascript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: false });
    
    const formSchema = {
      type: "object",
      properties: {
        firstName: { type: "string" },
        lastName: { type: "string" },
        email: { type: "string", format: "email" },
        age: { type: "number", minimum: 18 }
      },
      required: ["firstName", "lastName", "email", "age"]
    };
    
    const validate = ajv.compile(formSchema);
    return validate(formData);
  }
  
  return processForm;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  // Using safe configuration in a class constructor
  class SchemaValidator {
    constructor() {
      // ok: javascript-ajv-allerrors-true
      this.ajv = new Ajv();
      
      this.schema = {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          createdAt: { type: "string", format: "date-time" },
          data: { type: "object" }
        },
        required: ["id", "createdAt", "data"]
      };
      
      this.validate = this.ajv.compile(this.schema);
    }
    
    isValid(data) {
      return this.validate(data);
    }
  }
  
  return new SchemaValidator();
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  // Using safe configuration with async validation
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: false });
  
  const schema = {
    type: "object",
    properties: {
      id: { type: "string" },
      email: { type: "string", format: "email" }
    },
    required: ["id", "email"]
  };
  
  async function validateData(data) {
    const validate = ajv.compile(schema);
    const valid = validate(data);
    if (!valid) {
      throw new Error("Validation failed: " + JSON.stringify(validate.errors));
    }
    return data;
  }
  
  return validateData;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  // Using conditional logic to set allErrors to false
  const enableAllErrors = false;
  
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: enableAllErrors,
    strict: false
  });
  
  const schema = {
    type: "object",
    properties: {
      username: { type: "string", minLength: 3 },
      password: { type: "string", minLength: 8 }
    },
    required: ["username", "password"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  // Using safe configuration in a factory function
  function createValidator(schema) {
    // ok: javascript-ajv-allerrors-true
    const ajv = new Ajv();
    return ajv.compile(schema);
  }
  
  const userSchema = {
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" }
    },
    required: ["name", "age"]
  };
  
  return createValidator(userSchema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  // Using safe configuration with a complex nested schema
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: false });
  
  const schema = {
    type: "object",
    properties: {
      user: {
        type: "object",
        properties: {
          profile: {
            type: "object",
            properties: {
              name: { type: "string" },
              address: {
                type: "object",
                properties: {
                  street: { type: "string" },
                  city: { type: "string" },
                  zipCode: { type: "string", pattern: "^\\d{5}$" }
                },
                required: ["street", "city", "zipCode"]
              }
            },
            required: ["name", "address"]
          }
        },
        required: ["profile"]
      }
    },
    required: ["user"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  // Using safe configuration with custom error handling
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: false,
    messages: true
  });
  
  // Add custom error messages
  ajv.addFormat("email", {
    validate: (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
    compare: () => 0
  });
  
  const schema = {
    type: "object",
    properties: {
      email: { type: "string", format: "email" }
    },
    required: ["email"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  // Using safe configuration with a schema that has many potential validation points
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv();
  
  const schema = {
    type: "object",
    properties: {
      items: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string", minLength: 3 },
            price: { type: "number", minimum: 0 },
            tags: {
              type: "array",
              items: { type: "string" },
              minItems: 1
            }
          },
          required: ["id", "name", "price", "tags"]
        },
        minItems: 1
      },
      customer: {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
          email: { type: "string", format: "email" }
        },
        required: ["id", "name", "email"]
      }
    },
    required: ["items", "customer"]
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  // Using safe configuration with dynamic schema generation
  function generateSchema(fields) {
    const properties = {};
    const required = [];
    
    fields.forEach(field => {
      properties[field.name] = { type: field.type };
      if (field.required) {
        required.push(field.name);
      }
    });
    
    return {
      type: "object",
      properties,
      required
    };
  }
  
  const fields = [
    { name: "username", type: "string", required: true },
    { name: "email", type: "string", required: true },
    { name: "age", type: "number", required: false }
  ];
  
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv();
  const schema = generateSchema(fields);
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  // Using safe configuration with schema references
  // ok: javascript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: false });
  
  const addressSchema = {
    $id: "http://example.com/schemas/address",
    type: "object",
    properties: {
      street: { type: "string" },
      city: { type: "string" },
      state: { type: "string", pattern: "^[A-Z]{2}$" },
      zipCode: { type: "string", pattern: "^\\d{5}$" }
    },
    required: ["street", "city", "state", "zipCode"]
  };
  
  const userSchema = {
    $id: "http://example.com/schemas/user",
    type: "object",
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      address: { $ref: "http://example.com/schemas/address" }
    },
    required: ["name", "email", "address"]
  };
  
  ajv.addSchema(addressSchema);
  return ajv.compile(userSchema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  // Using safe configuration in an Express middleware
  function validationMiddleware(schema) {
    // ok: javascript-ajv-allerrors-true
    const ajv = new Ajv();
    const validate = ajv.compile(schema);
    
    return (req, res, next) => {
      const valid = validate(req.body);
      if (!valid) {
        return res.status(400).json({ error: validate.errors[0] });
      }
      next();
    };
  }
  
  const app = express();
  app.use(bodyParser.json());
  
  const userSchema = {
    type: "object",
    properties: {
      username: { type: "string", minLength: 3 },
      password: { type: "string", minLength: 8 }
    },
    required: ["username", "password"]
  };
  
  app.post('/register', validationMiddleware(userSchema), (req, res) => {
    res.status(201).json({ message: "User registered successfully" });
  });
  
  return app;
}
// {/fact}