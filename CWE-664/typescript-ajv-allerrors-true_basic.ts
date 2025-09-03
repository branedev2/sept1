// File: ajv_test_cases.ts
import Ajv from 'ajv';
import express from 'express';
import bodyParser from 'body-parser';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
  // Basic case with allErrors set to true
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true });
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" }
    },
    required: ["name", "age"]
  };
  
  const validate = ajv.compile(schema);
  return validate;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
  // Using allErrors with express API endpoint
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/validate-user', (req: Request, res: Response) => {
    // ruleid: typescript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    
    const schema = {
      type: "object",
      properties: {
        username: { type: "string", minLength: 3 },
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 }
      },
      required: ["username", "email", "password"]
    };
    
    const validate = ajv.compile(schema);
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
  // Using allErrors with additional options
  // ruleid: typescript-ajv-allerrors-true
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
        items: { type: "string" }
      }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
  // Using allErrors in a function that processes user input
  return function processUserData(userData: any) {
    // ruleid: typescript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    
    const schema = {
      type: "object",
      properties: {
        users: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "number" },
              name: { type: "string" }
            },
            required: ["id", "name"]
          }
        }
      },
      required: ["users"]
    };
    
    const validate = ajv.compile(schema);
    return validate(userData);
  };
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
  // Using allErrors with a complex schema
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: true, verbose: true });
  
  const addressSchema = {
    type: "object",
    properties: {
      street: { type: "string" },
      city: { type: "string" },
      state: { type: "string" },
      zipCode: { type: "string", pattern: "^\\d{5}(-\\d{4})?$" }
    },
    required: ["street", "city", "state", "zipCode"]
  };
  
  const userSchema = {
    type: "object",
    properties: {
      name: { type: "string" },
      email: { type: "string", format: "email" },
      address: addressSchema
    },
    required: ["name", "email", "address"]
  };
  
  return ajv.compile(userSchema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
  // Using allErrors with boolean literal true
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: true as boolean
  });
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
  // Using allErrors with variable set to true
  const options = {
    allErrors: true
  };
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      id: { type: "number" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
  // Using allErrors in an API validation middleware
  const app = express();
  app.use(bodyParser.json());
  
  function validateMiddleware(schema: object) {
    // ruleid: typescript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: true });
    const validate = ajv.compile(schema);
    
    return (req: Request, res: Response, next: Function) => {
      const valid = validate(req.body);
      if (!valid) {
        return res.status(400).json({ errors: validate.errors });
      }
      next();
    };
  }
  
  const userSchema = {
    type: "object",
    properties: {
      username: { type: "string" }
    },
    required: ["username"]
  };
  
  app.post('/users', validateMiddleware(userSchema), (req, res) => {
    res.status(201).json({ message: "User created" });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
  // Using allErrors with conditional initialization
  const isProduction = process.env.NODE_ENV === 'production';
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: !isProduction ? false : true
  });
  
  const schema = {
    type: "object",
    properties: {
      data: { type: "string" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
  // Using allErrors with destructured options
  const options = { allErrors: true, useDefaults: true };
  const { allErrors, useDefaults } = options;
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors, useDefaults });
  
  const schema = {
    type: "object",
    properties: {
      config: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
  // Using allErrors with a factory function
  function createAjvInstance(options = {}) {
    // ruleid: typescript-ajv-allerrors-true
    return new Ajv({ allErrors: true, ...options });
  }
  
  const ajv = createAjvInstance({ useDefaults: true });
  
  const schema = {
    type: "object",
    properties: {
      items: { type: "array" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
  // Using allErrors with a class
  class SchemaValidator {
    private ajv: any;
    
    constructor() {
      // ruleid: typescript-ajv-allerrors-true
      this.ajv = new Ajv({ allErrors: true });
    }
    
    validate(data: any, schema: object) {
      const validate = this.ajv.compile(schema);
      return validate(data);
    }
  }
  
  const validator = new SchemaValidator();
  return validator;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
  // Using allErrors with a ternary operator
  const debugMode = true;
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: debugMode ? true : false
  });
  
  const schema = {
    type: "object",
    properties: {
      settings: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
  // Using allErrors with object spread
  const baseOptions = { useDefaults: true, coerceTypes: true };
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    ...baseOptions,
    allErrors: true
  });
  
  const schema = {
    type: "object",
    properties: {
      metadata: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
  // Using allErrors with logical OR assignment
  let options: any = { useDefaults: true };
  options.allErrors ||= true;
  
  // ruleid: typescript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      tags: { type: "array" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
  // Basic case with allErrors set to false
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors: false });
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string" },
      age: { type: "number" }
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
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv();
  
  const schema = {
    type: "object",
    properties: {
      username: { type: "string" },
      email: { type: "string" }
    },
    required: ["username", "email"]
  };
  
  const validate = ajv.compile(schema);
  return validate;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
  // Using allErrors explicitly set to false with other options
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: false,
    removeAdditional: true,
    useDefaults: true,
    coerceTypes: true
  });
  
  const schema = {
    type: "object",
    properties: {
      items: {
        type: "array",
        items: { type: "string" }
      }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
  // Using express with safe Ajv configuration
  const app = express();
  app.use(bodyParser.json());
  
  app.post('/validate-user', (req: Request, res: Response) => {
    // ok: typescript-ajv-allerrors-true
    const ajv = new Ajv({ allErrors: false });
    
    const schema = {
      type: "object",
      properties: {
        username: { type: "string", minLength: 3 },
        email: { type: "string", format: "email" },
        password: { type: "string", minLength: 8 }
      },
      required: ["username", "email", "password"]
    };
    
    const validate = ajv.compile(schema);
    const valid = validate(req.body);
    
    if (!valid) {
      return res.status(400).json({ error: validate.errors?.[0] });
    }
    
    return res.status(200).json({ message: "User data is valid" });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
  // Using a variable set to false for allErrors
  const options = {
    allErrors: false
  };
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      id: { type: "number" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
  // Using environment-based configuration safely
  const isProduction = process.env.NODE_ENV === 'production';
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: false
  });
  
  const schema = {
    type: "object",
    properties: {
      data: { type: "string" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
  // Using a factory function with safe defaults
  function createAjvInstance(options = {}) {
    // ok: typescript-ajv-allerrors-true
    return new Ajv({ allErrors: false, ...options });
  }
  
  const ajv = createAjvInstance({ useDefaults: true });
  
  const schema = {
    type: "object",
    properties: {
      items: { type: "array" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
  // Using a class with safe configuration
  class SchemaValidator {
    private ajv: any;
    
    constructor() {
      // ok: typescript-ajv-allerrors-true
      this.ajv = new Ajv({ allErrors: false });
    }
    
    validate(data: any, schema: object) {
      const validate = this.ajv.compile(schema);
      return validate(data);
    }
  }
  
  const validator = new SchemaValidator();
  return validator;
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
  // Using a validation middleware with safe configuration
  const app = express();
  app.use(bodyParser.json());
  
  function validateMiddleware(schema: object) {
    // ok: typescript-ajv-allerrors-true
    const ajv = new Ajv();  // Default is allErrors: false
    const validate = ajv.compile(schema);
    
    return (req: Request, res: Response, next: Function) => {
      const valid = validate(req.body);
      if (!valid) {
        return res.status(400).json({ error: validate.errors?.[0] });
      }
      next();
    };
  }
  
  const userSchema = {
    type: "object",
    properties: {
      username: { type: "string" }
    },
    required: ["username"]
  };
  
  app.post('/users', validateMiddleware(userSchema), (req, res) => {
    res.status(201).json({ message: "User created" });
  });
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
  // Using object spread with safe configuration
  const baseOptions = { useDefaults: true, coerceTypes: true };
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    ...baseOptions,
    allErrors: false
  });
  
  const schema = {
    type: "object",
    properties: {
      metadata: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
  // Using conditional initialization safely
  const debugMode = true;
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({
    allErrors: false
  });
  
  const schema = {
    type: "object",
    properties: {
      settings: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
  // Using destructured options safely
  const options = { allErrors: false, useDefaults: true };
  const { allErrors, useDefaults } = options;
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv({ allErrors, useDefaults });
  
  const schema = {
    type: "object",
    properties: {
      config: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
  // Using a different validator approach
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv();
  
  // Custom validation function that limits error reporting
  function validateWithLimitedErrors(schema: object, data: any) {
    const validate = ajv.compile(schema);
    const valid = validate(data);
    
    if (!valid && validate.errors) {
      // Only return the first error to prevent DoS
      return { valid: false, error: validate.errors[0] };
    }
    
    return { valid: true };
  }
  
  const schema = {
    type: "object",
    properties: {
      name: { type: "string" }
    }
  };
  
  return (data: any) => validateWithLimitedErrors(schema, data);
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
  // Using Ajv with alternative error handling
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv();
  
  const schema = {
    type: "object",
    properties: {
      tags: { type: "array" }
    }
  };
  
  const validate = ajv.compile(schema);
  
  return function validateData(data: any) {
    const valid = validate(data);
    if (!valid) {
      // Process only the first error
      const firstError = validate.errors?.[0];
      return { valid: false, error: firstError };
    }
    return { valid: true };
  };
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
  // Using Ajv with explicit options object that doesn't include allErrors
  const options = {
    removeAdditional: true,
    useDefaults: true,
    coerceTypes: true
  };
  
  // ok: typescript-ajv-allerrors-true
  const ajv = new Ajv(options);
  
  const schema = {
    type: "object",
    properties: {
      metadata: { type: "object" }
    }
  };
  
  return ajv.compile(schema);
}
// {/fact}