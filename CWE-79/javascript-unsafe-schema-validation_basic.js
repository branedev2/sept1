const express = require('express');
const Ajv = require('ajv');
const ajv = new Ajv();
const { body, validationResult } = require('express-validator');
const escapeHtml = require('escape-html');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate', (req, res) => {
    const userSchema = req.body.schema;
    const data = req.body.data;
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(data);
      if (!valid) {
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`Validation error: ${JSON.stringify(validate.errors)}`);
      } else {
        res.send('Valid data');
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-check', (req, res) => {
    const externalSchema = req.body.schema;
    const userInput = req.body.input;
    
    try {
      const validator = ajv.compile(externalSchema);
      const isValid = validator(userInput);
      if (!isValid) {
        // ruleid: javascript-unsafe-schema-validation
        res.send(`<div class="error">Invalid input: ${validator.errors[0].message}</div>`);
      } else {
        res.send('Success');
      }
    } catch (err) {
      res.status(500).send(`Schema compilation error: ${err.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-form', (req, res) => {
    const schemaFromClient = JSON.parse(req.headers['x-custom-schema']);
    const formData = req.body;
    
    try {
      const validate = ajv.compile(schemaFromClient);
      const valid = validate(formData);
      if (!valid) {
        const errorMessages = validate.errors.map(e => e.message).join(', ');
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`<p>The following errors were found: ${errorMessages}</p>`);
      } else {
        res.send('Form data is valid');
      }
    } catch (error) {
      res.status(500).send(`Error processing form: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-validation', async (req, res) => {
    const userProvidedSchema = req.query.schema ? JSON.parse(req.query.schema) : null;
    const dataToValidate = req.body;
    
    if (!userProvidedSchema) {
      return res.status(400).send('Schema is required');
    }
    
    try {
      const validator = ajv.compile(userProvidedSchema);
      const isValid = validator(dataToValidate);
      
      if (!isValid) {
        const errors = validator.errors;
        // ruleid: javascript-unsafe-schema-validation
        res.render('validation-result', { errors: errors });
      } else {
        res.send('Validation passed');
      }
    } catch (error) {
      res.status(500).send(`Schema error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  app.use(express.json());
  
  app.post('/check-data', (req, res) => {
    const schemaDefinition = req.cookies.savedSchema ? JSON.parse(req.cookies.savedSchema) : {};
    const inputData = req.body;
    
    try {
      const validate = ajv.compile(schemaDefinition);
      const valid = validate(inputData);
      
      if (!valid) {
        const errorList = validate.errors.map(err => `${err.dataPath} ${err.message}`);
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`<ul>${errorList.map(e => `<li>${e}</li>`).join('')}</ul>`);
      } else {
        res.send('All good!');
      }
    } catch (error) {
      res.status(500).send(`Processing error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  app.use(express.json());
  
  app.post('/dynamic-validation', (req, res) => {
    const dynamicSchema = req.body.schemaDefinition;
    const userPayload = req.body.payload;
    
    try {
      const validate = ajv.compile(dynamicSchema);
      const result = validate(userPayload);
      
      if (!result) {
        let errorOutput = '<h3>Validation Errors:</h3>';
        validate.errors.forEach(err => {
          // ruleid: javascript-unsafe-schema-validation
          errorOutput += `<p>${err.dataPath}: ${err.message}</p>`;
        });
        res.status(400).send(errorOutput);
      } else {
        res.send('Validation successful');
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/validate-json', (req, res) => {
    const schemaFromRequest = req.body.jsonSchema;
    const dataToCheck = req.body.jsonData;
    let responseHtml = '<div class="result">';
    
    try {
      const validator = ajv.compile(schemaFromRequest);
      if (!validator(dataToCheck)) {
        // ruleid: javascript-unsafe-schema-validation
        responseHtml += `<div class="error">Found ${validator.errors.length} errors: ${JSON.stringify(validator.errors)}</div>`;
      } else {
        responseHtml += '<div class="success">Validation passed</div>';
      }
      responseHtml += '</div>';
      res.send(responseHtml);
    } catch (error) {
      res.status(500).send(`Error during validation: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-test', (req, res) => {
    const { schema, testData } = req.body;
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(testData);
      
      if (!valid) {
        const errorDetails = validate.errors.map(e => {
          return {
            path: e.dataPath,
            message: e.message,
            params: e.params
          };
        });
        
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`
          <div class="validation-errors">
            <h2>Validation Failed</h2>
            <pre>${JSON.stringify(errorDetails, null, 2)}</pre>
          </div>
        `);
      } else {
        res.send('<div class="success">Schema validation passed</div>');
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-with-custom-schema', (req, res) => {
    const customSchema = JSON.parse(req.headers['x-schema']);
    const userData = req.body;
    
    try {
      const validate = ajv.compile(customSchema);
      const valid = validate(userData);
      
      if (!valid) {
        let errorMessage = 'Validation failed with the following errors:\n';
        validate.errors.forEach(err => {
          errorMessage += `- ${err.dataPath} ${err.message}\n`;
        });
        
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`<textarea readonly style="width:100%;height:200px">${errorMessage}</textarea>`);
      } else {
        res.send('Data is valid according to the provided schema');
      }
    } catch (error) {
      res.status(500).send(`Error processing request: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-validator', (req, res) => {
    const schemaSource = req.query.source === 'header' 
      ? JSON.parse(req.headers['x-schema']) 
      : req.body.schema;
    
    const dataToValidate = req.body.data;
    
    try {
      const validate = ajv.compile(schemaSource);
      const valid = validate(dataToValidate);
      
      if (!valid) {
        const errorReport = {
          valid: false,
          errors: validate.errors
        };
        
        // ruleid: javascript-unsafe-schema-validation
        res.status(400).send(`
          <html>
            <body>
              <h1>Validation Report</h1>
              <div id="errors">${JSON.stringify(errorReport)}</div>
            </body>
          </html>
        `);
      } else {
        res.send('Validation successful');
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-complex-schema', (req, res) => {
    const userSchema = req.body.schema;
    const userInput = req.body.input;
    let output = '';
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(userInput);
      
      if (!valid) {
        output = '<h2>Validation Errors</h2><ul>';
        validate.errors.forEach(error => {
          // ruleid: javascript-unsafe-schema-validation
          output += `<li>Path: ${error.dataPath}, Error: ${error.message}</li>`;
        });
        output += '</ul>';
        res.status(400).send(output);
      } else {
        res.send('<h2>Validation Successful</h2>');
      }
    } catch (error) {
      res.status(500).send(`Error during validation: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-check', (req, res) => {
    const schema = req.body.schema;
    const data = req.body.data;
    const format = req.query.format || 'json';
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(data);
      
      if (!valid) {
        if (format === 'html') {
          let htmlResponse = '<div class="validation-result">';
          // ruleid: javascript-unsafe-schema-validation
          htmlResponse += `<p>Found ${validate.errors.length} errors:</p>
                          <ul>${validate.errors.map(e => `<li>${e.dataPath} ${e.message}</li>`).join('')}</ul>`;
          htmlResponse += '</div>';
          res.status(400).send(htmlResponse);
        } else {
          res.status(400).json({ valid: false, errors: validate.errors });
        }
      } else {
        res.send(format === 'html' ? '<div class="success">Valid</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-validation-report', (req, res) => {
    const { schema, data, reportType } = req.body;
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(data);
      
      if (!valid) {
        const errors = validate.errors;
        let response;
        
        switch (reportType) {
          case 'detailed':
            // ruleid: javascript-unsafe-schema-validation
            response = `
              <div class="detailed-report">
                <h2>Detailed Validation Report</h2>
                <div class="error-count">Found ${errors.length} errors</div>
                <div class="error-details">
                  ${errors.map(e => `<div class="error-item">
                    <span class="path">${e.dataPath}</span>: 
                    <span class="message">${e.message}</span>
                  </div>`).join('')}
                </div>
              </div>
            `;
            break;
          default:
            response = { valid: false, errorCount: errors.length };
        }
        
        res.status(400).send(response);
      } else {
        res.send(reportType === 'detailed' ? '<div class="success">Valid data</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-with-options', (req, res) => {
    const schemaFromUser = req.body.schema;
    const dataToValidate = req.body.data;
    const displayMode = req.query.display || 'simple';
    
    try {
      const validate = ajv.compile(schemaFromUser);
      const valid = validate(dataToValidate);
      
      if (!valid) {
        if (displayMode === 'interactive') {
          // ruleid: javascript-unsafe-schema-validation
          const htmlOutput = `
            <div id="validation-results">
              <h3>Validation Failed</h3>
              <div class="errors-container">
                ${validate.errors.map((err, i) => `
                  <div class="error-item" data-index="${i}">
                    <div class="error-path">${err.dataPath}</div>
                    <div class="error-message">${err.message}</div>
                    <div class="error-params">${JSON.stringify(err.params)}</div>
                  </div>
                `).join('')}
              </div>
              <script>
                document.querySelectorAll('.error-item').forEach(item => {
                  item.addEventListener('click', () => {
                    alert('Error details: ' + item.querySelector('.error-message').textContent);
                  });
                });
              </script>
            </div>
          `;
          res.status(400).send(htmlOutput);
        } else {
          res.status(400).json({ valid: false, errors: validate.errors });
        }
      } else {
        res.send(displayMode === 'interactive' ? '<div class="success">Valid data</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/validate-and-display', (req, res) => {
    const userSchema = req.body.schema;
    const userInput = req.body.input;
    const template = req.query.template || 'default';
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(userInput);
      
      if (!valid) {
        let responseContent;
        
        if (template === 'developer') {
          // ruleid: javascript-unsafe-schema-validation
          responseContent = `
            <!DOCTYPE html>
            <html>
              <head>
                <title>Validation Results</title>
                <style>
                  .error { color: red; margin-bottom: 10px; }
                  .error-path { font-weight: bold; }
                </style>
              </head>
              <body>
                <h1>Schema Validation Failed</h1>
                <div id="error-container">
                  ${validate.errors.map(err => `
                    <div class="error">
                      <span class="error-path">${err.dataPath}</span>: ${err.message}
                      <pre>${JSON.stringify(err.params, null, 2)}</pre>
                    </div>
                  `).join('')}
                </div>
                <div>
                  <h3>Tested Schema:</h3>
                  <pre>${JSON.stringify(userSchema, null, 2)}</pre>
                  <h3>Input Data:</h3>
                  <pre>${JSON.stringify(userInput, null, 2)}</pre>
                </div>
              </body>
            </html>
          `;
        } else {
          responseContent = { valid: false, errors: validate.errors };
        }
        
        res.status(400).send(responseContent);
      } else {
        res.send(template === 'developer' ? '<h1>Validation Passed</h1>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${error.message}`);
    }
  });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate', (req, res) => {
    const userSchema = req.body.schema;
    const data = req.body.data;
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(data);
      if (!valid) {
        // ok: javascript-unsafe-schema-validation
        res.status(400).json({ errors: validate.errors });
      } else {
        res.send('Valid data');
      }
    } catch (error) {
      res.status(500).json({ error: 'Schema compilation error' });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-check', (req, res) => {
    const externalSchema = req.body.schema;
    const userInput = req.body.input;
    
    try {
      const validator = ajv.compile(externalSchema);
      const isValid = validator(userInput);
      if (!isValid) {
        // ok: javascript-unsafe-schema-validation
        const safeErrorMessage = escapeHtml(validator.errors[0].message);
        res.send(`<div class="error">Invalid input: ${safeErrorMessage}</div>`);
      } else {
        res.send('Success');
      }
    } catch (err) {
      res.status(500).send(`Schema compilation error: ${escapeHtml(err.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-form', (req, res) => {
    const schemaFromClient = JSON.parse(req.headers['x-custom-schema']);
    const formData = req.body;
    
    try {
      const validate = ajv.compile(schemaFromClient);
      const valid = validate(formData);
      if (!valid) {
        const errorMessages = validate.errors.map(e => e.message);
        // ok: javascript-unsafe-schema-validation
        const safeErrorMessages = errorMessages.map(msg => escapeHtml(msg)).join(', ');
        res.status(400).send(`<p>The following errors were found: ${safeErrorMessages}</p>`);
      } else {
        res.send('Form data is valid');
      }
    } catch (error) {
      res.status(500).send(`Error processing form: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-validation', async (req, res) => {
    const userProvidedSchema = req.query.schema ? JSON.parse(req.query.schema) : null;
    const dataToValidate = req.body;
    
    if (!userProvidedSchema) {
      return res.status(400).send('Schema is required');
    }
    
    try {
      const validator = ajv.compile(userProvidedSchema);
      const isValid = validator(dataToValidate);
      
      if (!isValid) {
        const errors = validator.errors;
        // ok: javascript-unsafe-schema-validation
        const sanitizedErrors = errors.map(err => ({
          path: escapeHtml(err.dataPath),
          message: escapeHtml(err.message),
          params: JSON.parse(JSON.stringify(err.params))
        }));
        
        res.render('validation-result', { errors: sanitizedErrors });
      } else {
        res.send('Validation passed');
      }
    } catch (error) {
      res.status(500).send(`Schema error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  const app = express();
  app.use(express.json());
  
  app.post('/check-data', (req, res) => {
    const schemaDefinition = req.cookies.savedSchema ? JSON.parse(req.cookies.savedSchema) : {};
    const inputData = req.body;
    
    try {
      const validate = ajv.compile(schemaDefinition);
      const valid = validate(inputData);
      
      if (!valid) {
        const errorList = validate.errors.map(err => `${err.dataPath} ${err.message}`);
        // ok: javascript-unsafe-schema-validation
        const safeErrorList = errorList.map(e => escapeHtml(e));
        res.status(400).send(`<ul>${safeErrorList.map(e => `<li>${e}</li>`).join('')}</ul>`);
      } else {
        res.send('All good!');
      }
    } catch (error) {
      res.status(500).send(`Processing error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  const app = express();
  app.use(express.json());
  
  app.post('/dynamic-validation', (req, res) => {
    const dynamicSchema = req.body.schemaDefinition;
    const userPayload = req.body.payload;
    
    try {
      const validate = ajv.compile(dynamicSchema);
      const result = validate(userPayload);
      
      if (!result) {
        let errorOutput = '<h3>Validation Errors:</h3>';
        // ok: javascript-unsafe-schema-validation
        validate.errors.forEach(err => {
          const safePath = escapeHtml(err.dataPath);
          const safeMessage = escapeHtml(err.message);
          errorOutput += `<p>${safePath}: ${safeMessage}</p>`;
        });
        res.status(400).send(errorOutput);
      } else {
        res.send('Validation successful');
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/validate-json', (req, res) => {
    const schemaFromRequest = req.body.jsonSchema;
    const dataToCheck = req.body.jsonData;
    
    try {
      const validator = ajv.compile(schemaFromRequest);
      if (!validator(dataToCheck)) {
        // ok: javascript-unsafe-schema-validation
        res.status(400).json({
          valid: false,
          errors: validator.errors
        });
      } else {
        res.json({ valid: true });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-test', (req, res) => {
    const { schema, testData } = req.body;
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(testData);
      
      if (!valid) {
        const errorDetails = validate.errors.map(e => {
          return {
            path: e.dataPath,
            message: e.message,
            params: e.params
          };
        });
        
        // ok: javascript-unsafe-schema-validation
        const sanitizedErrorDetails = errorDetails.map(err => ({
          path: escapeHtml(err.path),
          message: escapeHtml(err.message),
          params: JSON.parse(JSON.stringify(err.params))
        }));
        
        res.status(400).send(`
          <div class="validation-errors">
            <h2>Validation Failed</h2>
            <pre>${escapeHtml(JSON.stringify(sanitizedErrorDetails, null, 2))}</pre>
          </div>
        `);
      } else {
        res.send('<div class="success">Schema validation passed</div>');
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-with-custom-schema', (req, res) => {
    const customSchema = JSON.parse(req.headers['x-schema']);
    const userData = req.body;
    
    try {
      const validate = ajv.compile(customSchema);
      const valid = validate(userData);
      
      if (!valid) {
        let errorMessage = 'Validation failed with the following errors:\n';
        validate.errors.forEach(err => {
          errorMessage += `- ${err.dataPath} ${err.message}\n`;
        });
        
        // ok: javascript-unsafe-schema-validation
        const safeErrorMessage = escapeHtml(errorMessage);
        res.status(400).send(`<textarea readonly style="width:100%;height:200px">${safeErrorMessage}</textarea>`);
      } else {
        res.send('Data is valid according to the provided schema');
      }
    } catch (error) {
      res.status(500).send(`Error processing request: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-validator', (req, res) => {
    const schemaSource = req.query.source === 'header' 
      ? JSON.parse(req.headers['x-schema']) 
      : req.body.schema;
    
    const dataToValidate = req.body.data;
    
    try {
      const validate = ajv.compile(schemaSource);
      const valid = validate(dataToValidate);
      
      if (!valid) {
        // ok: javascript-unsafe-schema-validation
        res.status(400).json({
          valid: false,
          errors: validate.errors
        });
      } else {
        res.json({ valid: true });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-complex-schema', (req, res) => {
    const userSchema = req.body.schema;
    const userInput = req.body.input;
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(userInput);
      
      if (!valid) {
        // ok: javascript-unsafe-schema-validation
        const sanitizedErrors = validate.errors.map(error => ({
          path: purify.sanitize(error.dataPath),
          message: purify.sanitize(error.message)
        }));
        
        let output = '<h2>Validation Errors</h2><ul>';
        sanitizedErrors.forEach(error => {
          output += `<li>Path: ${error.path}, Error: ${error.message}</li>`;
        });
        output += '</ul>';
        
        res.status(400).send(output);
      } else {
        res.send('<h2>Validation Successful</h2>');
      }
    } catch (error) {
      res.status(500).send(`Error during validation: ${purify.sanitize(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/schema-check', (req, res) => {
    const schema = req.body.schema;
    const data = req.body.data;
    const format = req.query.format || 'json';
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(data);
      
      if (!valid) {
        if (format === 'html') {
          // ok: javascript-unsafe-schema-validation
          const safeErrors = validate.errors.map(e => ({
            path: escapeHtml(e.dataPath),
            message: escapeHtml(e.message)
          }));
          
          let htmlResponse = '<div class="validation-result">';
          htmlResponse += `<p>Found ${safeErrors.length} errors:</p>
                          <ul>${safeErrors.map(e => `<li>${e.path} ${e.message}</li>`).join('')}</ul>`;
          htmlResponse += '</div>';
          
          res.status(400).send(htmlResponse);
        } else {
          res.status(400).json({ valid: false, errors: validate.errors });
        }
      } else {
        res.send(format === 'html' ? '<div class="success">Valid</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  const app = express();
  app.use(express.json());
  
  app.post('/schema-validation-report', (req, res) => {
    const { schema, data, reportType } = req.body;
    
    try {
      const validate = ajv.compile(schema);
      const valid = validate(data);
      
      if (!valid) {
        const errors = validate.errors;
        
        if (reportType === 'detailed') {
          // ok: javascript-unsafe-schema-validation
          const sanitizedErrors = errors.map(e => ({
            path: escapeHtml(e.dataPath || ''),
            message: escapeHtml(e.message || '')
          }));
          
          const response = `
            <div class="detailed-report">
              <h2>Detailed Validation Report</h2>
              <div class="error-count">Found ${sanitizedErrors.length} errors</div>
              <div class="error-details">
                ${sanitizedErrors.map(e => `<div class="error-item">
                  <span class="path">${e.path}</span>: 
                  <span class="message">${e.message}</span>
                </div>`).join('')}
              </div>
            </div>
          `;
          
          res.status(400).send(response);
        } else {
          res.status(400).json({ valid: false, errorCount: errors.length });
        }
      } else {
        res.send(reportType === 'detailed' ? '<div class="success">Valid data</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  const app = express();
  app.use(express.json());
  
  app.post('/validate-with-options', (req, res) => {
    const schemaFromUser = req.body.schema;
    const dataToValidate = req.body.data;
    const displayMode = req.query.display || 'simple';
    
    try {
      const validate = ajv.compile(schemaFromUser);
      const valid = validate(dataToValidate);
      
      if (!valid) {
        if (displayMode === 'interactive') {
          // ok: javascript-unsafe-schema-validation
          const sanitizedErrors = validate.errors.map((err, i) => ({
            index: i,
            path: escapeHtml(err.dataPath || ''),
            message: escapeHtml(err.message || ''),
            params: JSON.stringify(err.params || {})
          }));
          
          const htmlOutput = `
            <div id="validation-results">
              <h3>Validation Failed</h3>
              <div class="errors-container">
                ${sanitizedErrors.map(err => `
                  <div class="error-item" data-index="${err.index}">
                    <div class="error-path">${err.path}</div>
                    <div class="error-message">${err.message}</div>
                    <div class="error-params">${escapeHtml(err.params)}</div>
                  </div>
                `).join('')}
              </div>
              <script>
                document.querySelectorAll('.error-item').forEach(item => {
                  item.addEventListener('click', () => {
                    alert('Error details: ' + item.querySelector('.error-message').textContent);
                  });
                });
              </script>
            </div>
          `;
          
          res.status(400).send(htmlOutput);
        } else {
          res.status(400).json({ valid: false, errors: validate.errors });
        }
      } else {
        res.send(displayMode === 'interactive' ? '<div class="success">Valid data</div>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(express.json());
  
  app.post('/api/validate-and-display', (req, res) => {
    const userSchema = req.body.schema;
    const userInput = req.body.input;
    const template = req.query.template || 'default';
    
    try {
      const validate = ajv.compile(userSchema);
      const valid = validate(userInput);
      
      if (!valid) {
        if (template === 'developer') {
          // ok: javascript-unsafe-schema-validation
          const sanitizedErrors = validate.errors.map(err => ({
            path: escapeHtml(err.dataPath || ''),
            message: escapeHtml(err.message || ''),
            params: JSON.parse(JSON.stringify(err.params || {}))
          }));
          
          const sanitizedSchema = escapeHtml(JSON.stringify(userSchema, null, 2));
          const sanitizedInput = escapeHtml(JSON.stringify(userInput, null, 2));
          
          const responseContent = `
            <!DOCTYPE html>
            <html>
              <head>
                <title>Validation Results</title>
                <style>
                  .error { color: red; margin-bottom: 10px; }
                  .error-path { font-weight: bold; }
                </style>
              </head>
              <body>
                <h1>Schema Validation Failed</h1>
                <div id="error-container">
                  ${sanitizedErrors.map(err => `
                    <div class="error">
                      <span class="error-path">${err.path}</span>: ${err.message}
                      <pre>${escapeHtml(JSON.stringify(err.params, null, 2))}</pre>
                    </div>
                  `).join('')}
                </div>
                <div>
                  <h3>Tested Schema:</h3>
                  <pre>${sanitizedSchema}</pre>
                  <h3>Input Data:</h3>
                  <pre>${sanitizedInput}</pre>
                </div>
              </body>
            </html>
          `;
          
          res.status(400).send(responseContent);
        } else {
          res.status(400).json({ valid: false, errors: validate.errors });
        }
      } else {
        res.send(template === 'developer' ? '<h1>Validation Passed</h1>' : { valid: true });
      }
    } catch (error) {
      res.status(500).send(`Error: ${escapeHtml(error.message)}`);
    }
  });
}
// {/fact}