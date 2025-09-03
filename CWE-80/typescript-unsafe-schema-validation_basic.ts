import express from 'express';
import { Request, Response } from 'express';
import Ajv from 'ajv';
import { validate } from 'jsonschema';
import * as yup from 'yup';
import Joi from 'joi';
import { z } from 'zod';
import { sanitizeHtml } from 'sanitize-html';
import { escape } from 'html-escaper';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const app = express();
app.use(express.json());
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userSchema = req.body.schema;
    const userData = req.body.data;
    
    const ajv = new Ajv();
    const validate = ajv.compile(userSchema);
    const valid = validate(userData);
    
    if (!valid) {
        // ruleid: typescript-unsafe-schema-validation
        res.status(400).send(`Validation error: ${validate.errors[0].message}`);
    } else {
        res.status(200).send('Data is valid');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const schemaFromUser = JSON.parse(req.query.schema as string);
    const dataToValidate = req.body;
    
    try {
        const result = validate(dataToValidate, schemaFromUser);
        if (!result.valid) {
            // ruleid: typescript-unsafe-schema-validation
            res.send(`<div class="error">Invalid data: ${result.errors[0].stack}</div>`);
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userProvidedSchema = yup.object().shape(JSON.parse(req.headers['x-schema'] as string));
    const userData = req.body;
    
    userProvidedSchema.validate(userData).catch(error => {
        // ruleid: typescript-unsafe-schema-validation
        res.status(400).send(`<p>Validation failed: ${error.message}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const externalSchema = Joi.object(JSON.parse(req.cookies.schema));
    const userInput = req.body;
    
    const { error } = externalSchema.validate(userInput);
    if (error) {
        // ruleid: typescript-unsafe-schema-validation
        return res.status(400).json({ 
            error: true, 
            message: `<span class="error">${error.details[0].message}</span>` 
        });
    }
    
    return res.status(200).json({ success: true });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const zodSchema = z.object(JSON.parse(req.body.schemaDefinition));
    const userInput = req.body.data;
    
    try {
        zodSchema.parse(userInput);
        res.send('Valid data');
    } catch (error) {
        if (error instanceof z.ZodError) {
            // ruleid: typescript-unsafe-schema-validation
            res.status(400).send(`<div id="errors">${error.errors[0].message}</div>`);
        }
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const ajv = new Ajv();
    const schemaFromRequest = req.body.jsonSchema;
    const dataToValidate = req.body.data;
    
    if (!ajv.validateSchema(schemaFromRequest)) {
        // ruleid: typescript-unsafe-schema-validation
        return res.status(400).send(`Invalid schema: ${ajv.errorsText()}`);
    }
    
    const validate = ajv.compile(schemaFromRequest);
    const valid = validate(dataToValidate);
    
    if (!valid) {
        // ruleid: typescript-unsafe-schema-validation
        return res.status(400).send(`Data validation failed: ${validate.errors![0].message}`);
    }
    
    res.send('Success');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const schema = JSON.parse(req.query.schema as string);
    const validator = new Ajv({ allErrors: true });
    const validate = validator.compile(schema);
    
    const data = req.body;
    const valid = validate(data);
    
    if (!valid) {
        const errorMessages = validate.errors!.map(err => err.message).join(', ');
        // ruleid: typescript-unsafe-schema-validation
        res.status(400).send(`<ul class="errors">${errorMessages}</ul>`);
    } else {
        res.send('Data is valid');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const userSchema = yup.object().shape(JSON.parse(req.body.schemaConfig));
    
    try {
        userSchema.validateSync(req.body.data);
        res.send('Valid');
    } catch (error) {
        // ruleid: typescript-unsafe-schema-validation
        res.status(400).render('error', { message: error.message });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const externalSchema = req.body.schema;
    const validator = new Ajv();
    
    try {
        const validate = validator.compile(externalSchema);
        const valid = validate(req.body.data);
        
        if (!valid) {
            let errorHTML = '<div class="validation-errors">';
            validate.errors!.forEach(err => {
                // ruleid: typescript-unsafe-schema-validation
                errorHTML += `<p>${err.instancePath}: ${err.message}</p>`;
            });
            errorHTML += '</div>';
            res.status(400).send(errorHTML);
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const joiSchema = Joi.object().keys(JSON.parse(req.body.schemaDefinition));
    
    joiSchema.validate(req.body.data, (err, value) => {
        if (err) {
            const errorDetails = err.details.map(detail => detail.message).join('\n');
            // ruleid: typescript-unsafe-schema-validation
            res.status(400).send(`<pre>${errorDetails}</pre>`);
        } else {
            res.send('Valid data');
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const zodSchema = z.object(JSON.parse(req.headers['x-schema'] as string));
    
    try {
        zodSchema.parse(req.body);
        res.json({ valid: true });
    } catch (error) {
        // ruleid: typescript-unsafe-schema-validation
        res.status(400).send(`
            <html>
                <body>
                    <h1>Validation Error</h1>
                    <p>${error.errors[0].message}</p>
                </body>
            </html>
        `);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const validator = new Ajv();
    const schema = JSON.parse(req.query.schema as string);
    
    if (!validator.validateSchema(schema)) {
        // ruleid: typescript-unsafe-schema-validation
        return res.status(400).send(`Invalid schema: ${validator.errorsText()}`);
    }
    
    const validate = validator.compile(schema);
    const isValid = validate(req.body);
    
    if (!isValid) {
        let errorMessage = '';
        for (const error of validate.errors!) {
            // ruleid: typescript-unsafe-schema-validation
            errorMessage += `<li>${error.dataPath} ${error.message}</li>`;
        }
        return res.status(400).send(`<ul>${errorMessage}</ul>`);
    }
    
    res.send('Valid data');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const { jsonSchema } = req.body;
    
    try {
        const validator = new Ajv();
        const validate = validator.compile(jsonSchema);
        const valid = validate(req.body.data);
        
        if (!valid) {
            const errors = validate.errors!;
            let errorResponse = '<div class="errors">';
            
            for (const err of errors) {
                // ruleid: typescript-unsafe-schema-validation
                errorResponse += `<p>${err.instancePath} ${err.message}</p>`;
            }
            
            errorResponse += '</div>';
            res.status(400).send(errorResponse);
        } else {
            res.send('Success');
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const schemaFromUser = JSON.parse(req.cookies.schema);
    const dataToValidate = req.body;
    
    const result = validate(dataToValidate, schemaFromUser);
    if (!result.valid) {
        const errorMessages = result.errors.map(err => err.stack).join('\n');
        // ruleid: typescript-unsafe-schema-validation
        res.render('error', { message: errorMessages });
    } else {
        res.send('Valid data');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const userSchema = yup.object().shape(JSON.parse(req.query.schema as string));
    const userData = req.body;
    
    userSchema.validate(userData)
        .then(() => {
            res.send('Valid data');
        })
        .catch(error => {
            // ruleid: typescript-unsafe-schema-validation
            res.status(400).send(`
                <div class="alert alert-danger">
                    ${error.errors.join('<br>')}
                </div>
            `);
        });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userSchema = req.body.schema;
    const userData = req.body.data;
    
    const ajv = new Ajv();
    const validate = ajv.compile(userSchema);
    const valid = validate(userData);
    
    if (!valid) {
        // ok: typescript-unsafe-schema-validation
        res.status(400).send(`Validation error: ${escape(validate.errors[0].message)}`);
    } else {
        res.status(200).send('Data is valid');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const schemaFromUser = JSON.parse(req.query.schema as string);
    const dataToValidate = req.body;
    
    try {
        const result = validate(dataToValidate, schemaFromUser);
        if (!result.valid) {
            // ok: typescript-unsafe-schema-validation
            res.send(`<div class="error">Invalid data: ${purify.sanitize(result.errors[0].stack)}</div>`);
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const userProvidedSchema = yup.object().shape(JSON.parse(req.headers['x-schema'] as string));
    const userData = req.body;
    
    userProvidedSchema.validate(userData).catch(error => {
        // ok: typescript-unsafe-schema-validation
        const sanitizedMessage = sanitizeHtml(error.message);
        res.status(400).send(`<p>Validation failed: ${sanitizedMessage}</p>`);
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const externalSchema = Joi.object(JSON.parse(req.cookies.schema));
    const userInput = req.body;
    
    const { error } = externalSchema.validate(userInput);
    if (error) {
        // ok: typescript-unsafe-schema-validation
        return res.status(400).json({ 
            error: true, 
            message: error.details[0].message // No HTML in JSON response
        });
    }
    
    return res.status(200).json({ success: true });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const zodSchema = z.object(JSON.parse(req.body.schemaDefinition));
    const userInput = req.body.data;
    
    try {
        zodSchema.parse(userInput);
        res.send('Valid data');
    } catch (error) {
        if (error instanceof z.ZodError) {
            // ok: typescript-unsafe-schema-validation
            const sanitizedMessage = escape(error.errors[0].message);
            res.status(400).send(`<div id="errors">${sanitizedMessage}</div>`);
        }
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const ajv = new Ajv();
    const schemaFromRequest = req.body.jsonSchema;
    const dataToValidate = req.body.data;
    
    if (!ajv.validateSchema(schemaFromRequest)) {
        // ok: typescript-unsafe-schema-validation
        return res.status(400).json({ error: ajv.errorsText() }); // JSON response, not HTML
    }
    
    const validate = ajv.compile(schemaFromRequest);
    const valid = validate(dataToValidate);
    
    if (!valid) {
        // ok: typescript-unsafe-schema-validation
        return res.status(400).json({ 
            error: validate.errors!.map(e => e.message)
        });
    }
    
    res.send('Success');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const schema = JSON.parse(req.query.schema as string);
    const validator = new Ajv({ allErrors: true });
    const validate = validator.compile(schema);
    
    const data = req.body;
    const valid = validate(data);
    
    if (!valid) {
        const errorMessages = validate.errors!.map(err => err.message);
        // ok: typescript-unsafe-schema-validation
        const safeErrorList = errorMessages.map(msg => `<li>${purify.sanitize(msg)}</li>`).join('');
        res.status(400).send(`<ul class="errors">${safeErrorList}</ul>`);
    } else {
        res.send('Data is valid');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const userSchema = yup.object().shape(JSON.parse(req.body.schemaConfig));
    
    try {
        userSchema.validateSync(req.body.data);
        res.send('Valid');
    } catch (error) {
        // ok: typescript-unsafe-schema-validation
        res.status(400).render('error', { message: escape(error.message) });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const externalSchema = req.body.schema;
    const validator = new Ajv();
    
    try {
        const validate = validator.compile(externalSchema);
        const valid = validate(req.body.data);
        
        if (!valid) {
            const errors = validate.errors!.map(err => ({
                path: err.instancePath,
                message: err.message
            }));
            
            // ok: typescript-unsafe-schema-validation
            res.status(400).json({ errors }); // Return JSON instead of HTML
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const joiSchema = Joi.object().keys(JSON.parse(req.body.schemaDefinition));
    
    joiSchema.validate(req.body.data, (err, value) => {
        if (err) {
            const errorDetails = err.details.map(detail => detail.message);
            // ok: typescript-unsafe-schema-validation
            const sanitizedErrors = errorDetails.map(error => escape(error));
            res.status(400).send(`<pre>${sanitizedErrors.join('\n')}</pre>`);
        } else {
            res.send('Valid data');
        }
    });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const zodSchema = z.object(JSON.parse(req.headers['x-schema'] as string));
    
    try {
        zodSchema.parse(req.body);
        res.json({ valid: true });
    } catch (error) {
        // ok: typescript-unsafe-schema-validation
        const sanitizedErrors = error.errors.map((e: any) => ({
            path: e.path,
            message: e.message
        }));
        res.status(400).json({ errors: sanitizedErrors });
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const validator = new Ajv();
    const schema = JSON.parse(req.query.schema as string);
    
    if (!validator.validateSchema(schema)) {
        // ok: typescript-unsafe-schema-validation
        const sanitizedError = escape(validator.errorsText());
        return res.status(400).send(`Invalid schema: ${sanitizedError}`);
    }
    
    const validate = validator.compile(schema);
    const isValid = validate(req.body);
    
    if (!isValid) {
        // ok: typescript-unsafe-schema-validation
        const safeErrors = validate.errors!.map(error => 
            `<li>${escape(error.dataPath)} ${escape(error.message)}</li>`
        ).join('');
        return res.status(400).send(`<ul>${safeErrors}</ul>`);
    }
    
    res.send('Valid data');
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const { jsonSchema } = req.body;
    
    try {
        const validator = new Ajv();
        const validate = validator.compile(jsonSchema);
        const valid = validate(req.body.data);
        
        if (!valid) {
            // ok: typescript-unsafe-schema-validation
            res.status(400).json({
                valid: false,
                errors: validate.errors
            });
        } else {
            res.send('Success');
        }
    } catch (err) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const schemaFromUser = JSON.parse(req.cookies.schema);
    const dataToValidate = req.body;
    
    const result = validate(dataToValidate, schemaFromUser);
    if (!result.valid) {
        const errorMessages = result.errors.map(err => err.stack);
        // ok: typescript-unsafe-schema-validation
        const sanitizedMessages = errorMessages.map(msg => sanitizeHtml(msg));
        res.render('error', { message: sanitizedMessages.join('\n') });
    } else {
        res.send('Valid data');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const userSchema = yup.object().shape(JSON.parse(req.query.schema as string));
    const userData = req.body;
    
    userSchema.validate(userData)
        .then(() => {
            res.send('Valid data');
        })
        .catch(error => {
            // ok: typescript-unsafe-schema-validation
            const sanitizedErrors = error.errors.map((err: string) => escape(err));
            res.status(400).json({ errors: sanitizedErrors });
        });
}
// {/fact}

export default app;