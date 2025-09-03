// File: regex_security_test_cases.js

const express = require('express');
const escapeStringRegexp = require('escape-string-regexp');
const app = express();
app.use(express.json());

// True Positives (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req, res) {
  const userInput = req.query.pattern;
  
  // ruleid: javascript-do-not-construct-regular-expression-from-user-input
  const regex = new RegExp(userInput);
  
  const text = "Some text to test against";
  const matches = text.match(regex);
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req, res) {
  const searchTerm = req.body.search;
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const pattern = new RegExp(searchTerm, 'gi');
    
    const content = "This is some content to search through";
    const result = content.replace(pattern, '<mark>$&</mark>');
    
    res.send(result);
  } catch (error) {
    res.status(500).send('Invalid search pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req, res) {
  const userRegex = req.params.regex;
  const data = ["apple", "banana", "cherry", "date"];
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const filter = RegExp(userRegex);
    
    const filteredData = data.filter(item => filter.test(item));
    res.json(filteredData);
  } catch (error) {
    res.status(400).send('Invalid regex pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req, res) {
  const headerPattern = req.headers['x-search-pattern'];
  const content = "This is the content we want to search through";
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(headerPattern, 'i');
    
    const hasMatch = regex.test(content);
    res.json({ hasMatch });
  } catch (error) {
    res.status(400).send('Invalid pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req, res) {
  const cookieValue = req.cookies.searchPattern;
  
  // ruleid: javascript-do-not-construct-regular-expression-from-user-input
  const pattern = new RegExp(`^${cookieValue}.*$`);
  
  const validStrings = ["foo", "bar", "baz"];
  const matches = validStrings.filter(str => pattern.test(str));
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req, res) {
  const userInput = req.query.validate;
  const emailList = ["user@example.com", "admin@example.com"];
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const validator = new RegExp(userInput);
    
    const validEmails = emailList.filter(email => validator.test(email));
    res.json({ validEmails });
  } catch (error) {
    res.status(400).send('Invalid validation pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req, res) {
  const userPattern = req.body.pattern || '';
  const flags = req.body.flags || 'g';
  
  // ruleid: javascript-do-not-construct-regular-expression-from-user-input
  const regex = new RegExp(userPattern, flags);
  
  const text = "Sample text for testing regex patterns";
  const matches = text.match(regex) || [];
  
  res.json({ matchCount: matches.length, matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req, res) {
  let patterns = req.body.patterns || [];
  let results = {};
  
  patterns.forEach((pattern, index) => {
    try {
      // ruleid: javascript-do-not-construct-regular-expression-from-user-input
      const regex = new RegExp(pattern);
      
      const testString = "Test string for pattern matching";
      results[`pattern_${index}`] = regex.test(testString);
    } catch (error) {
      results[`pattern_${index}`] = { error: "Invalid pattern" };
    }
  });
  
  res.json(results);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req, res) {
  const searchQuery = req.query.q;
  const content = "This is some searchable content";
  
  if (searchQuery) {
    try {
      // ruleid: javascript-do-not-construct-regular-expression-from-user-input
      const searchRegex = RegExp(searchQuery, 'i');
      
      const found = searchRegex.test(content);
      res.json({ found });
    } catch (error) {
      res.status(400).send('Search query is not a valid regex pattern');
    }
  } else {
    res.status(400).send('No search query provided');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req, res) {
  const prefix = req.query.prefix || '';
  const suffix = req.query.suffix || '';
  
  // ruleid: javascript-do-not-construct-regular-expression-from-user-input
  const regex = new RegExp(`${prefix}.*${suffix}`);
  
  const testStrings = ["abc123", "def456", "ghi789"];
  const matches = testStrings.filter(str => regex.test(str));
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req, res) {
  const userInput = req.body.input;
  const wordList = ["apple", "banana", "cherry"];
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const pattern = new RegExp(`\\b${userInput}\\b`, 'i');
    
    const matches = wordList.filter(word => pattern.test(word));
    res.json({ matches });
  } catch (error) {
    res.status(400).send('Invalid input pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req, res) {
  const dynamicPart = req.query.part;
  const staticPart = "static";
  
  // ruleid: javascript-do-not-construct-regular-expression-from-user-input
  const combinedPattern = new RegExp(`${staticPart}${dynamicPart}`);
  
  const testString = "staticdynamic";
  const isMatch = combinedPattern.test(testString);
  
  res.json({ isMatch });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req, res) {
  const userRegexString = req.body.regex;
  
  try {
    // ruleid: javascript-do-not-construct-regular-expression-from-user-input
    const userRegex = new RegExp(userRegexString);
    
    // Simulate validating a form field
    const email = "user@example.com";
    const isValid = userRegex.test(email);
    
    res.json({ isValid });
  } catch (error) {
    res.status(400).send('Invalid regex pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req, res) {
  const searchTerms = req.query.terms ? req.query.terms.split(',') : [];
  const content = "This is content to search through";
  const results = {};
  
  searchTerms.forEach((term, index) => {
    try {
      // ruleid: javascript-do-not-construct-regular-expression-from-user-input
      const regex = new RegExp(term, 'g');
      
      const matches = content.match(regex) || [];
      results[`term_${index}`] = {
        term,
        matches: matches.length
      };
    } catch (error) {
      results[`term_${index}`] = { error: "Invalid pattern" };
    }
  });
  
  res.json(results);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req, res) {
  const userInput = req.query.filter || '';
  const dataList = ["item1", "item2", "item3"];
  
  if (userInput) {
    try {
      // ruleid: javascript-do-not-construct-regular-expression-from-user-input
      const filterRegex = RegExp(userInput);
      
      const filteredList = dataList.filter(item => filterRegex.test(item));
      res.json({ filtered: filteredList });
    } catch (error) {
      res.status(400).send('Invalid filter pattern');
    }
  } else {
    res.json({ filtered: dataList });
  }
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req, res) {
  const userInput = req.query.pattern;
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const escapedPattern = escapeStringRegexp(userInput);
  const regex = new RegExp(escapedPattern);
  
  const text = "Some text to test against";
  const matches = text.match(regex);
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req, res) {
  const searchTerm = req.body.search;
  
  try {
    // ok: javascript-do-not-construct-regular-expression-from-user-input
    const escapedTerm = escapeStringRegexp(searchTerm);
    const pattern = new RegExp(escapedTerm, 'gi');
    
    const content = "This is some content to search through";
    const result = content.replace(pattern, '<mark>$&</mark>');
    
    res.send(result);
  } catch (error) {
    res.status(500).send('Invalid search pattern');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req, res) {
  // Using a predefined regex pattern instead of user input
  const data = ["apple", "banana", "cherry", "date"];
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const filter = /^[a-c]/; // Fixed pattern that matches items starting with a, b, or c
  
  const filteredData = data.filter(item => filter.test(item));
  res.json(filteredData);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req, res) {
  // Using a whitelist of allowed patterns
  const patternId = req.headers['x-search-pattern-id'];
  const content = "This is the content we want to search through";
  
  const allowedPatterns = {
    'email': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
    'phone': /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
    'zipcode': /\b\d{5}(?:[-\s]\d{4})?\b/
  };
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const regex = allowedPatterns[patternId] || /\b\w+\b/;
  
  const matches = content.match(regex) || [];
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req, res) {
  // Using a fixed pattern with user input as literal text to search for
  const searchText = req.cookies.searchText;
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const escapedText = escapeStringRegexp(searchText);
  const pattern = new RegExp(`\\b${escapedText}\\b`);
  
  const validStrings = ["foo", "bar", "baz"];
  const matches = validStrings.filter(str => pattern.test(str));
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req, res) {
  // Using a fixed regex pattern for email validation
  const emailList = ["user@example.com", "admin@example.com", "invalid-email"];
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const emailValidator = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$/;
  
  const validEmails = emailList.filter(email => emailValidator.test(email));
  res.json({ validEmails });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req, res) {
  // Using string methods instead of regex for simple pattern matching
  const userPattern = req.body.pattern || '';
  const text = "Sample text for testing patterns";
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const hasPattern = text.includes(userPattern);
  const position = text.indexOf(userPattern);
  
  res.json({ hasPattern, position });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req, res) {
  // Using a map of predefined regex patterns
  const patternType = req.body.type;
  const testString = "Test string for pattern matching";
  
  const patternMap = {
    'digits': /\d+/g,
    'words': /\b\w+\b/g,
    'spaces': /\s+/g
  };
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const regex = patternMap[patternType] || /./g;
  
  const matches = testString.match(regex) || [];
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req, res) {
  // Using exact string matching instead of regex
  const searchQuery = req.query.q || '';
  const content = "This is some searchable content";
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const found = content.toLowerCase().includes(searchQuery.toLowerCase());
  
  res.json({ found });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req, res) {
  // Using a fixed set of regex patterns
  const patternChoice = parseInt(req.query.pattern) || 0;
  const testStrings = ["abc123", "def456", "ghi789"];
  
  const patterns = [
    /^\w{3}\d{3}$/,
    /^[a-d]\w{2}\d{3}$/,
    /^[e-h]\w{2}\d{3}$/,
    /^[i-l]\w{2}\d{3}$/
  ];
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const selectedPattern = patterns[patternChoice % patterns.length];
  
  const matches = testStrings.filter(str => selectedPattern.test(str));
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req, res) {
  // Using a fixed regex with a literal search term
  const userInput = req.body.input || '';
  const wordList = ["apple", "banana", "cherry"];
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const matches = wordList.filter(word => word.includes(userInput));
  
  res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req, res) {
  // Using a predefined set of regex patterns
  const patternId = req.query.id;
  
  const validPatterns = {
    'email': /^[\w.-]+@[\w.-]+\.\w+$/,
    'phone': /^\d{3}-\d{3}-\d{4}$/,
    'date': /^\d{4}-\d{2}-\d{2}$/
  };
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const selectedPattern = validPatterns[patternId] || /./;
  
  const testString = "test@example.com";
  const isValid = selectedPattern.test(testString);
  
  res.json({ isValid });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req, res) {
  // Using a fixed regex for email validation
  const email = req.body.email;
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const emailRegex = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$/;
  
  const isValid = emailRegex.test(email);
  res.json({ isValid });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req, res) {
  // Using string methods for multiple search terms
  const searchTerms = req.query.terms ? req.query.terms.split(',') : [];
  const content = "This is content to search through";
  const results = {};
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  searchTerms.forEach((term, index) => {
    const count = (content.match(new RegExp(escapeStringRegexp(term), 'g')) || []).length;
    results[`term_${index}`] = {
      term,
      matches: count
    };
  });
  
  res.json(results);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req, res) {
  // Using a fixed set of filter functions instead of user-provided regex
  const filterType = req.query.filter || 'all';
  const dataList = ["item1", "item2", "item3"];
  
  const filters = {
    'all': () => true,
    'containsNumber': item => /\d/.test(item),
    'endsWithNumber': item => /\d$/.test(item)
  };
  
  // ok: javascript-do-not-construct-regular-expression-from-user-input
  const filterFn = filters[filterType] || filters['all'];
  
  const filteredList = dataList.filter(filterFn);
  res.json({ filtered: filteredList });
}
// {/fact}

// Export the app for testing
module.exports = app;