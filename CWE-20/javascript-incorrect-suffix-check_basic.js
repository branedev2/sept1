// Examples for javascript-incorrect-suffix-check rule
// This rule detects incorrect usage of indexOf/lastIndexOf for suffix checking

// True Positives (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1() {
  const filename = "document.pdf";
  // ruleid: javascript-incorrect-suffix-check
  if (filename.indexOf(".pdf") == filename.length - 4) {
    console.log("This is a PDF file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2() {
  const url = "https://example.com/api/endpoint";
  // ruleid: javascript-incorrect-suffix-check
  if (url.lastIndexOf("/api") == url.length - 4) {
    console.log("This is an API endpoint");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3() {
  const email = "user@example.com";
  // ruleid: javascript-incorrect-suffix-check
  if (email.indexOf("@example.com") == email.length - 12) {
    console.log("This is an example.com email");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4() {
  const filePath = "/var/www/html/index.html";
  // ruleid: javascript-incorrect-suffix-check
  if (filePath.lastIndexOf(".html") >= filePath.length - 5) {
    console.log("This is an HTML file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5() {
  const userInput = document.getElementById("input").value;
  // ruleid: javascript-incorrect-suffix-check
  if (userInput.indexOf(".exe") == userInput.length - 4) {
    console.log("This is an executable file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6() {
  const filename = "report.docx";
  // ruleid: javascript-incorrect-suffix-check
  if (filename.lastIndexOf(".docx") >= filename.length - 5) {
    console.log("This is a Word document");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7() {
  const url = "https://example.com";
  // ruleid: javascript-incorrect-suffix-check
  if (url.indexOf(".com") == url.length - 4) {
    console.log("This is a .com domain");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8() {
  const imagePath = "/images/logo.png";
  // ruleid: javascript-incorrect-suffix-check
  const isPNG = imagePath.lastIndexOf(".png") == imagePath.length - 4;
  if (isPNG) {
    console.log("This is a PNG image");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9() {
  function checkFileExtension(filename) {
    // ruleid: javascript-incorrect-suffix-check
    return filename.indexOf(".jpg") == filename.length - 4;
  }
  
  const isJPG = checkFileExtension("photo.jpg");
  console.log("Is JPG:", isJPG);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10() {
  const cssFile = "styles.css";
  // ruleid: javascript-incorrect-suffix-check
  if (cssFile.lastIndexOf(".css") >= cssFile.length - 4) {
    console.log("This is a CSS file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11() {
  const hostname = "server-prod-01";
  // ruleid: javascript-incorrect-suffix-check
  if (hostname.indexOf("-prod") == hostname.length - 5) {
    console.log("This is a production server");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12() {
  const jsonFile = "data.json";
  // ruleid: javascript-incorrect-suffix-check
  const isJSON = jsonFile.lastIndexOf(".json") == jsonFile.length - 5;
  if (isJSON) {
    console.log("This is a JSON file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13() {
  const userAgent = navigator.userAgent;
  // ruleid: javascript-incorrect-suffix-check
  if (userAgent.indexOf("Firefox") == userAgent.length - 7) {
    console.log("Browser is Firefox");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14() {
  const version = "v1.2.3";
  // ruleid: javascript-incorrect-suffix-check
  if (version.lastIndexOf(".3") == version.length - 2) {
    console.log("Version ends with .3");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15() {
  const apiKey = "sk_test_abcdefghijklmnopqrstuvwxyz";
  // ruleid: javascript-incorrect-suffix-check
  if (apiKey.indexOf("sk_test") == 0 && apiKey.lastIndexOf("xyz") == apiKey.length - 3) {
    console.log("This is a test API key ending with xyz");
  }
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1() {
  const filename = "document.pdf";
  // ok: javascript-incorrect-suffix-check
  if (filename.endsWith(".pdf")) {
    console.log("This is a PDF file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2() {
  const url = "https://example.com/api/endpoint";
  // ok: javascript-incorrect-suffix-check
  if (url.endsWith("/api/endpoint")) {
    console.log("This is an API endpoint");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3() {
  const email = "user@example.com";
  // ok: javascript-incorrect-suffix-check
  const index = email.indexOf("@example.com");
  if (index !== -1 && index === email.length - 12) {
    console.log("This is an example.com email");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4() {
  const filePath = "/var/www/html/index.html";
  // ok: javascript-incorrect-suffix-check
  const index = filePath.lastIndexOf(".html");
  if (index !== -1 && index === filePath.length - 5) {
    console.log("This is an HTML file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5() {
  const userInput = document.getElementById("input").value;
  // ok: javascript-incorrect-suffix-check
  const suffix = ".exe";
  if (userInput.length >= suffix.length && 
      userInput.substring(userInput.length - suffix.length) === suffix) {
    console.log("This is an executable file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6() {
  const filename = "report.docx";
  // ok: javascript-incorrect-suffix-check
  if (filename.match(/\.docx$/)) {
    console.log("This is a Word document");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7() {
  const url = "https://example.com";
  // ok: javascript-incorrect-suffix-check
  const comIndex = url.indexOf(".com");
  if (comIndex !== -1 && comIndex + 4 === url.length) {
    console.log("This is a .com domain");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8() {
  const imagePath = "/images/logo.png";
  // ok: javascript-incorrect-suffix-check
  const isPNG = imagePath.slice(-4) === ".png";
  if (isPNG) {
    console.log("This is a PNG image");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9() {
  function checkFileExtension(filename) {
    // ok: javascript-incorrect-suffix-check
    return filename.endsWith(".jpg");
  }
  
  const isJPG = checkFileExtension("photo.jpg");
  console.log("Is JPG:", isJPG);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10() {
  const cssFile = "styles.css";
  // ok: javascript-incorrect-suffix-check
  const index = cssFile.lastIndexOf(".css");
  if (index !== -1 && index === cssFile.length - 4) {
    console.log("This is a CSS file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11() {
  const hostname = "server-prod-01";
  // ok: javascript-incorrect-suffix-check
  if (/-prod-\d+$/.test(hostname)) {
    console.log("This is a production server");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12() {
  const jsonFile = "data.json";
  // ok: javascript-incorrect-suffix-check
  const extension = jsonFile.split('.').pop();
  const isJSON = extension === "json";
  if (isJSON) {
    console.log("This is a JSON file");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13() {
  const userAgent = navigator.userAgent;
  // ok: javascript-incorrect-suffix-check
  if (userAgent.endsWith("Firefox")) {
    console.log("Browser is Firefox");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14() {
  const version = "v1.2.3";
  // ok: javascript-incorrect-suffix-check
  const parts = version.split('.');
  if (parts.length > 0 && parts[parts.length - 1] === "3") {
    console.log("Version ends with .3");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15() {
  const apiKey = "sk_test_abcdefghijklmnopqrstuvwxyz";
  // ok: javascript-incorrect-suffix-check
  if (apiKey.startsWith("sk_test") && apiKey.endsWith("xyz")) {
    console.log("This is a test API key ending with xyz");
  }
}
// {/fact}