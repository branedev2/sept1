// File: incorrect_suffix_check_examples.ts

/**
 * Examples demonstrating incorrect and correct suffix checking in TypeScript
 * Rule ID: typescript-incorrect-suffix-check
 */

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(): boolean {
  const filename = "document.pdf";
  const extension = ".pdf";
  // ruleid: typescript-incorrect-suffix-check
  return filename.indexOf(extension) == filename.length - extension.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(): boolean {
  const url = "https://example.com/api/v1";
  const apiSuffix = "/api/v1";
  // ruleid: typescript-incorrect-suffix-check
  return url.indexOf(apiSuffix) === url.length - apiSuffix.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(): boolean {
  const email = "user@example.com";
  const domain = "example.com";
  // ruleid: typescript-incorrect-suffix-check
  return email.lastIndexOf(domain) == email.length - domain.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(): void {
  const filePath = "/home/user/documents/report.docx";
  const fileExtension = ".docx";
  // ruleid: typescript-incorrect-suffix-check
  if (filePath.indexOf(fileExtension) === filePath.length - fileExtension.length) {
    console.log("This is a Word document");
  } else {
    console.log("This is not a Word document");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(): boolean {
  const hostname = "server-prod-01";
  const environmentSuffix = "-prod-";
  // ruleid: typescript-incorrect-suffix-check
  return hostname.indexOf(environmentSuffix) === hostname.length - environmentSuffix.length - 2;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(input: string): boolean {
  const validSuffix = "Token";
  // ruleid: typescript-incorrect-suffix-check
  return input.lastIndexOf(validSuffix) === input.length - validSuffix.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(): void {
  const cssClass = "btn-primary-large";
  const suffix = "-large";
  // ruleid: typescript-incorrect-suffix-check
  if (cssClass.indexOf(suffix) == cssClass.length - suffix.length) {
    console.log("This is a large button");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(): boolean {
  const version = "v2.0.1-beta";
  const betaSuffix = "-beta";
  // ruleid: typescript-incorrect-suffix-check
  return version.lastIndexOf(betaSuffix) === version.length - betaSuffix.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(): string {
  const filename = "report_2023_Q1.xlsx";
  const quarterSuffix = "_Q1";
  // ruleid: typescript-incorrect-suffix-check
  if (filename.indexOf(quarterSuffix) == filename.length - quarterSuffix.length - 5) {
    return "First quarter report";
  }
  return "Other report";
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(): boolean {
  const url = "https://api.example.org/endpoint";
  const apiPrefix = "api.";
  const urlWithoutProtocol = url.replace("https://", "");
  // ruleid: typescript-incorrect-suffix-check
  return urlWithoutProtocol.indexOf(apiPrefix) === 0;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(): void {
  const logMessage = "Operation completed with status: ERROR";
  const errorSuffix = "ERROR";
  // ruleid: typescript-incorrect-suffix-check
  if (logMessage.indexOf(errorSuffix) === logMessage.length - errorSuffix.length) {
    console.error("An error occurred");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(): boolean {
  const packageName = "@company/component-lib";
  const orgPrefix = "@company/";
  // ruleid: typescript-incorrect-suffix-check
  return packageName.indexOf(orgPrefix) === 0;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(): string {
  const configKey = "app:feature:enabled";
  const featurePrefix = "app:feature:";
  // ruleid: typescript-incorrect-suffix-check
  if (configKey.indexOf(featurePrefix) === 0) {
    return "Feature configuration found";
  }
  return "Not a feature configuration";
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(): boolean {
  const imagePath = "/assets/images/logo.png";
  const imageExtension = ".png";
  // ruleid: typescript-incorrect-suffix-check
  return imagePath.lastIndexOf(imageExtension) === imagePath.length - imageExtension.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(): void {
  const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
  const windowsSignature = "Windows";
  // ruleid: typescript-incorrect-suffix-check
  if (userAgent.indexOf(windowsSignature) !== -1) {
    const isWindows10 = userAgent.indexOf("Windows NT 10.0") === userAgent.indexOf("Windows");
    console.log(`Is Windows 10: ${isWindows10}`);
  }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(): boolean {
  const filename = "document.pdf";
  const extension = ".pdf";
  // ok: typescript-incorrect-suffix-check
  return filename.endsWith(extension);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(): boolean {
  const url = "https://example.com/api/v1";
  const apiSuffix = "/api/v1";
  // ok: typescript-incorrect-suffix-check
  return url.endsWith(apiSuffix);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(): boolean {
  const email = "user@example.com";
  const domain = "example.com";
  // ok: typescript-incorrect-suffix-check
  return email.endsWith(domain);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(): void {
  const filePath = "/home/user/documents/report.docx";
  const fileExtension = ".docx";
  // ok: typescript-incorrect-suffix-check
  if (filePath.endsWith(fileExtension)) {
    console.log("This is a Word document");
  } else {
    console.log("This is not a Word document");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(): boolean {
  const hostname = "server-prod-01";
  const environmentSuffix = "-01";
  // ok: typescript-incorrect-suffix-check
  return hostname.endsWith(environmentSuffix);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(input: string): boolean {
  const validSuffix = "Token";
  // ok: typescript-incorrect-suffix-check
  const index = input.lastIndexOf(validSuffix);
  return index !== -1 && index === input.length - validSuffix.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(): void {
  const cssClass = "btn-primary-large";
  const suffix = "-large";
  // ok: typescript-incorrect-suffix-check
  const index = cssClass.indexOf(suffix);
  if (index !== -1 && index === cssClass.length - suffix.length) {
    console.log("This is a large button");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(): boolean {
  const version = "v2.0.1-beta";
  const betaSuffix = "-beta";
  // ok: typescript-incorrect-suffix-check
  const index = version.lastIndexOf(betaSuffix);
  if (index === -1) {
    return false;
  }
  return index === version.length - betaSuffix.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(): string {
  const filename = "report_2023_Q1.xlsx";
  const quarterSuffix = "_Q1.xlsx";
  // ok: typescript-incorrect-suffix-check
  if (filename.endsWith(quarterSuffix)) {
    return "First quarter report";
  }
  return "Other report";
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(): boolean {
  const url = "https://api.example.org/endpoint";
  const apiPrefix = "api.";
  const urlWithoutProtocol = url.replace("https://", "");
  // ok: typescript-incorrect-suffix-check
  const index = urlWithoutProtocol.indexOf(apiPrefix);
  return index === 0;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(): void {
  const logMessage = "Operation completed with status: ERROR";
  const errorSuffix = "ERROR";
  // ok: typescript-incorrect-suffix-check
  if (logMessage.endsWith(errorSuffix)) {
    console.error("An error occurred");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(): boolean {
  const packageName = "@company/component-lib";
  const orgPrefix = "@company/";
  // ok: typescript-incorrect-suffix-check
  return packageName.startsWith(orgPrefix);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(): string {
  const configKey = "app:feature:enabled";
  const featurePrefix = "app:feature:";
  // ok: typescript-incorrect-suffix-check
  if (configKey.startsWith(featurePrefix)) {
    return "Feature configuration found";
  }
  return "Not a feature configuration";
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(): boolean {
  const imagePath = "/assets/images/logo.png";
  const imageExtension = ".png";
  // ok: typescript-incorrect-suffix-check
  const index = imagePath.lastIndexOf(imageExtension);
  if (index === -1) return false;
  return index === imagePath.length - imageExtension.length;
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(): void {
  const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
  const windowsSignature = "Windows";
  // ok: typescript-incorrect-suffix-check
  if (userAgent.includes(windowsSignature)) {
    const windowsIndex = userAgent.indexOf(windowsSignature);
    const isWindows10 = userAgent.indexOf("Windows NT 10.0") === windowsIndex;
    console.log(`Is Windows 10: ${isWindows10}`);
  }
}
// {/fact}