import express from 'express';
import helmet from 'helmet';

// True Positives (Vulnerable/Insecure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: false
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'no-referrer-when-downgrade'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'unsafe-url'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  const config = {
    referrerPolicy: false
  };
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet(config));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const policy = 'no-referrer-when-downgrade';
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policy
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const options = {
    policy: 'unsafe-url'
  };
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy(options));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  let policyType = 'unsafe-url';
  if (process.env.NODE_ENV === 'production') {
    policyType = 'unsafe-url'; // Still using unsafe policy
  }
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policyType
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const helmetConfig = {};
  helmetConfig['referrerPolicy'] = false;
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet(helmetConfig));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const securityOptions = {
    contentSecurityPolicy: true,
    referrerPolicy: false,
    xssFilter: true
  };
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet(securityOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  function getHelmetConfig() {
    return {
      referrerPolicy: false
    };
  }
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet(getHelmetConfig()));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const isDevEnvironment = process.env.NODE_ENV === 'development';
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: isDevEnvironment ? false : { policy: 'no-referrer-when-downgrade' }
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const policies = ['no-referrer', 'no-referrer-when-downgrade', 'unsafe-url'];
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policies[1] // This is 'no-referrer-when-downgrade'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const middlewares = [
    helmet({
      // ruleid: typescript-http-no-refer-policy
      referrerPolicy: false
    })
  ];
  app.use(middlewares[0]);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const configureHelmet = () => {
    return helmet.referrerPolicy({
      // ruleid: typescript-http-no-refer-policy
      policy: 'unsafe-url'
    });
  };
  app.use(configureHelmet());
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const referrerPolicyOptions = {
    policy: ['no-referrer-when-downgrade']
  };
  // ruleid: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy(referrerPolicyOptions));
  app.listen(3000);
}
// {/fact}

// True Negatives (Safe/Secure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: typescript-http-no-refer-policy
  app.use(helmet({
    referrerPolicy: true
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'no-referrer'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: 'same-origin'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const config = {
    referrerPolicy: true
  };
  // ok: typescript-http-no-refer-policy
  app.use(helmet(config));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  const policy = 'strict-origin';
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policy
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const options = {
    policy: 'origin'
  };
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy(options));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  let policyType = 'no-referrer';
  if (process.env.NODE_ENV === 'production') {
    policyType = 'strict-origin-when-cross-origin';
  }
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policyType
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const helmetConfig = {};
  helmetConfig['referrerPolicy'] = { policy: 'same-origin' };
  // ok: typescript-http-no-refer-policy
  app.use(helmet(helmetConfig));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const securityOptions = {
    contentSecurityPolicy: true,
    referrerPolicy: { policy: 'strict-origin' },
    xssFilter: true
  };
  // ok: typescript-http-no-refer-policy
  app.use(helmet(securityOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  function getHelmetConfig() {
    return {
      referrerPolicy: { policy: 'origin-when-cross-origin' }
    };
  }
  // ok: typescript-http-no-refer-policy
  app.use(helmet(getHelmetConfig()));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  // ok: typescript-http-no-refer-policy
  app.use(helmet()); // Default configuration is secure
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const policies = ['no-referrer', 'strict-origin', 'origin'];
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy({
    policy: policies[0] // This is 'no-referrer'
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  const middlewares = [
    helmet({
      // ok: typescript-http-no-refer-policy
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
    })
  ];
  app.use(middlewares[0]);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const configureHelmet = () => {
    return helmet.referrerPolicy({
      // ok: typescript-http-no-refer-policy
      policy: 'origin'
    });
  };
  app.use(configureHelmet());
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  const referrerPolicyOptions = {
    policy: ['strict-origin', 'origin-when-cross-origin']
  };
  // ok: typescript-http-no-refer-policy
  app.use(helmet.referrerPolicy(referrerPolicyOptions));
  app.listen(3000);
}
// {/fact}