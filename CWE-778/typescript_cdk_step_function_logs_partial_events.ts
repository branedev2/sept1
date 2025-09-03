import * as cdk from 'aws-cdk-lib';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

// True Positive Examples (Vulnerable Code)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1() {
  const stack = new cdk.Stack();
  
  // Creating a state machine without specifying logging configuration
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging but not including ALL events
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ERROR,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging but only including FATAL events
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.FATAL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4() {
  const stack = new cdk.Stack();
  
  // Creating a state machine with logging configuration but not specifying level
  // ruleid: typescript_cdk_step_function_logs_partial_events
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      // No log level specified, defaults to ERROR
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5() {
  const stack = new cdk.Stack();
  
  // Creating a state machine with logging but using a variable that's set to ERROR
  const logLevel = sfn.LogLevel.ERROR;
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: logLevel,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const logGroup = new logs.LogGroup(this, 'LogGroup');
      
      // Creating a state machine in a class with insufficient logging
      // ruleid: typescript_cdk_step_function_logs_partial_events
      new sfn.StateMachine(this, 'StateMachine', {
        definition: new sfn.Pass(this, 'Pass'),
        logs: {
          destination: logGroup,
          level: sfn.LogLevel.ERROR,
        },
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging configuration in a conditional block
  const isProd = process.env.ENV === 'prod';
  
  if (isProd) {
    // ruleid: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, 'StateMachine', {
      definition: new sfn.Pass(stack, 'Pass'),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ERROR,
      },
    });
  } else {
    // ruleid: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, 'StateMachine', {
      definition: new sfn.Pass(stack, 'Pass'),
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8() {
  const stack = new cdk.Stack();
  
  // Function that creates a state machine with insufficient logging
  function createStateMachine(id: string) {
    const logGroup = new logs.LogGroup(stack, `${id}LogGroup`);
    
    // ruleid: typescript_cdk_step_function_logs_partial_events
    return new sfn.StateMachine(stack, id, {
      definition: new sfn.Pass(stack, `${id}Pass`),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ERROR,
      },
    });
  }
  
  createStateMachine('StateMachine1');
  createStateMachine('StateMachine2');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Using object spread to create state machine options
  const baseOptions = {
    definition: new sfn.Pass(stack, 'Pass'),
  };
  
  const loggingOptions = {
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ERROR,
    },
  };
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    ...baseOptions,
    ...loggingOptions,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging but using a dynamic log level that's not ALL
  function getLogLevel() {
    return sfn.LogLevel.ERROR;
  }
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: getLogLevel(),
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11() {
  const stack = new cdk.Stack();
  
  // Creating multiple state machines with different configurations but all insufficient
  const logGroup1 = new logs.LogGroup(stack, 'LogGroup1');
  const logGroup2 = new logs.LogGroup(stack, 'LogGroup2');
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine1', {
    definition: new sfn.Pass(stack, 'Pass1'),
    logs: {
      destination: logGroup1,
      level: sfn.LogLevel.ERROR,
    },
  });
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine2', {
    definition: new sfn.Pass(stack, 'Pass2'),
    logs: {
      destination: logGroup2,
      level: sfn.LogLevel.FATAL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging in a loop but all with insufficient logging
  const stateNames = ['State1', 'State2', 'State3'];
  
  for (const name of stateNames) {
    // ruleid: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, `StateMachine-${name}`, {
      definition: new sfn.Pass(stack, `Pass-${name}`),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ERROR,
      },
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13() {
  const stack = new cdk.Stack();
  
  // Creating a state machine with a more complex definition but still insufficient logging
  const definition = new sfn.Choice(stack, 'Choice')
    .when(sfn.Condition.stringEquals('$.status', 'SUCCESS'), new sfn.Pass(stack, 'Success'))
    .otherwise(new sfn.Fail(stack, 'Fail'));
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition,
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ERROR,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14() {
  const stack = new cdk.Stack();
  
  // Creating a state machine with no logging configuration at all
  const definition = new sfn.Pass(stack, 'Pass');
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  const stateMachine = new sfn.StateMachine(stack, 'StateMachine', {
    definition,
    // No logs property at all
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging but using a variable that might be set to ERROR
  let logLevel: sfn.LogLevel;
  
  if (Math.random() > 0.5) {
    logLevel = sfn.LogLevel.ERROR;
  } else {
    logLevel = sfn.LogLevel.FATAL;
  }
  
  // ruleid: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: logLevel,
    },
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with ALL logging level
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ALL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging using a variable that's set to ALL
  const logLevel = sfn.LogLevel.ALL;
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: logLevel,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3() {
  class MyStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const logGroup = new logs.LogGroup(this, 'LogGroup');
      
      // Creating a state machine in a class with ALL logging
      // ok: typescript_cdk_step_function_logs_partial_events
      new sfn.StateMachine(this, 'StateMachine', {
        definition: new sfn.Pass(this, 'Pass'),
        logs: {
          destination: logGroup,
          level: sfn.LogLevel.ALL,
        },
      });
    }
  }
  
  const app = new cdk.App();
  new MyStack(app, 'MyStack');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging configuration in a conditional block, both with ALL
  const isProd = process.env.ENV === 'prod';
  
  if (isProd) {
    // ok: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, 'StateMachine', {
      definition: new sfn.Pass(stack, 'Pass'),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
    });
  } else {
    // ok: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, 'StateMachine', {
      definition: new sfn.Pass(stack, 'Pass'),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5() {
  const stack = new cdk.Stack();
  
  // Function that creates a state machine with ALL logging
  function createStateMachine(id: string) {
    const logGroup = new logs.LogGroup(stack, `${id}LogGroup`);
    
    // ok: typescript_cdk_step_function_logs_partial_events
    return new sfn.StateMachine(stack, id, {
      definition: new sfn.Pass(stack, `${id}Pass`),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
    });
  }
  
  createStateMachine('StateMachine1');
  createStateMachine('StateMachine2');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Using object spread to create state machine options with ALL logging
  const baseOptions = {
    definition: new sfn.Pass(stack, 'Pass'),
  };
  
  const loggingOptions = {
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ALL,
    },
  };
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    ...baseOptions,
    ...loggingOptions,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging using a function that returns ALL
  function getLogLevel() {
    return sfn.LogLevel.ALL;
  }
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: getLogLevel(),
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8() {
  const stack = new cdk.Stack();
  
  // Creating multiple state machines with different configurations but all with ALL logging
  const logGroup1 = new logs.LogGroup(stack, 'LogGroup1');
  const logGroup2 = new logs.LogGroup(stack, 'LogGroup2');
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine1', {
    definition: new sfn.Pass(stack, 'Pass1'),
    logs: {
      destination: logGroup1,
      level: sfn.LogLevel.ALL,
    },
  });
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine2', {
    definition: new sfn.Pass(stack, 'Pass2'),
    logs: {
      destination: logGroup2,
      level: sfn.LogLevel.ALL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating state machines in a loop, all with ALL logging
  const stateNames = ['State1', 'State2', 'State3'];
  
  for (const name of stateNames) {
    // ok: typescript_cdk_step_function_logs_partial_events
    new sfn.StateMachine(stack, `StateMachine-${name}`, {
      definition: new sfn.Pass(stack, `Pass-${name}`),
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
    });
  }
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10() {
  const stack = new cdk.Stack();
  
  // Creating a state machine with a more complex definition and ALL logging
  const definition = new sfn.Choice(stack, 'Choice')
    .when(sfn.Condition.stringEquals('$.status', 'SUCCESS'), new sfn.Pass(stack, 'Success'))
    .otherwise(new sfn.Fail(stack, 'Fail'));
  
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition,
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ALL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging using a constant
  const ALL_LOG_LEVEL = sfn.LogLevel.ALL;
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: ALL_LOG_LEVEL,
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with logging using an environment-based approach
  const getLogLevel = () => {
    if (process.env.DEBUG === 'true') {
      return sfn.LogLevel.ALL;
    }
    return sfn.LogLevel.ALL; // Still using ALL even in non-debug mode
  };
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: getLogLevel(),
    },
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with ALL logging and additional properties
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', {
    definition: new sfn.Pass(stack, 'Pass'),
    logs: {
      destination: logGroup,
      level: sfn.LogLevel.ALL,
      includeExecutionData: true,
    },
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with ALL logging using a factory pattern
  class StateMachineFactory {
    static create(stack: cdk.Stack, id: string) {
      // ok: typescript_cdk_step_function_logs_partial_events
      return new sfn.StateMachine(stack, id, {
        definition: new sfn.Pass(stack, `${id}Pass`),
        logs: {
          destination: logGroup,
          level: sfn.LogLevel.ALL,
        },
      });
    }
  }
  
  StateMachineFactory.create(stack, 'StateMachine');
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15() {
  const stack = new cdk.Stack();
  const logGroup = new logs.LogGroup(stack, 'LogGroup');
  
  // Creating a state machine with ALL logging using a higher-order function
  const withAllLogging = (options: Partial<sfn.StateMachineProps>) => {
    return {
      ...options,
      logs: {
        destination: logGroup,
        level: sfn.LogLevel.ALL,
      },
    };
  };
  
  // ok: typescript_cdk_step_function_logs_partial_events
  new sfn.StateMachine(stack, 'StateMachine', withAllLogging({
    definition: new sfn.Pass(stack, 'Pass'),
  }));
}
// {/fact}