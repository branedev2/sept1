import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';

// True positives (vulnerable code that should be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a state machine without enabling X-Ray tracing
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine1', {
    definition: new sfn.Pass(scope, 'Pass'),
    stateMachineType: sfn.StateMachineType.STANDARD,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const task = new sfn.Task(scope, 'InvokeFunction', {
    task: new tasks.LambdaInvoke(scope, 'LambdaTask', {
      lambdaFunction: lambda.Function.fromFunctionArn(scope, 'ImportedFunction', 'arn:aws:lambda:us-east-1:123456789012:function:my-function'),
    }),
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine2', {
    definition: task,
    timeout: cdk.Duration.minutes(5),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const definition = new sfn.Pass(scope, 'StartState', {
    result: sfn.Result.fromObject({ message: 'Hello World' }),
  });
  
  // Explicitly setting tracingEnabled to false
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine3', {
    definition,
    tracingEnabled: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const wait = new sfn.Wait(scope, 'Wait', {
    time: sfn.WaitTime.duration(cdk.Duration.seconds(10)),
  });
  
  const pass = new sfn.Pass(scope, 'Pass');
  
  const definition = wait.next(pass);
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine4', {
    definition,
    stateMachineType: sfn.StateMachineType.EXPRESS,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const lambdaFn = new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromInline('exports.handler = async () => { return "Hello"; }'),
  });
  
  const task = new tasks.LambdaInvoke(scope, 'InvokeFunction', {
    lambdaFunction: lambdaFn,
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine5', {
    definition: task,
    logs: {
      destination: new logs.LogGroup(scope, 'LogGroup'),
      level: sfn.LogLevel.ALL,
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const props = {
    definition: new sfn.Pass(scope, 'Pass'),
    stateMachineType: sfn.StateMachineType.STANDARD,
  };
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine6', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const choice = new sfn.Choice(scope, 'Choice')
    .when(sfn.Condition.stringEquals('$.status', 'SUCCESS'), new sfn.Pass(scope, 'Success'))
    .otherwise(new sfn.Pass(scope, 'Failure'));
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine7', {
    definition: choice,
    timeout: cdk.Duration.minutes(30),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const map = new sfn.Map(scope, 'Map', {
    maxConcurrency: 10,
    itemsPath: '$.items',
  });
  map.iterator(new sfn.Pass(scope, 'ProcessItem'));
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine8', {
    definition: map,
    stateMachineType: sfn.StateMachineType.EXPRESS,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const parallel = new sfn.Parallel(scope, 'Parallel');
  parallel.branch(new sfn.Pass(scope, 'Branch1'));
  parallel.branch(new sfn.Pass(scope, 'Branch2'));
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine9', {
    definition: parallel,
    stateMachineType: sfn.StateMachineType.STANDARD,
    role: new iam.Role(scope, 'Role', {
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com'),
    }),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const task = new tasks.SnsPublish(scope, 'Publish', {
    topic: { topicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic' },
    message: sfn.TaskInput.fromText('Hello from Step Functions!'),
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine10', {
    definition: task,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const succeed = new sfn.Succeed(scope, 'Succeed');
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine11', {
    definition: succeed,
    stateMachineType: sfn.StateMachineType.STANDARD,
    timeout: cdk.Duration.hours(1),
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const fail = new sfn.Fail(scope, 'Fail', {
    cause: 'Something went wrong',
    error: 'ErrorCode',
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine12', {
    definition: fail,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const task = new tasks.DynamoPutItem(scope, 'PutItem', {
    item: {
      id: tasks.DynamoAttributeValue.fromString('123'),
      value: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.value')),
    },
    tableName: 'my-table',
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine13', {
    definition: task,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const config = {
    definition: new sfn.Pass(scope, 'Pass'),
    stateMachineType: sfn.StateMachineType.EXPRESS,
    timeout: cdk.Duration.minutes(5),
  };
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine14', config);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const wait = new sfn.Wait(scope, 'Wait15', {
    time: sfn.WaitTime.timestampPath('$.triggerTime'),
  });
  
  // ruleid: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine15', {
    definition: wait,
    stateMachineType: sfn.StateMachineType.STANDARD,
    comment: 'This is a state machine without X-Ray tracing',
  });
}
// {/fact}

// True negatives (secure code that should not be detected)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Properly enabling X-Ray tracing
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine1', {
    definition: new sfn.Pass(scope, 'Pass'),
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const task = new sfn.Task(scope, 'InvokeFunction', {
    task: new tasks.LambdaInvoke(scope, 'LambdaTask', {
      lambdaFunction: lambda.Function.fromFunctionArn(scope, 'ImportedFunction', 'arn:aws:lambda:us-east-1:123456789012:function:my-function'),
    }),
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine2', {
    definition: task,
    timeout: cdk.Duration.minutes(5),
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const definition = new sfn.Pass(scope, 'StartState', {
    result: sfn.Result.fromObject({ message: 'Hello World' }),
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine3', {
    definition,
    tracingEnabled: true,
    stateMachineType: sfn.StateMachineType.STANDARD,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const wait = new sfn.Wait(scope, 'Wait', {
    time: sfn.WaitTime.duration(cdk.Duration.seconds(10)),
  });
  
  const pass = new sfn.Pass(scope, 'Pass');
  
  const definition = wait.next(pass);
  
  // ok: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine4', {
    definition,
    stateMachineType: sfn.StateMachineType.EXPRESS,
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const lambdaFn = new lambda.Function(scope, 'MyFunction', {
    runtime: lambda.Runtime.NODEJS_14_X,
    handler: 'index.handler',
    code: lambda.Code.fromInline('exports.handler = async () => { return "Hello"; }'),
  });
  
  const task = new tasks.LambdaInvoke(scope, 'InvokeFunction', {
    lambdaFunction: lambdaFn,
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine5', {
    definition: task,
    logs: {
      destination: new logs.LogGroup(scope, 'LogGroup'),
      level: sfn.LogLevel.ALL,
    },
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const props = {
    definition: new sfn.Pass(scope, 'Pass'),
    stateMachineType: sfn.StateMachineType.STANDARD,
    tracingEnabled: true,
  };
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine6', props);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const choice = new sfn.Choice(scope, 'Choice')
    .when(sfn.Condition.stringEquals('$.status', 'SUCCESS'), new sfn.Pass(scope, 'Success'))
    .otherwise(new sfn.Pass(scope, 'Failure'));
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine7', {
    definition: choice,
    timeout: cdk.Duration.minutes(30),
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const map = new sfn.Map(scope, 'Map', {
    maxConcurrency: 10,
    itemsPath: '$.items',
  });
  map.iterator(new sfn.Pass(scope, 'ProcessItem'));
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine8', {
    definition: map,
    stateMachineType: sfn.StateMachineType.EXPRESS,
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const parallel = new sfn.Parallel(scope, 'Parallel');
  parallel.branch(new sfn.Pass(scope, 'Branch1'));
  parallel.branch(new sfn.Pass(scope, 'Branch2'));
  
  // ok: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine9', {
    definition: parallel,
    stateMachineType: sfn.StateMachineType.STANDARD,
    role: new iam.Role(scope, 'Role', {
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com'),
    }),
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const task = new tasks.SnsPublish(scope, 'Publish', {
    topic: { topicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic' },
    message: sfn.TaskInput.fromText('Hello from Step Functions!'),
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine10', {
    definition: task,
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const succeed = new sfn.Succeed(scope, 'Succeed');
  
  // Using a variable to store configuration with tracing enabled
  const stateMachineProps = {
    definition: succeed,
    stateMachineType: sfn.StateMachineType.STANDARD,
    timeout: cdk.Duration.hours(1),
    tracingEnabled: true,
  };
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine11', stateMachineProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const fail = new sfn.Fail(scope, 'Fail', {
    cause: 'Something went wrong',
    error: 'ErrorCode',
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine12', {
    definition: fail,
    tracingEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const task = new tasks.DynamoPutItem(scope, 'PutItem', {
    item: {
      id: tasks.DynamoAttributeValue.fromString('123'),
      value: tasks.DynamoAttributeValue.fromString(sfn.JsonPath.stringAt('$.value')),
    },
    tableName: 'my-table',
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine13', {
    definition: task,
    tracingEnabled: true,
    stateMachineType: sfn.StateMachineType.EXPRESS,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const config = {
    definition: new sfn.Pass(scope, 'Pass'),
    stateMachineType: sfn.StateMachineType.EXPRESS,
    timeout: cdk.Duration.minutes(5),
    tracingEnabled: true,
  };
  
  // ok: typescript_cdk_step_function_state_machine_xray
  new sfn.StateMachine(scope, 'StateMachine14', config);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const wait = new sfn.Wait(scope, 'Wait15', {
    time: sfn.WaitTime.timestampPath('$.triggerTime'),
  });
  
  // ok: typescript_cdk_step_function_state_machine_xray
  const stateMachine = new sfn.StateMachine(scope, 'StateMachine15', {
    definition: wait,
    stateMachineType: sfn.StateMachineType.STANDARD,
    comment: 'This is a state machine with X-Ray tracing',
    tracingEnabled: true,
  });
}
// {/fact}