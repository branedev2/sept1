import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_codepipeline as codepipeline } from 'aws-cdk-lib';
import { aws_codepipeline_actions as codepipeline_actions } from 'aws-cdk-lib';
import { aws_codebuild as codebuild } from 'aws-cdk-lib';
import { aws_iam as iam } from 'aws-cdk-lib';
import { Duration } from 'aws-cdk-lib';
import { PipelineDeployStackAction } from 'aws-cdk-lib/pipelines';
import { CodePipeline, ShellStep, ManualApprovalStep, CodePipelineSource, Step } from 'aws-cdk-lib/pipelines';

// True Positives (Vulnerable Code Examples)

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Prod'), {
    post: [
      new ShellStep('IntegrationTest', {
        commands: ['npm run integration-test']
      })
    ]
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stackSteps: [
      {
        stack: 'MainStack',
        changeSet: true,
      }
    ]
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  new PipelineDeployStackAction({
    stack: new cdk.Stack(app, 'DeployStack'),
    input: new codepipeline.Artifact(),
    adminPermissions: true,
    region: 'us-west-2',
    productionAccount: '123456789012',
    // No bake time specified for production deployment
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    pre: [
      new ManualApprovalStep('ApproveDeployment')
    ],
    // Missing bake time configuration
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Prod'));
  prodStage.addPost(new ShellStep('RunTests', {
    commands: ['npm run test']
  }));
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  const pipeline = new codepipeline.Pipeline(stack, 'ProductionPipeline', {
    crossAccountKeys: true,
    pipelineName: 'ProdDeployPipeline',
    // No bake time configuration for production pipeline
  });
  
  const deployAction = new codepipeline_actions.CloudFormationCreateUpdateStackAction({
    actionName: 'DeployToProduction',
    stackName: 'ProductionStack',
    templatePath: new codepipeline.Artifact().atPath('template.yaml'),
    adminPermissions: true,
  });
  
  pipeline.addStage({
    stageName: 'Deploy',
    actions: [deployAction],
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addWave('ProductionWave', {
    post: [
      new ShellStep('PostDeployTests', {
        commands: ['npm run integration-test']
      })
    ]
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stackSteps: [
      {
        stack: 'ProdStack',
        changeSet: true,
      }
    ],
    // Bake time is set to 0, which is insufficient
    stageBakeTime: Duration.seconds(0)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    // Bake time is too short for production (only 1 minute)
    stageBakeTime: Duration.minutes(1)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  new PipelineDeployStackAction({
    stack: new cdk.Stack(app, 'ProdStack'),
    input: new codepipeline.Artifact(),
    adminPermissions: true,
    region: 'us-east-1',
    productionAccount: '123456789012',
    // Bake time is too short (only 30 seconds)
    bakeTime: Duration.seconds(30)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    }),
    // ruleid: typescript-cdk-insufficient-bake-time-duration
    // No default bake time for the pipeline
  });
  
  pipeline.addStage(new MyApplicationStage(stack, 'Production'));
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Production'));
  
  // Adding wave without bake time
  pipeline.addWave('DeployWave', {
    stages: [prodStage]
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    // Bake time is set to 2 minutes, which is insufficient for production
    stageBakeTime: Duration.minutes(2)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  const deployAction = new codepipeline_actions.CloudFormationCreateUpdateStackAction({
    actionName: 'DeployToProduction',
    stackName: 'ProductionStack',
    templatePath: new codepipeline.Artifact().atPath('template.yaml'),
    adminPermissions: true,
    // No bake time specified for production deployment
  });
  
  const pipeline = new codepipeline.Pipeline(stack, 'ProductionPipeline');
  pipeline.addStage({
    stageName: 'Deploy',
    actions: [deployAction],
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ruleid: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    // Using a variable that could be set to an insufficient value
    stageBakeTime: getBakeTime()
  });
  
  function getBakeTime() {
    // This could return an insufficient bake time
    return Duration.minutes(3);
  }
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stageBakeTime: Duration.hours(2),
    post: [
      new ShellStep('IntegrationTest', {
        commands: ['npm run integration-test']
      })
    ]
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stackSteps: [
      {
        stack: 'MainStack',
        changeSet: true,
      }
    ],
    stageBakeTime: Duration.minutes(30)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  new PipelineDeployStackAction({
    stack: new cdk.Stack(app, 'DeployStack'),
    input: new codepipeline.Artifact(),
    adminPermissions: true,
    region: 'us-west-2',
    productionAccount: '123456789012',
    bakeTime: Duration.hours(1)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    pre: [
      new ManualApprovalStep('ApproveDeployment')
    ],
    stageBakeTime: Duration.minutes(45)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Prod'), {
    stageBakeTime: Duration.hours(1)
  });
  
  prodStage.addPost(new ShellStep('RunTests', {
    commands: ['npm run test']
  }));
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_6() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  const pipeline = new codepipeline.Pipeline(stack, 'ProductionPipeline', {
    crossAccountKeys: true,
    pipelineName: 'ProdDeployPipeline',
  });
  
  const deployAction = new codepipeline_actions.CloudFormationCreateUpdateStackAction({
    actionName: 'DeployToProduction',
    stackName: 'ProductionStack',
    templatePath: new codepipeline.Artifact().atPath('template.yaml'),
    adminPermissions: true,
    // For non-CDK pipelines, this is a development pipeline, so no bake time is required
  });
  
  pipeline.addStage({
    stageName: 'Deploy',
    actions: [deployAction],
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addWave('ProductionWave', {
    post: [
      new ShellStep('PostDeployTests', {
        commands: ['npm run integration-test']
      })
    ],
    stageBakeTime: Duration.hours(3)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stackSteps: [
      {
        stack: 'ProdStack',
        changeSet: true,
      }
    ],
    stageBakeTime: Duration.minutes(120)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'DevelopmentPipeline', // This is not a production pipeline
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Development'), {
    // No bake time needed for development pipeline
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  new PipelineDeployStackAction({
    stack: new cdk.Stack(app, 'ProdStack'),
    input: new codepipeline.Artifact(),
    adminPermissions: true,
    region: 'us-east-1',
    productionAccount: '123456789012',
    bakeTime: Duration.hours(2)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    }),
    // ok: typescript-cdk-insufficient-bake-time-duration
    defaultBakeTime: Duration.minutes(60)
  });
  
  pipeline.addStage(new MyApplicationStage(stack, 'Production'));
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Production'));
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addWave('DeployWave', {
    stages: [prodStage],
    stageBakeTime: Duration.hours(1)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  const prodStage = pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stageBakeTime: Duration.minutes(90)
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  // This is a test pipeline, not production
  const deployAction = new codepipeline_actions.CloudFormationCreateUpdateStackAction({
    actionName: 'DeployToTest',
    stackName: 'TestStack',
    templatePath: new codepipeline.Artifact().atPath('template.yaml'),
    adminPermissions: true,
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  const pipeline = new codepipeline.Pipeline(stack, 'TestPipeline');
  pipeline.addStage({
    stageName: 'Deploy',
    actions: [deployAction],
  });
}
// {/fact}

// {fact rule=mass-assignment@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  
  const pipeline = new CodePipeline(stack, 'Pipeline', {
    pipelineName: 'ProductionPipeline',
    synth: new ShellStep('Synth', {
      input: CodePipelineSource.gitHub('owner/repo', 'main'),
      commands: ['npm ci', 'npm run build', 'npx cdk synth']
    })
  });
  
  // ok: typescript-cdk-insufficient-bake-time-duration
  pipeline.addStage(new MyApplicationStage(stack, 'Production'), {
    stageBakeTime: getProductionBakeTime()
  });
  
  function getProductionBakeTime() {
    // Returns a sufficient bake time for production
    return Duration.hours(4);
  }
}
// {/fact}

// Helper class for examples
class MyApplicationStage extends cdk.Stage {
  constructor(scope: Construct, id: string, props?: cdk.StageProps) {
    super(scope, id, props);
    
    // Create stacks for this stage
    new cdk.Stack(this, 'MainStack');
  }
}