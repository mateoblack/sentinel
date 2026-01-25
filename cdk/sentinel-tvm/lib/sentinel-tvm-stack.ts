import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import { Construct } from 'constructs';

/**
 * Configuration properties for the Sentinel TVM stack.
 */
export interface SentinelTvmStackProps extends cdk.StackProps {
  /**
   * Path to the Lambda deployment package (zip file).
   */
  lambdaZipPath: string;

  /**
   * SSM Parameter path for Sentinel policies.
   * Example: /sentinel/policies/production
   */
  policyParameter: string;

  /**
   * Optional root path for policy hierarchy.
   */
  policyRoot?: string;

  /**
   * Optional DynamoDB table name for session tracking.
   */
  sessionTable?: string;

  /**
   * Optional DynamoDB table name for approval workflow.
   */
  approvalTable?: string;

  /**
   * Optional DynamoDB table name for break-glass access.
   */
  breakglassTable?: string;

  /**
   * Lambda memory size in MB. Default: 256
   */
  memorySize?: number;

  /**
   * Lambda timeout in seconds. Default: 30
   */
  timeout?: number;
}

/**
 * AWS CDK Stack for Sentinel Lambda TVM with API Gateway.
 *
 * This stack deploys:
 * - Lambda function running the Sentinel TVM binary
 * - HTTP API Gateway with IAM authorization
 * - IAM execution role with least-privilege permissions
 */
export class SentinelTvmStack extends cdk.Stack {
  /**
   * The HTTP API endpoint URL.
   */
  public readonly apiEndpoint: string;

  /**
   * The Lambda execution role ARN.
   */
  public readonly executionRoleArn: string;

  constructor(scope: Construct, id: string, props: SentinelTvmStackProps) {
    super(scope, id, props);

    const memorySize = props.memorySize ?? 256;
    const timeout = props.timeout ?? 30;

    // Build list of DynamoDB tables for IAM policy
    const dynamoTables: string[] = [];
    if (props.sessionTable) dynamoTables.push(props.sessionTable);
    if (props.approvalTable) dynamoTables.push(props.approvalTable);
    if (props.breakglassTable) dynamoTables.push(props.breakglassTable);

    // Create IAM execution role for Lambda
    const executionRole = new iam.Role(this, 'SentinelTvmExecutionRole', {
      roleName: 'SentinelTvmLambdaRole',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for Sentinel Lambda TVM',
    });

    // CloudWatch Logs permissions
    executionRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'CloudWatchLogs',
        effect: iam.Effect.ALLOW,
        actions: [
          'logs:CreateLogGroup',
          'logs:CreateLogStream',
          'logs:PutLogEvents',
        ],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/lambda/*`,
        ],
      })
    );

    // SSM Parameter Store permissions for policy retrieval
    executionRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'SSMGetPolicies',
        effect: iam.Effect.ALLOW,
        actions: ['ssm:GetParameter', 'ssm:GetParametersByPath'],
        resources: [
          `arn:aws:ssm:${this.region}:${this.account}:parameter/sentinel/policies/*`,
        ],
      })
    );

    // AssumeRole permission for credential vending
    // Only allows assuming roles prefixed with SentinelProtected-
    // Requires SourceIdentity to be set for audit trail
    executionRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'AssumeRoleSentinelProtected',
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRole', 'sts:SetSourceIdentity'],
        resources: [`arn:aws:iam::${this.account}:role/SentinelProtected-*`],
        conditions: {
          StringLike: {
            'sts:SourceIdentity': '*',
          },
        },
      })
    );

    // DynamoDB permissions (conditional - only if tables are specified)
    if (dynamoTables.length > 0) {
      executionRole.addToPolicy(
        new iam.PolicyStatement({
          sid: 'DynamoDBAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'dynamodb:UpdateItem',
            'dynamodb:DeleteItem',
            'dynamodb:Query',
          ],
          resources: dynamoTables.map(
            (table) => `arn:aws:dynamodb:${this.region}:${this.account}:table/${table}`
          ),
        })
      );
    }

    // Build Lambda environment variables
    const environment: Record<string, string> = {
      SENTINEL_POLICY_PARAMETER: props.policyParameter,
    };

    if (props.policyRoot) {
      environment['SENTINEL_POLICY_ROOT'] = props.policyRoot;
    }
    if (props.sessionTable) {
      environment['SENTINEL_SESSION_TABLE'] = props.sessionTable;
    }
    if (props.approvalTable) {
      environment['SENTINEL_APPROVAL_TABLE'] = props.approvalTable;
    }
    if (props.breakglassTable) {
      environment['SENTINEL_BREAKGLASS_TABLE'] = props.breakglassTable;
    }

    // Create Lambda function
    const tvmFunction = new lambda.Function(this, 'SentinelTvmFunction', {
      functionName: 'sentinel-tvm',
      description: 'Sentinel Token Vending Machine - issues temporary AWS credentials based on policy',
      runtime: lambda.Runtime.PROVIDED_AL2023,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.lambdaZipPath),
      role: executionRole,
      memorySize: memorySize,
      timeout: cdk.Duration.seconds(timeout),
      environment: environment,
      architecture: lambda.Architecture.ARM_64,
    });

    // Create HTTP API
    const httpApi = new apigatewayv2.HttpApi(this, 'SentinelTvmApi', {
      apiName: 'sentinel-tvm',
      description: 'Sentinel Token Vending Machine HTTP API',
    });

    // Create Lambda integration
    const lambdaIntegration = new integrations.HttpLambdaIntegration(
      'SentinelTvmIntegration',
      tvmFunction
    );

    // Add routes with IAM authorization
    // GET / - Request credentials for a profile
    httpApi.addRoutes({
      path: '/',
      methods: [apigatewayv2.HttpMethod.GET],
      integration: lambdaIntegration,
      authorizationType: apigatewayv2.HttpRouteAuthorizationType.AWS_IAM,
    });

    // POST / - Request credentials (alternative method)
    httpApi.addRoutes({
      path: '/',
      methods: [apigatewayv2.HttpMethod.POST],
      integration: lambdaIntegration,
      authorizationType: apigatewayv2.HttpRouteAuthorizationType.AWS_IAM,
    });

    // GET /profiles - List available profiles
    httpApi.addRoutes({
      path: '/profiles',
      methods: [apigatewayv2.HttpMethod.GET],
      integration: lambdaIntegration,
      authorizationType: apigatewayv2.HttpRouteAuthorizationType.AWS_IAM,
    });

    // Store outputs
    this.apiEndpoint = httpApi.apiEndpoint;
    this.executionRoleArn = executionRole.roleArn;

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: httpApi.apiEndpoint,
      description: 'HTTP API endpoint URL for Sentinel TVM',
      exportName: 'SentinelTvmApiEndpoint',
    });

    new cdk.CfnOutput(this, 'ExecutionRoleArn', {
      value: executionRole.roleArn,
      description: 'Lambda execution role ARN',
      exportName: 'SentinelTvmExecutionRoleArn',
    });

    new cdk.CfnOutput(this, 'LambdaFunctionArn', {
      value: tvmFunction.functionArn,
      description: 'Lambda function ARN',
      exportName: 'SentinelTvmLambdaArn',
    });
  }
}
