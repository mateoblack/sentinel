#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SentinelTvmStack } from '../lib/sentinel-tvm-stack';

const app = new cdk.App();

// Read configuration from CDK context or environment variables
const policyParameter = app.node.tryGetContext('policyParameter')
  || process.env.SENTINEL_POLICY_PARAMETER
  || '/sentinel/policies/default';

const lambdaZipPath = app.node.tryGetContext('lambdaZipPath')
  || process.env.LAMBDA_ZIP_PATH
  || '../dist/lambda-tvm.zip';

const policyRoot = app.node.tryGetContext('policyRoot')
  || process.env.SENTINEL_POLICY_ROOT;

const sessionTable = app.node.tryGetContext('sessionTable')
  || process.env.SENTINEL_SESSION_TABLE;

const approvalTable = app.node.tryGetContext('approvalTable')
  || process.env.SENTINEL_APPROVAL_TABLE;

const breakglassTable = app.node.tryGetContext('breakglassTable')
  || process.env.SENTINEL_BREAKGLASS_TABLE;

const memorySize = parseInt(
  app.node.tryGetContext('memorySize') || process.env.LAMBDA_MEMORY_SIZE || '256',
  10
);

const timeout = parseInt(
  app.node.tryGetContext('timeout') || process.env.LAMBDA_TIMEOUT || '30',
  10
);

new SentinelTvmStack(app, 'SentinelTvmStack', {
  lambdaZipPath,
  policyParameter,
  policyRoot,
  sessionTable,
  approvalTable,
  breakglassTable,
  memorySize,
  timeout,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
