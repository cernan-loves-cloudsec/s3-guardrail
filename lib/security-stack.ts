import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import * as path from "path";

interface SecurityStackProps extends cdk.StackProps {
  memberAccountId: string;
  /** If set, the bus trusts every account in this org instead of one account. */
  organizationId?: string;
  names: { eventBus: string; lambdaRole: string; memberRole: string };
}

/**
 * Lives in the SECURITY account.
 *
 *   member account  --PutEvents-->  custom event bus  --rule-->  remediation Lambda
 *
 * The Lambda then assumes a role back in the member account to fix the bucket.
 */
export class SecurityStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: SecurityStackProps) {
    super(scope, id, props);

    // 1. A custom event bus. Member accounts forward their findings here.
    const bus = new events.EventBus(this, "FindingsBus", {
      eventBusName: props.names.eventBus,
    });

    // 2. Resource policy: who may put events on this bus.
    //    This is the cross-account trust on the *inbound* side.
    //    With an org ID, any account in the org is allowed, so new accounts
    //    work with no change here. Without one, only the single member account.
    bus.addToResourcePolicy(
      props.organizationId
        ? new iam.PolicyStatement({
            sid: "AllowOrgPutEvents",
            effect: iam.Effect.ALLOW,
            principals: [new iam.AnyPrincipal()],
            actions: ["events:PutEvents"],
            resources: [bus.eventBusArn],
            conditions: {
              StringEquals: { "aws:PrincipalOrgID": props.organizationId },
            },
          })
        : new iam.PolicyStatement({
            sid: "AllowMemberAccountPutEvents",
            effect: iam.Effect.ALLOW,
            principals: [new iam.AccountPrincipal(props.memberAccountId)],
            actions: ["events:PutEvents"],
            resources: [bus.eventBusArn],
          })
    );

    // 3. The Lambda's execution role. Fixed name so the member stack can
    //    reference it in a trust policy without a cross-stack lookup.
    //    It can do exactly one thing outside its own account: assume the
    //    remediation role in member accounts.
    const lambdaRole = new iam.Role(this, "RemediatorRole", {
      roleName: props.names.lambdaRole,
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          "service-role/AWSLambdaBasicExecutionRole"
        ),
      ],
    });
    lambdaRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["sts:AssumeRole"],
        // Scoped to the specific role name, in any account...
        resources: [`arn:aws:iam::*:role/${props.names.memberRole}`],
        // ...but only accounts inside our org, when we have one.
        conditions: props.organizationId
          ? { StringEquals: { "aws:ResourceOrgID": props.organizationId } }
          : undefined,
      })
    );

    // 4. The remediation Lambda, bundled from TypeScript with esbuild.
    const remediator = new NodejsFunction(this, "Remediator", {
      entry: path.join(__dirname, "..", "lambda", "remediate.ts"),
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_24_X,
      role: lambdaRole,
      timeout: cdk.Duration.seconds(30),
      environment: {
        MEMBER_ROLE_NAME: props.names.memberRole,
      },
    });

    // 5. Rule: match S3 API calls that could expose a bucket, invoke the Lambda.
    //    In the full design SQS sits between the rule and the Lambda; omitted
    //    here to keep the project minimal. See README for the upgrade.
    new events.Rule(this, "PublicBucketRule", {
      eventBus: bus,
      description: "S3 calls that may make a bucket public",
      eventPattern: {
        source: ["aws.s3"],
        detailType: ["AWS API Call via CloudTrail"],
        detail: {
          eventSource: ["s3.amazonaws.com"],
          eventName: [
            "PutBucketPolicy",
            "PutBucketAcl",
            "DeleteBucketPublicAccessBlock",
            "PutBucketPublicAccessBlock",
          ],
        },
      },
      targets: [new targets.LambdaFunction(remediator)],
    });

    new cdk.CfnOutput(this, "EventBusArn", { value: bus.eventBusArn });
    new cdk.CfnOutput(this, "LambdaRoleArn", { value: lambdaRole.roleArn });
  }
}
