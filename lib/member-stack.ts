import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as cloudtrail from "aws-cdk-lib/aws-cloudtrail";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";

interface MemberStackProps extends cdk.StackProps {
  securityAccountId: string;
  names: { eventBus: string; lambdaRole: string; memberRole: string };
}

/**
 * Lives in the MEMBER account. In a real org this would be a StackSet
 * deployed to every account.
 *
 *   CloudTrail --> default event bus --rule--> security account bus
 *
 * Plus a role the security account's Lambda can assume to fix buckets here.
 */
export class MemberStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: MemberStackProps) {
    // This template is deployed as a service-managed StackSet to every account
    // in the OU, including accounts that were never CDK-bootstrapped. So it must
    // not depend on bootstrap resources: no version-check rule, and no assets.
    super(scope, id, {
      synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      ...props,
    });

    // 1. CloudTrail. EventBridge only receives "AWS API Call via CloudTrail"
    //    events when a trail is logging in the region. One management-event
    //    trail per account is free; the log bucket costs cents.
    const trailBucket = new s3.Bucket(this, "TrailBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      // RETAIN, not DESTROY + autoDeleteObjects: auto-delete is a custom-resource
      // Lambda whose code is an asset in the bootstrap bucket. Retaining also means
      // a stack instance deletion never fails on a non-empty log bucket.
      // Empty and delete the bucket by hand at teardown.
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    new cloudtrail.Trail(this, "Trail", {
      bucket: trailBucket,
      isMultiRegionTrail: false,
      includeGlobalServiceEvents: false,
      sendToCloudWatchLogs: false,
    });

    // 2. Rule on the DEFAULT bus: forward the interesting S3 calls to the
    //    security account. CDK creates the IAM role EventBridge needs to
    //    PutEvents cross-account.
    const securityBus = events.EventBus.fromEventBusArn(
      this,
      "SecurityBus",
      `arn:aws:events:${this.region}:${props.securityAccountId}:event-bus/${props.names.eventBus}`
    );

    new events.Rule(this, "ForwardS3Changes", {
      description: "Forward S3 bucket-exposure calls to the security account",
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
      targets: [new targets.EventBus(securityBus)],
    });

    // 3. The remediation target role. This is the most sensitive piece.
    //    Trust policy: ONLY the specific Lambda role in the security account.
    //    Permissions: ONLY what the fix needs. No wildcards.
    const remediationRole = new iam.Role(this, "RemediationTargetRole", {
      roleName: props.names.memberRole,
      assumedBy: new iam.ArnPrincipal(
        `arn:aws:iam::${props.securityAccountId}:role/${props.names.lambdaRole}`
      ),
      description: "Assumed by the security account guardrail to fix public S3 buckets",
    });
    remediationRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:DeleteBucketPolicy",
        ],
        resources: ["arn:aws:s3:::*"],
      })
    );

    new cdk.CfnOutput(this, "RemediationRoleArn", { value: remediationRole.roleArn });
  }
}
