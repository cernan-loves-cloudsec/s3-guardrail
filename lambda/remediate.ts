import type { EventBridgeEvent } from "aws-lambda";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import {
  S3Client,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
  DeleteBucketPolicyCommand,
  PutPublicAccessBlockCommand,
  type PublicAccessBlockConfiguration,
} from "@aws-sdk/client-s3";
import { planRemediation } from "./remediation-plan";

// Shape of the CloudTrail detail we care about. CloudTrail events have far
// more fields; we only type what we read.
interface S3CloudTrailDetail {
  eventName: string;
  awsRegion: string;
  requestParameters?: { bucketName?: string };
  userIdentity?: { arn?: string };
}

const sts = new STSClient({});
const MEMBER_ROLE_NAME = process.env.MEMBER_ROLE_NAME!;

/**
 * Assume the remediation role in the account that emitted the event and
 * return an S3 client that uses those temporary credentials.
 */
async function s3ClientForAccount(accountId: string, region: string): Promise<S3Client> {
  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: `arn:aws:iam::${accountId}:role/${MEMBER_ROLE_NAME}`,
      RoleSessionName: `s3-guardrail-${Date.now()}`,
      DurationSeconds: 900,
    })
  );
  const c = assumed.Credentials!;
  return new S3Client({
    region,
    credentials: {
      accessKeyId: c.AccessKeyId!,
      secretAccessKey: c.SecretAccessKey!,
      sessionToken: c.SessionToken!,
    },
  });
}

async function isBucketPolicyPublic(s3: S3Client, bucket: string): Promise<boolean> {
  try {
    const res = await s3.send(new GetBucketPolicyStatusCommand({ Bucket: bucket }));
    return res.PolicyStatus?.IsPublic === true;
  } catch (err: any) {
    // No policy at all is the common case; treat as not public.
    if (err?.name === "NoSuchBucketPolicy") return false;
    throw err;
  }
}

async function getPublicAccessBlock(
  s3: S3Client,
  bucket: string
): Promise<PublicAccessBlockConfiguration | undefined> {
  try {
    const res = await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket }));
    return res.PublicAccessBlockConfiguration;
  } catch (err: any) {
    // No configuration at all means every flag is effectively off.
    if (err?.name === "NoSuchPublicAccessBlockConfiguration") return undefined;
    throw err;
  }
}

export async function handler(
  event: EventBridgeEvent<"AWS API Call via CloudTrail", S3CloudTrailDetail>
): Promise<void> {
  const accountId = event.account;
  const { eventName, awsRegion, requestParameters, userIdentity } = event.detail;
  const bucket = requestParameters?.bucketName;

  if (!bucket) {
    console.log(JSON.stringify({ msg: "no bucketName in event, skipping", eventName }));
    return;
  }

  console.log(
    JSON.stringify({
      msg: "evaluating",
      accountId,
      bucket,
      eventName,
      actor: userIdentity?.arn,
    })
  );

  const s3 = await s3ClientForAccount(accountId, awsRegion);

  // ASSESS: is the bucket actually public right now? The event only tells us
  // something *changed*; it might have been a change toward safety.
  const policyPublic = await isBucketPolicyPublic(s3, bucket);
  const publicAccessBlock = await getPublicAccessBlock(s3, bucket);
  const plan = planRemediation({ policyPublic, publicAccessBlock });

  // REMEDIATE. Write only what is wrong. Our own PutBucketPublicAccessBlock
  // matches the trigger rule, so an unconditional write would loop forever.
  // Each step is still idempotent, which matters because EventBridge
  // delivers at-least-once.
  const actions: string[] = [];

  if (plan.deletePolicy) {
    await s3.send(new DeleteBucketPolicyCommand({ Bucket: bucket }));
    actions.push("deleted-public-bucket-policy");
  }

  if (plan.enableBlockPublicAccess) {
    await s3.send(
      new PutPublicAccessBlockCommand({
        Bucket: bucket,
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      })
    );
    actions.push("enabled-block-public-access");
  }

  if (actions.length === 0) {
    console.log(JSON.stringify({ msg: "already safe, no action", accountId, bucket, eventName }));
    return;
  }

  // AUDIT. In the full design this is a DynamoDB write with the prior state.
  console.log(
    JSON.stringify({
      msg: "remediated",
      accountId,
      bucket,
      triggeringEvent: eventName,
      actor: userIdentity?.arn,
      wasPolicyPublic: policyPublic,
      actions,
    })
  );
}
