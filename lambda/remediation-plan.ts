import type { PublicAccessBlockConfiguration } from "@aws-sdk/client-s3";

export interface BucketExposure {
  policyPublic: boolean;
  /** undefined when the bucket has no Block Public Access configuration. */
  publicAccessBlock: PublicAccessBlockConfiguration | undefined;
}

export interface RemediationPlan {
  deletePolicy: boolean;
  enableBlockPublicAccess: boolean;
}

/**
 * Decide which writes are needed. Write only what is actually wrong: our own
 * PutBucketPublicAccessBlock call matches the trigger rule, so writing to an
 * already-safe bucket would re-trigger the guardrail forever.
 */
export function planRemediation(exposure: BucketExposure): RemediationPlan {
  const bpa = exposure.publicAccessBlock;
  const bpaFullyOn =
    bpa?.BlockPublicAcls === true &&
    bpa.IgnorePublicAcls === true &&
    bpa.BlockPublicPolicy === true &&
    bpa.RestrictPublicBuckets === true;
  return {
    deletePolicy: exposure.policyPublic,
    enableBlockPublicAccess: !bpaFullyOn,
  };
}
