#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { SecurityStack } from "../lib/security-stack";
import { MemberStack } from "../lib/member-stack";

const app = new cdk.App();

// Deployment-specific values live in cdk.context.json (gitignored).
// Copy cdk.context.example.json to cdk.context.json and fill it in.
function requireContext(key: string): string {
  const value = app.node.tryGetContext(key);
  if (typeof value !== "string" || value === "") {
    throw new Error(
      `Missing context "${key}". Copy cdk.context.example.json to cdk.context.json and set it.`
    );
  }
  return value;
}

const securityAccountId = requireContext("securityAccountId");
const memberAccountId = requireContext("memberAccountId");
const region = requireContext("region");
// Optional. Set to your org ID (o-xxxxxxxxxx) once the accounts are in an
// Organization; the security stack then trusts the whole org.
const organizationId = (app.node.tryGetContext("organizationId") as string | undefined) || undefined;

// Shared names. Hardcoded on purpose so neither stack needs to look the
// other up at deploy time, which avoids the chicken-and-egg problem of
// cross-account references.
export const NAMES = {
  eventBus: "security-findings",
  lambdaRole: "s3-guardrail-remediator",
  memberRole: "s3-guardrail-remediation-target",
};

// Deploy this first: it needs to know the member account ID so it can
// allow that account to send events to the bus.
new SecurityStack(app, "SecurityStack", {
  env: { account: securityAccountId, region },
  memberAccountId,
  organizationId,
  names: NAMES,
});

// Deploy second: it points its rule at the security account bus and
// trusts the Lambda role that the security stack created.
new MemberStack(app, "MemberStack", {
  env: { account: memberAccountId, region },
  securityAccountId,
  names: NAMES,
});
