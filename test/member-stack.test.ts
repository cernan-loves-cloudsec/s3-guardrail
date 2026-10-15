import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as cdk from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { MemberStack } from "../lib/member-stack";

// The member template is deployed as a service-managed StackSet, including to
// accounts that were never CDK-bootstrapped. These tests pin that it stays
// self-contained.

function synthMemberTemplate(): Template {
  const app = new cdk.App();
  const stack = new MemberStack(app, "MemberStack", {
    env: { account: "222222222222", region: "us-west-1" },
    securityAccountId: "111111111111",
    names: {
      eventBus: "security-findings",
      lambdaRole: "s3-guardrail-remediator",
      memberRole: "s3-guardrail-remediation-target",
    },
  });
  return Template.fromStack(stack);
}

test("has no bootstrap version parameter or rule", () => {
  const json = synthMemberTemplate().toJSON();
  assert.equal(json.Parameters?.BootstrapVersion, undefined);
  assert.equal(json.Rules?.CheckBootstrapVersion, undefined);
});

test("has no Lambda-backed custom resources", () => {
  const template = synthMemberTemplate();
  template.resourceCountIs("Custom::S3AutoDeleteObjects", 0);
  template.resourceCountIs("AWS::Lambda::Function", 0);
});

test("does not reference the CDK bootstrap asset bucket", () => {
  const body = JSON.stringify(synthMemberTemplate().toJSON());
  assert.doesNotMatch(body, /cdk-hnb659fds/);
});

test("retains the trail bucket so stack deletion cannot fail on a non-empty bucket", () => {
  synthMemberTemplate().hasResource("AWS::S3::Bucket", {
    DeletionPolicy: "Retain",
    UpdateReplacePolicy: "Retain",
  });
});
