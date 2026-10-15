import { test } from "node:test";
import * as assert from "node:assert/strict";
import { planRemediation } from "../lambda/remediation-plan";

const ALL_ON = {
  BlockPublicAcls: true,
  IgnorePublicAcls: true,
  BlockPublicPolicy: true,
  RestrictPublicBuckets: true,
};

// Regression: the remediation's own PutBucketPublicAccessBlock call matches
// the trigger rule. If an already-safe bucket still gets a write, every
// remediation triggers another one, forever.
test("already-safe bucket needs no writes", () => {
  assert.deepEqual(planRemediation({ policyPublic: false, publicAccessBlock: ALL_ON }), {
    deletePolicy: false,
    enableBlockPublicAccess: false,
  });
});

test("public policy is deleted even when Block Public Access is already on", () => {
  assert.deepEqual(planRemediation({ policyPublic: true, publicAccessBlock: ALL_ON }), {
    deletePolicy: true,
    enableBlockPublicAccess: false,
  });
});

test("missing Block Public Access configuration is enabled", () => {
  assert.deepEqual(planRemediation({ policyPublic: true, publicAccessBlock: undefined }), {
    deletePolicy: true,
    enableBlockPublicAccess: true,
  });
});

for (const flag of Object.keys(ALL_ON) as (keyof typeof ALL_ON)[]) {
  test(`Block Public Access is re-enabled when only ${flag} is off`, () => {
    const plan = planRemediation({
      policyPublic: false,
      publicAccessBlock: { ...ALL_ON, [flag]: false },
    });
    assert.equal(plan.enableBlockPublicAccess, true);
  });
}
