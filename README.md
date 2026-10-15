# S3 public-bucket guardrail (two-account demo)

The smallest working version of a cross-account auto-remediation guardrail.
When someone in a workload account makes an S3 bucket public, a Lambda in a separate security account notices within seconds and fixes it.

```
MEMBER ACCOUNT                           SECURITY ACCOUNT
--------------                           ----------------
someone makes a bucket public
        |
   CloudTrail logs the API call
        |
   default EventBridge bus
        |  rule: s3 PutBucketPolicy / PutBucketAcl / *PublicAccessBlock
        v
   PutEvents  --------------------->  custom bus "security-findings"
                                             |  rule
                                             v
                                     remediation Lambda (TypeScript)
                                             |  sts:AssumeRole
   role "s3-guardrail-remediation-target" <--+
        |
   delete public policy, enable Block Public Access
```



https://github.com/user-attachments/assets/22705b47-2a50-4d43-821d-5e34f1f103f8



## What each piece is for

| Piece | Account | Why it exists |
|---|---|---|
| CloudTrail trail | member | EventBridge only receives `AWS API Call via CloudTrail` events when a trail is logging. |
| Rule on default bus | member | Filters S3 exposure calls and forwards them cross-account. CDK auto-creates the PutEvents role. |
| `s3-guardrail-remediation-target` role | member | What the Lambda assumes. Trusts exactly one role ARN; permits exactly four S3 actions. |
| Custom bus + resource policy | security | Only the member account (or, with `organizationId` set, any principal in the org) may put events on it. |
| Rule on custom bus | security | Routes matching events to the Lambda. |
| `s3-guardrail-remediator` role | security | Lambda execution role. Its only cross-account power is AssumeRole on the target role name. |
| Lambda | security | Assess (is the policy public? is Block Public Access on?), remediate only what is wrong, audit (structured log). |
| SCP (optional) | org | Preventive layer: stops anyone switching off account-level Block Public Access or tampering with the guardrail. |

## Repository layout

```
bin/app.ts                     CDK app: wires both stacks, reads context
lib/security-stack.ts          bus, bus policy, Lambda, Lambda role, rule
lib/member-stack.ts            trail, forwarding rule, remediation target role
lambda/remediate.ts            Lambda handler: assess, remediate, audit
lambda/remediation-plan.ts     pure function deciding which writes are needed
test/                          unit tests (node:test, no extra dependencies)
scp/                           service control policy for the preventive layer
cdk.context.example.json       template for your deployment-specific values
```

## Prerequisites

- Two AWS accounts.
  They do **not** need to be in the same Organization for the basic demo; the Organization setup further down is optional.
- Two CLI profiles, `security` and `member`, each with admin rights in its account.
- Node 20+ locally. The Lambda itself runs on Node.js 24.
- `npx cdk bootstrap` run once in each account, in the region you deploy to.
- One region for everything.
  The member trail is single-region and S3 records a bucket's API calls in the bucket's own region, so buckets in any other region are not watched.

## Configure

Deployment-specific values live in `cdk.context.json`, which is gitignored so account IDs never end up in the repo.

```bash
cp cdk.context.example.json cdk.context.json
```

Then set:

| Key | Value |
|---|---|
| `securityAccountId` | Account that hosts the bus and the Lambda. |
| `memberAccountId` | Account being guarded. |
| `region` | The one region everything runs in, for example `us-west-1`. |
| `organizationId` | Optional. Your `o-...` ID once both accounts are in an Organization. Leave empty otherwise. |

If a required value is missing, `cdk synth` fails with a message telling you which key to set.

## Deploy

1. `npm install`
2. `npm run deploy:security` first (the bus policy needs the member account ID).
3. `npm run deploy:member` second (it targets the bus and trusts the Lambda role by name).

CloudTrail can take a few minutes after creation before events flow.

## Run the unit tests

```bash
npm test
```

- `test/member-stack.test.ts` pins that the member template stays self-contained: no CDK bootstrap version check, no asset-backed custom resources, no reference to the bootstrap bucket.
  That is what lets it deploy as a StackSet to accounts that were never bootstrapped.
- `test/remediation-plan.test.ts` pins the remediation decisions, including the regression test for the self-triggering loop described below.

## Test it

In the **member** account:

```bash
B=guardrail-test-$RANDOM
aws s3 mb s3://$B --profile member

# New buckets have Block Public Access on. Turn it off, like a careless deploy would.
aws s3api delete-public-access-block --bucket $B --profile member

# Attach a public-read policy.
cat > /tmp/pub.json <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::$B/*"}]}
JSON
aws s3api put-bucket-policy --bucket $B --policy file:///tmp/pub.json --profile member
```

Run the last two commands back to back.
If you pause between them, the guardrail may re-enable Block Public Access first, and the public policy is then rejected.

Remediation usually lands within seconds.
Allow up to a few minutes on a freshly created trail, then:

```bash
aws s3api get-public-access-block --bucket $B --profile member   # all four should be true
aws s3api get-bucket-policy --bucket $B --profile member         # NoSuchBucketPolicy
```

In the **security** account, watch the Lambda's log group live:

```bash
aws logs tail /aws/lambda/<remediator-function-name> --follow --format short --profile security
```

You should see an `evaluating` line and a `remediated` line with `wasPolicyPublic: true`.
Expect one or two `already safe, no action` lines after it: late events, plus the Lambda reacting to its own Block Public Access write.
Then nothing more.

Doing the same in the console works too: switch Block Public Access off on a bucket and it is back on a few seconds later.

Clean up: `aws s3 rb s3://$B --force --profile member`, then `cdk destroy` in each account.
The member stack retains its CloudTrail log bucket on destroy (so the template needs no bootstrap assets), so remove it afterwards with `aws s3 rb s3://<trail-bucket> --force --profile member`.

## Design decisions

- **Why a trail is needed.** Config would also work and would catch pre-existing public buckets, not just new changes. CloudTrail was chosen here because it's faster and cheaper to stand up.
- **Why the names are hardcoded.** Cross-account references can't be resolved at deploy time, so both stacks agree on role and bus names up front. The security stack deploys first because its bus policy needs the member account ID.
- **Why the Lambda assesses before acting.** The rule fires on *any* change to those APIs, including changes toward safety. The Lambda checks `GetBucketPolicyStatus` so it only deletes a policy that is actually public.
- **Why both remediations are idempotent.** Running twice is harmless, which matters because EventBridge delivers at-least-once.
- **Why the Lambda writes only what is wrong.** Its own `PutBucketPublicAccessBlock` call matches the trigger rule. Writing to an already-safe bucket would re-trigger the guardrail forever, so it reads Block Public Access first and skips writes that change nothing. An early version did loop: about 170 invocations in nine minutes before it was caught.
- **Least privilege on the target role.** Trust policy names one role ARN, not the account. Permissions list four actions. If the Lambda is compromised, this is all an attacker gets.
- **Why the member template is self-contained.** No auto-delete custom resource and no bootstrap version check, so a StackSet can deploy it to brand-new accounts. The trade-off is a retained trail bucket that has to be removed by hand.

## Known limitations

- **Concurrent invocations can race.** Two events for the same bucket can arrive a fraction of a second apart, both see the bucket as public, and write at the same time. S3 rejects one write with `OperationAborted` (409). The end state is still correct, and Lambda's automatic async retry re-runs the failed invocation, which then finds the bucket safe. But it shows up as a Lambda error, and an event that fails all retries is dropped silently. Upgrade 1 fixes this.
- **Changes only.** The guardrail reacts to API calls. A bucket that was already public before the guardrail existed is not touched until something changes it. Upgrade 5 covers that.
- **One region.** See Prerequisites.

## Upgrades, in the order you'd add them

1. **SQS FIFO + DLQ** between the security bus rule and the Lambda, with the message group set to account plus bucket. Events for the same bucket are processed one at a time, a burst queues instead of throttling, and a failed remediation is visible in the DLQ.
2. **Exemptions**: skip buckets tagged `guardrail-exempt=<ticket>` before remediating.
3. **DynamoDB audit table**: store the deleted policy so it can be restored.
4. **Notify the owner**: SNS or Slack message including `userIdentity.arn` from the event.
5. **Config rule** `s3-bucket-public-read-prohibited` as a second detector that also catches buckets that were already public before the guardrail existed.

The StackSet rollout and the SCP preventive layer are already implemented; see the next section.

## Running it inside an AWS Organization

Putting the accounts in an Organization unlocks the three things the "real" design relies on.
Do them in this order.
The commands use a `mgmt` profile for the management account.
In a two-account setup the security account can also be the management account; SCPs never apply to the management account.

### 1. Create the org and move the accounts in

From whichever account will be the **management** account (use a third account if you can; the management account should run nothing else):

```bash
aws organizations create-organization --feature-set ALL --profile mgmt
aws organizations create-organizational-unit --parent-id <root-id> --name Workloads --profile mgmt
# Invite the member account and accept the invite from inside it,
# or create it with `aws organizations create-account`. Then:
aws organizations move-account --account-id <member-id> \
  --source-parent-id <root-id> --destination-parent-id <workloads-ou-id> --profile mgmt
aws organizations describe-organization --profile mgmt   # note the Id: o-xxxxxxxxxx
```

An account created with `create-account` can be reached by assuming `OrganizationAccountAccessRole` from the management account:

```ini
[profile member]
role_arn = arn:aws:iam::<member-id>:role/OrganizationAccountAccessRole
source_profile = mgmt
region = <region>
```

The security account can stay directly under root or in its own `Security` OU.
Don't put it in `Workloads`, or the SCP in step 4 will apply to it too.

### 2. Trust the org, not one account

Set `organizationId` in `cdk.context.json` to the `o-...` value and redeploy the security stack.
Two things change:

- The bus policy now allows `events:PutEvents` from any principal whose `aws:PrincipalOrgID` matches. New accounts work with no edit.
- The Lambda role's `sts:AssumeRole` is restricted with `aws:ResourceOrgID`, so even if someone created a role with the same name in an outside account, the Lambda couldn't assume it.

### 3. Deploy the member stack as a StackSet

Instead of `cdk deploy MemberStack` per account, synthesize once and let the org push it to every account in the OU, including ones created later.

```bash
# Enable trusted access so StackSets can deploy with org-managed permissions.
# Do it from the CloudFormation side: the Organizations call alone can leave
# `aws cloudformation describe-organizations-access` reporting DISABLED.
aws cloudformation activate-organizations-access --region <region> --profile mgmt
aws cloudformation describe-organizations-access --region <region> --profile mgmt   # ENABLED

# Synthesize the member stack to a plain CloudFormation template.
npx cdk synth MemberStack > member.yaml

# Create the StackSet in the management account, targeting the Workloads OU.
aws cloudformation create-stack-set \
  --stack-set-name s3-guardrail-member \
  --template-body file://member.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <region> --profile mgmt

aws cloudformation create-stack-instances \
  --stack-set-name s3-guardrail-member \
  --deployment-targets OrganizationalUnitIds=<workloads-ou-id> \
  --regions <region> \
  --region <region> --profile mgmt

# Wait until the instance is CURRENT.
aws cloudformation list-stack-instances --stack-set-name s3-guardrail-member \
  --region <region> --profile mgmt
```

If you already deployed `MemberStack` directly into the member account, `cdk destroy MemberStack --profile member` first so the names don't collide.

Note on CloudTrail: in a real org you'd create one **organization trail** in the management account instead of a trail per member.
The per-account trail in `member-stack.ts` is kept here because it's self-contained; swap it out once you have the org trail, and the EventBridge rule keeps working unchanged.

### 4. Add the preventive layer (SCP)

`scp/deny-disable-block-public-access.json` does two things:

- Denies turning off **account-level** Block Public Access. This doesn't stop someone making a *bucket* public (that's what the Lambda is for), but it stops them removing the account-wide backstop.
- Denies tampering with the guardrail itself: stopping the trail, disabling the forwarding rule, or editing the remediation role.

Both carve out `OrganizationAccountAccessRole` so you can still administer accounts from the management account, and `stacksets-exec-*`, the role service-managed StackSets use inside member accounts.
Without the second exemption, the SCP would block every StackSet update or deletion of the guardrail itself.

```bash
# Only needed once per org; skip if SERVICE_CONTROL_POLICY is already enabled on the root.
aws organizations enable-policy-type --root-id <root-id> --policy-type SERVICE_CONTROL_POLICY --profile mgmt

aws organizations create-policy --name DenyDisableBPA --type SERVICE_CONTROL_POLICY \
  --content file://scp/deny-disable-block-public-access.json --profile mgmt
aws organizations attach-policy --policy-id <p-id> --target-id <workloads-ou-id> --profile mgmt
```

Test it with a principal in the member account that is **not** exempt.
The `member` profile above assumes `OrganizationAccountAccessRole`, so it will still be allowed.
A temporary admin role that trusts your management-account user works without creating any access keys:

```bash
aws iam create-role --role-name guardrail-scp-test --profile member \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<your-mgmt-user-arn>"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name guardrail-scp-test \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile member
# Add a [profile member-scp-test] that assumes it with source_profile = mgmt, then:
aws s3control delete-public-access-block --account-id <member-id> --profile member-scp-test
```

It should fail with `AccessDenied ... with an explicit deny in a service control policy`.
The error names `s3:PutAccountPublicAccessBlock`, because that is the permission S3 checks for the account-level delete API too.
Delete the test role afterwards.
If you recreate it within the hour, clear its cached session from `~/.aws/cli/cache` first, or STS returns `InvalidClientTokenId`.

Together, the SCP and the Lambda split the work: prevent what can be prevented, then detect and fix the rest.

### 5. Tear down the Organization setup

Order matters: the stack set has to go before the security stack, and the trail bucket is retained.

```bash
aws s3 rb s3://<test-bucket> --force --profile member

aws cloudformation delete-stack-instances --stack-set-name s3-guardrail-member \
  --deployment-targets OrganizationalUnitIds=<workloads-ou-id> --regions <region> \
  --no-retain-stacks --region <region> --profile mgmt
# Wait for the operation to finish, then:
aws cloudformation delete-stack-set --stack-set-name s3-guardrail-member --region <region> --profile mgmt

aws s3 rb s3://<member-trail-bucket> --force --profile member

aws organizations detach-policy --policy-id <p-id> --target-id <workloads-ou-id> --profile mgmt
aws organizations delete-policy --policy-id <p-id> --profile mgmt

npx cdk destroy SecurityStack --profile security
```

### Operational gotchas

- Trusted access for StackSets must be enabled from the CloudFormation side (`activate-organizations-access`), not only through Organizations.
- Keep the security account outside the OU the SCP is attached to.
- The SCP must exempt the role that deploys the guardrail (`stacksets-exec-*`), or every StackSet update and deletion fails.
- A remediation must not trigger itself: the Lambda writes only what is wrong.
- SCPs can't evaluate bucket-level conditions, so they can't stop an individual bucket being made public. That is why the detective loop exists.
