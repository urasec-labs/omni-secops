# Playbook - AWS IAM Privilege Escalation

| Field | Value |
|---|---|
| `playbook_id` | PB-CLOUD-AWS-IAM |
| `attack_ids` | T1548, T1078.004, T1552.005 |
| `controls` | OWASP AUTHZ-2, NIST AC-6 |
| `detections` | `06-defense/blue-team/controls/controls.csv` (CLOUD-01..) |

## 1. Escalation primitives

| Primitive | Required permission | Impact |
|---|---|---|
| `iam:CreatePolicyVersion` on a managed policy you can attach | `iam:CreatePolicyVersion`, `iam:AttachUserPolicy` | Full account takeover |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Lambda | Code execution in a privileged role |
| `lambda:UpdateFunctionCode` on any function you can see | Lambda | In-place hijack |
| `sts:AssumeRole` with `trust` to your principal | STS | Cross-account |
| `iam:CreateAccessKey` for any user | IAM | Persistent access |
| `ec2:RunInstances` with an over-privileged instance profile | EC2 | Host the next stage in your account |
| `cloudformation:CreateStack` | CFN | Arbitrary service calls with any role you can pass |

## 2. Enumeration

```bash
# What can I do?
aws sts get-caller-identity
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::ACCT:user/me \
    --action-names iam:CreatePolicyVersion lambda:UpdateFunctionCode

# Who can I become?
aws iam list-roles --query 'Roles[].[RoleName, Arn]' --output table
# Read trust policies and look for external accounts, service principals, wildcards
```

## 3. Least-privilege remediation checklist

1. Deny `iam:*` on `*` except the self-service paths you need (OWASP AUTHZ-2).
2. Scope conditions: `aws:RequestedRegion`, `aws:SourceVpce`, `aws:TagKeys`.
3. Split roles per function; never reuse a "power" role across workloads.
4. Require `aws:MultiFactorAuthPresent` in the principal condition block.
5. Invalidate and rotate any credential found in a wordlist scan
   (`03-wordlists/credentials/aws-keys.txt`).

## 4. Detection

* CloudTrail `CreatePolicyVersion`, `AttachUserPolicy`, `UpdateFunctionCode`
  without a matching change ticket.
* GuardDuty findings: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`,
  `Stealth:IAMUser/CloudTrailLoggingDisabled`.
* Anomalous `AssumeRole` chain depth > 2 in a session.
