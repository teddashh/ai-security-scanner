#!/usr/bin/env node
// A stand-in for the AWS CLI that answers the calls `cloud-setup/aws-read-only.sh`
// makes. Answers use the response shapes in the AWS API references for STS,
// EC2, Organizations, IAM Identity Center (sso-admin) and Identity Store, as
// the CLI prints them with `--output json`. State lives in the JSON file named
// by FAKE_AWS_STATE, and every call is appended to its `calls` list.

import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const statePath = process.env.FAKE_AWS_STATE;
if (!statePath) {
  process.stderr.write("FAKE_AWS_STATE is not set\n");
  process.exit(255);
}
const state = JSON.parse(readFileSync(statePath, "utf8"));
const [service, operation, ...rest] = process.argv.slice(2);
const options = {};
for (let index = 0; index < rest.length; index += 2) {
  const name = rest[index];
  if (!name?.startsWith("--")) {
    process.stderr.write(`unexpected argument ${name}\n`);
    process.exit(252);
  }
  options[name.slice(2)] = rest[index + 1];
}
state.calls.push({ service, operation, options });

const save = () => writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
const answer = (value) => {
  save();
  if (value !== undefined) process.stdout.write(`${JSON.stringify(value, null, 4)}\n`);
  process.exit(0);
};
const refuse = (code, message) => {
  save();
  process.stderr.write(`\nAn error occurred (${code}) when calling the ${operation} operation: ${message}\n`);
  process.exit(254);
};

if (options.output !== "json") refuse("ValidationException", "the setup script must ask for JSON");

const instance = () => {
  const found = Object.values(state.instances ?? {}).flat().find((item) => item.InstanceArn === options["instance-arn"]);
  if (!found) refuse("ResourceNotFoundException", "Instance not found");
  return found;
};
const permissionSet = () => {
  instance();
  const found = state.permissionSets.find((item) => item.arn === options["permission-set-arn"]);
  if (!found) refuse("ResourceNotFoundException", "PermissionSet not found");
  return found;
};

const key = `${service} ${operation}`;
if (state.failOperation === operation) refuse("AccessDeniedException", "Fixture refusal");
switch (key) {
  case "sts get-caller-identity":
    answer(state.caller);
    break;
  case "ec2 describe-regions":
    answer({
      Regions: state.enabledRegions.map((region) => ({
        Endpoint: `ec2.${region}.amazonaws.com`,
        RegionName: region,
        OptInStatus: "opt-in-not-required",
      })),
    });
    break;
  case "organizations describe-organization":
    if (!state.organization) {
      refuse("AWSOrganizationsNotInUseException", "Your account is not a member of an organization.");
    }
    answer({ Organization: state.organization });
    break;
  case "sso-admin list-instances":
    answer({ Instances: state.instances?.[options.region] ?? [] });
    break;
  case "sso-admin list-permission-sets":
    instance();
    answer({ PermissionSets: state.permissionSets.map((item) => item.arn) });
    break;
  case "sso-admin describe-permission-set": {
    const found = permissionSet();
    answer({
      PermissionSet: {
        Name: found.name,
        PermissionSetArn: found.arn,
        Description: found.description,
        CreatedDate: "2026-10-01T12:00:00+00:00",
        SessionDuration: found.sessionDuration,
        RelayState: found.relayState,
      },
    });
    break;
  }
  case "sso-admin create-permission-set": {
    instance();
    if (state.permissionSets.some((item) => item.name === options.name)) {
      refuse("ConflictException", "PermissionSet with name already exists");
    }
    const created = {
      arn: `${options["instance-arn"].replace(":::instance/", ":::permissionSet/")}/ps-${randomUUID().replaceAll("-", "").slice(0, 16)}`,
      name: options.name,
      description: options.description,
      sessionDuration: options["session-duration"],
      managed: [],
      customer: [],
      inline: "",
      provisionedAccounts: [],
      tags: JSON.parse(options.tags ?? "[]"),
    };
    state.permissionSets.push(created);
    if (state.loseReply === operation) refuse("InternalServerException", "Fixture lost reply");
    answer({
      PermissionSet: {
        Name: created.name,
        PermissionSetArn: created.arn,
        Description: created.description,
        CreatedDate: "2026-10-02T12:00:00+00:00",
        SessionDuration: created.sessionDuration,
      },
    });
    break;
  }
  case "sso-admin attach-managed-policy-to-permission-set": {
    const found = permissionSet();
    const arn = options["managed-policy-arn"];
    if (found.managed.some((policy) => policy.Arn === arn)) refuse("ConflictException", "Policy already attached");
    found.managed.push({ Name: arn.split("/").at(-1), Arn: arn });
    answer();
    break;
  }
  case "sso-admin list-managed-policies-in-permission-set":
    answer({ AttachedManagedPolicies: permissionSet().managed });
    break;
  case "sso-admin list-customer-managed-policy-references-in-permission-set":
    answer({ CustomerManagedPolicyReferences: permissionSet().customer });
    break;
  case "sso-admin get-inline-policy-for-permission-set": {
    const found = permissionSet();
    answer(found.inline ? { InlinePolicy: found.inline } : {});
    break;
  }
  case "sso-admin get-permissions-boundary-for-permission-set":
    if (state.boundaryNotFound && !permissionSet().boundary) refuse("ResourceNotFoundException", "No boundary attached");
    answer(permissionSet().boundary ? { PermissionsBoundary: permissionSet().boundary } : {});
    break;
  case "sso-admin list-tags-for-resource": {
    instance();
    const found = state.permissionSets.find((item) => item.arn === options["resource-arn"]);
    if (!found) refuse("ResourceNotFoundException", "PermissionSet not found");
    answer({ Tags: found.tags ?? [] });
    break;
  }
  case "sso-admin list-accounts-for-provisioned-permission-set":
    answer({ AccountIds: permissionSet().provisionedAccounts });
    break;
  case "sso-admin provision-permission-set": {
    const found = permissionSet();
    const requestId = randomUUID();
    state.requests[requestId] = "SUCCEEDED";
    answer({
      PermissionSetProvisioningStatus: {
        Status: "IN_PROGRESS",
        RequestId: requestId,
        PermissionSetArn: found.arn,
        CreatedDate: "2026-10-02T12:00:00+00:00",
      },
    });
    break;
  }
  case "sso-admin describe-permission-set-provisioning-status":
    instance();
    answer({
      PermissionSetProvisioningStatus: {
        Status: state.requests[options["provision-permission-set-request-id"]] ?? "FAILED",
        RequestId: options["provision-permission-set-request-id"],
      },
    });
    break;
  case "identitystore list-users":
    if (options["identity-store-id"] !== Object.values(state.instances ?? {}).flat()[0]?.IdentityStoreId) {
      refuse("ResourceNotFoundException", "Identity store not found");
    }
    answer({ Users: state.users });
    break;
  case "sso-admin list-account-assignments":
    permissionSet();
    answer({
      AccountAssignments: state.assignments.filter((item) => (
        item.AccountId === options["account-id"] && item.PermissionSetArn === options["permission-set-arn"]
      )),
    });
    break;
  case "sso-admin create-account-assignment": {
    const found = permissionSet();
    if (options["target-type"] !== "AWS_ACCOUNT" || options["principal-type"] !== "USER") {
      refuse("ValidationException", "unexpected assignment target");
    }
    if (!state.users.some((user) => user.UserId === options["principal-id"])) {
      refuse("ResourceNotFoundException", "Principal not found");
    }
    const assignment = {
      AccountId: options["target-id"],
      PermissionSetArn: found.arn,
      PrincipalType: "USER",
      PrincipalId: options["principal-id"],
    };
    state.assignments.push(assignment);
    if (!found.provisionedAccounts.includes(assignment.AccountId)) found.provisionedAccounts.push(assignment.AccountId);
    const requestId = randomUUID();
    state.requests[requestId] = "SUCCEEDED";
    if (state.loseReply === operation) refuse("InternalServerException", "Fixture lost reply");
    answer({
      AccountAssignmentCreationStatus: {
        Status: "IN_PROGRESS",
        RequestId: requestId,
        TargetId: assignment.AccountId,
        TargetType: "AWS_ACCOUNT",
        PermissionSetArn: found.arn,
        PrincipalType: "USER",
        PrincipalId: assignment.PrincipalId,
        CreatedDate: "2026-10-02T12:00:00+00:00",
      },
    });
    break;
  }
  case "sso-admin describe-account-assignment-creation-status":
    instance();
    answer({
      AccountAssignmentCreationStatus: {
        Status: state.requests[options["account-assignment-creation-request-id"]] ?? "FAILED",
        RequestId: options["account-assignment-creation-request-id"],
      },
    });
    break;
  case "sso-admin delete-account-assignment": {
    const found = permissionSet();
    if (options["target-type"] !== "AWS_ACCOUNT" || options["principal-type"] !== "USER") {
      refuse("ValidationException", "unexpected assignment target");
    }
    const requestId = randomUUID();
    state.requests[requestId] = state.deleteStatus ?? "SUCCEEDED";
    if (state.requests[requestId] === "SUCCEEDED" && !state.ignoreDelete) {
      state.assignments = state.assignments.filter((a) => !(a.AccountId === options["target-id"] &&
        a.PermissionSetArn === found.arn && a.PrincipalId === options["principal-id"] && a.PrincipalType === "USER"));
      found.provisionedAccounts = found.provisionedAccounts.filter((account) => state.assignments.some((a) =>
        a.AccountId === account && a.PermissionSetArn === found.arn));
    }
    if (state.loseReply === operation) refuse("InternalServerException", "Fixture lost reply");
    answer({ AccountAssignmentDeletionStatus: { RequestId: requestId, Status: "IN_PROGRESS" } });
    break;
  }
  case "sso-admin describe-account-assignment-deletion-status":
    instance();
    answer({ AccountAssignmentDeletionStatus: {
      RequestId: options["account-assignment-deletion-request-id"],
      Status: state.requests[options["account-assignment-deletion-request-id"]] ?? "FAILED",
    } });
    break;
  case "sso-admin delete-permission-set": {
    const found = permissionSet();
    if (state.assignments.some((a) => a.PermissionSetArn === found.arn)) refuse("ConflictException", "Still assigned");
    if (!state.ignorePermissionSetDelete) state.permissionSets = state.permissionSets.filter((p) => p.arn !== found.arn);
    if (state.loseReply === operation) refuse("InternalServerException", "Fixture lost reply");
    answer();
    break;
  }
  default:
    refuse("InvalidAction", `the fake does not answer ${key}`);
}
