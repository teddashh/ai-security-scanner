#!/usr/bin/env bash
# Prepares read-only AWS access for ai-security-scanner.
#
# Run it in AWS CloudShell while signed in to the account that manages IAM
# Identity Center, usually your organization's management account:
#
#   bash aws-read-only.sh [--user <user name or email>] [--account <account ID>]
#
# It makes sure a permission set named SecurityAudit grants only the AWS
# managed SecurityAudit policy, and that the person who scans holds it on the
# account. It then prints the four values for step 2 of the app's connection
# guide and saves them as a setup file the app can import.
#
# Running it again adds only what is missing. It never removes or replaces
# anything; when something is in the way, it stops and says what to change.
set -euo pipefail

# Temporary access has its own receipt and a matching cleanup command. Keep
# the long-lived SecurityAudit workflow below compatible with existing users.
for option in "$@"; do
  if [ "$option" = "--temporary" ]; then
    command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Python 3 is required for temporary access.' >&2; exit 1; }
    exec python3 "$(dirname "${BASH_SOURCE[0]}")/aws-cleanup.py" setup "$@"
  fi
done

readonly PERMISSION_SET_NAME="SecurityAudit"
readonly POLICY_ARN="arn:aws:iam::aws:policy/SecurityAudit"
readonly SETUP_FILE="ai-security-scanner-aws-setup.json"

export AWS_PAGER=""

say() { printf '%s\n' "$*"; }
stop() {
  printf '\nStopped: %s\n' "$*" >&2
  exit 1
}

usage() {
  say "Usage: bash aws-read-only.sh [--user <user name or email>] [--account <account ID>]"
  say ""
  say "  --user     The IAM Identity Center user who will sign in to scan."
  say "             Needed only when there is more than one user."
  say "  --account  The 12-digit AWS account to scan. Defaults to this account."
  say "  --temporary  Create dedicated scan access with a cleanup receipt (requires aws-cleanup.py)."
}

user_hint=""
account_id=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --user)
      [ "$#" -ge 2 ] || stop "--user needs a user name or email address."
      user_hint=$2
      shift 2
      ;;
    --account)
      [ "$#" -ge 2 ] || stop "--account needs a 12-digit account ID."
      account_id=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      stop "unknown option $1"
      ;;
  esac
done

command -v aws >/dev/null 2>&1 || stop "the AWS CLI is not installed. Run this in AWS CloudShell."
command -v jq >/dev/null 2>&1 || stop "jq is not installed. Run this in AWS CloudShell."

error_file=$(mktemp)
trap 'rm -f "$error_file"' EXIT

# Runs one AWS CLI call and prints its JSON answer, or stops with AWS's reason.
aws_json() {
  local output
  if ! output=$(aws "$@" --output json 2>"$error_file"); then
    stop "AWS refused '$1 $2': $(tr -s '\r\n' '  ' <"$error_file")"
  fi
  if [ -z "$output" ]; then output="{}"; fi
  printf '%s\n' "$output"
}

caller=$(aws_json sts get-caller-identity)
caller_account=$(jq -r '.Account' <<<"$caller")
account_id=${account_id:-$caller_account}
[[ $account_id =~ ^[0-9]{12}$ ]] || stop "the account ID must be 12 digits."

# IAM Identity Center lives in one Region. Look in CloudShell's Region first,
# then in every Region enabled for the account.
ic_region=""
ic_json=""
find_identity_center() {
  local region json
  for region in "$@"; do
    [ -n "$region" ] || continue
    json=$(aws sso-admin list-instances --region "$region" --output json 2>/dev/null) || continue
    if [ "$(jq '.Instances | length' <<<"$json")" -gt 0 ]; then
      ic_region=$region
      ic_json=$json
      return 0
    fi
  done
  return 1
}

if ! find_identity_center "${AWS_REGION:-}" "${AWS_DEFAULT_REGION:-}"; then
  say "Looking for IAM Identity Center in every enabled Region..."
  regions=$(aws_json ec2 describe-regions --region "${AWS_REGION:-us-east-1}" | jq -r '.Regions[].RegionName')
  # shellcheck disable=SC2086 # one Region name per word
  find_identity_center $regions ||
    stop "account $caller_account cannot see IAM Identity Center. If it is off, open IAM Identity Center in the AWS console and choose Enable, then Enable with AWS Organizations; AWS offers that step only in the console. If your organization already uses it, run this script in the management account."
fi

instance_arn=$(jq -r '.Instances[0].InstanceArn' <<<"$ic_json")
identity_store_id=$(jq -r '.Instances[0].IdentityStoreId' <<<"$ic_json")
instance_owner=$(jq -r '.Instances[0].OwnerAccountId // empty' <<<"$ic_json")
instance_status=$(jq -r '.Instances[0].Status // "ACTIVE"' <<<"$ic_json")
[ "$instance_status" = "ACTIVE" ] ||
  stop "IAM Identity Center in $ic_region is $instance_status. Run this script again when it is active."

# Only an organization instance can give people access to AWS accounts.
if organization=$(aws organizations describe-organization --output json 2>"$error_file"); then
  management_account=$(jq -r '.Organization.MasterAccountId // empty' <<<"$organization")
  if [ -n "$management_account" ] && [ -n "$instance_owner" ] && [ "$instance_owner" != "$management_account" ]; then
    stop "the IAM Identity Center in $ic_region belongs to account $instance_owner alone, and AWS does not let it grant access to AWS accounts. Sign in to your organization's management account, turn on IAM Identity Center there with AWS Organizations, and run this script in that account."
  fi
elif grep -q 'AWSOrganizationsNotInUseException' "$error_file"; then
  # Outside AWS Organizations, the only kind of instance is an account instance.
  stop "the IAM Identity Center in $ic_region is an account instance. AWS does not let an account instance grant access to AWS accounts, and cannot turn it into an organization instance. If nothing else uses it, delete it under Settings in IAM Identity Center, then choose Enable, then Enable with AWS Organizations, and run this script again."
fi

say "IAM Identity Center: $ic_region"
say "Account to scan:     $account_id"

ic_args=(--instance-arn "$instance_arn" --region "$ic_region")

# Waits for an assignment or provisioning request. $1 is the describe call,
# $2 its request-ID option, $3 the request ID and $4 the status field.
wait_for_request() {
  local attempt status_json state
  for attempt in $(seq 1 60); do
    status_json=$(aws_json sso-admin "$1" "${ic_args[@]}" "$2" "$3")
    state=$(jq -r ".$4.Status" <<<"$status_json")
    case "$state" in
      SUCCEEDED) return 0 ;;
      FAILED) stop "AWS could not finish: $(jq -r ".$4.FailureReason // \"no reason given\"" <<<"$status_json")" ;;
    esac
    sleep 2
  done
  stop "AWS is still working on it. Run this script again in a minute."
}

# 1. The person who signs in to scan. Chosen first, so a question about who
# it is never interrupts a half-made change.
users=$(aws_json identitystore list-users --identity-store-id "$identity_store_id" --region "$ic_region")
user_count=$(jq '.Users | length' <<<"$users")

if [ -n "$user_hint" ]; then
  wanted=$(tr '[:upper:]' '[:lower:]' <<<"$user_hint")
  match=$(jq -r --arg wanted "$wanted" '[.Users[]
      | select((.UserName | ascii_downcase) == $wanted or any(.Emails[]?; (.Value | ascii_downcase) == $wanted))]
    | if length == 1 then .[0] | [.UserId, .UserName] | @tsv else empty end' <<<"$users")
  [ -n "$match" ] || stop "IAM Identity Center has no user named $user_hint."
elif [ "$user_count" -eq 0 ]; then
  stop "IAM Identity Center has no users yet. In the console, open IAM Identity Center, then Users, and choose Add user. Add yourself with your email address and set your password from the invitation email. Then run this script again."
elif [ "$user_count" -eq 1 ]; then
  match=$(jq -r '.Users[0] | [.UserId, .UserName] | @tsv' <<<"$users")
else
  (: </dev/tty) 2>/dev/null ||
    stop "IAM Identity Center has several users. Run this script again with --user and the user name of the person who will scan."
  say ""
  say "Who will sign in to scan?"
  jq -r '.Users | to_entries[] | "  \(.key + 1)) \(.value.UserName)"
    + (if (.value.DisplayName // "") != "" then " (\(.value.DisplayName))" else "" end)' <<<"$users"
  read -r -p "Enter a number: " choice </dev/tty
  [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$user_count" ] ||
    stop "$choice is not one of the numbers shown."
  match=$(jq -r --argjson index "$((choice - 1))" '.Users[$index] | [.UserId, .UserName] | @tsv' <<<"$users")
fi
user_id=$(cut -f1 <<<"$match")
user_name=$(cut -f2 <<<"$match")

# 2. The SecurityAudit permission set.
permission_set_arn=""
permission_sets=$(aws_json sso-admin list-permission-sets "${ic_args[@]}" | jq -r '.PermissionSets[]')
for arn in $permission_sets; do
  name=$(aws_json sso-admin describe-permission-set "${ic_args[@]}" --permission-set-arn "$arn" | jq -r '.PermissionSet.Name')
  if [ "$name" = "$PERMISSION_SET_NAME" ]; then
    permission_set_arn=$arn
    break
  fi
done

if [ -z "$permission_set_arn" ]; then
  permission_set_arn=$(aws_json sso-admin create-permission-set "${ic_args[@]}" \
    --name "$PERMISSION_SET_NAME" \
    --description "Read-only security audit access for ai-security-scanner" \
    --session-duration PT1H | jq -r '.PermissionSet.PermissionSetArn')
  aws_json sso-admin attach-managed-policy-to-permission-set "${ic_args[@]}" \
    --permission-set-arn "$permission_set_arn" --managed-policy-arn "$POLICY_ARN" >/dev/null
  say "Created permission set $PERMISSION_SET_NAME with the AWS managed SecurityAudit policy."
else
  managed=$(aws_json sso-admin list-managed-policies-in-permission-set "${ic_args[@]}" --permission-set-arn "$permission_set_arn")
  customer=$(aws_json sso-admin list-customer-managed-policy-references-in-permission-set "${ic_args[@]}" --permission-set-arn "$permission_set_arn")
  inline=$(aws_json sso-admin get-inline-policy-for-permission-set "${ic_args[@]}" --permission-set-arn "$permission_set_arn")
  extras=$(jq -rn --arg policy "$POLICY_ARN" \
    --argjson managed "$managed" --argjson customer "$customer" --argjson inline "$inline" \
    '[($managed.AttachedManagedPolicies // [])[] | select(.Arn != $policy) | .Name]
     + [($customer.CustomerManagedPolicyReferences // [])[] | .Name]
     + (if (($inline.InlinePolicy // "") | length) > 0 then ["an inline policy"] else [] end)
     | join(", ")')
  [ -z "$extras" ] ||
    stop "the permission set $PERMISSION_SET_NAME also grants $extras. The scanner signs in only with a permission set that grants SecurityAudit alone. In IAM Identity Center, remove those policies from $PERMISSION_SET_NAME, then run this script again."
  if jq -e --arg policy "$POLICY_ARN" '[(.AttachedManagedPolicies // [])[] | select(.Arn == $policy)] | length > 0' <<<"$managed" >/dev/null; then
    say "Permission set $PERMISSION_SET_NAME is already in place."
  else
    aws_json sso-admin attach-managed-policy-to-permission-set "${ic_args[@]}" \
      --permission-set-arn "$permission_set_arn" --managed-policy-arn "$POLICY_ARN" >/dev/null
    provisioned=$(aws_json sso-admin list-accounts-for-provisioned-permission-set "${ic_args[@]}" \
      --permission-set-arn "$permission_set_arn" | jq '.AccountIds // [] | length')
    if [ "$provisioned" -gt 0 ]; then
      request_id=$(aws_json sso-admin provision-permission-set "${ic_args[@]}" \
        --permission-set-arn "$permission_set_arn" --target-type ALL_PROVISIONED_ACCOUNTS |
        jq -r '.PermissionSetProvisioningStatus.RequestId')
      wait_for_request describe-permission-set-provisioning-status \
        --provision-permission-set-request-id "$request_id" PermissionSetProvisioningStatus
    fi
    say "Added the AWS managed SecurityAudit policy to permission set $PERMISSION_SET_NAME."
  fi
fi

# 3. The assignment of SecurityAudit to that person on the account.
assigned=$(aws_json sso-admin list-account-assignments "${ic_args[@]}" \
  --account-id "$account_id" --permission-set-arn "$permission_set_arn" |
  jq --arg user "$user_id" '[.AccountAssignments[] | select(.PrincipalType == "USER" and .PrincipalId == $user)] | length')
if [ "$assigned" -gt 0 ]; then
  say "$user_name already holds $PERMISSION_SET_NAME on account $account_id."
else
  request_id=$(aws_json sso-admin create-account-assignment "${ic_args[@]}" \
    --target-id "$account_id" --target-type AWS_ACCOUNT \
    --permission-set-arn "$permission_set_arn" \
    --principal-type USER --principal-id "$user_id" |
    jq -r '.AccountAssignmentCreationStatus.RequestId')
  wait_for_request describe-account-assignment-creation-status \
    --account-assignment-creation-request-id "$request_id" AccountAssignmentCreationStatus
  say "Assigned $PERMISSION_SET_NAME on account $account_id to $user_name."
fi

start_url="https://$identity_store_id.awsapps.com/start"
jq -n --arg start_url "$start_url" --arg region "$ic_region" --arg account_id "$account_id" --arg role_name "$PERMISSION_SET_NAME" \
  '{schema_version: "1.0.0", provider: "aws", connection_method: "existing_read_only",
    details: {start_url: $start_url, region: $region, account_id: $account_id, role_name: $role_name}}' >"$SETUP_FILE"

say ""
say "Read-only AWS access is ready. Enter these values in step 2 of the app's connection guide:"
say ""
say "  AWS access portal start URL:    $start_url"
say "  IAM Identity Center region:     $ic_region"
say "  AWS account ID:                 $account_id"
say "  Read-only permission set name:  $PERMISSION_SET_NAME"
say ""
say "When AWS's sign-in page opens, sign in as $user_name, not as the root user."
say "To hand these values to someone else, send $(pwd)/$SETUP_FILE. They import it"
say "with Choose setup file, under \"Someone else manages this account?\" in step 1."
