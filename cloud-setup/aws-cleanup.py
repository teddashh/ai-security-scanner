#!/usr/bin/env python3
"""Dedicated AWS scan access and receipt-bound cleanup; uses the signed-in AWS CLI.

No credentials are requested or saved. Intended for AWS CloudShell/Linux.
Existing SecurityAudit permission sets and historical unrecorded access are
outside this workflow. See README.md for the report/export and session limits.
"""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

KIND = "aws-temporary-access-v1"
POLICY = "arn:aws:iam::aws:policy/SecurityAudit"
TAG = "ai-security-scanner:cleanup-id"
DESCRIPTION = "Temporary ai-security-scanner access: "
TERMINAL = {"completed", "partially_completed", "failed", "cancelled", "not_executed"}
REJECTED = {"AccessDeniedException", "ValidationException", "ThrottlingException", "ServiceQuotaExceededException"}


class Stop(Exception):
    pass


class AwsError(Stop):
    def __init__(self, operation, code):
        self.code = code
        super().__init__(f"AWS {operation} failed ({code}). Keep the receipt and retry after resolving this error.")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value, exclusive=False):
    """Durable replacement in the same directory; never leave a temporary file."""
    path = Path(path)
    if path.is_symlink():
        raise Stop("Refusing a symbolic-link output file.")
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(name, path)  # Atomic no-overwrite creation.
        else:
            os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def locked(path):
    # Keep the lock inode: unlinking it would permit concurrent cleanup.
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop("This receipt is already in use by another setup or cleanup.")
        yield
    finally:
        os.close(fd)


def aws(service, operation, **options):
    command = ["aws", service, operation]
    for key, value in options.items():
        command += ["--" + key.replace("_", "-"), str(value)]
    command += ["--output", "json"]
    # A mutation with a lost reply must not be retried blindly by the CLI.
    attempts = "3" if operation.startswith(("get-", "list-", "describe-")) else "1"
    env = dict(os.environ, AWS_PAGER="", AWS_MAX_ATTEMPTS=attempts, AWS_CLI_AUTO_PROMPT="off")
    try:
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=120)
    except subprocess.TimeoutExpired:
        raise AwsError(operation, "Timeout; outcome unknown")
    if result.returncode:
        match = re.search(r"\(([A-Za-z]+Exception)\)", result.stderr)
        raise AwsError(operation, match[1] if match else "CLIError; outcome unknown")
    try:
        value = json.loads(result.stdout or "{}")
    except ValueError:
        raise AwsError(operation, "InvalidJSON; outcome unknown")
    if not isinstance(value, dict) or value.get("NextToken"):
        raise Stop("AWS returned an incomplete response. No partial list can authorize cleanup.")
    return value


def sso(r, operation, **options):
    return aws("sso-admin", operation, instance_arn=r["instance_arn"], region=r["region"], **options)


def ps(r, operation, **options):
    return sso(r, operation, permission_set_arn=r["permission_set_arn"], **options)


def save(path, r, **changes):
    r.update(changes)
    r["updated_at"] = now()
    write_json(path, r)


def wait_request(r, kind, request_id, allow_failed=False):
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", request_id or ""):
        raise Stop("AWS did not return a valid request ID. The operation remains unconfirmed.")
    for _ in range(60):
        response = sso(r, f"describe-account-assignment-{kind}-status",
                       **{f"account_assignment_{kind}_request_id": request_id})
        status = response[f"AccountAssignment{kind.title()}Status"]["Status"]
        if status == "SUCCEEDED":
            return True
        if status == "FAILED":
            if allow_failed:
                return False
            raise Stop(f"AWS assignment {kind} failed. Keep the receipt; cleanup is incomplete.")
        if status != "IN_PROGRESS":
            raise Stop("AWS returned an unknown operation status.")
        time.sleep(2)
    raise Stop("AWS is still processing the assignment. Keep the receipt and retry later.")


def setup(args):
    caller = aws("sts", "get-caller-identity")
    account = args.account or caller["Account"]
    if not re.fullmatch(r"[0-9]{12}", account):
        raise Stop("--account must contain 12 digits.")
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    regions = [region] + [item["RegionName"] for item in aws("ec2", "describe-regions", region=region)["Regions"]]
    found = None
    for region in dict.fromkeys(regions):
        try:
            instances = aws("sso-admin", "list-instances", region=region)["Instances"]
        except AwsError:
            print(f"Could not inspect Identity Center in {region}.", file=sys.stderr)
            continue
        if instances:
            if len(instances) != 1:
                raise Stop("More than one Identity Center instance is visible; no instance was selected.")
            found = instances[0]
            break
    if not found or found.get("Status", "ACTIVE") != "ACTIVE":
        raise Stop("No active IAM Identity Center instance was found. Use its management account in CloudShell.")
    org = aws("organizations", "describe-organization")["Organization"]
    if found.get("OwnerAccountId") != org["MasterAccountId"]:
        raise Stop("This is not the organization's IAM Identity Center instance.")
    users = aws("identitystore", "list-users", identity_store_id=found["IdentityStoreId"], region=region)["Users"]
    if args.user:
        wanted = args.user.casefold()
        users = [u for u in users if u["UserName"].casefold() == wanted or
                 any(e["Value"].casefold() == wanted for e in u.get("Emails", []))]
    if len(users) != 1:
        raise Stop("Choose one existing Identity Center user with --user NAME_OR_EMAIL.")
    marker = str(uuid.uuid4())
    r = dict(kind=KIND, id=marker, state="setup_pending", created_at=now(),
             caller_account=caller["Account"], instance_owner=found["OwnerAccountId"],
             instance_arn=found["InstanceArn"], identity_store_id=found["IdentityStoreId"],
             region=region, account_id=account, user_id=users[0]["UserId"],
             name="AISS-" + marker.replace("-", "")[:20], permission_set_arn=None,
             creation_confirmed=False, assignment_state="not_attempted")
    validate_receipt(r)  # Reject unsupported partitions before creating anything.
    path = Path.cwd() / f"ai-security-scanner-aws-cleanup-{marker}.json"
    setup_path = Path.cwd() / f"ai-security-scanner-aws-setup-{marker}.json"
    with locked(path):
        write_json(path, r, exclusive=True)
        print(f"Cleanup receipt: {path}", flush=True)
        print("If setup stops, keep this receipt and use cleanup, rather than creating another setup.\n"
              + cleanup_command(path), flush=True)
        created = sso(r, "create-permission-set", name=r["name"],
                      description=DESCRIPTION + marker, session_duration="PT1H",
                      tags=json.dumps([{"Key": TAG, "Value": marker}]))["PermissionSet"]
        save(path, r, permission_set_arn=created["PermissionSetArn"], creation_confirmed=True)
        validate_receipt(r)
        check_owned(r)
        ps(r, "attach-managed-policy-to-permission-set", managed_policy_arn=POLICY)
        save(path, r, policy_attached=True)
        check_owned(r)
        check_assignments(r)  # A dedicated set must not already be in use.
        save(path, r, assignment_state="pending")
        try:
            result = ps(r, "create-account-assignment", target_id=account, target_type="AWS_ACCOUNT",
                        principal_type="USER", principal_id=r["user_id"])["AccountAssignmentCreationStatus"]
        except AwsError as error:
            if error.code in REJECTED:
                save(path, r, assignment_state="not_attempted")
            raise
        request = result["RequestId"]
        save(path, r, assignment_state="requested", creation_request=request)
        wait_request(r, "creation", request)
        save(path, r, assignment_state="complete")
        rows = check_assignments(r)
        if len(rows) != 1:
            raise Stop("AWS has not confirmed the new assignment. Keep the receipt.")
        setup_value = dict(schema_version="1.0.0", provider="aws", connection_method="existing_read_only",
                           details=dict(start_url=f"https://{r['identity_store_id']}.awsapps.com/start",
                                        region=region, account_id=account, role_name=r["name"]))
        write_json(setup_path, setup_value, exclusive=True)
        save(path, r, state="ready", setup_file_sha256=digest(setup_path))
    print(f"Import setup file: {setup_path}\nAfter the report is saved, run:\n"
          + cleanup_command(path))


def cleanup_command(path):
    return "python3 " + shlex.quote(str(Path(__file__).resolve())) + " cleanup --receipt " + shlex.quote(str(path)) + " --revoke-now"


def validate_receipt(r):
    if r.get("kind") != KIND or str(uuid.UUID(r["id"])) != r["id"]:
        raise Stop("Unsupported cleanup receipt.")
    if r.get("name") != "AISS-" + r["id"].replace("-", "")[:20]:
        raise Stop("Receipt permission-set name does not match its ownership marker.")
    for key in ("caller_account", "instance_owner", "account_id"):
        if not re.fullmatch(r"[0-9]{12}", r[key]):
            raise Stop("Invalid account in receipt.")
    if not re.fullmatch(r"arn:aws:sso:::instance/ssoins-[A-Za-z0-9]{16}", r["instance_arn"]):
        raise Stop("Unsupported Identity Center instance ARN.")
    if not re.fullmatch(r"(?:[0-9a-f]{10}-)?[0-9a-fA-F-]{36}", r["user_id"]):
        raise Stop("Invalid user ID in receipt.")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]", r["region"]):
        raise Stop("Invalid Region in receipt.")
    arn = r.get("permission_set_arn")
    prefix = r["instance_arn"].replace(":::instance/", ":::permissionSet/") + "/ps-"
    if arn and not re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{16}", arn):
        raise Stop("Permission set belongs to a different instance.")
    if r.get("assignment_state") not in {"not_attempted", "pending", "requested", "complete", "deleted"}:
        raise Stop("Invalid assignment state in receipt.")


def check_owned(r):
    details = ps(r, "describe-permission-set")["PermissionSet"]
    if (details["PermissionSetArn"] != r["permission_set_arn"] or details["Name"] != r["name"] or
            details.get("Description") != DESCRIPTION + r["id"] or
            details.get("SessionDuration") != "PT1H" or details.get("RelayState")):
        raise Stop("The temporary permission set was changed. It has been preserved for review.")
    tags = aws("sso-admin", "list-tags-for-resource", instance_arn=r["instance_arn"],
               resource_arn=r["permission_set_arn"], region=r["region"])["Tags"]
    if tags != [{"Key": TAG, "Value": r["id"]}]:
        raise Stop("The permission set's ownership tags changed. No cleanup was authorized by this receipt.")
    managed = ps(r, "list-managed-policies-in-permission-set")["AttachedManagedPolicies"]
    customer = ps(r, "list-customer-managed-policy-references-in-permission-set")["CustomerManagedPolicyReferences"]
    inline = ps(r, "get-inline-policy-for-permission-set").get("InlinePolicy")
    try:
        boundary = ps(r, "get-permissions-boundary-for-permission-set").get("PermissionsBoundary")
    except AwsError as error:
        if error.code != "ResourceNotFoundException":
            raise
        # AWS can report an absent boundary this way. Recheck the set itself
        # so its concurrent deletion cannot be mistaken for an empty boundary.
        ps(r, "describe-permission-set")
        boundary = None
    if any(p["Arn"] != POLICY for p in managed) or customer or inline or boundary:
        raise Stop("The permission set now contains different access settings. It has been preserved.")
    if r.get("policy_attached") and [p["Arn"] for p in managed] != [POLICY]:
        raise Stop("The permission set's managed policy changed. It has been preserved.")


def check_assignments(r):
    accounts = ps(r, "list-accounts-for-provisioned-permission-set")["AccountIds"]
    if any(a != r["account_id"] for a in accounts):
        raise Stop("This permission set is now used by another account. It has been preserved.")
    rows = ps(r, "list-account-assignments", account_id=r["account_id"])["AccountAssignments"]
    expected = dict(AccountId=r["account_id"], PermissionSetArn=r["permission_set_arn"],
                    PrincipalType="USER", PrincipalId=r["user_id"])
    if any(row != expected for row in rows) or len(rows) > 1:
        raise Stop("This permission set has other assignments. All assignments have been preserved.")
    if rows and r["assignment_state"] in {"not_attempted", "deleted"}:
        raise Stop("An unexpected or replacement assignment exists. It has been preserved.")
    return rows


def scanner(gate, *arguments):
    result = subprocess.run([gate["cli"], "--data-dir", gate["data_dir"], "--json", *arguments],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise Stop("The scanner CLI could not complete the request.")
    return json.loads(result.stdout)


def wait_and_export(path, r, args):
    gate = r["scan_gate"]
    deadline = time.monotonic() + args.wait_minutes * 60
    while True:
        status = scanner(gate, "scan", "status", "--case-id", gate["case_id"], "--run-id", gate["run_id"])
        runs = status.get("runs", [])
        if (status.get("case_id") != gate["case_id"] or len(runs) != 1 or
                runs[0].get("id") != gate["run_id"] or runs[0].get("case_id") != gate["case_id"]):
            raise Stop("Scanner returned a different case or run. Access has not been revoked.")
        run = runs[0]
        if run.get("completed_at") and all(e.get("status") in TERMINAL for e in run["engine_runs"]):
            break
        if args.dry_run:
            print("The selected scan is still active. Cleanup would wait for it.")
            return False
        if time.monotonic() >= deadline:
            raise Stop("The scan is unfinished. Keep the receipt and retry, or choose --revoke-now.")
        time.sleep(args.poll_seconds)
    if args.dry_run:
        print("The selected scan is finished. Cleanup would save its report first.")
        return False
    try:
        report = Path(gate["report"])
        saved = r.get("report")
        if saved and report.is_file() and digest(report) == saved["sha256"]:
            return True
        output = scanner(gate, "export", "create", "--case-id", gate["case_id"], "--run-id", gate["run_id"],
                         "--format", "html", "--redaction", "standard", "--locale", gate["locale"],
                         "--destination", str(report))
        if (output.get("case_id") != gate["case_id"] or output.get("run_id") != gate["run_id"] or
                output.get("path") != str(report) or output.get("sha256") != digest(report)):
            raise Stop("The exported report could not be verified.")
        save(path, r, report={"path": str(report), "sha256": output["sha256"]}, report_error=None)
        print(f"Report saved: {report}")
    except (Stop, OSError, ValueError, subprocess.TimeoutExpired) as error:
        save(path, r, report_error=str(error))
        print("HTML export failed. Saved case evidence is retained; access cleanup will still run.", file=sys.stderr)
    return True


def check_account(r):
    if aws("sts", "get-caller-identity")["Account"] != r["caller_account"]:
        raise Stop("Sign in to the same administrative AWS account used during setup.")
    instances = aws("sso-admin", "list-instances", region=r["region"])["Instances"]
    match = [i for i in instances if i["InstanceArn"] == r["instance_arn"] and
             i["IdentityStoreId"] == r["identity_store_id"] and i.get("OwnerAccountId") == r["instance_owner"]]
    if len(match) != 1:
        raise Stop("The recorded Identity Center instance could not be verified.")


def permission_set_exists(r):
    try:
        ps(r, "describe-permission-set")
        return True
    except AwsError as error:
        if error.code != "ResourceNotFoundException":
            raise
        return False


def cleanup(args):
    path = Path(args.receipt).absolute()
    if path.is_symlink():
        raise Stop("Refusing a symbolic-link receipt.")
    path = path.parent.resolve(strict=True) / path.name
    with locked(path):
        r = json.loads(path.read_text())
        validate_receipt(r)
        if r.get("state") == "completed":
            print("Cleanup was already verified. No AWS sign-in or changes were requested.")
            return 2 if r.get("report_error") else 0
        check_account(r)
        if args.wait_for_run:
            if not all((args.case_id, args.run_id, args.data_dir, args.report)):
                raise Stop("--wait-for-run requires --case-id, --run-id, --data-dir and --report.")
            gate = dict(case_id=args.case_id, run_id=args.run_id, data_dir=str(Path(args.data_dir).resolve()),
                        report=str(Path(args.report).resolve()), cli=args.cli, locale=args.locale)
            if r.get("scan_gate") and r["scan_gate"] != gate:
                raise Stop("This receipt is bound to a different scan or report path.")
            if args.dry_run:
                r["scan_gate"] = gate
            else:
                save(path, r, scan_gate=gate)
        if not args.revoke_now:
            if not r.get("scan_gate"):
                raise Stop("Select --wait-for-run, or --revoke-now after saving the report.")
            if not shutil.which(r["scan_gate"]["cli"]) or not Path(r["scan_gate"]["data_dir"]).is_dir():
                raise Stop("The installed scanner CLI and its data directory must be on this computer.")
            if not wait_and_export(path, r, args):
                return 0
        # Validate the admin account and the exact organization instance before mutations.
        check_account(r)
        # Recover a lost CreatePermissionSet reply by its unique marker, never by name alone.
        if not r.get("permission_set_arn"):
            matches = []
            for arn in sso(r, "list-permission-sets")["PermissionSets"]:
                details = sso(r, "describe-permission-set", permission_set_arn=arn)["PermissionSet"]
                if details["Name"] == r["name"]:
                    candidate = dict(r, permission_set_arn=arn)
                    check_owned(candidate)
                    matches.append(arn)
            if len(matches) != 1:
                raise Stop("Permission-set creation is unconfirmed. Keep this receipt; no resource was removed.")
            r["permission_set_arn"] = matches[0]
            if not args.dry_run:
                save(path, r, creation_confirmed=True)
        exists = permission_set_exists(r)
        if exists:
            check_owned(r)
            if r["assignment_state"] == "pending":
                raise Stop("Assignment creation has no confirmed request ID. Manual review is needed before cleanup.")
            if r["assignment_state"] == "requested":
                succeeded = wait_request(r, "creation", r["creation_request"], allow_failed=True)
                if not succeeded and check_assignments(r):
                    raise Stop("A failed creation now has an assignment. It has been preserved.")
            rows = check_assignments(r)
            if args.dry_run:
                print(f"Would remove this scan's assignment and dedicated permission set: {r['name']}")
                return 0
            if r.get("deletion_request") and r["assignment_state"] != "deleted":
                if wait_request(r, "deletion", r["deletion_request"], allow_failed=True):
                    if check_assignments(r):
                        raise Stop("A prior deletion succeeded but an assignment is present. It has been preserved.")
                    rows = []
                else:
                    save(path, r, deletion_request=None, deletion_sent=False)
                    raise Stop("AWS confirmed the deletion failed. Retry cleanup to submit a new request.")
            if rows:
                if r.get("deletion_sent"):
                    raise Stop("A previous deletion has no confirmed reply. A present assignment is preserved for review.")
                # Recheck ownership immediately before the first mutation.
                check_owned(r)
                save(path, r, state="cleanup_pending", deletion_sent=True)
                try:
                    response = ps(r, "delete-account-assignment", target_id=r["account_id"], target_type="AWS_ACCOUNT",
                                  principal_type="USER", principal_id=r["user_id"])["AccountAssignmentDeletionStatus"]
                except AwsError as error:
                    if error.code in REJECTED:
                        save(path, r, deletion_sent=False)
                    raise
                save(path, r, deletion_request=response["RequestId"])
                wait_request(r, "deletion", r["deletion_request"])
            if check_assignments(r):
                raise Stop("AWS has not confirmed assignment removal. Keep the receipt and retry later.")
            save(path, r, assignment_state="deleted")
            check_owned(r)
            check_assignments(r)
            ps(r, "delete-permission-set")
            if permission_set_exists(r):
                raise Stop("AWS has not confirmed permission-set removal. Keep the receipt and retry later.")
        elif not r.get("creation_confirmed"):
            raise Stop("Creation is unconfirmed. An empty list cannot establish successful cleanup.")
        elif args.dry_run:
            print("The recorded permission set is already absent.")
            return 0
        # A receipt moved to a different directory cannot authorize deleting another path.
        setup_file = path.parent / f"ai-security-scanner-aws-setup-{r['id']}.json"
        file_state = "absent"
        if setup_file.is_symlink():
            file_state = "preserved_changed"
        elif setup_file.exists():
            if r.get("setup_file_sha256") == digest(setup_file):
                setup_file.unlink()
                file_state = "removed"
            else:
                file_state = "preserved_changed"
        save(path, r, state="completed", completed_at=now(), setup_file_state=file_state)
        print(f"Verified removal of this scan's AWS access. Receipt: {path}")
        print("Previously issued AWS sessions may remain valid until they expire; the session limit was one hour.")
        return 2 if r.get("report_error") else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("setup", help="Create dedicated temporary read-only access")
    start.add_argument("--temporary", action="store_true")
    start.add_argument("--user")
    start.add_argument("--account")
    end = sub.add_parser("cleanup", help="Revoke only the access recorded by temporary setup")
    end.add_argument("--receipt", required=True)
    mode = end.add_mutually_exclusive_group()
    mode.add_argument("--revoke-now", action="store_true")
    mode.add_argument("--wait-for-run", action="store_true")
    end.add_argument("--dry-run", action="store_true")
    end.add_argument("--case-id")
    end.add_argument("--run-id")
    end.add_argument("--data-dir")
    end.add_argument("--report")
    end.add_argument("--cli", default="ai-security-scanner-cli")
    end.add_argument("--locale", choices=("en", "zh-Hant"), default="zh-Hant")
    end.add_argument("--wait-minutes", type=float, default=120)
    end.add_argument("--poll-seconds", type=float, default=5)
    args = parser.parse_args()
    if args.command == "cleanup" and (args.wait_minutes < 0 or args.poll_seconds <= 0):
        parser.error("Wait duration must be non-negative and polling must be positive.")
    try:
        return setup(args) if args.command == "setup" else cleanup(args)
    except (Stop, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
        print(f"Stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
