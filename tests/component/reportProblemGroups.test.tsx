import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { FindingsPage } from "../../src/pages/FindingsPage";
import type { BeginnerMasterReport, BeginnerReportFinding } from "../../src/types";

const finding = (id: string, severity: BeginnerReportFinding["severity"]): BeginnerReportFinding => ({
  findingId:id, fingerprint:id, snapshotSource:"frozen_selected_run", title:`Original ${id}`,
  plainLanguageRisk:`Risk ${id}`, possibleImpact:`Impact ${id}`, severity, confidence:"high", priority:50,
  priorityReasons:[], targetAssetIds:["aws"], nextStep:`Review ${id}`, recommendedExpertType:"cloud",
  evidenceReferences:[{evidenceId:`evidence-${id}`, engineId: id === "low" ? "prowler" : "scoutsuite",
    detailsFrozen:true, sourceRule:`rule-${id}`, artifactSha256:`hash-${id}`, observedAt:"2026-10-02T12:00:00Z",
    location:`location-${id}`, summary:`Evidence ${id}`}],
  frameworkReferences:[], officialReferences:[],
});
const report = (): BeginnerMasterReport => ({
  schemaVersion:"1.1.0", caseId:"case",runId:"run",projectTitle:"AWS review",
  state:{summary:"complete",lifecycle:"final",lastDurableUpdate:"2026-10-02T12:00:00Z",explanation:"Completed"},
  requested:{targets:[{assetId:"aws",label:"AWS account",assetKind:"cloud_account",labelAvailability:"recorded",assetKindAvailability:"recorded"}],
    stage:{availability:"not_applicable",explanation:""},limits:[],requestedCheckIds:["prowler","scoutsuite"],automaticReductions:[],reductionsAvailability:"recorded",unavailableDimensions:[]},
  actual:{checks:[{taskId:"prowler",checkId:"prowler",resultKind:"security_check",targetAssetIds:["aws"],status:"tested_complete",testedDimensions:[]}],networkScopes:[],unavailableDimensions:[]},
  coverageGaps:[],coverageCounts:{testedComplete:1,testedPartial:0,failed:0,timedOut:0,cancelled:0,notTested:0,excluded:0,truncated:0,unavailable:0,unattributed:0,manualReview:0},
  findings:[finding("low","low"),finding("high","high"),finding("separate","medium")],
  problemGroups:[{groupId:"password",ruleVersion:"aws-related-checks-1",kind:"iam_password_policy",title:"IAM password policy needs attention",
    targetAssetId:"aws",representativeFindingId:"high",findingIds:["low","high"]}],
  nextSteps:[],technicalDetails:{collapsedByDefault:true,tasks:[]},frameworkNotice:{nonCertification:"",aidefendMappingStatus:""},dataQualityWarnings:[],
});
const update = vi.fn(async () => true);
const page = (value: BeginnerMasterReport) => render(<I18nProvider><FindingsPage report={value} findings={[]} findingGroups={[]}
  findingGroupEvents={[]} runs={[]} workflowEvents={[]} busy={false} onUpdateWorkflow={update}
  onGroupFindings={async()=>true} onUngroupFindings={async()=>{}} onOpenCoverage={()=>{}} onOpenProgress={()=>{}} onOpenExport={()=>{}}/></I18nProvider>);
beforeEach(()=>window.localStorage.setItem(localeStorageKey,"en"));
afterEach(()=>{cleanup();window.localStorage.clear();vi.clearAllMocks();});

test("a grouped row and asset count preserve accessible source findings and distinct ratings", () => {
  const {container} = page(report());
  expect(container.querySelectorAll(".finding-row")).toHaveLength(2);
  expect(container.querySelector(".asset-result-row__outcome strong")?.textContent).toContain("2");
  expect(container.querySelector(".count-label")?.textContent).toContain("3 original findings");
  const row = container.querySelector<HTMLButtonElement>(".finding-row")!;
  expect(row.textContent).toContain("Evidence records: 2");
  expect(row.textContent).toContain("prowler");
  expect(row.textContent).toContain("scoutsuite");
  expect(row.textContent).not.toContain("High confidence");
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  const detail = container.querySelector<HTMLElement>(".finding-detail")!;
  const related = detail.querySelector("details")!;
  expect(related.textContent).toContain("Original low");
  expect(related.textContent).toContain("Original high");
  expect(related.textContent).toContain("Low");
  expect(related.textContent).toContain("High");
  expect(detail.querySelector("h2")?.textContent).toBe("Original high");
  fireEvent.click(within(related).getByRole("button",{name:"Original low"}));
  expect(detail.querySelector("h2")?.textContent).toBe("Original low");
  expect(detail.textContent).toContain("location-low");
  expect(detail.textContent).toContain("rule-low");
});
test("search matches the group and originals; severity filtering preserves the matching observation", () => {
  const {container} = page(report());
  const search = container.querySelector<HTMLInputElement>('input[type="search"]')!;
  fireEvent.change(search,{target:{value:"needs attention"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("IAM password policy needs attention");
  fireEvent.change(search,{target:{value:"Original low"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("Original low");
  fireEvent.change(search,{target:{value:""}});
  fireEvent.change(within(container).getByRole("combobox",{name:"Severity"}),{target:{value:"low"}});
  expect(container.querySelectorAll(".finding-row")).toHaveLength(1);
  expect(container.querySelector(".finding-row")?.textContent).toContain("Original low");
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  expect(container.querySelector(".finding-detail h2")?.textContent).toBe("Original low");
});
test("older reports retain separate rows", () => {
  const value = report();
  delete value.problemGroups;
  const {container} = page(value);
  expect(container.querySelectorAll(".finding-row")).toHaveLength(3);
});

test("a workflow decision updates only the selected original, never the group ID", async () => {
  const {container} = page(report());
  fireEvent.click(container.querySelector<HTMLButtonElement>(".finding-row")!);
  const detail = container.querySelector<HTMLElement>(".finding-detail")!;
  fireEvent.click(within(detail.querySelector("details")!).getByRole("button",{name:"Original low"}));
  const form = detail.querySelector("form")!;
  fireEvent.change(form.querySelector("select")!,{target:{value:"confirmed"}});
  fireEvent.change(form.querySelector("input")!,{target:{value:"Reviewer"}});
  fireEvent.change(form.querySelector("textarea")!,{target:{value:"Reviewed this source observation"}});
  fireEvent.submit(form);
  await waitFor(()=>expect(update).toHaveBeenCalledWith(expect.objectContaining({findingId:"low",status:"confirmed"})));
  expect(update).toHaveBeenCalledTimes(1);
});
