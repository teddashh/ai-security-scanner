#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
const path = join(process.env.HOME, 'scanner-state.json');
const state = JSON.parse(readFileSync(path, 'utf8'));
const args = process.argv.slice(2);
const arg = (flag) => args[args.indexOf(flag) + 1];
const save = () => writeFileSync(path, JSON.stringify(state));
state.calls.push(args);
if (arg('--case-id') !== state.caseId || arg('--run-id') !== state.runId || arg('--data-dir') !== process.env.HOME) {
  save(); process.exit(9);
}
if (args.includes('status')) {
  const status = state.statuses.shift();
  save();
  if (!status) process.exit(2);
  if (state.expireTokenOnFinish && status.runs[0].completed_at) {
    const graph = JSON.parse(readFileSync(process.env.FAKE_GRAPH_STATE, 'utf8'));
    graph.expiredToken = true;
    writeFileSync(process.env.FAKE_GRAPH_STATE, JSON.stringify(graph));
  }
  console.log(JSON.stringify(status));
} else if (args.includes('create')) {
  const graph = JSON.parse(readFileSync(process.env.FAKE_GRAPH_STATE, 'utf8'));
  state.grantsAtExport = graph.oauth2PermissionGrants.length;
  save();
  if (state.failExport) process.exit(3);
  const report = '<!doctype html><html><body>Saved scan report</body></html>';
  const destination = arg('--destination');
  writeFileSync(destination, report, { flag: 'wx' });
  console.log(JSON.stringify({ case_id: state.caseId, run_id: state.runId, path: destination, sha256: createHash('sha256').update(report).digest('hex') }));
} else { process.exit(4); }
