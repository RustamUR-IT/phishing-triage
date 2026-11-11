// Parse and semantically check detections/*.kql with Microsoft's Kusto.Language
// (the analyser behind the Sentinel and ADX query editors), against the columns the
// rules use. Catches syntax errors, unknown columns/functions and type mismatches.
//
//   npm install --no-save @kusto/language-service-next@12.4.1
//   node scripts/check_kql.cjs
//
// The schemas below are subsets of the Microsoft Sentinel / Defender XDR tables
// (types as documented in the Azure Monitor table reference).
"use strict";

const fs = require("node:fs");
const path = require("node:path");

require("@kusto/language-service-next/bridge.min.js");
require("@kusto/language-service-next/Kusto.Language.Bridge.min.js");

const signin =
  "(TimeGenerated:datetime, UserPrincipalName:string, IPAddress:string, ResultType:string," +
  " AppDisplayName:string, ClientAppUsed:string, UserAgent:string, Location:string)";

const TABLES = {
  SigninLogs: signin,
  AADNonInteractiveUserSignInLogs: signin,
  UrlClickEvents:
    "(TimeGenerated:datetime, ActionType:string, AccountUpn:string, Url:string," +
    " NetworkMessageId:string, IPAddress:string, IsClickedThrough:bool, ThreatTypes:string," +
    " Workload:string, UrlChain:string, DetectionMethods:string, ReportId:string)",
  EmailEvents:
    "(TimeGenerated:datetime, NetworkMessageId:string, RecipientEmailAddress:string," +
    " SenderFromAddress:string, SenderFromDomain:string, Subject:string, ThreatTypes:string," +
    " DeliveryAction:string, DeliveryLocation:string)",
  EmailPostDeliveryEvents:
    "(TimeGenerated:datetime, NetworkMessageId:string, Action:string, ActionType:string," +
    " ActionTrigger:string, ActionResult:string, RecipientEmailAddress:string," +
    " DeliveryLocation:string, ThreatTypes:string)",
  OfficeActivity:
    "(TimeGenerated:datetime, UserId:string, Operation:string, OfficeWorkload:string," +
    " ResultStatus:string, Parameters:string, ClientIP:string, MailboxOwnerUPN:string," +
    " OfficeObjectId:string)",
};

const K = Kusto.Language;
const tables = Object.entries(TABLES).map(
  ([name, schema]) => new K.Symbols.TableSymbol.$ctor7(name, schema, null),
);
const db = new K.Symbols.DatabaseSymbol.$ctor3("sentinel", null, Bridge.toList(tables), false);
const globals = K.GlobalState.Default.WithDatabase(db);

const dir = path.join(__dirname, "..", "detections");
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".kql")).sort();
let failed = 0;

for (const file of files) {
  const text = fs.readFileSync(path.join(dir, file), "utf8");
  const code = K.KustoCode.ParseAndAnalyze(text, globals);
  const diags = Bridge.toArray(code.GetDiagnostics()).filter(
    (d) => d.Severity === "Error" || d.Severity === "Warning",
  );
  if (diags.length === 0) {
    console.log(`ok    ${file}`);
    continue;
  }
  failed += 1;
  console.log(`FAIL  ${file}`);
  for (const d of diags) {
    const line = text.slice(0, d.Start).split("\n").length;
    const snippet = text.substr(d.Start, Math.max(d.Length, 1)).replace(/\s+/g, " ");
    console.log(`  line ${line}: ${d.Severity} ${d.Code}: ${d.Message} [${snippet}]`);
  }
}

if (files.length === 0) {
  console.log("no .kql files found");
  process.exit(1);
}
process.exit(failed ? 1 : 0);
