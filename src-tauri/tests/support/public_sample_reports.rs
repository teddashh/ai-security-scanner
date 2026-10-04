//! Reproducible public examples use the same adapters, persisted case and HTML
//! exporter as ordinary scans. Only the execution transport is simulated.
use super::*;

#[test]
#[ignore = "writes public examples only when AI_SCANNER_PUBLIC_SAMPLE_DIR is supplied"]
fn generate_public_sample_reports() {
    let destination = PathBuf::from(
        std::env::var_os("AI_SCANNER_PUBLIC_SAMPLE_DIR")
            .expect("set AI_SCANNER_PUBLIC_SAMPLE_DIR to a new empty directory"),
    );
    assert!(
        !destination.exists() || fs::read_dir(&destination).unwrap().next().is_none(),
        "public sample destination must be empty"
    );
    fs::create_dir_all(&destination).unwrap();
    all_engines_in_one_report(
        AssessmentIntent::InternalItEnvironment,
        AiGeneratedArtifactAnswer::No,
        EngineOutcomes::EveryDetectorReports,
        |subject| {
            let storage = Storage::open(subject.database).unwrap();
            let mut case = subject.completed.clone();
            case.title = "ExampleCo — sample IT security assessment".into();
            case.profile.organization_name = "ExampleCo (fictional organization)".into();
            case.profile.notes = Some(
                "Simulated assessment using representative upstream-format inputs. No live organization or customer data."
                    .into(),
            );
            case.is_demo = true;
            storage
                .save_case(&mut case, "public_sample.prepared")
                .unwrap();
            let service = CaseService::new(
                &storage,
                subject.engines,
                subject.adapters,
                subject.artifact_root,
                subject.signing_key,
            );
            let report = build_beginner_master_report(&case, subject.scan_run_id).unwrap();
            let mut sources = Vec::new();
            for engine_id in dispatchable_engine_ids(subject.engines) {
                let findings = report
                    .findings
                    .iter()
                    .filter(|finding| {
                        finding
                            .evidence_references
                            .iter()
                            .any(|source| source.engine_id == engine_id)
                    })
                    .count();
                let observations = report
                    .inventory
                    .items
                    .iter()
                    .filter(|item| {
                        item.sources
                            .iter()
                            .any(|source| source.engine_id == engine_id)
                    })
                    .count();
                assert!(
                    findings + observations > 0,
                    "{engine_id} has no report result"
                );
                if INVENTORY_ONLY_ENGINES.contains(&engine_id) {
                    assert_eq!(findings, 0, "inventory must not become a vulnerability");
                }
                let manifest = subject.engines.get(engine_id).unwrap();
                let (fixture, fixture_name) =
                    fixture(engine_id, EngineOutcomes::EveryDetectorReports);
                sources.push(serde_json::json!({
                    "engineId": engine_id,
                    "displayName": manifest.display_name,
                    "findings": findings,
                    "inventoryObservations": observations,
                    "inputFormat": fixture_name.rsplit('.').next().unwrap(),
                    "fixtureFileName": fixture_name,
                    "fixtureSha256": hex::encode(Sha256::digest(fixture)),
                    "engineVersion": manifest.engine_version,
                    "adapterVersion": manifest.adapter_version,
                    "dataOrigin": "simulated scenario; representative upstream-format fixture"
                }));
            }
            assert_eq!(sources.len(), BUILTIN_ENGINE_IDS.len());

            // Export through the production service after reopening the saved
            // case. No report facts or detector severities are rewritten.
            let mut exports = Vec::new();
            for (disclosure, redaction) in [
                ("redacted", RedactionProfile::Standard),
                ("full", RedactionProfile::None),
            ] {
                for (language, locale) in
                    [("en", ReportLocale::En), ("zh-TW", ReportLocale::ZhHant)]
                {
                    let name = format!("sample-report-{disclosure}-{language}.html");
                    let path = destination.join(&name);
                    service
                        .export_case(
                            subject.case_id,
                            subject.scan_run_id,
                            CaseExportFormat::Html,
                            path.clone(),
                            ExportOptions {
                                redaction,
                                include_raw_artifacts: false,
                                locale,
                            },
                        )
                        .unwrap();
                    let html = fs::read_to_string(&path).unwrap();
                    assert_paragraphs_are_well_formed(&html, &name);
                    for secret in [
                        "SECRET_SENTINEL_MUST_NEVER_LEAK",
                        "synthetic-fixture-only-no-provider-access",
                    ] {
                        assert!(!html.contains(secret), "credential escaped into {name}");
                    }
                    if disclosure == "redacted" {
                        for private in [
                            "123456789012",
                            "portal.example.test",
                            "passive.example.test",
                            "model.example.test",
                            "ExampleCo",
                        ] {
                            assert!(
                                !html.contains(private),
                                "{private} escaped redaction in {name}"
                            );
                        }
                    } else {
                        assert!(html.contains("123456789012"));
                        assert!(html.contains("portal.example.test"));
                    }
                    exports.push(serde_json::json!({
                        "file": name, "locale": language, "redaction": redaction.as_str(),
                        "standardExportSha256": hex::encode(Sha256::digest(html.as_bytes()))
                    }));
                }
            }
            fs::write(destination.join("sample-generation.json"), serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "productVersion": env!("CARGO_PKG_VERSION"),
                "scenario": "simulated multi-asset IT environment",
                "liveTargetContact": false,
                "pipeline": "upstream-format fixtures -> production adapters -> persisted terminal case -> standard HTML export",
                "scannerCount": sources.len(),
                "findings": report.findings.len(),
                "inventoryObservations": report.inventory.total,
                "sources": sources,
                "exports": exports
            })).unwrap()).unwrap();
        },
    );
}
