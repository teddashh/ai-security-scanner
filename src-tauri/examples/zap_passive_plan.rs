//! Generate the real product plan for controlled local runtime verification.
//! This example only serializes a plan; it performs no target contact.
use ai_security_scanner_lib::zap_work_plan::{
    ZapGatewayEndpoint, ZapPassiveBounds, build_zap_passive_plan,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [origin, gateway, port, rate] = args.as_slice() else {
        return Err(
            "expected: <approved-origin> <gateway-host> <gateway-port> <requests-per-second>"
                .into(),
        );
    };
    let plan = build_zap_passive_plan(
        &url::Url::parse(origin)?,
        &ZapGatewayEndpoint {
            host: gateway.clone(),
            port: port.parse()?,
        },
        &ZapPassiveBounds {
            requests_per_second: rate.parse()?,
            request_timeout_seconds: 10,
            max_depth: 5,
            max_children: 100,
            spider_max_duration_minutes: 2,
            passive_wait_max_duration_minutes: 2,
            thread_count: 5,
            max_alerts_per_rule: 100,
        },
        "/output",
        "zap",
    )?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}
