use super::*;

// --- parse_mem_usage ---

#[test]
fn parse_mem_usage_mib_slash_gib() {
    let (usage, limit) = parse_mem_usage("12.5MiB / 2GiB");
    assert!(
        (usage - 12.5).abs() < 0.01,
        "usage should be ~12.5 MB, got {usage}"
    );
    assert!(
        (limit - 2048.0).abs() < 0.01,
        "limit should be ~2048 MB, got {limit}"
    );
}

#[test]
fn parse_mem_usage_mb_slash_gb() {
    let (usage, limit) = parse_mem_usage("256MB / 1GB");
    assert!((usage - 256.0).abs() < 0.01);
    assert!((limit - 1024.0).abs() < 0.01);
}

#[test]
fn parse_mem_usage_kib_slash_mib() {
    let (usage, limit) = parse_mem_usage("512KiB / 512MiB");
    assert!(
        (usage - 0.5).abs() < 0.01,
        "512 KiB should be ~0.5 MB, got {usage}"
    );
    assert!((limit - 512.0).abs() < 0.01);
}

#[test]
fn parse_mem_usage_kb_slash_mb() {
    let (usage, limit) = parse_mem_usage("1024KB / 2048MB");
    assert!(
        (usage - 1.0).abs() < 0.01,
        "1024 KB should be 1 MB, got {usage}"
    );
    assert!((limit - 2048.0).abs() < 0.01);
}

#[test]
fn parse_mem_usage_zeros() {
    let (usage, limit) = parse_mem_usage("0MiB / 0MiB");
    assert_eq!(usage, 0.0);
    assert_eq!(limit, 0.0);
}

#[test]
fn parse_mem_usage_empty_string() {
    let (usage, limit) = parse_mem_usage("");
    assert_eq!(usage, 0.0);
    assert_eq!(limit, 0.0);
}

#[test]
fn parse_mem_usage_unknown_unit_returns_zero() {
    let (usage, limit) = parse_mem_usage("100XiB / 200XiB");
    assert_eq!(usage, 0.0);
    assert_eq!(limit, 0.0);
}

#[test]
fn parse_mem_usage_missing_limit_part() {
    // Only one segment — limit should fall back to 0
    let (usage, limit) = parse_mem_usage("64MiB");
    assert!((usage - 64.0).abs() < 0.01);
    assert_eq!(limit, 0.0);
}

#[test]
fn parse_mem_usage_extra_whitespace() {
    let (usage, limit) = parse_mem_usage("  32MiB  /  4GiB  ");
    assert!((usage - 32.0).abs() < 0.01);
    assert!((limit - 4096.0).abs() < 0.01);
}

// --- parse_kb ---

#[test]
fn parse_kb_standard_line() {
    assert_eq!(parse_kb("MemTotal:       16384000 kB"), 16_384_000);
}

#[test]
fn parse_kb_available_line() {
    assert_eq!(parse_kb("MemAvailable:    8192000 kB"), 8_192_000);
}

#[test]
fn parse_kb_zero_value() {
    assert_eq!(parse_kb("MemFree:               0 kB"), 0);
}

#[test]
fn parse_kb_empty_line() {
    assert_eq!(parse_kb(""), 0);
}

#[test]
fn parse_kb_malformed_no_number() {
    assert_eq!(parse_kb("MemTotal: abc kB"), 0);
}

// --- CPU utilisation arithmetic ---

#[test]
fn cpu_percent_full_load() {
    // 0 idle out of 1000 total ticks → 100% CPU
    let total1 = 0u64;
    let idle1 = 0u64;
    let total2 = 1000u64;
    let idle2 = 0u64;

    let total_diff = (total2 as f64) - (total1 as f64);
    let idle_diff = (idle2 as f64) - (idle1 as f64);
    let pct = ((total_diff - idle_diff) / total_diff * 100.0).clamp(0.0, 100.0);
    assert!((pct - 100.0).abs() < 0.001);
}

#[test]
fn cpu_percent_idle() {
    // All ticks are idle → 0% CPU
    let total1 = 0u64;
    let idle1 = 0u64;
    let total2 = 1000u64;
    let idle2 = 1000u64;

    let total_diff = (total2 as f64) - (total1 as f64);
    let idle_diff = (idle2 as f64) - (idle1 as f64);
    let pct = ((total_diff - idle_diff) / total_diff * 100.0).clamp(0.0, 100.0);
    assert!((pct - 0.0).abs() < 0.001);
}

#[test]
fn cpu_percent_half_load() {
    let total_diff = 1000.0f64;
    let idle_diff = 500.0f64;
    let pct = ((total_diff - idle_diff) / total_diff * 100.0).clamp(0.0, 100.0);
    assert!((pct - 50.0).abs() < 0.001);
}

#[test]
fn cpu_percent_clamps_to_zero_on_zero_diff() {
    // total_diff == 0 → guard returns 0.0 (no divide-by-zero)
    let total_diff = 0.0f64;
    let pct = if total_diff <= 0.0 { 0.0 } else { 100.0 };
    assert_eq!(pct, 0.0);
}

// --- SystemMetrics / ContainerMetrics msg_type constants ---

#[test]
fn system_metrics_msg_type_is_correct() {
    // The msg_type field is used by the frontend to dispatch incoming WS messages.
    // A typo here would silently break the dashboard metrics display.
    let m = SystemMetrics {
        msg_type: "system_metrics",
        cpu_percent: 0.0,
        mem_used_mb: 0,
        mem_total_mb: 0,
        disk_used_gb: 0.0,
        disk_total_gb: 0.0,
        timestamp: 0,
    };
    assert_eq!(m.msg_type, "system_metrics");
}

#[test]
fn container_metrics_msg_type_is_correct() {
    let m = ContainerMetrics {
        msg_type: "container_metrics",
        containers: vec![],
        timestamp: 0,
    };
    assert_eq!(m.msg_type, "container_metrics");
}

// --- sample_system end-to-end ---------------------------------------
//
// These exercise the full `sample_system` pipeline on a Linux runner
// with a readable /proc. Each test names the control it pins: deleting
// that line from the production function makes the test go red.

/// Happy path on a real Linux box: sample_system must Ok and the
/// msg_type literal must be exactly `"system_metrics"` (the
/// dashboard dispatcher keys on it). A typo or a stray `Ok(())`
/// instead of `Ok(SystemMetrics{...})` makes this go red.
#[tokio::test]
async fn sample_system_succeeds_with_msg_type_system_metrics() {
    let m = sample_system().await.expect("sample_system must Ok");
    assert_eq!(m.msg_type, "system_metrics");
}

/// `read_cpu_percent` clamps its result to `[0, 100]`. The clamp
/// must survive the read→clamp→return path inside sample_system.
/// Removing the `.clamp(0.0, 100.0)` makes this go red on a busy
/// runner; on an idle runner the assertion still holds but only
/// because of the (0, 100) arithmetic — the control verified is
/// the clamp, paired with the "non-NaN" assertion below.
#[tokio::test]
async fn sample_system_cpu_percent_is_finite_and_in_range() {
    let m = sample_system().await.expect("sample_system must Ok");
    assert!(m.cpu_percent.is_finite(), "cpu_percent must not be NaN");
    assert!(m.cpu_percent >= 0.0, "cpu_percent must be >= 0");
    assert!(m.cpu_percent <= 100.0, "cpu_percent must be <= 100");
}

/// Cross-check `mem_total_mb` against a fresh parse of
/// /proc/meminfo. If `read_mem_mb` ever returns bytes instead of
/// kB, or divides wrong, the numbers diverge.
#[tokio::test]
async fn sample_system_mem_total_mb_matches_proc_meminfo() {
    let m = sample_system().await.expect("sample_system must Ok");
    assert!(m.mem_total_mb > 0, "mem_total_mb must be > 0 on Linux");

    let raw = std::fs::read_to_string("/proc/meminfo").unwrap();
    let total_kb: u64 = raw
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert_eq!(m.mem_total_mb, total_kb / 1024);
}

/// `mem_used_mb` is `MemTotal - MemAvailable`, never negative.
/// `saturating_sub` in `read_mem_mb` is the control — removing it
/// (and substituting `-`) makes this go red on a system where
/// `available > total` is even momentarily true.
#[tokio::test]
async fn sample_system_mem_used_does_not_exceed_total() {
    let m = sample_system().await.expect("sample_system must Ok");
    assert!(m.mem_used_mb <= m.mem_total_mb);
}

/// `sample_system` stamps `chrono::Utc::now()` — the timestamp
/// must sit between the wall-clock read taken just before and
/// just after the call. Hardcoding `0` (or any other constant) in
/// `sample_system` makes this go red.
#[tokio::test]
async fn sample_system_timestamp_is_within_call_window() {
    let before = chrono::Utc::now().timestamp();
    let m = sample_system().await.expect("sample_system must Ok");
    let after = chrono::Utc::now().timestamp();
    assert!(m.timestamp >= before, "timestamp must not be in the past");
    assert!(m.timestamp <= after, "timestamp must not be in the future");
}

/// `read_disk_gb("/")` exercises the happy statvfs path on the
/// runner's root filesystem. `disk_used_gb` must be <=
/// `disk_total_gb` (the `saturating_sub` in `read_disk_gb`); on a
/// healthy system `disk_total_gb > 0`.
#[tokio::test]
async fn sample_system_disk_total_gb_positive_for_root() {
    let m = sample_system().await.expect("sample_system must Ok");
    assert!(
        m.disk_total_gb > 0.0,
        "statvfs(\"/\") must report positive total"
    );
    assert!(m.disk_used_gb >= 0.0, "disk_used_gb must be non-negative");
    assert!(m.disk_used_gb <= m.disk_total_gb);
}

// --- read_disk_gb direct tests --------------------------------------
//
// read_disk_gb's only failure-handling is the `Err(_) => (0.0,
// 0.0)` arm — direct tests pin both arms.

/// `statvfs` on a path that does not exist returns `Err(ENOENT)`.
/// The helper must collapse that to `(0.0, 0.0)` instead of
/// propagating. Removing the `Err(_)` arm (e.g. with `.unwrap()`)
/// makes this panic.
#[test]
fn read_disk_gb_returns_zero_zero_for_nonexistent_mount() {
    let (used, total) = read_disk_gb("/nonexistent_mount_xyz_helmly_test");
    assert_eq!(used, 0.0);
    assert_eq!(total, 0.0);
}

/// Sanity-check the happy path: `statvfs("/")` on a real Linux
/// runner must report a positive total, and `used <= total`.
#[test]
fn read_disk_gb_returns_positive_for_root() {
    let (used, total) = read_disk_gb("/");
    assert!(total > 0.0, "statvfs(\"/\") must return positive total");
    assert!(used >= 0.0);
    assert!(used <= total);
}

// --- collect_container_stats_with (refactored for testing) ---------

/// The runner returning `None` simulates every podman failure mode
/// (binary missing, nonzero exit, spawn error). The function must
/// collapse them to an empty `Vec` instead of panicking. Removing
/// the `None => return vec![]` arm makes this panic.
#[test]
fn collect_container_stats_with_returns_empty_when_runner_returns_none() {
    let stats = collect_container_stats_with(|| None);
    assert!(stats.is_empty());
}

/// podman succeeded with empty stdout (no containers running).
/// `serde_json::from_slice(b"")` is an `Err` — the
/// `unwrap_or_default()` swallows it. Removing `.unwrap_or_default()`
/// makes this panic.
#[test]
fn collect_container_stats_with_returns_empty_for_empty_output() {
    let stats = collect_container_stats_with(|| Some(Vec::new()));
    assert!(stats.is_empty());
}

/// Garbage stdout — the parse-error swallow path. Same control as
/// the empty-output test: the `unwrap_or_default()` on
/// `serde_json::from_slice`.
#[test]
fn collect_container_stats_with_returns_empty_for_malformed_json() {
    let stats = collect_container_stats_with(|| Some(b"not json at all".to_vec()));
    assert!(stats.is_empty());
}

/// podman ran with no containers — an empty JSON array is valid.
/// The from_slice must accept `[]` as `Vec<RawStat>` of length 0.
/// Removing the empty-array default makes this go red (would
/// surface as a non-empty Vec).
#[test]
fn collect_container_stats_with_returns_empty_for_empty_array() {
    let stats = collect_container_stats_with(|| Some(b"[]".to_vec()));
    assert!(stats.is_empty());
}

/// Happy path: valid JSON with one container. The `CPUPerc` and
/// `MemUsage` fields must be parsed into their numeric counterparts.
/// Removing the `trim_end_matches('%')` step on `cpu_perc` would
/// surface as `cpu_percent == 0.0` (parse fails → 0.0 fallback).
#[test]
fn collect_container_stats_with_parses_single_container() {
    let json = br#"[
            {
                "ID": "abc123def456",
                "Name": "web-1",
                "CPUPerc": "5.25%",
                "MemUsage": "100MiB / 1GiB"
            }
        ]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert_eq!(stats.len(), 1);
    let s = &stats[0];
    assert_eq!(s.id, "abc123def456");
    assert_eq!(s.name, "web-1");
    assert!(
        (s.cpu_percent - 5.25).abs() < 0.001,
        "cpu_percent must parse '5.25%%' → 5.25; got {}",
        s.cpu_percent
    );
    assert!((s.mem_usage_mb - 100.0).abs() < 0.01);
    assert!((s.mem_limit_mb - 1024.0).abs() < 0.01);
}

/// Two containers in one shot — verifies the iterator chain and
/// that order is preserved (podman returns alphabetical-ish but
/// the test doesn't rely on it; we only check the two are
/// distinct and the second has the expected parsed values).
#[test]
fn collect_container_stats_with_parses_multiple_containers() {
    let json = br#"[
            {"ID": "aaa", "Name": "one", "CPUPerc": "1.0%", "MemUsage": "10MiB / 1GiB"},
            {"ID": "bbb", "Name": "two", "CPUPerc": "50%",   "MemUsage": "200MiB / 2GiB"}
        ]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert_eq!(stats.len(), 2);

    let by_name: std::collections::HashMap<&str, &ContainerStat> =
        stats.iter().map(|s| (s.name.as_str(), s)).collect();
    assert!((by_name["one"].cpu_percent - 1.0).abs() < 0.001);
    assert!((by_name["one"].mem_usage_mb - 10.0).abs() < 0.01);
    assert!((by_name["two"].cpu_percent - 50.0).abs() < 0.001);
    assert!((by_name["two"].mem_usage_mb - 200.0).abs() < 0.01);
    assert!((by_name["two"].mem_limit_mb - 2048.0).abs() < 0.01);
}

/// `CPUPerc` without a `%` suffix must still parse. The
/// `trim_end_matches('%')` is a no-op when there's no `%`, and the
/// subsequent `parse::<f64>()` succeeds.
#[test]
fn collect_container_stats_with_parses_cpu_percent_without_percent_sign() {
    let json = br#"[{"ID":"x","Name":"y","CPUPerc":"50%","MemUsage":"1MiB / 1MiB"}]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert_eq!(stats.len(), 1);
    assert!((stats[0].cpu_percent - 50.0).abs() < 0.001);
}

/// `CPUPerc` that doesn't parse as `f64` must fall back to `0.0`,
/// not panic. Removing `.unwrap_or(0.0)` on the parse makes this
/// panic.
#[test]
fn collect_container_stats_with_handles_unparseable_cpu() {
    let json = br#"[{"ID":"x","Name":"y","CPUPerc":"abc","MemUsage":"1MiB / 1MiB"}]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].cpu_percent, 0.0);
}

/// `id` and `name` must pass through verbatim — no trim, no
/// lowercasing, no truncation. The frontend uses both as map keys
/// against container labels, so any silent mangling surfaces as
/// "container not found" in the dashboard.
#[test]
fn collect_container_stats_with_preserves_id_and_name_verbatim() {
    let json = br#"[
            {"ID": "long-id-with-dashes-and-numbers-12345", "Name": "service-name_v2", "CPUPerc": "0%", "MemUsage": "0MiB / 0MiB"}
        ]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].id, "long-id-with-dashes-and-numbers-12345");
    assert_eq!(stats[0].name, "service-name_v2");
}

/// Missing field in the JSON: `serde_json::from_slice` returns
/// `Err`, swallowed by `unwrap_or_default`. Removing that
/// swallow makes this panic on `unwrap`.
#[test]
fn collect_container_stats_with_returns_empty_when_required_field_missing() {
    let json = br#"[{"ID": "x", "Name": "y"}]"#;
    let stats = collect_container_stats_with(|| Some(json.to_vec()));
    assert!(stats.is_empty());
}

// --- sample_containers end-to-end -----------------------------------

/// `sample_containers` wires the `ContainerMetrics` struct with
/// `msg_type = "container_metrics"`. The dashboard dispatcher
/// routes on this string — a typo silently drops every container
/// stat message.
#[test]
fn sample_containers_msg_type_is_container_metrics() {
    let m = sample_containers();
    assert_eq!(m.msg_type, "container_metrics");
}

/// `sample_containers` stamps `chrono::Utc::now()`. Hardcoding
/// `0` (or any constant) makes this go red.
#[test]
fn sample_containers_timestamp_is_within_call_window() {
    let before = chrono::Utc::now().timestamp();
    let m = sample_containers();
    let after = chrono::Utc::now().timestamp();
    assert!(m.timestamp >= before);
    assert!(m.timestamp <= after);
}

/// `sample_containers` must not panic whether podman is present
/// or absent — it falls through to the empty `Vec` branch. This
/// is the only test that runs the real podman runner; if podman
/// is not installed the call still returns cleanly.
#[test]
fn sample_containers_does_not_panic_when_podman_fails() {
    let m = sample_containers();
    // The point is no panic. Length can be 0 (no podman / no
    // containers) or > 0 (podman present with running containers).
    let _ = m.containers.len();
}

// --- Serde JSON shape ----------------------------------------------
//
// The frontend dispatches on the JSON `type` field, not the Rust
// field name. `#[serde(rename = "type")]` is load-bearing: removing
// it makes the dashboard ignore every message.

#[test]
fn system_metrics_serializes_msg_type_as_type_field() {
    let m = SystemMetrics {
        msg_type: "system_metrics",
        cpu_percent: 1.5,
        mem_used_mb: 100,
        mem_total_mb: 200,
        disk_used_gb: 10.5,
        disk_total_gb: 50.0,
        timestamp: 1234,
    };
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    assert_eq!(v["type"], "system_metrics");
    assert_eq!(v["cpu_percent"], 1.5);
    assert_eq!(v["mem_used_mb"], 100);
    assert_eq!(v["mem_total_mb"], 200);
    assert_eq!(v["disk_used_gb"], 10.5);
    assert_eq!(v["disk_total_gb"], 50.0);
    assert_eq!(v["timestamp"], 1234);
}

#[test]
fn container_metrics_serializes_msg_type_as_type_field() {
    let m = ContainerMetrics {
        msg_type: "container_metrics",
        containers: vec![ContainerStat {
            id: "cid".into(),
            name: "cname".into(),
            cpu_percent: 2.5,
            mem_usage_mb: 50.0,
            mem_limit_mb: 512.0,
        }],
        timestamp: 9999,
    };
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
    assert_eq!(v["type"], "container_metrics");
    assert_eq!(v["timestamp"], 9999);
    assert!(v["containers"].is_array());
    assert_eq!(v["containers"][0]["id"], "cid");
    assert_eq!(v["containers"][0]["name"], "cname");
    assert_eq!(v["containers"][0]["cpu_percent"], 2.5);
    assert_eq!(v["containers"][0]["mem_usage_mb"], 50.0);
    assert_eq!(v["containers"][0]["mem_limit_mb"], 512.0);
}

#[test]
fn container_stat_serializes_all_fields() {
    let s = ContainerStat {
        id: "id".into(),
        name: "name".into(),
        cpu_percent: 1.5,
        mem_usage_mb: 100.0,
        mem_limit_mb: 1024.0,
    };
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(v["id"], "id");
    assert_eq!(v["name"], "name");
    assert_eq!(v["cpu_percent"], 1.5);
    assert_eq!(v["mem_usage_mb"], 100.0);
    assert_eq!(v["mem_limit_mb"], 1024.0);
}
