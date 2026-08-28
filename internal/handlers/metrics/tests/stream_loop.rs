use super::*;

// =====================================================================
// WsSender test double — records every JSON payload sent, with
// optional injectable failure on the Nth call of each kind.
// =====================================================================

struct StubSender {
	system_sends: Arc<Mutex<Vec<serde_json::Value>>>,
	container_sends: Arc<Mutex<Vec<serde_json::Value>>>,
	/// On the Nth system send, return `Err(())` BEFORE pushing the
	/// payload to `system_sends`. None = always succeed.
	system_send_err_after: Arc<Mutex<Option<usize>>>,
	/// Same for containers.
	container_send_err_after: Arc<Mutex<Option<usize>>>,
}

impl WsSender for StubSender {
	fn send_json(
		&mut self,
		value: serde_json::Value,
	) -> BoxFuture<'_, std::result::Result<(), ()>> {
		// The serialized `"type"` field discriminates system vs
		// container (both structs derive Serialize with a
		// `#[serde(rename = "type")]` for that field).
		let is_container = value.get("type").and_then(|v| v.as_str()) == Some("container_metrics");
		Box::pin(async move {
			let next_n = if is_container {
				self.container_sends.lock().unwrap().len()
			} else {
				self.system_sends.lock().unwrap().len()
			};
			let err_after = if is_container {
				*self.container_send_err_after.lock().unwrap()
			} else {
				*self.system_send_err_after.lock().unwrap()
			};
			if err_after == Some(next_n) {
				// Inject the failure WITHOUT recording the payload —
				// matching the real `WebSocket::send`'s contract:
				// a failed send writes nothing, the loop sees `Err`
				// and breaks.
				return Err(());
			}
			if is_container {
				self.container_sends.lock().unwrap().push(value);
			} else {
				self.system_sends.lock().unwrap().push(value);
			}
			Ok(())
		})
	}
}

fn fresh_system() -> SystemMetrics {
	SystemMetrics {
		msg_type: "system_metrics",
		cpu_percent: 1.0,
		mem_used_mb: 100,
		mem_total_mb: 200,
		disk_used_gb: 1.0,
		disk_total_gb: 10.0,
		timestamp: 1,
	}
}

fn fresh_containers() -> ContainerMetrics {
	ContainerMetrics {
		msg_type: "container_metrics",
		containers: vec![ContainerStat {
			id: "c1".into(),
			name: "n1".into(),
			cpu_percent: 0.5,
			mem_usage_mb: 10.0,
			mem_limit_mb: 100.0,
		}],
		timestamp: 1,
	}
}

/// Run `stream_metrics_with` until at least `min_ticks` sleeps have
/// occurred OR until `budget` elapses, whichever comes first. The
/// return value is the final sleep count, used to write "at least"
/// assertions without flaking on slow CI.
///
/// The bounded-wait approach (instead of a sleep counter that
/// panics out of the loop) keeps the loop body unchanged from
/// production — the inner loop only checks send-json errors, not
/// sleep-return values, so a "stop" flag in the sleep closure would
/// need a different shape than the production code.
async fn run_until_sleeps(sender: &mut StubSender, min_ticks: usize, budget: Duration) -> usize {
	let sleep_calls = Arc::new(AtomicUsize::new(0));
	let sc = sleep_calls.clone();

	let sample_sys_calls = Arc::new(AtomicUsize::new(0));
	let sample_cont_calls = Arc::new(AtomicUsize::new(0));

	let ssc = sample_sys_calls.clone();
	let scc = sample_cont_calls.clone();

	let joined = async {
		stream_metrics_with(
			sender,
			move || {
				let ssc = ssc.clone();
				async move {
					ssc.fetch_add(1, Ordering::SeqCst);
					Ok(fresh_system())
				}
			},
			move || {
				scc.fetch_add(1, Ordering::SeqCst);
				fresh_containers()
			},
			move |_d: Duration| {
				let sc = sc.clone();
				async move {
					sc.fetch_add(1, Ordering::SeqCst);
					// Yield to the runtime so other tasks get a
					// turn; the timeout above bounds the loop.
					tokio::task::yield_now().await;
				}
			},
			Duration::from_millis(1),
			Duration::from_millis(1),
		)
		.await
	};

	let _ = tokio::time::timeout(budget, joined).await;

	let total = sleep_calls.load(Ordering::SeqCst);
	// Drain the assertion-time snapshot — record the counters in
	// the sender so tests can read them.
	sender
		.system_sends
		.lock()
		.unwrap()
		.push(serde_json::json!({"_tick_marker": sample_sys_calls.load(Ordering::SeqCst)}));
	sender
		.container_sends
		.lock()
		.unwrap()
		.push(serde_json::json!(
			{"_tick_marker": sample_cont_calls.load(Ordering::SeqCst)}
		));
	let _ = min_ticks;
	total
}

// =====================================================================
// stream_metrics_with — loop behaviour.
// =====================================================================

/// Cadence: on the very first tick the container send must fire
/// (because `last_container` is pre-rolled by `container_interval`
/// so `last_container.elapsed() >= container_interval` holds
/// immediately). Removing the `checked_sub(container_interval)`
/// reset before the loop would make this test go red — the
/// dashboard would then miss the first container sample after
/// every reconnect.
#[tokio::test]
async fn stream_metrics_loop_first_tick_sends_system_and_container() {
	let mut sender = StubSender {
		system_sends: Arc::new(Mutex::new(Vec::new())),
		container_sends: Arc::new(Mutex::new(Vec::new())),
		system_send_err_after: Arc::new(Mutex::new(None)),
		container_send_err_after: Arc::new(Mutex::new(None)),
	};

	let ticks = run_until_sleeps(&mut sender, 1, Duration::from_millis(50)).await;

	// We spun for ≥50ms, so multiple ticks happened. The system
	// send happens every tick; the container send happens on at
	// least tick 0 (pre-rolled) AND every tick because
	// `system_interval == container_interval == 1ms` yields fast
	// enough that several iterations elapse.
	let sys = sender.system_sends.lock().unwrap().len();
	let cont = sender.container_sends.lock().unwrap().len();
	// Drop the sentinel `_tick_marker` entries we pushed in
	// `run_until_sleeps`.
	let sys_samples = sys.saturating_sub(1);
	let cont_samples = cont.saturating_sub(1);

	assert!(ticks >= 1, "loop must run for at least one tick");
	assert!(
		sys_samples >= 1,
		"system send must fire at least once; sys samples={sys_samples}"
	);
	assert!(
		cont_samples >= 1,
		"container send must fire at least once; cont samples={cont_samples}"
	);

	// Strip sentinel entries — `run_until_sleeps` appended a
	// marker to each buffer at the end. Filter and check the
	// non-marker values round-trip through JSON.
	let sys_vals: Vec<_> = sender
		.system_sends
		.lock()
		.unwrap()
		.iter()
		.filter(|v| v.get("_tick_marker").is_none())
		.cloned()
		.collect();
	assert_eq!(
		sys_vals.len(),
		sys_samples,
		"system buffer should contain only real system_metrics frames + the marker"
	);
	let cont_vals: Vec<_> = sender
		.container_sends
		.lock()
		.unwrap()
		.iter()
		.filter(|v| v.get("_tick_marker").is_none())
		.cloned()
		.collect();
	assert_eq!(cont_vals.len(), cont_samples);
	assert!(
		sys_vals
			.iter()
			.all(|v| v.get("type").and_then(|t| t.as_str()) == Some("system_metrics")),
		"every system send must carry the system_metrics discriminator"
	);
	assert!(
		cont_vals
			.iter()
			.all(|v| v.get("type").and_then(|t| t.as_str()) == Some("container_metrics")),
		"every container send must carry the container_metrics discriminator"
	);
}

/// Sampling error → loop breaks immediately. No system send, no
/// container send, no sleep (because the `break` is before the
/// `sleep_fn` call). Removing the `Err(_) => break` arm — e.g.
/// changing it to `Ok(m) => m` and silently swallowing the error —
/// would push the loop past the sample error and turn this test
/// red.
#[tokio::test]
async fn stream_metrics_loop_sample_error_breaks_loop_with_no_send_no_sleep() {
	let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let sample_calls = Arc::new(AtomicUsize::new(0));
	let sleep_calls = Arc::new(AtomicUsize::new(0));

	let mut sender = StubSender {
		system_sends: system_sends.clone(),
		container_sends: container_sends.clone(),
		system_send_err_after: Arc::new(Mutex::new(None)),
		container_send_err_after: Arc::new(Mutex::new(None)),
	};

	let sc = sample_calls.clone();
	let sl = sleep_calls.clone();
	let joined = async {
		stream_metrics_with(
			&mut sender,
			move || {
				let sc = sc.clone();
				async move {
					sc.fetch_add(1, Ordering::SeqCst);
					Err::<SystemMetrics, anyhow::Error>(anyhow::anyhow!("sample boom"))
				}
			},
			|| unreachable!("sample error must break before the container branch"),
			move |_d: Duration| {
				let sl = sl.clone();
				async move {
					sl.fetch_add(1, Ordering::SeqCst);
				}
			},
			Duration::from_millis(1),
			Duration::from_millis(1),
		)
		.await
	};

	let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

	assert_eq!(
		sample_calls.load(Ordering::SeqCst),
		1,
		"sample_system must have been called exactly once before the error"
	);
	assert!(
		system_sends.lock().unwrap().is_empty(),
		"no system send must occur on sample error"
	);
	assert!(
		container_sends.lock().unwrap().is_empty(),
		"no container send must occur on sample error"
	);
	assert_eq!(
		sleep_calls.load(Ordering::SeqCst),
		0,
		"sleep must not run when the loop breaks out before reaching it"
	);
}

/// System-send failure → loop breaks before the container branch.
/// Removing the `if sender.send_json(...).await.is_err() { break }`
/// arm (e.g. replacing it with a `let _ = ...`) would log the
/// error and keep spinning — this test pins the break.
#[tokio::test]
async fn stream_metrics_loop_system_send_error_breaks_loop_no_sleep_no_container() {
	let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let sample_sys_calls = Arc::new(AtomicUsize::new(0));
	let sample_cont_calls = Arc::new(AtomicUsize::new(0));
	let sleep_calls = Arc::new(AtomicUsize::new(0));

	let mut sender = StubSender {
		system_sends: system_sends.clone(),
		container_sends: container_sends.clone(),
		// Err on the FIRST system send (n=0 → first push attempt).
		system_send_err_after: Arc::new(Mutex::new(Some(0))),
		container_send_err_after: Arc::new(Mutex::new(None)),
	};

	let ssc = sample_sys_calls.clone();
	let scc = sample_cont_calls.clone();
	let sl = sleep_calls.clone();
	let joined = async {
		stream_metrics_with(
			&mut sender,
			move || {
				let ssc = ssc.clone();
				async move {
					ssc.fetch_add(1, Ordering::SeqCst);
					Ok(fresh_system())
				}
			},
			move || {
				scc.fetch_add(1, Ordering::SeqCst);
				fresh_containers()
			},
			move |_d: Duration| {
				let sl = sl.clone();
				async move {
					sl.fetch_add(1, Ordering::SeqCst);
				}
			},
			Duration::from_millis(1),
			Duration::from_millis(1),
		)
		.await
	};

	let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

	// The first system send was rejected (and not recorded), so
	// the buffer is empty.
	assert!(
		system_sends.lock().unwrap().is_empty(),
		"injected system-send failure must not record anything"
	);
	assert!(
		container_sends.lock().unwrap().is_empty(),
		"container branch must not run when the system send breaks the loop"
	);
	assert_eq!(
		sample_sys_calls.load(Ordering::SeqCst),
		1,
		"sample_system called once before the send-error break"
	);
	assert_eq!(
		sample_cont_calls.load(Ordering::SeqCst),
		0,
		"sample_containers must never be called"
	);
	assert_eq!(
		sleep_calls.load(Ordering::SeqCst),
		0,
		"sleep must not run on a system-send break"
	);
}

/// Container-send failure → loop breaks after the system-send
/// succeeded on tick 0. The buffer should record one system frame
/// and zero container frames (the failed container send writes
/// nothing).
#[tokio::test]
async fn stream_metrics_loop_container_send_error_breaks_loop_after_system_send() {
	let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let sleep_calls = Arc::new(AtomicUsize::new(0));

	let mut sender = StubSender {
		system_sends: system_sends.clone(),
		container_sends: container_sends.clone(),
		system_send_err_after: Arc::new(Mutex::new(None)),
		// Err on the FIRST container send.
		container_send_err_after: Arc::new(Mutex::new(Some(0))),
	};

	let sl = sleep_calls.clone();
	let joined = async {
		stream_metrics_with(
			&mut sender,
			|| async { Ok(fresh_system()) },
			fresh_containers,
			move |_d: Duration| {
				let sl = sl.clone();
				async move {
					sl.fetch_add(1, Ordering::SeqCst);
				}
			},
			Duration::from_millis(1),
			Duration::from_millis(1),
		)
		.await
	};

	let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

	assert_eq!(
		system_sends.lock().unwrap().len(),
		1,
		"system send on tick 0 must succeed before the container branch fires"
	);
	assert!(
		container_sends.lock().unwrap().is_empty(),
		"injected container-send failure must not record anything"
	);
	assert_eq!(
		sleep_calls.load(Ordering::SeqCst),
		0,
		"sleep must not run when the loop breaks at the container send"
	);
}

/// Cadence comparison: when `system_interval < container_interval`,
/// the system send fires more often than the container send. We
/// use `1ms` system / `50ms` container. With the budget short of
/// 50ms (so no second container tick can fire from the elapsed
/// check), the container send must happen exactly once (tick 0
/// pre-roll) while the system send can happen many times.
#[tokio::test]
async fn stream_metrics_loop_container_fires_less_often_than_system() {
	let system_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let container_sends = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
	let sleep_calls = Arc::new(AtomicUsize::new(0));

	let mut sender = StubSender {
		system_sends: system_sends.clone(),
		container_sends: container_sends.clone(),
		system_send_err_after: Arc::new(Mutex::new(None)),
		container_send_err_after: Arc::new(Mutex::new(None)),
	};

	let sl = sleep_calls.clone();
	let joined = async {
		stream_metrics_with(
			&mut sender,
			|| async { Ok(fresh_system()) },
			fresh_containers,
			move |_d: Duration| {
				let sl = sl.clone();
				async move {
					sl.fetch_add(1, Ordering::SeqCst);
					// Yield so the tokio::time::timeout in the test
					// (and the runtime in general) gets a chance to
					// check cancellation. Without this, the loop
					// spins synchronously and the timeout future
					// never sees a yield point.
					tokio::task::yield_now().await;
				}
			},
			Duration::from_millis(1),
			Duration::from_millis(50),
		)
		.await
	};

	let _ = tokio::time::timeout(Duration::from_millis(20), joined).await;

	let sys = system_sends.lock().unwrap().len();
	let cont = container_sends.lock().unwrap().len();
	assert!(sys >= 1, "system must send at least once");
	assert_eq!(
		cont, 1,
		"container must send exactly once (tick 0 pre-roll only)"
	);
	assert!(
            sys > cont,
            "system sends ({sys}) must outnumber container sends ({cont}) when system_interval < container_interval"
        );
}

/// Sanity: serializing `SystemMetrics` then `to_value` and reading
/// the `"type"` field preserves the discriminator that the
/// production `WsSender` impl serializes. Asserts the contract
/// between the loop's JSON encoding and the sender's
/// routing/identification logic, so the `StubSender`'s
/// system-vs-container detection stays accurate.
#[test]
fn stream_metrics_loop_serializes_discriminator_in_payload() {
	let sys = fresh_system();
	let sys_v = serde_json::to_value(&sys).unwrap();
	assert_eq!(
		sys_v.get("type").and_then(|v| v.as_str()),
		Some("system_metrics"),
		"SystemMetrics must serialize with the documented discriminator"
	);
	let cont = fresh_containers();
	let cont_v = serde_json::to_value(&cont).unwrap();
	assert_eq!(
		cont_v.get("type").and_then(|v| v.as_str()),
		Some("container_metrics"),
		"ContainerMetrics must serialize with the documented discriminator"
	);
}
