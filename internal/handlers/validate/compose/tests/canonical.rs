//! Bind sources resolved through links on a real directory tree. The link
//! targets are `/etc` and a path that does not exist, so they sit outside the
//! permitted roots wherever the temporary directory is.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::*;

/// A temporary tree removed on drop: `<root>/projects/t1/p1` is the project.
struct Tree {
	root: PathBuf,
}

impl Tree {
	fn new(name: &str) -> Self {
		let root = std::env::temp_dir().join(format!(
			"helmly-agent-compose-{}-{name}",
			std::process::id()
		));
		let _ = std::fs::remove_dir_all(&root);
		std::fs::create_dir_all(root.join("projects/t1/p1/real")).expect("create project tree");
		Self { root }
	}

	fn project(&self) -> PathBuf {
		self.root.join("projects/t1/p1")
	}

	fn check(&self, project_dir: &Path, yaml: &str) -> Result<()> {
		let policy = ComposePolicy {
			project_dir,
			reserved_ports: RESERVED,
		};
		validate_compose(yaml, &policy)
	}
}

impl Drop for Tree {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.root);
	}
}

fn bind(src: &str) -> String {
	format!("services:\n  web:\n    image: nginx\n    volumes: [\"{src}:/x\"]\n")
}

fn refusal(r: Result<()>) -> String {
	match r {
		Ok(()) => panic!("a source that resolves outside the project was accepted"),
		Err(e) => format!("{e:#}"),
	}
}

#[test]
fn link_out_of_the_project_is_refused_in_every_form() {
	let tree = Tree::new("out");
	let project = tree.project();
	symlink("/etc", project.join("data")).expect("create link");
	let absolute = format!("{}/data", project.display());
	let long = "services:\n  web:\n    image: nginx\n    volumes:\n      - type: bind\n        source: data\n        target: /x\n";
	for (name, yaml) in [
		("relative", bind("./data")),
		("relative, below the link", bind("./data/not-there-yet")),
		("absolute", bind(&absolute)),
		("long form", long.to_string()),
	] {
		let msg = refusal(tree.check(&project, &yaml));
		assert!(
			msg.contains("resolves to /etc") && msg.contains("outside the tenant root"),
			"{name}: refused for another reason: {msg}"
		);
	}
}

#[test]
fn dangling_link_is_refused() {
	let tree = Tree::new("dangling");
	let project = tree.project();
	symlink("/nonexistent-helmly-agent-target", project.join("data")).expect("create link");
	let msg = refusal(tree.check(&project, &bind("./data")));
	assert!(
		msg.contains("cannot be resolved"),
		"refused for another reason: {msg}"
	);
}

#[test]
fn links_that_stay_inside_the_project_are_accepted() {
	let tree = Tree::new("inside");
	let project = tree.project();
	symlink(project.join("real"), project.join("alias")).expect("create link");
	for src in ["./real", "./alias", "./alias/sub", "./missing/sub"] {
		let r = tree.check(&project, &bind(src));
		assert!(r.is_ok(), "{src} must pass: {r:?}");
	}
}

/// When the project directory is itself reached through a link, the permitted
/// root is resolved the same way as the source, so its own paths still pass.
#[test]
fn project_dir_behind_a_link_is_resolved_like_its_sources() {
	let tree = Tree::new("linked-project");
	let linked = tree.root.join("linked");
	symlink(tree.project(), &linked).expect("create link");
	let absolute = format!("{}/real", linked.display());
	for yaml in [bind("./real"), bind(&absolute)] {
		let r = tree.check(&linked, &yaml);
		assert!(r.is_ok(), "{yaml} must pass: {r:?}");
	}
}
