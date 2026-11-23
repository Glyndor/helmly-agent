//! The database the tests that need PostgreSQL run against: the authentication
//! tests (nonce replay, stale timestamps) and the audit log chain tests. On a
//! workstation without one they skip, loudly. Under `CI` a missing database is a
//! failure: a skipped test asserts nothing, and a suite that skips itself in the
//! one place it is supposed to gate would pass whatever the code did.

use sqlx::PgPool;

/// What the tests should do about the database.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Access {
	/// Connect to this URL.
	Use(String),
	/// There is none and nobody asked for one: skip, with a warning.
	Skip,
}

/// Decide from the two variables. `ci` is the value of `CI`, `url` that of `DATABASE_URL`.
///
/// An empty URL counts as absent, which is what a CI variable set from a missing
/// secret looks like. `CI` is on for `true` and `1`; anything else is a workstation.
pub(crate) fn access(ci: Option<&str>, url: Option<&str>) -> Result<Access, &'static str> {
	let in_ci = matches!(ci, Some("true" | "1"));
	match url.filter(|u| !u.is_empty()) {
		Some(url) => Ok(Access::Use(url.to_string())),
		None if in_ci => {
			Err("CI is set but DATABASE_URL is not: the database tests cannot be skipped in CI")
		}
		None => Ok(Access::Skip),
	}
}

/// A pool on the test database with the migrations applied, or `None` when the
/// tests are allowed to skip. A database that is configured and cannot be reached,
/// or migrated, panics: that is a broken setup, not a missing one.
pub(crate) async fn db_pool() -> Option<PgPool> {
	let ci = std::env::var("CI").ok();
	let url = std::env::var("DATABASE_URL").ok();
	match access(ci.as_deref(), url.as_deref()) {
		Err(reason) => panic!("{reason}"),
		Ok(Access::Skip) => {
			eprintln!("SKIPPED: DATABASE_URL is not set, so this database test did not run");
			None
		}
		Ok(Access::Use(url)) => {
			let pool = PgPool::connect(&url)
				.await
				.unwrap_or_else(|e| panic!("cannot connect to the test database: {e}"));
			sqlx::migrate!("./migrations")
				.run(&pool)
				.await
				.unwrap_or_else(|e| {
					panic!("cannot apply the migrations to the test database: {e}")
				});
			Some(pool)
		}
	}
}

#[cfg(test)]
mod tests;
