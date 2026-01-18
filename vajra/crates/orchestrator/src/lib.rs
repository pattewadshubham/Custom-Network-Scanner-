//! Orchestrator - Job management and task distribution

mod orchestrator;
mod rate_limiter;
mod progress;

pub use orchestrator::Orchestrator;
pub use rate_limiter::RateLimiter;
pub use progress::ProgressTracker;

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn orchestrator_run_no_scanners() {
		// Create orchestrator with low concurrency
		let orch = Orchestrator::new(1, 100);

		// Create an empty scan job and submit it
		let job = vajra_common::ScanJob::new(Vec::new());
		orch.submit_job(job).await.unwrap();

		// Running with no scanners registered should return Ok (job is skipped internally)
		let res = orch.run(None).await;
		assert!(res.is_ok());
	}
}
