// crates/orchestrator/src/orchestrator.rs
//! Orchestrator - job scheduling and worker coordination

use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex};
use tracing::{info, instrument};

use vajra_common::{ProbeResult, ScanJob, Scanner};
use crate::progress::ProgressTracker;
use crate::rate_limiter::RateLimiter;

/// Orchestrator coordinates scan jobs, workers, rate limiting and collects results.
pub struct Orchestrator {
    job_queue: Arc<Mutex<VecDeque<ScanJob>>>,
    rate_limiter: Arc<RateLimiter>,
    progress: Arc<ProgressTracker>,
    scanners: HashMap<String, Arc<dyn Scanner + Send + Sync>>,
    concurrency: usize,
    results: Arc<Mutex<Vec<ProbeResult>>>,
}

impl Orchestrator {
    /// Create a new orchestrator with a concurrency limit and a rate limit (requests/sec).
    pub fn new(concurrency: usize, rate_limit: u32) -> Self {
        Self {
            job_queue: Arc::new(Mutex::new(VecDeque::new())),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit)),
            progress: Arc::new(ProgressTracker::new()),
            scanners: HashMap::new(),
            concurrency,
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a scanner implementation under a name (e.g. "tcp").
    pub fn add_scanner(&mut self, name: &str, scanner: Arc<dyn Scanner + Send + Sync>) {
        self.scanners.insert(name.to_string(), scanner);
    }

    /// Submit a scan job to the queue.
    pub async fn submit_job(&self, job: ScanJob) -> Result<()> {
        let target_count = job.targets.len();
        self.progress.set_total(target_count).await;
        self.job_queue.lock().await.push_back(job);
        Ok(())
    }

    /// Main run loop for a single job — pops one job, schedules workers and waits.
    /// Optionally takes a scanner name; defaults to "tcp".
    #[instrument(skip(self))]
    pub async fn run(&self, scanner_name: Option<&str>) -> Result<()> {
        let mut queue = self.job_queue.lock().await;
        let job = match queue.pop_front() {
            Some(j) => j,
            None => return Ok(()),
        };
        drop(queue);

        info!("Starting job {} targets={}", job.id, job.targets.len());

        // Select scanner (TCP by default)
        let scanner = match self.select_scanner(scanner_name) {
            Ok(s) => s,
            Err(e) => {
                info!("Job {} skipped: {}", job.id, e);
                return Ok(()); // gracefully skip job
            }
        };

    // Use a bounded channel and a fixed worker pool to avoid per-target task spawn overhead
        // Shared queue pattern: push all targets into a VecDeque protected by a Mutex.
        use std::collections::VecDeque;
        let queue = Arc::new(Mutex::new(VecDeque::<vajra_common::Target>::new()));
        {
            let mut q = queue.lock().await;
            for t in job.targets.into_iter() {
                q.push_back(t);
            }
        }

        // Spawn worker tasks equal to concurrency. Each worker pops from the shared queue.
        let mut workers = Vec::new();
        for _ in 0..self.concurrency {
            let queue = queue.clone();
            let rate_limiter = self.rate_limiter.clone();
            let scanner = scanner.clone();
            let progress = self.progress.clone();
            let results = self.results.clone();

            let worker = tokio::spawn(async move {
                loop {
                    // Pop a target from the shared queue
                    let maybe_target = {
                        let mut q = queue.lock().await;
                        q.pop_front()
                    };

                    let target = match maybe_target {
                        Some(t) => t,
                        None => break, // queue empty, exit worker
                    };

                    rate_limiter.acquire().await;
                    match scanner.scan(&target).await {
                        Ok(result) => {
                            progress.increment_completed().await;
                            let mut r = results.lock().await;
                            r.push(result);
                        }
                        Err(_) => {
                            progress.increment_failed().await;
                        }
                    }
                }
            });
            workers.push(worker);
        }

        // Wait for workers to finish
        for w in workers {
            w.await?;
        }

        self.progress.print_summary().await;
        Ok(())
    }

    /// Drain current results (clone) for external consumption.
    pub async fn get_results(&self) -> Vec<ProbeResult> {
        self.results.lock().await.clone()
    }

    /// Select a scanner by name. Defaults to "tcp" if name is None.
    fn select_scanner(
        &self,
        name: Option<&str>,
    ) -> Result<Arc<dyn Scanner + Send + Sync>> {
        let key = name.unwrap_or("tcp"); // default to "tcp"
        self.scanners
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Scanner '{}' not registered", key))
    }
}
