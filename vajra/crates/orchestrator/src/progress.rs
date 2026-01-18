//! Progress tracking

use tokio::sync::Mutex;
use tracing::info;

pub struct ProgressTracker {
    total: Mutex<usize>,
    completed: Mutex<usize>,
    failed: Mutex<usize>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            total: Mutex::new(0),
            completed: Mutex::new(0),
            failed: Mutex::new(0),
        }
    }

    pub async fn set_total(&self, total: usize) {
        *self.total.lock().await = total;
    }

    pub async fn increment_completed(&self) {
        *self.completed.lock().await += 1;
    }

    pub async fn increment_failed(&self) {
        *self.failed.lock().await += 1;
    }

    pub async fn print_summary(&self) {
        let total = *self.total.lock().await;
        let completed = *self.completed.lock().await;
        let failed = *self.failed.lock().await;

        info!("Scan Summary:");
        info!("  Total targets: {}", total);
        info!("  Completed: {}", completed);
        info!("  Failed: {}", failed);
        if total > 0 {
            info!("  Success rate: {:.1}%", (completed as f64 / total as f64) * 100.0);
        }
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}
