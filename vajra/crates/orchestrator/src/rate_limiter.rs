use std::time::{Duration, Instant};
use tokio::sync::Mutex;
pub struct RateLimiter {
tokens: Mutex<f64>,
capacity: f64,
refill_rate: f64,
last_refill: Mutex<Instant>,
}
impl RateLimiter {
pub fn new(requests_per_second: u32) -> Self {
let capacity = requests_per_second as f64;
Self {
tokens: Mutex::new(capacity),
capacity,
refill_rate: requests_per_second as f64,
last_refill: Mutex::new(Instant::now()),
}
}
pub async fn acquire(&self) {
loop {
let mut tokens = self.tokens.lock().await;
let mut last_refill = self.last_refill.lock().await;
let now = Instant::now();
let elapsed = now.duration_since(*last_refill).as_secs_f64();
let new_tokens = (*tokens + elapsed * self.refill_rate).min(self.capacity);
if new_tokens >= 1.0 {
*tokens = new_tokens - 1.0;
*last_refill = now;
return;
}
let wait_time = Duration::from_secs_f64((1.0 - new_tokens) / self.refill_rate);
drop(tokens);
drop(last_refill);
tokio::time::sleep(wait_time).await;
}
}
}