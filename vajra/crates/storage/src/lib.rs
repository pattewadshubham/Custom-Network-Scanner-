//! Storage - Persistence layer
//! TODO: Implement

pub struct SqliteStorage;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn create_storage() {
		let _ = SqliteStorage;
	}
}
