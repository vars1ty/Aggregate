/// Time-related utilities.
pub struct TimeUtils;

impl TimeUtils {
    /// Gets the milliseconds since the UNIX EPOCH.
    pub fn get_unix_millis_timestamp() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }
}
