// Regression: cfg! keeps both branches type checked; test acquisitions are not production.
macro_rules! harmless {
    ($value:expr) => {
        format!("{}", $value)
    };
}

pub fn target_label() -> String {
    if cfg!(windows) {
        harmless!("windows")
    } else {
        harmless!("other")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixture_acquisition_is_not_production() {
        let _ = std::fs::read("fixture");
    }
}
