use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Probe<'a>(bool, &'a AtomicUsize);
impl RequestMatcher for Probe<'_> {
    fn matches(&self, _: &Parts) -> bool {
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0
    }
}

#[test]
fn combines_results_and_short_circuits() {
    let (parts, _) = http::Request::new(()).into_parts();
    for (left, right) in [(false, false), (false, true), (true, false), (true, true)] {
        let calls = AtomicUsize::new(0);
        let matcher = OrRequestMatcher::new(Probe(left, &calls), Probe(right, &calls));
        assert_eq!(matcher.matches(&parts), left || right);
        assert_eq!(calls.load(Ordering::SeqCst), if left { 1 } else { 2 });
    }
}
