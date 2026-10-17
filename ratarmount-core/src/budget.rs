//! Process-wide accounting for optional buffers. Refused reservations mean
//! synchronous I/O or disk spill, never a failed user read.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Reclaim speculative work first, retained caches next, SQLite last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Speculative,
    Cache,
    Sqlite,
}

type Shrink = Arc<dyn Fn() + Send + Sync>;
#[derive(Default)]
struct State {
    used: u64,
    high_water: u64,
    pools: BTreeMap<String, PoolState>,
}
struct PoolState {
    minimum: u64,
    preferred: u64,
    priority: Priority,
    used: u64,
    high_water: u64,
    shrink: BTreeMap<u64, Shrink>,
    next_hook: u64,
}

/// Install before opening sources. Library callers may instead pass isolated
/// accountants to pools in tests; the global is never reset underneath readers.
pub struct MemoryBudget {
    limit: Option<u64>,
    state: Mutex<State>,
}
static GLOBAL: OnceLock<Arc<MemoryBudget>> = OnceLock::new();

impl MemoryBudget {
    pub fn new(limit: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(State::default()),
        })
    }

    pub fn global() -> Arc<Self> {
        Arc::clone(GLOBAL.get_or_init(|| Self::new(None)))
    }

    pub fn install(limit: u64) -> Result<(), &'static str> {
        GLOBAL
            .set(Self::new(Some(limit)))
            .map_err(|_| "memory budget already initialized")
    }

    pub fn enabled(&self) -> bool {
        self.limit.is_some()
    }

    pub fn register(
        self: &Arc<Self>,
        name: &str,
        minimum: u64,
        preferred: u64,
        priority: Priority,
    ) -> MemoryPool {
        let mut state = self.state.lock().unwrap();
        state.pools.entry(name.into()).or_insert_with(|| PoolState {
            minimum,
            preferred: preferred.max(minimum),
            priority,
            used: 0,
            high_water: 0,
            shrink: BTreeMap::new(),
            next_hook: 0,
        });
        MemoryPool {
            budget: Arc::clone(self),
            name: name.into(),
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        Snapshot {
            limit: self.limit,
            reserved: state.used,
            high_water: state.high_water,
            pools: state
                .pools
                .iter()
                .map(|(name, p)| PoolSnapshot {
                    name: name.clone(),
                    reserved: p.used,
                    high_water: p.high_water,
                    cap: self.cap(p),
                })
                .collect(),
        }
    }

    fn cap(&self, pool: &PoolState) -> u64 {
        // Stable shares avoid reducing a live pool's cap when another codec opens.
        // Unused capacity remains available for other instances of the same pool.
        self.limit.map_or(pool.preferred, |limit| {
            pool.preferred.min((limit / 8).max(pool.minimum.min(limit)))
        })
    }

    pub fn status_text(&self) -> String {
        let s = self.snapshot();
        let mut out = format!(
            "memory_budget {}\nmemory_reserved {}\nmemory_high_water {}\n",
            s.limit
                .map_or_else(|| "unlimited".into(), |v| v.to_string()),
            s.reserved,
            s.high_water
        );
        for p in s.pools {
            out.push_str(&format!(
                "memory_pool {} reserved={} high_water={} cap={}\n",
                p.name, p.reserved, p.high_water, p.cap
            ));
        }
        out
    }
}

#[derive(Debug)]
pub struct Snapshot {
    pub limit: Option<u64>,
    pub reserved: u64,
    pub high_water: u64,
    pub pools: Vec<PoolSnapshot>,
}
#[derive(Debug)]
pub struct PoolSnapshot {
    pub name: String,
    pub reserved: u64,
    pub high_water: u64,
    pub cap: u64,
}

#[derive(Clone)]
pub struct MemoryPool {
    budget: Arc<MemoryBudget>,
    name: String,
}
impl MemoryPool {
    pub fn global(name: &str, preferred: u64, priority: Priority) -> Self {
        MemoryBudget::global().register(name, 0, preferred, priority)
    }
    pub fn enabled(&self) -> bool {
        self.budget.enabled()
    }
    pub fn cap(&self) -> u64 {
        self.budget
            .cap(&self.budget.state.lock().unwrap().pools[&self.name])
    }
    /// Callbacks must use weak ownership and nonblocking cache locks: reserve
    /// can be called while another consumer holds its own cache lock. Keep the
    /// returned hook alive for as long as the consumer can reclaim memory.
    pub fn on_pressure(&self, shrink: impl Fn() + Send + Sync + 'static) -> PressureHook {
        let mut state = self.budget.state.lock().unwrap();
        let pool = state.pools.get_mut(&self.name).unwrap();
        let id = pool.next_hook;
        pool.next_hook += 1;
        pool.shrink.insert(id, Arc::new(shrink));
        PressureHook {
            budget: Arc::downgrade(&self.budget),
            name: self.name.clone(),
            id,
        }
    }
    pub fn reserve(&self, bytes: u64) -> Option<Reservation> {
        if !self.enabled() {
            return Some(Reservation { pool: None, bytes });
        }
        if bytes > self.cap() {
            return None;
        }
        if let Some(r) = self.try_reserve(bytes) {
            return Some(r);
        }
        let callbacks = {
            let state = self.budget.state.lock().unwrap();
            let mut pools: Vec<_> = state.pools.values().collect();
            pools.sort_by_key(|p| p.priority);
            pools
                .into_iter()
                .flat_map(|p| p.shrink.values().cloned())
                .collect::<Vec<_>>()
        };
        for shrink in callbacks {
            shrink();
            if let Some(r) = self.try_reserve(bytes) {
                return Some(r);
            }
        }
        None
    }
    fn try_reserve(&self, bytes: u64) -> Option<Reservation> {
        let mut state = self.budget.state.lock().unwrap();
        let pool = &state.pools[&self.name];
        let total = state.used.checked_add(bytes)?;
        let used = pool.used.checked_add(bytes)?;
        if total > self.budget.limit? || used > self.budget.cap(pool) {
            return None;
        }
        let pool = state.pools.get_mut(&self.name).unwrap();
        pool.used = used;
        pool.high_water = pool.high_water.max(used);
        state.used = total;
        state.high_water = state.high_water.max(total);
        Some(Reservation {
            pool: Some(self.clone()),
            bytes,
        })
    }
}

/// Removes a shrink hook when its consumer closes; no registry growth per open.
#[derive(Debug)]
#[must_use]
pub struct PressureHook {
    budget: std::sync::Weak<MemoryBudget>,
    name: String,
    id: u64,
}
impl Drop for PressureHook {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.upgrade() {
            budget
                .state
                .lock()
                .unwrap()
                .pools
                .get_mut(&self.name)
                .unwrap()
                .shrink
                .remove(&self.id);
        }
    }
}

/// Own this alongside the allocation, including all shared readers of it.
pub struct Reservation {
    pool: Option<MemoryPool>,
    bytes: u64,
}
impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation")
            .field("bytes", &self.bytes)
            .finish()
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(pool) = &self.pool {
            let mut state = pool.budget.state.lock().unwrap();
            state.used -= self.bytes;
            state.pools.get_mut(&pool.name).unwrap().used -= self.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regression_budget_release_degrade_and_no_flag() {
        let budget = MemoryBudget::new(Some(64));
        let pool = budget.register("cache", 0, 100, Priority::Cache);
        let guard = pool.reserve(8).unwrap();
        assert!(pool.reserve(1).is_none());
        assert_eq!(budget.snapshot().reserved, 8);
        drop(guard);
        assert_eq!(budget.snapshot().reserved, 0);
        assert_eq!(budget.snapshot().high_water, 8);
        assert!(MemoryBudget::new(None)
            .register("legacy", 0, 1, Priority::Cache)
            .reserve(u64::MAX)
            .is_some());
    }
    #[test]
    fn regression_budget_pressure_priority() {
        let budget = MemoryBudget::new(Some(64));
        let order = Arc::new(Mutex::new(Vec::new()));
        let mut hooks = Vec::new();
        for (name, priority) in [
            ("sql", Priority::Sqlite),
            ("cache", Priority::Cache),
            ("ahead", Priority::Speculative),
        ] {
            let pool = budget.register(name, 0, 64, priority);
            let order = order.clone();
            hooks.push(pool.on_pressure(move || order.lock().unwrap().push(priority)));
        }
        let request = budget.register("request", 0, 64, Priority::Cache);
        let _held = request.reserve(8).unwrap();
        assert!(request.reserve(1).is_none());
        assert_eq!(
            *order.lock().unwrap(),
            [Priority::Speculative, Priority::Cache, Priority::Sqlite]
        );
    }
    #[test]
    fn regression_budget_concurrent_reservations_never_exceed_limit() {
        let budget = MemoryBudget::new(Some(64));
        std::thread::scope(|s| {
            for i in 0..16 {
                let pool = budget.register(&format!("pool{i}"), 0, 64, Priority::Cache);
                s.spawn(move || {
                    for _ in 0..1000 {
                        let _guard = pool.reserve(8);
                        std::thread::yield_now();
                    }
                });
            }
        });
        assert!(budget.snapshot().high_water <= 64);
        assert_eq!(budget.snapshot().reserved, 0);
        assert!(budget.status_text().contains("memory_pool pool0"));
    }
}
