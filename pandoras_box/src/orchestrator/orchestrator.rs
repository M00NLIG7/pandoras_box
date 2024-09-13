use crate::propagator::Propagator;
use crate::enumerator::Enumerator;
use crate::config::Config;

#[allow(dead_code)]
pub struct Orchestrator {
    pub propagator: Propagator,
    pub enumerator: Enumerator,
}

/*
impl Orchestrator {
    pub fn new(config: Config) -> Orchestrator {
        Orchestrator {
            propagator: Propagator{},
            enumerator: Enumerator::new(config.subnet),
        }
    }

    pub fn run(&mut self) {
        self.propagator.run();
        self.enumerator.run();
    }
}
*/
