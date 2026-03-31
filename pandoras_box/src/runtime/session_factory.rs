use async_trait::async_trait;

use super::mission::{HostPlan, TransportKind};
use super::transport::HostSession;
use crate::Result;

pub type BoxedHostSession = Box<dyn HostSession + Send>;

#[async_trait]
pub trait SessionFactory: Send + Sync {
    async fn connect(&self, plan: &HostPlan, transport: TransportKind) -> Result<BoxedHostSession>;
}
