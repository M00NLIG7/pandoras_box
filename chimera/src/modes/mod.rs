pub mod baseline;
pub mod credentials;
pub mod inventory;
pub mod serve;


use crate::types::ExecutionResult;

pub trait ModeExecutor {
    type Args;
    type ArgRequirement: ArgumentRequirement<Self::Args>;

    async fn execute(
        &self,
        args: <Self::ArgRequirement as ArgumentRequirement<Self::Args>>::Container,
    ) -> ExecutionResult;
}

pub trait ArgumentRequirement<T> {
    type Container;
}

pub struct Required;
pub struct Optional;

impl<T> ArgumentRequirement<T> for Required {
    type Container = T;
}

impl<T> ArgumentRequirement<T> for Optional {
    type Container = Option<T>;
}

/*
// Usage example:
impl ModeExecutor for InventoryExecutor {
    type Args = InventoryArgs;
    type ArgRequirement = Required;  // This executor requires args

    async fn execute(&self, args: InventoryArgs) -> ExecutionResult {
        // Implementation
    }
}
*/
