use crate::provider::{BackendProvider, Host};
use anyhow::{Result, bail};
use async_trait::async_trait;

pub struct FixedProvider {
    hosts: Vec<Host>,
}

impl FixedProvider {
    pub fn new(hosts: Vec<Host>) -> Self {
        Self { hosts }
    }
}

#[async_trait]
impl BackendProvider for FixedProvider {
    async fn start(&self) -> Result<()> {
        if self.hosts.is_empty() {
            bail!("At least one backend must be specified for static deployments");
        }

        Ok(())
    }

    fn get_backends(&self) -> Vec<Host> {
        self.hosts.clone()
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}
