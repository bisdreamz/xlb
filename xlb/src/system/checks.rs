use anyhow::{Result, bail};
use sysctl::Sysctl;

pub fn check_ip_forwarding() -> Result<()> {
    let ctl = sysctl::Ctl::new("net.ipv4.conf.all.forwarding")?;
    let value = ctl.value_string()?;

    if value == "0" {
        bail!(
            "IP forwarding is disabled. XDP load balancing requires IP forwarding to be enabled.\n\
             \n\
             Enable it with:\n\
             sudo sysctl -w net.ipv4.conf.all.forwarding=1\n\
             \n\
             Note: This is automatically enabled on Kubernetes nodes."
        );
    }

    Ok(())
}
