use crate::enumerator::Subnet;

#[derive(Debug, Default)]
pub struct Config {
    pub subnet: Subnet,
}

impl TryFrom<&clap::ArgMatches> for Config {
    type Error = crate::Error;

    fn try_from(matches: &clap::ArgMatches) -> crate::Result<Self> {
        Ok(Self {
            subnet: matches.get_one::<String>("range").unwrap().into(),
        })
    }
}
