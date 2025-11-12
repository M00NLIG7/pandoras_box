use crate::enumerator::Subnet;

#[derive(Debug, Default)]
pub struct Config {
    pub subnet: Subnet,
}

impl TryFrom<&clap::ArgMatches> for Config {
    type Error = crate::Error;

    fn try_from(matches: &clap::ArgMatches) -> crate::Result<Self> {
        let subnet = matches
            .get_one::<String>("range")
            .ok_or_else(|| crate::Error::ArgumentError("Missing required argument 'range'".to_string()))?
            .into();

        Ok(Self { subnet })
    }
}
