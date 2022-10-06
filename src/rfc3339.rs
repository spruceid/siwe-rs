use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Clone, Debug, PartialEq, Eq)]
/// Wrapper for [OffsetDateTime], meant to enable transitivity of deserialisation and serialisation.
pub struct TimeStamp(String, OffsetDateTime);

impl From<OffsetDateTime> for TimeStamp {
    fn from(t: OffsetDateTime) -> Self {
        Self(t.format(&Rfc3339).expect("Rfc3339 formatting works"), t)
    }
}

impl AsRef<OffsetDateTime> for TimeStamp {
    fn as_ref(&self) -> &OffsetDateTime {
        &self.1
    }
}

impl Display for TimeStamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.0)
    }
}

impl FromStr for TimeStamp {
    type Err = time::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.into(), OffsetDateTime::parse(s, &Rfc3339)?))
    }
}

impl PartialEq<OffsetDateTime> for TimeStamp {
    fn eq(&self, other: &OffsetDateTime) -> bool {
        &self.1 == other
    }
}

impl PartialOrd<OffsetDateTime> for TimeStamp {
    fn partial_cmp(&self, other: &OffsetDateTime) -> Option<Ordering> {
        self.1.partial_cmp(other)
    }
}
