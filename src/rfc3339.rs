use chrono::{format::ParseError, offset::TimeZone, DateTime, FixedOffset, SecondsFormat};
use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    str::FromStr,
};

#[derive(Clone, PartialEq)]
pub struct TimeStamp(String, DateTime<FixedOffset>);

impl<T> From<DateTime<T>> for TimeStamp
where
    T: TimeZone,
    T::Offset: Display,
    DateTime<T>: Into<DateTime<FixedOffset>>,
{
    fn from(t: DateTime<T>) -> Self {
        Self(t.to_rfc3339_opts(SecondsFormat::Millis, true), t.into())
    }
}

impl AsRef<DateTime<FixedOffset>> for TimeStamp {
    fn as_ref(&self) -> &DateTime<FixedOffset> {
        &self.1
    }
}

impl Display for TimeStamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", &self.0)
    }
}

impl FromStr for TimeStamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            s.into(),
            DateTime::<FixedOffset>::parse_from_rfc3339(s)?,
        ))
    }
}

impl<T> PartialEq<DateTime<T>> for TimeStamp
where
    T: TimeZone,
{
    fn eq(&self, other: &DateTime<T>) -> bool {
        &self.1 == other
    }
}

impl<T> PartialOrd<DateTime<T>> for TimeStamp
where
    T: TimeZone,
{
    fn partial_cmp(&self, other: &DateTime<T>) -> Option<Ordering> {
        self.1.partial_cmp(other)
    }
}
