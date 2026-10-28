//! UTC timestamps <-> ASN.1 time, without a date library.

use crate::der::{tag, tlv};
use crate::Error;

pub fn now_unix() -> Result<i64, Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| Error::Cert("системные часы показывают время до 1970 года".into()))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub struct Parts {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

pub fn parts(unix: i64) -> Parts {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Parts {
        year,
        month,
        day,
        hour: (secs / 3600) as u32,
        minute: (secs / 60 % 60) as u32,
        second: (secs % 60) as u32,
    }
}

/// `2032-02-27 21:04:15 UTC`
pub fn format_human(unix: i64) -> String {
    let p = parts(unix);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        p.year, p.month, p.day, p.hour, p.minute, p.second
    )
}

/// RFC 5280: UTCTime through 2049, GeneralizedTime from 2050.
pub fn encode(unix: i64) -> Vec<u8> {
    let p = parts(unix);
    if (1950..2050).contains(&p.year) {
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            p.year % 100,
            p.month,
            p.day,
            p.hour,
            p.minute,
            p.second
        );
        tlv(tag::UTC_TIME, s.as_bytes())
    } else {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            p.year, p.month, p.day, p.hour, p.minute, p.second
        );
        tlv(tag::GENERALIZED_TIME, s.as_bytes())
    }
}

pub fn decode(t: u8, content: &[u8]) -> Result<i64, Error> {
    let s = std::str::from_utf8(content).map_err(|_| Error::Der("время не ASCII"))?;
    let digits = |r: std::ops::Range<usize>| -> Result<i64, Error> {
        s.get(r)
            .filter(|x| x.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|x| x.parse::<i64>().ok())
            .ok_or(Error::Der("некорректное время"))
    };
    let (year, off) = match t {
        tag::UTC_TIME if s.len() == 13 && s.ends_with('Z') => {
            let yy = digits(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        tag::GENERALIZED_TIME if s.len() == 15 && s.ends_with('Z') => (digits(0..4)?, 4),
        _ => return Err(Error::Der("неподдерживаемый формат времени")),
    };
    let month = digits(off..off + 2)? as u32;
    let day = digits(off + 2..off + 4)? as u32;
    let hour = digits(off + 4..off + 6)?;
    let minute = digits(off + 6..off + 8)?;
    let second = digits(off + 8..off + 10)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return Err(Error::Der("время вне диапазона"));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for z in [-800_000i64, -1, 0, 1, 18_000, 22_336, 2_932_896] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    }

    #[test]
    fn asn1_roundtrip() {
        // 2032-02-27 21:04:15 UTC: notAfter of the Mintsifry root.
        let t = days_from_civil(2032, 2, 27) * 86_400 + 21 * 3600 + 4 * 60 + 15;
        let enc = encode(t);
        assert_eq!(&enc[2..], b"320227210415Z");
        assert_eq!(decode(enc[0], &enc[2..]).unwrap(), t);
        let far = days_from_civil(2051, 1, 1) * 86_400;
        let enc = encode(far);
        assert_eq!(enc[0], tag::GENERALIZED_TIME);
        assert_eq!(decode(enc[0], &enc[2..]).unwrap(), far);
        assert_eq!(format_human(t), "2032-02-27 21:04:15 UTC");
    }
}
