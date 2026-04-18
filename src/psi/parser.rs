use anyhow::{anyhow, Context, Result};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Pressure {
    pub some_avg10: f64,
    pub some_avg60: f64,
    pub some_avg300: f64,
    pub some_total_usec: u64,
    pub full_avg10: f64,
    pub full_avg60: f64,
    pub full_avg300: f64,
    pub full_total_usec: u64,
}

/// Parse the two-line PSI format emitted by `/proc/pressure/{cpu,memory,io}`
/// and each cgroup's `{cpu,memory,io}.pressure` file.
///
/// Example input:
/// ```text
/// some avg10=0.00 avg60=0.00 avg300=0.00 total=239910903
/// full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// ```
///
/// Some CPU pressure files on older kernels emit only the `some` line; in that
/// case the `full_*` fields are left at zero rather than raising an error.
/// The `some` line is required.
pub fn parse(input: &str) -> Result<Pressure> {
    let mut p = Pressure::default();
    let mut saw_some = false;

    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut tokens = line.split_ascii_whitespace();
        let kind = tokens.next().ok_or_else(|| anyhow!("empty PSI line"))?;
        let (avg10, avg60, avg300, total) = parse_fields(tokens)
            .with_context(|| format!("parsing PSI {kind} line: {line:?}"))?;

        match kind {
            "some" => {
                p.some_avg10 = avg10;
                p.some_avg60 = avg60;
                p.some_avg300 = avg300;
                p.some_total_usec = total;
                saw_some = true;
            }
            "full" => {
                p.full_avg10 = avg10;
                p.full_avg60 = avg60;
                p.full_avg300 = avg300;
                p.full_total_usec = total;
            }
            other => return Err(anyhow!("unknown PSI line kind: {other:?}")),
        }
    }

    if !saw_some {
        return Err(anyhow!("PSI input missing required 'some' line"));
    }
    Ok(p)
}

fn parse_fields<'a, I: Iterator<Item = &'a str>>(tokens: I) -> Result<(f64, f64, f64, u64)> {
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total = None;
    for field in tokens {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed PSI field {field:?} (expected key=value)"))?;
        match key {
            "avg10" => avg10 = Some(value.parse().context("avg10")?),
            "avg60" => avg60 = Some(value.parse().context("avg60")?),
            "avg300" => avg300 = Some(value.parse().context("avg300")?),
            "total" => total = Some(value.parse().context("total")?),
            _ => {}
        }
    }
    Ok((
        avg10.ok_or_else(|| anyhow!("missing avg10"))?,
        avg60.ok_or_else(|| anyhow!("missing avg60"))?,
        avg300.ok_or_else(|| anyhow!("missing avg300"))?,
        total.ok_or_else(|| anyhow!("missing total"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CPU: &str = "\
some avg10=0.00 avg60=0.00 avg300=0.00 total=239910903
full avg10=0.00 avg60=0.00 avg300=0.00 total=0
";

    const SAMPLE_MEMORY: &str = "\
some avg10=1.23 avg60=4.56 avg300=7.89 total=12345678
full avg10=0.50 avg60=1.00 avg300=2.00 total=87654321
";

    #[test]
    fn parses_cpu_sample() {
        let p = parse(SAMPLE_CPU).unwrap();
        assert_eq!(p.some_total_usec, 239_910_903);
        assert_eq!(p.full_total_usec, 0);
        assert_eq!(p.some_avg10, 0.0);
        assert_eq!(p.some_avg60, 0.0);
        assert_eq!(p.some_avg300, 0.0);
    }

    #[test]
    fn parses_memory_sample() {
        let p = parse(SAMPLE_MEMORY).unwrap();
        assert_eq!(p.some_avg10, 1.23);
        assert_eq!(p.some_avg60, 4.56);
        assert_eq!(p.some_avg300, 7.89);
        assert_eq!(p.some_total_usec, 12_345_678);
        assert_eq!(p.full_avg10, 0.50);
        assert_eq!(p.full_avg60, 1.00);
        assert_eq!(p.full_avg300, 2.00);
        assert_eq!(p.full_total_usec, 87_654_321);
    }

    #[test]
    fn accepts_some_only() {
        let input = "some avg10=0.00 avg60=0.00 avg300=0.00 total=100\n";
        let p = parse(input).unwrap();
        assert_eq!(p.some_total_usec, 100);
        assert_eq!(p.full_total_usec, 0);
    }

    #[test]
    fn rejects_missing_some() {
        let input = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert!(parse(input).is_err());
    }

    #[test]
    fn rejects_missing_required_field() {
        let input = "some avg10=0.00 avg60=0.00 total=100\n";
        assert!(parse(input).is_err());
    }

    #[test]
    fn rejects_garbage_numeric_value() {
        let input = "some avg10=oops avg60=0.00 avg300=0.00 total=100\n";
        assert!(parse(input).is_err());
    }

    #[test]
    fn rejects_bare_token_without_equals() {
        let input = "some avg10 avg60=0.00 avg300=0.00 total=100\n";
        assert!(parse(input).is_err());
    }

    #[test]
    fn rejects_unknown_line_kind() {
        let input = "partial avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
                     some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
        assert!(parse(input).is_err());
    }

    #[test]
    fn ignores_blank_lines_and_whitespace() {
        let input = "\n  \nsome avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\n\
                     full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\n";
        assert!(parse(input).is_ok());
    }

    #[test]
    fn tolerates_unknown_field_keys() {
        let input = "some avg10=0.00 avg60=0.00 avg300=0.00 total=100 future_field=42\n";
        let p = parse(input).unwrap();
        assert_eq!(p.some_total_usec, 100);
    }
}
