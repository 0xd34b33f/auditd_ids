use nom;
use nom::branch::alt;
use nom::bytes::complete::{escaped, escaped_transform, is_not, tag, take, take_until, take_while};
use nom::character::complete::{alpha1, alphanumeric1, anychar, char, one_of};
use nom::character::{is_alphanumeric, is_digit, is_space};
use nom::combinator::{map, value};
use nom::error::{ErrorKind, ParseError};
use nom::multi::{count, many_till};
use nom::sequence::{delimited, delimitedc, preceded};
use nom::{AsChar, IResult, InputTakeAtPosition};

pub struct AuditRecord {
    pid: u32,
    ppid: u32,
    exe_path: String,
}

fn filter_audit_record(i: &str) -> IResult<&str, &str> {
    tag("type=SYSCALL")(i)
}

fn get_timestamp(i: &str) -> IResult<&str, &str> {
    let unneded = match take_until("(")(i) {
        Ok((unparsed, _)) => unparsed,
        Err(e) => return Err(e),
    };
    take_until(".")(unneded)
}

fn get_audit_id(i: &str) -> IResult<&str, &str> {
    let unused = match take_until(":")(i) {
        Ok((unparsed, _)) => unparsed,
        Err(e) => return Err(e),
    };

    take_until(")")(unused)
}

fn get_syscall_number(i: &str) -> IResult<&str, &str> {
    let (unparsed, _) = take_until("syscall=")(i)?;
    let (unparsed, _) = take_while(|x: char| !is_digit(x as u8))(unparsed)?;
    tag("59")(unparsed)
}

fn get_after_equals(i: &str) -> IResult<&str, &str> {
    let (unparsed, _) = take_until("=")(i)?;
    let (unparsed, _) = take(1usize)(unparsed)?;
    take_while(|x: char| !is_space(x as u8))(unparsed)
}
fn get_ppid(i: &str) -> IResult<&str, &str> {
    let (unparsed, _) = take_until("ppid")(i)?;
    get_after_equals(unparsed)
}
fn get_u32_after_equlas<'a>(data: &'a str) -> Option<(&'a str, u32)> {
    let (unparsed, id) = match get_after_equals(data) {
        Ok((unparsed, uid)) => {
            let uid = match uid.parse::<u32>() {
                Ok(a) => a,
                Err(e) => {
                    println!("{}", e);
                    return None;
                }
            };
            (unparsed, uid)
        }
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    Some((unparsed, id))
}

fn valid_name<T, E: ParseError<T>>(input: T) -> IResult<T, T, E>
where
    T: InputTakeAtPosition,
    <T as InputTakeAtPosition>::Item: AsChar,
{
    input.split_at_position1_complete(
        |item| {
            let character = item.as_char();
            !(!character.is_alphanumeric() && !character.is_ascii_punctuation() && character == '"')
        },
        ErrorKind::AlphaNumeric,
    )
}

fn parse_char<'a, E: ParseError<&'a str>>(i: &'a str) -> IResult<&'a str, char, E> {
    preceded(
        char('\\'),
        // `alt` tries each each parser in sequence, returning the result of
        // the first successful match
        alt((
            // The `value` parser returns a fixed value (the first argument) if its
            // parser (the second argument) succeeds. In these cases, it looks for
            // the marker characters (n, r, t, etc) and returns the matching
            // character (\n, \r, \t, etc).
            value('\n', char('n')),
            value('\r', char('r')),
            value('\t', char('t')),
            value('\u{08}', char('b')),
            value('\u{0C}', char('f')),
            value('\\', char('\\')),
            value('/', char('/')),
            value('"', char('"')),
        )),
    )(i)
}
fn parse_str(input: &str) -> IResult<&str, &str> {
    take_until("\"")(input)
}

fn get_string_in_quotes(i: &str) -> IResult<&str, &str> {
    delimited(char('"'), parse_str, char('"'))(i)
}

fn get_comm(i: &str) -> IResult<&str, &str> {
    let (unparsed, _) = take_until("comm=")(i)?;
    let (unparsed, data) = get_after_equals(unparsed)?;
    return match get_string_in_quotes(data) {
        Ok(a) => IResult::Ok((unparsed, a.1)),
        Err(e) => IResult::Err(e),
    };
}

fn get_exe(i: &str) -> IResult<&str, &str> {
    let (unparsed, data) = get_after_equals(i)?;
    return match get_string_in_quotes(data) {
        Ok(a) => IResult::Ok((unparsed, a.1)),
        Err(e) => IResult::Err(e),
    };
}
#[inline]
pub fn parse_record(record: &str) -> Option<AuditRecord> {
    let unparsed: &str = match filter_audit_record(record) {
        Ok((unparsed, _)) => unparsed,
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let (timestamp, unparsed) = match get_timestamp(unparsed) {
        Ok((unparsed, timestamp)) => (timestamp[1..].parse::<u64>(), unparsed),
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let (audit_id, unparsed): (u64, &str) = match get_audit_id(&unparsed) {
        Ok((unparsed, auid)) => {
            let auid = match auid[1..].parse::<u64>() {
                Ok(a) => a,
                Err(e) => {
                    println!("{}: {}", e, auid);
                    return None;
                }
            };
            (auid, unparsed)
        }
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let unparsed = match get_syscall_number(unparsed) {
        Ok((a, _q)) => a,
        Err(_) => return None,
    };
    let (unparsed, status) = match get_after_equals(unparsed) {
        Ok((unparsed, data)) => {
            let status = match data {
                "yes" => true, //todo parse it using nom value method
                "no" => false,
                _ => false,
            };
            (unparsed, status)
        }
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let (unparsed, ppid) = match get_ppid(unparsed) {
        Ok((unparsed, data)) => match data.parse::<u32>() {
            Ok(b) => (unparsed, b),
            Err(e) => {
                println!("{}:{}", e, data);
                return None;
            }
        },
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let (unparsed, pid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, auid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, uid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, gid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, euid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, suid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, fsuid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, egid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, sgid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, fsgid) = get_u32_after_equlas(unparsed)?;
    let (unparsed, tty) = match get_after_equals(unparsed) {
        Ok(a) => a,
        Err(_) => return None,
    };
    let (unparsed, comm) = match get_comm(unparsed) {
        Ok(a) => a,
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    let (_, exe) = match get_exe(unparsed) {
        Ok(a) => a,
        Err(e) => {
            println!("{}", e);
            return None;
        }
    };
    Some(AuditRecord {
        pid: pid,
        ppid: ppid,
        exe_path: exe.to_string(),
    })
}
