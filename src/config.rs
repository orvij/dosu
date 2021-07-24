#[allow(unused)]
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use nom::branch::alt;
use nom::bytes::complete::{tag, take_till, take_while};
use nom::character::complete::{char, space0, space1};
use nom::character::{is_alphanumeric, is_newline};
use nom::combinator::{opt, value};
use nom::error::ParseError;
use nom::multi::{many0, separated_list0};
use nom::sequence::{delimited, pair, preceded, separated_pair, tuple};
use nom::IResult;

use crate::{Error, Options, Rule};

// Arbitrary maximum length for a config file
// FIXME: add command-line option to set?
const MAX_CONFIG_LEN: u64 = 2048;

fn ws<'a, F: 'a, O, E: ParseError<&'a [u8]>>(
    inner: F,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
where
    F: Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
{
    delimited(space0, inner, space0)
}

fn action_parser(i: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag("permit"), tag("deny")))(i)
}

fn envelem_parser(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c: u8| is_alphanumeric(c) || c == b'-' || c == b'_')(i)
}

fn envalue_parser(i: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c: u8| is_alphanumeric(c) || c == b'$' || c == b'_')(i)
}

fn envlone_parser(i: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let (rem, res) = envelem_parser(i)?;
    Ok((rem, (res, b"".as_ref())))
}

fn envpair_parser(i: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    separated_pair(envelem_parser, char('='), envalue_parser)(i)
}

fn env_parser(i: &[u8]) -> IResult<&[u8], Vec<(&[u8], &[u8])>> {
    separated_list0(tag(" "), alt((envpair_parser, envlone_parser)))(i)
}

fn setenv_parser(i: &[u8]) -> IResult<&[u8], Vec<(&[u8], &[u8])>> {
    preceded(
        ws(tag("setenv")),
        delimited(char('{'), ws(env_parser), char('}')),
    )(i)
}

fn options_parser(i: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    many0(alt((
        ws(tag("keepenv")),
        ws(tag("nolog")),
        ws(tag("nopass")),
        ws(tag("persist")),
    )))(i)
}

fn user_parser(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (rem, res) = take_while(is_alphanumeric)(i)?;
    Ok((rem, res.to_vec()))
}

fn group_parser(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (rem, res) = preceded(char(':'), take_while(is_alphanumeric))(i)?;
    Ok((rem, res.to_vec()))
}

fn target_parser(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (rem, res) = preceded(preceded(tag("as"), space1), user_parser)(i)?;
    Ok((rem, res.to_vec()))
}

fn cmd_parser(i: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (c, _) = preceded(tag("cmd"), space1)(i)?;
    let (rem, res) = take_while(is_alphanumeric)(c)?;
    Ok((rem, res.to_vec()))
}

fn args_parser(i: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
    let (a, _) = preceded(tag("args"), space0)(i)?;
    let (rem, res) = separated_list0(
        tag(" "),
        take_while(|c: u8| c == b'-' || c == b'_' || is_alphanumeric(c)),
    )(a)?;

    Ok((rem, res.iter().map(|o| o.to_vec()).collect()))
}

fn comment_parser(i: &[u8]) -> IResult<&[u8], ()> {
    value(
        (),
        preceded(
            pair(char('#'), take_till(is_newline)),
            take_while(is_newline),
        ),
    )(i)
}

/// Parse a doas config line into a Rule
pub fn config_line_parser(i: &[u8]) -> IResult<&[u8], Rule> {
    let (i, (action, options, setenv, ident, target, cmd, cmd_args, _)) = tuple((
        ws(action_parser),
        opt(ws(options_parser)),
        opt(ws(setenv_parser)),
        alt((ws(user_parser), ws(group_parser))),
        opt(ws(target_parser)),
        opt(ws(cmd_parser)),
        opt(ws(args_parser)),
        take_while(is_newline),
    ))(i)?;

    let options = options.unwrap_or(vec![]);
    let mut parsed_options = vec![];
    if options.contains(&b"keepenv".as_ref()) {
        parsed_options.push(Options::KeepEnv);
    }
    if options.contains(&b"nolog".as_ref()) {
        parsed_options.push(Options::NoLog);
    }
    if options.contains(&b"nopass".as_ref()) {
        parsed_options.push(Options::NoPass);
    }
    if options.contains(&b"persist".as_ref()) {
        parsed_options.push(Options::Persist);
    }

    let setenv: Vec<(&[u8], &[u8])> = setenv.unwrap_or(vec![]);

    if setenv.len() > 0 {
        parsed_options.push(Options::SetEnv);
    }

    let envlist: HashMap<Vec<u8>, Vec<u8>> = setenv
        .iter()
        .map(|(e, v)| (e.to_vec(), v.to_vec()))
        .collect();

    Ok((
        i,
        Rule {
            action: action.into(),
            options: parsed_options,
            ident,
            target,
            cmd,
            cmd_args,
            envlist,
        },
    ))
}

/// Parse doas.conf(5) style configuration file
pub fn parse_config(path: &str) -> Result<Vec<Rule>, Error> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len > MAX_CONFIG_LEN {
        return Err(Error::MaxConfigLen(file_len));
    }
    let mut config_bytes = Vec::with_capacity(file_len as usize);
    let len = file.read_to_end(&mut config_bytes)?;

    let mut rules = vec![];
    let mut rem = config_bytes.as_slice();
    loop {
        if let Ok((r, _)) = comment_parser(rem) {
            rem = r;
        } else {
            let (r, rule) = config_line_parser(rem)?;
            rem = r;
            rules.push(rule);
        }
        if rem.len() == 0 {
            break;
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setenv() {
        let setenv = b"setenv { PATH -CC CXX=cc }".as_ref();
        let (_, res) = setenv_parser(setenv).unwrap();
        assert_eq!(
            res,
            vec![
                (b"PATH".as_ref(), b"".as_ref()),
                (b"-CC".as_ref(), b"".as_ref()),
                (b"CXX".as_ref(), b"cc".as_ref()),
                (&[], &[])
            ]
        );
    }

    #[test]
    fn test_envpair() {
        let pair = b"CXX=cc".as_ref();
        let (_, res) = envpair_parser(pair).unwrap();
        assert_eq!(res, (b"CXX".as_ref(), b"cc".as_ref()));
    }
}
