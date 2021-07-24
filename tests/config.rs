use dosu::{config, Action, Options};
use std::collections::HashMap;

#[test]
fn test_config_line_parser_simple() {
    let simple_bytes = include_bytes!("configs/simple_doas.conf");
    let (_, rule) = config::config_line_parser(simple_bytes.as_ref()).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[]);
    assert_eq!(rule.ident(), b"user".as_ref());
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());
}

#[test]
fn test_config_line_parser_options() {
    let options_bytes = include_bytes!("configs/options_doas.conf");
    let (rem, rule) = config::config_line_parser(options_bytes.as_ref()).unwrap();
    let user = b"user".as_ref();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[Options::KeepEnv]);
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[Options::NoLog]);
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[Options::NoPass]);
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[Options::Persist]);
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[Options::KeepEnv, Options::NoLog]);
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(
        rule.options(),
        &[Options::KeepEnv, Options::NoLog, Options::NoPass]
    );
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (rem, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(
        rule.options(),
        &[
            Options::KeepEnv,
            Options::NoLog,
            Options::NoPass,
            Options::Persist
        ]
    );
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (_, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(
        rule.options(),
        &[
            Options::KeepEnv,
            Options::NoLog,
            Options::NoPass,
            Options::Persist,
            Options::SetEnv
        ]
    );
    assert_eq!(rule.ident(), user);
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);

    let envlist = rule.envlist();
    assert_eq!(envlist[b"PATH".as_ref()], Vec::new());
}

#[test]
fn test_config_line_parser_target() {
    let target_bytes = include_bytes!("configs/target_doas.conf");
    let (_, rule) = config::config_line_parser(target_bytes.as_ref()).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[]);
    assert_eq!(rule.ident(), b"user".as_ref());
    assert_eq!(rule.target(), Some(b"root".as_ref()));
    assert_eq!(rule.cmd(), None);
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());
}

#[test]
fn test_config_line_parser_cmd() {
    let cmd_bytes = include_bytes!("configs/cmd_doas.conf");
    let (rem, rule) = config::config_line_parser(cmd_bytes.as_ref()).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[]);
    assert_eq!(rule.ident(), b"user".as_ref());
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), Some(b"su".as_ref()));
    assert_eq!(rule.cmd_args(), None);
    assert_eq!(rule.envlist(), &HashMap::new());

    let (_, rule) = config::config_line_parser(rem).unwrap();

    assert_eq!(rule.action(), Action::Permit);
    assert_eq!(rule.options(), &[]);
    assert_eq!(rule.ident(), b"user".as_ref());
    assert_eq!(rule.target(), None);
    assert_eq!(rule.cmd(), Some(b"su".as_ref()));
    assert_eq!(
        rule.cmd_args(),
        Some([b"-l".as_ref().to_vec(), b"root".as_ref().to_vec()].as_ref())
    );
    assert_eq!(rule.envlist(), &HashMap::new());
}
