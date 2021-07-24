/* $OpenBSD: dosu, v0.0.1 2021/07/15 orvi Exp $ */
/*
 * NoCopyright () 2021 orvi
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#![allow(unused)]

#[macro_use]
extern crate nix;

use std::env;
use std::ffi::{CStr, CString};
use std::process::exit;

use bsd_auth::Session;
use dosu::config::parse_config;
use dosu::{Action, Error, Options, Rule};
use login_cap::{LoginCap, LoginFlags};
use nix::fcntl::open;
use nix::unistd::{
    close, getcwd, geteuid, getgroups, gethostname, getuid, setresuid, Group, SysconfVar, Uid, User,
};
use readpassphrase::{readpassphrase, Flags};

static APP: &'static str = env!("CARGO_PKG_NAME");
static VERSION: &'static str = env!("CARGO_PKG_VERSION");

static UID_MAX: usize = 65535;
static GID_MAX: usize = 65535;

static _PW_NAME_LEN: usize = 32;

#[cfg(target_os = "freebsd")]
static CONFIG_PATH: &'static str = "/usr/local/etc/doas.conf";
#[cfg(any(target_os = "linux", target_os = "openbsd"))]
static CONFIG_PATH: &'static str = "/etc/doas.conf";

static PATH_LOGIN_CONF: &'static str = "/etc/login.conf";
static PATH_LOGIN_CONF_DB: &'static str = "/etc/login.conf.db";

static SHELL: &'static str = "/bin/sh";
static STYLE: &'static str = "passwd";
static TARGET: &'static str = "root";

static GLOBAL_PATH: &'static str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
static SAFE_PATH: &'static str = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";

static MAX_ENV_LENGTH: usize = 1024;

/// Lookup a user entry in the password database
fn parseuid(name: &[u8]) -> Result<User, Error> {
    let n = std::str::from_utf8(name)?;
    User::from_name(n)?.ok_or(Error::from(nix::Error::Sys(nix::errno::Errno::ERANGE)))
}

/// Check that a UID exists, and matches the expected UID
fn uidcheck(name: &[u8], expected: &User) -> Result<bool, Error> {
    let uid = parseuid(name)?;
    Ok(&uid == expected)
}

/// Lookup a group entry in the password database
fn parsegid(name: &[u8]) -> Result<Group, Error> {
    let n = std::str::from_utf8(name)?;
    Group::from_name(n)?.ok_or(Error::from(nix::Error::Sys(nix::errno::Errno::ERANGE)))
}

/// Match a provided rule against the user, groups, target user, and command
fn match_rule(
    user: &User,
    groups: &[Group],
    target: &User,
    command: &[u8],
    args: &[&[u8]],
    rule: &Rule,
) -> Result<(), Error> {
    if rule.ident.len() >= 1 && rule.ident[0] == b':' {
        let gid = parsegid(&rule.ident[1..])?;
        let _ = groups
            .iter()
            .find(|&g| g == &gid)
            .ok_or(Error::UnmatchedGroup)?;
    } else {
        if !uidcheck(rule.ident(), user)? {
            return Err(Error::UnmatchedUser);
        }
    }

    if let Some(tgt) = rule.target() {
        if !uidcheck(tgt, target)? {
            return Err(Error::UnmatchedTarget);
        }
    }

    if let Some(cmd) = rule.cmd() {
        if cmd != command {
            return Err(Error::UnmatchedCommand);
        }
        if let Some(cmd_args) = rule.cmd_args() {
            if cmd_args.len() != args.len() {
                return Err(Error::UnmatchedCommandArgs);
            }
            for (arg, in_arg) in cmd_args.iter().zip(args.iter()) {
                if arg != in_arg {
                    return Err(Error::UnmatchedCommandArgs);
                }
            }
        } else {
            if args.len() > 0 {
                return Err(Error::UnmatchedCommandArgs);
            }
        }
    }

    Ok(())
}

/// Check if a set of rules matches the supplied parameters
///
/// Returns: a matching rule if found, Error if not
fn permit<'a>(
    user: &User,
    groups: &[Group],
    target: &User,
    command: &[u8],
    args: &[&[u8]],
    rules: &'a [Rule],
) -> Result<&'a Rule, Error> {
    let mut res = None;
    for rule in rules.iter() {
        if match_rule(user, groups, target, command, args, rule).is_ok()
            && rule.action() == Action::Permit
        {
            res = Some(rule);
        }
    }
    if let Some(rule) = res {
        Ok(rule)
    } else {
        Err(Error::UnmatchedRule)
    }
}

#[cfg(target_os = "openbsd")]
const IOC_PARM_MASK: u32 = 0x1fff;
#[cfg(target_os = "openbsd")]
const IOC_VOID: u32 = 0x20000000;
#[cfg(target_os = "openbsd")]
const IOC_IN: u32 = 0x80000000;

// _IOC defined in <sys/ioccom.h>
#[cfg(target_os = "openbsd")]
fn ioc(inout: u32, g: u32, n: u32, len: u32) -> u64 {
    (inout | ((len & IOC_PARM_MASK) << 16) | (g << 8) | n) as u64
}

#[cfg(target_os = "openbsd")]
fn authuser(name: &str, login_style: &str, persist: bool) -> Result<(), Error> {
    let mut fd = -1i32;

    if persist {
        fd = open(
            "/dev/tty",
            nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::S_IRWXU,
        )?;
    }
    if fd != -1 {
        let tiocchkverauth = ioc(IOC_VOID, b't' as u32, 30, 0);
        // safety: fd is a valid file descriptor, and ioctl(fd, TIOCCHKVERAUTH)
        // doesn't take any data arguments
        if unsafe { libc::ioctl(fd, tiocchkverauth) } == 0 {
            let iocsetverauth = ioc(IOC_IN, b't' as u32, 28, std::mem::size_of::<i32>() as u32);
            let mut secs = 5 * 60;
            // safety: fd is a valid file descriptor, and
            // secs is in valid range for ioctl(fd, TIOCSETVERAUTH, secs)
            unsafe { libc::ioctl(fd, iocsetverauth, &secs as *const _) };
            return close(fd).map_err(|e| e.into());
        }
    }
    let style_opt = if login_style.len() > 0 {
        Some(login_style)
    } else {
        None
    };

    let (session, challenge) = Session::auth_userchallenge(name, style_opt, Some("auth-doas"))?;

    // prompt the user for the passphrase
    let mut response = readpassphrase(&challenge, 1024, Flags::RequireTty.into())?;

    // Verify against the response, Session::auth_userresponse clears the response
    if !session.auth_userresponse(response.as_mut_str(), 0)?.1 {
        Err(Error::AuthUser)
    } else {
        Ok(())
    }
}

fn checkconfig(
    path: &str,
    user: &User,
    groups: &[Group],
    target: &User,
    cmd: &[u8],
    cmd_args: &[&[u8]],
) {
    setresuid(user.uid, user.uid, user.uid);
    #[cfg(target_os = "openbsd")]
    if let Err(e) = pledge(Some("stdio rpath getpw"), None) {
        println!("Error: unable to set pledge promises: {}", e);
        exit(1);
    }
    let rules = match parse_config(path) {
        Ok(r) => r,
        Err(e) => {
            println!("Error: error parsing config: {}", e);
            exit(1);
        }
    };

    let rule = match permit(user, groups, target, cmd, cmd_args, &rules) {
        Ok(r) => r,
        Err(e) => {
            println!("Error: no matching rule found: {}", e);
            exit(1);
        }
    };
    println!(
        "permit{}",
        if rule.options.contains(&Options::NoPass) {
            " nopass"
        } else {
            ""
        }
    );
    exit(0);
}

fn env_to_str<E, V>(e: E, v: V) -> Result<CString, Error>
where
    E: Into<Vec<u8>> + AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    let mut ev: Vec<u8> = e.into();
    ev.extend_from_slice(b"=".as_ref());
    ev.extend_from_slice(v.as_ref());
    CString::new(ev).map_err(|e| e.into())
}

fn prepenv(rule: &Rule, user: &User, target: &User) -> Result<Vec<CString>, Error> {
    use std::collections::HashMap;

    let mut envlist: HashMap<&[u8], &[u8]> = HashMap::new();

    envlist.insert(b"DOAS_USER".as_ref(), user.name.as_bytes());
    envlist.insert(
        b"HOME".as_ref(),
        target.dir.as_path().to_str().unwrap_or("").as_bytes(),
    );
    envlist.insert(b"LOGNAME".as_ref(), target.name.as_bytes());
    let path = env::var("PATH")?;
    envlist.insert(b"PATH".as_ref(), path.as_bytes());
    envlist.insert(
        b"SHELL".as_ref(),
        target.shell.as_path().to_str().unwrap_or("").as_bytes(),
    );
    envlist.insert(b"USER".as_ref(), target.name.as_bytes());

    let env_str_to_str = |e: &[u8], v: &str| -> Result<CString, Error> {
        let mut ev = e.to_vec();
        ev.extend_from_slice(b"=".as_ref());
        ev.extend_from_slice(v.as_bytes());
        CString::new(ev).map_err(|e| e.into())
    };

    let mut res = vec![];
    for (itm, val) in rule.envlist().iter() {
        if itm.len() > 0 {
            if itm[0] == b'-' {
                let _ = envlist.remove(&itm[1..]);
            } else {
                if val.len() > 0 && val[0] == b'$' {
                    let val_str = std::str::from_utf8(val)?;
                    let env_str = env::var(&val_str)?;
                    res.push(env_to_str(itm.as_slice(), &env_str)?);
                } else if val.len() > 0 {
                    res.push(env_to_str(itm.as_slice(), val.as_slice())?);
                } else {
                    res.push(CString::new(itm.as_slice())?);
                }
            }
        }
    }

    for (&itm, &val) in envlist.iter() {
        res.push(env_to_str(itm, val)?);
    }

    Ok(res)
}

#[cfg(target_os = "openbsd")]
fn unveil(path: &str, permissions: &str) -> Result<(), Error> {
    let path_c = CString::new(path)?;
    let perm_c = CString::new(permissions)?;
    // safety: pointers are guaranteed non-null, and point to valid memory
    let res = unsafe { libc::unveil(path_c.as_ptr(), perm_c.as_ptr()) };
    if res == -1 {
        Err(Error::Unveil(
            std::io::Error::last_os_error().raw_os_error().unwrap(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "openbsd")]
fn unveilcommands(path: &str, cmd: &[u8]) -> Result<usize, Error> {
    let mut unveils = 0;
    let cmd_str = std::str::from_utf8(cmd)?;

    if cmd.len() > 0 && cmd[0] == b'/' {
        if let Err(e) = unveil(&cmd_str, "x") {
            return Err(e);
        } else {
            unveils += 1;
            return Ok(unveils);
        }
    }

    for p in path.split(":") {
        let cmd_path = format!("{}/{}", p, cmd_str);
        if unveil(&cmd_path, "x").is_ok() {
            unveils += 1;
        }
    }

    Ok(unveils)
}

#[cfg(target_os = "openbsd")]
fn pledge(promises: Option<&str>, execpromises: Option<&str>) -> Result<(), Error> {
    let prom_c = CString::new(promises.unwrap_or(""))?;
    let exec_c = CString::new(execpromises.unwrap_or(""))?;

    let prom_ptr = match promises {
        Some(p) => prom_c.as_ptr(),
        None => std::ptr::null(),
    };
    let exec_ptr = match execpromises {
        Some(e) => exec_c.as_ptr(),
        None => std::ptr::null(),
    };

    // safety: pointers are either null (valid), or non-null pointing to valid memory
    let res = unsafe { libc::pledge(prom_ptr, exec_ptr) };
    if res == -1 {
        Err(Error::Pledge(
            std::io::Error::last_os_error().raw_os_error().unwrap(),
        ))
    } else {
        Ok(())
    }
}

fn version() {
    println!("{} {}", APP, VERSION);
    exit(0);
}

fn help() {
    println!("{} {}", APP, VERSION);
    println!("Rust port of OpenBSD's doas to run commands as another user");

    println!("");

    println!("USAGE:");
    println!("\t{} [FLAGS] [OPTIONS] [ARGS]", APP);

    println!("");

    println!("FLAGS:");
    println!("\t-h, --help\t\tPrints help information");
    println!("\t-n, --non-interactive\tNon-interactive mode, fails if nopass is not set");
    println!("\t-s, --shell\t\tExecutes the shell from SHELL or /etc/passwd");
    println!("\t-V, --version\t\tPrints version information");

    println!("");

    println!("OPTIONS:");
    println!("\t-C, --config <config>\tRead configuration file from this path");
    println!("\t-a, --style <style>\tLogin style to perform authentication");
    println!("\t-u, --user <user>\tTarget user to run the comman (name or uid)");

    println!("");

    println!("ARGS:");
    println!("\t<cmd>\t\t\tCommand to run as target user");
    println!("\t<cmd_args>...\t\tArguments to the command to run as target user");
    exit(0);
}

fn config_usage() {
    println!("{} [-C|--config] <config>", APP);
    exit(1);
}

fn style_usage() {
    println!("{} [-a|--style] <style>", APP);
    exit(1);
}

fn user_usage() {
    println!("{} [-u|--user] <user>", APP);
    exit(1);
}

fn cmd_usage() {
    println!("{} [FLAGS] [OPTIONS] <cmd> <cmd_args>...", APP);
    exit(1);
}

fn main() {
    let mut cli_args: Vec<String> = std::env::args().skip(1).collect();

    let args_len = cli_args.len();
    let mut check_config = false;
    let mut config_path = CONFIG_PATH.to_string();
    let mut login_style = STYLE.to_string();
    let mut user_str = TARGET.to_string();
    let mut is_non_interactive = false;
    let mut exec_shell = false;
    let mut i = 0;
    while i < args_len {
        match cli_args[i].as_str() {
            "-a" | "--style" => {
                if args_len > i + 1 {
                    login_style = cli_args[i + 1].clone();
                    i += 2;
                    continue;
                } else {
                    style_usage();
                }
            }
            "-C" | "--config" => {
                if args_len > i + 1 {
                    check_config = true;
                    config_path = cli_args[i + 1].clone();
                    i += 2;
                    continue;
                } else {
                    config_usage();
                }
            }
            "-u" | "--user" => {
                if args_len > i + 1 {
                    user_str = cli_args[i + 1].clone();
                    i += 2;
                    continue;
                } else {
                    user_usage();
                }
            }
            "-n" | "--non-interactive" => {
                is_non_interactive = true;
                i += 1;
                continue;
            }
            "-s" | "--shell" => {
                exec_shell = true;
                i += 1;
                continue;
            }
            "-V" | "--version" => {
                version();
            }
            "-h" | "--help" => {
                help();
            }
            _ => {
                if cli_args[i].len() > 0 && cli_args[i].as_bytes()[0] != b'-' {
                    break;
                } else {
                    help();
                }
            }
        }
    }

    let mut cmd = if i < args_len {
        let c = cli_args[i].clone();
        i += 1;
        c
    } else {
        "".to_string()
    };

    // cmd_args requires cmd
    if cmd.len() == 0 && i < args_len {
        cmd_usage();
    }

    let mut cmd_args: Vec<&[u8]> = cli_args[i..].iter().map(|a| a.as_bytes()).collect();

    let uid = getuid();
    let user = match User::from_uid(uid) {
        Ok(Some(u)) => u,
        _ => {
            println!("Error: No user found for UID: {}", uid);
            exit(1);
        }
    };
    let groups: Vec<Group> = match getgroups() {
        Ok(gs) => gs
            .iter()
            .map(|&g| match Group::from_gid(g) {
                Ok(Some(grp)) => grp,
                _ => {
                    println!("Error: No group entry found for gid: {}", g);
                    exit(1);
                }
            })
            .collect(),
        Err(e) => {
            println!("Error: Getting groups: {}", e);
            exit(1)
        }
    };
    let target = match User::from_name(&user_str) {
        Ok(Some(u)) => u,
        _ => {
            println!("Error: No entry found for target user: {}", user_str);
            exit(1);
        }
    };

    if exec_shell {
        cmd = env::var("SHELL").unwrap_or(SHELL.to_string());
        cmd_args.clear();
    }

    if check_config {
        checkconfig(
            &config_path,
            &user,
            &groups,
            &target,
            cmd.as_bytes(),
            &cmd_args,
        );
    }

    let rules: Vec<Rule> = match parse_config(&config_path) {
        Ok(r) => r,
        Err(e) => {
            println!("Error: parsing config file: {}", e);
            exit(1);
        }
    };

    let rule = match permit(&user, &groups, &target, cmd.as_bytes(), &cmd_args, &rules) {
        Ok(r) => r,
        Err(e) => {
            println!("Error: Could not find a permitting rule: {}", e);
            exit(1);
        }
    };

    if geteuid() != Uid::from_raw(0) {
        println!("Error: not installed setuid, euid({})", geteuid());
        exit(1);
    }

    let options = rule.options();
    if !options.contains(&Options::NoPass) {
        if is_non_interactive {
            println!("Error: Authentication required");
            exit(1);
        }
        #[cfg(target_os = "openbsd")]
        if let Err(e) = authuser(
            &user.name,
            &login_style,
            options.contains(&Options::Persist),
        ) {
            println!("Error: Authentication failed: {:?}", e);
            exit(1);
        }
    }

    let former_path = env::var("PATH").unwrap_or("".into());

    #[cfg(target_os = "openbsd")]
    if let Err(e) = unveil(PATH_LOGIN_CONF, "r") {
        println!("Error: unable to unveil {}, err: {}", PATH_LOGIN_CONF, e);
        exit(1);
    }

    #[cfg(target_os = "openbsd")]
    if let Err(e) = unveil(PATH_LOGIN_CONF_DB, "r") {
        println!("Error: unable to unveil {}, err: {}", PATH_LOGIN_CONF_DB, e);
        exit(1);
    }

    if rule.cmd.is_some() {
        env::set_var("PATH", SAFE_PATH);
    }

    #[cfg(target_os = "openbsd")]
    if let Err(e) = unveilcommands(
        &env::var("PATH").unwrap_or(SAFE_PATH.into()),
        cmd.as_bytes(),
    ) {
        println!("Error: unable to unveil command, err: {}", e);
        exit(1);
    };

    #[cfg(target_os = "openbsd")]
    if let Err(e) = pledge(Some("stdio rpath getpw exec id"), None) {
        println!(
            "Error: unable to pledge (stdio rpath getpw exec id), err:{}",
            e
        );
        exit(1);
    }

    #[cfg(target_os = "openbsd")]
    if let Ok(cap) = LoginCap::new("default") {
        // FIXME: use Some(target) as first argument
        // for the pwd entry if `From<User> to libc::passwd` is merged in nix
        if cap
            .setusercontext(
                None,
                target.uid,
                LoginFlags::SetGroup
                    | LoginFlags::SetPath
                    | LoginFlags::SetPriority
                    | LoginFlags::SetResources
                    | LoginFlags::SetUmask
                    | LoginFlags::SetUser,
            )
            .is_err()
        {
            println!("Error: failed to set user context as target");
            exit(1);
        }
    }

    #[cfg(target_os = "openbsd")]
    if let Err(e) = pledge(Some("stdio rpath exec"), None) {
        println!("Error: unable to pledge (stdio rpath exec), err:{}", e);
        exit(1);
    }

    // FIXME: use cwd for logging, once implemented
    let _cwd = getcwd().unwrap_or("(failed)".into());

    #[cfg(target_os = "openbsd")]
    if let Err(e) = pledge(Some("stdio exec"), None) {
        println!("Error: failed to pledge promises: {}", e);
        exit(1);
    }

    if rule.cmd.is_some() {
        env::set_var("PATH", SAFE_PATH);
    } else {
        env::set_var("PATH", &former_path);
    }

    let cmd_c = CString::new(cmd).unwrap();

    // add command and command arguments
    let mut argv = Vec::with_capacity(1 + cmd_args.len());
    argv.push(cmd_c.clone());
    for &a in cmd_args.iter() {
        argv.push(CString::new(a).unwrap());
    }

    if cfg!(any(target_os = "linux", target_os = "openbsd")) {
        let envp = match prepenv(&rule, &user, &target) {
            Ok(e) => e,
            Err(e) => {
                println!("unable to prepare environment, err: {}", e);
                exit(1);
            }
        };
        match nix::unistd::execvpe(&cmd_c, &argv, &envp) {
            Ok(_) => exit(0),
            Err(e) => {
                println!("Error: executing command: {:?}", e);
                exit(1);
            }
        }
    } else {
        match nix::unistd::execvp(&cmd_c, &argv) {
            Ok(_) => exit(0),
            Err(e) => {
                println!("Error: executing command: {:?}", e);
                exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parseuid() {
        assert!(parseuid(b"root".as_ref()).is_ok());
        assert!(parseuid(b"*&notAU$er".as_ref()).is_err());
    }

    #[test]
    fn test_uidcheck() {
        assert!(uidcheck(b"root".as_ref(), &parseuid(b"root".as_ref()).unwrap()).unwrap());
        assert!(!uidcheck(b"root".as_ref(), &parseuid(b"nobody".as_ref()).unwrap()).unwrap());
        assert!(uidcheck(
            b"*&notAU$ser".as_ref(),
            &parseuid(b"nobody".as_ref()).unwrap()
        )
        .is_err());
    }

    #[test]
    fn test_parsegid() {
        assert!(parsegid(b"nobody".as_ref()).is_ok());
        assert!(parsegid(b"*&notAU$er".as_ref()).is_err());
    }

    #[test]
    fn test_match_rule() {
        let mut rule = Rule::default();

        let empty = b"".as_ref();
        // check the rule matches against the ident and user
        rule.ident = b"nobody".as_ref().into();
        let uid = parseuid(b"nobody".as_ref()).unwrap();
        assert!(match_rule(&uid, &[], &uid, empty, &[], &rule).is_ok());

        // check the rule matches against the groups
        rule.ident = b":nobody".as_ref().into();
        let gid = parsegid(b"nobody".as_ref()).unwrap();
        let _ = match_rule(&uid, &[gid.clone()], &uid, empty, &[], &rule).unwrap();
        assert!(match_rule(&uid, &[gid.clone()], &uid, empty, &[], &rule).is_ok());

        // check the rule matches against the target
        rule.ident = b"nobody".as_ref().into();
        rule.target = Some(b"nobody".as_ref().into());
        assert!(match_rule(&uid, &[], &uid, empty, &[], &rule).is_ok());

        // check the rule matches against the command
        rule.cmd = Some(b"su".as_ref().into());
        assert!(match_rule(&uid, &[], &uid, b"su".as_ref(), &[], &rule).is_ok());

        // check the rule matches against the command arguments
        rule.cmd_args = Some(vec![b"-l".as_ref().into(), b"root".as_ref().into()]);
        assert!(match_rule(
            &uid,
            &[],
            &uid,
            b"su".as_ref(),
            &[b"-l".as_ref(), b"root".as_ref()],
            &rule
        )
        .is_ok());

        // check the rule fails match against empty ident and user
        rule.ident = empty.into();
        assert!(match_rule(&uid, &[], &uid, empty, &[], &rule).is_err());

        // check the rule fails match against different ident and user
        rule.ident = b"root".as_ref().into();
        assert!(match_rule(&uid, &[], &uid, empty, &[], &rule).is_err());

        // check the rule fails match against different groups
        rule.ident = b":root".as_ref().into();
        assert!(match_rule(&uid, &[gid], &uid, empty, &[], &rule).is_err());

        // check the rule fails match against different target
        rule.ident = b"nobody".as_ref().into();
        rule.target = Some(b"bin".as_ref().into());
        assert!(match_rule(&uid, &[], &uid, empty, &[], &rule).is_err());

        // check the rule fails match against different command
        rule.target = Some(b"nobody".as_ref().into());
        rule.cmd = Some(b"doas".as_ref().into());
        assert!(match_rule(&uid, &[], &uid, b"sudo".as_ref(), &[], &rule).is_err());

        // check the rule fails match against different command arguments
        rule.cmd = Some(b"su".as_ref().into());
        rule.cmd_args = Some(vec![b"-l".as_ref().into(), b"wheel".as_ref().into()]);
        assert!(match_rule(
            &uid,
            &[],
            &uid,
            b"su".as_ref(),
            &["-l".as_ref(), b"root".as_ref()],
            &rule
        )
        .is_err());
        assert!(match_rule(&uid, &[], &uid, b"su".as_ref(), &["-l".as_ref()], &rule).is_err());
    }

    #[test]
    fn test_permit() {
        let mut rule = Rule::default();
        let uid = parseuid(b"nobody".as_ref().into()).unwrap();
        let cmd = b"sudo".as_ref();

        rule.ident = b"nobody".as_ref().into();
        rule.action = Action::Permit;
        rule.cmd = Some(b"sudo".as_ref().into());
        let rules = vec![rule.clone(), Rule::default()];
        let rule_res = permit(&uid, &[], &uid, cmd, &[], &rules).unwrap();
        assert_eq!(rule_res, &rules[0]);

        // check that permit fails for no matching rules
        assert!(permit(&uid, &[], &uid, cmd, &[], &[]).is_err());

        // check that permit fails for matching rule with deny action
        rule.action = Action::Deny;
        assert!(permit(&uid, &[], &uid, cmd, &[], &[rule]).is_err());
    }
}
