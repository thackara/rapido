// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2026 SUSE LLC
use std::env;
use std::fs;
use std::io;
use std::path;
use std::process::Command;

// TODO: override cut dir at build time
const RAPIDO_CUT_DIR: &str = "cut";
const RAPIDO_CMDS: [&str; 6] = [
    "boot",
    "cut",
    "help",
    "list",
    "setup-network",
    "teardown-network",
];

fn complete_cut_script_name<W: io::Write>(out: &mut W, filter_inc: &str) -> bool {
    let cut_ls = match fs::read_dir(RAPIDO_CUT_DIR) {
        Err(_) => return false,
        Ok(i) => i,
    };
    for cut_ent in cut_ls {
        if cut_ent.is_err() {
            return false;
        }
        let ent = match cut_ent.unwrap().path().file_stem() {
            None => continue,
            Some(ent) => match ent.to_str() {
                None => continue,
                Some(ent_str) => ent_str.replace("_", "-"),
            },
        };
        if ent.starts_with(filter_inc) {
            writeln!(out, "{}", ent).unwrap();
        }
    }

    true
}

fn complete_filter<W: io::Write>(out: &mut W, options: &[&str], filter_inc: &str) {
    for param in options {
        if param.starts_with(filter_inc) {
            writeln!(out, "{}", param).unwrap();
        }
    }
}

// use bash compgen for file completion for now
fn complete_local_file<W: io::Write>(out: &mut W, filter_inc: String) -> bool {
    // complete -f <filename>
    let bash_cmd = format!("compgen -o filenames -A file -- {}", &filter_inc);
    match Command::new("bash")
        .args(&["--norc", "--noprofile", "-c"])
        .arg(bash_cmd)
        .output()
    {
        Err(_) => return false,
        Ok(o) => {
            out.write_all(&o.stdout).unwrap();
            o.status.success()
        }
    }
}

fn complete_cut_any_param<W: io::Write>(out: &mut W, cursor_cmpl: &str, seen_b: bool) -> bool {
    // -B is only valid once, don't suggest it again
    match seen_b {
        false => complete_filter(out, &["-B", "-f", "-x"], &cursor_cmpl),
        true => complete_filter(out, &["-f", "-x"], &cursor_cmpl),
    };
    return complete_cut_script_name(out, &cursor_cmpl);
}

fn complete_cut<W: io::Write>(
    out: &mut W,
    prior_args: &Vec<String>,
    cursor_cmpl: String,
    seen_b: bool,
) -> bool {
    assert_eq!(prior_args.get(1).unwrap().as_str(), "cut");

    // fast path if completing one parameter after "cut"
    if prior_args.len() == 2 {
        return complete_cut_any_param(out, &cursor_cmpl, false);
    }

    // else, more than one post-"cut" parameter...
    // TODO: this will still (incorrectly) offer completion if we have e.g.
    // rapido cut simple-example -f <file-path-completed>
    match prior_args.last().unwrap().as_str() {
        "-f" => complete_local_file(out, cursor_cmpl),
        // TODO: we currently filter out script ("-x") due to tokenization
        "-x" => false,
        "-B" => complete_cut_any_param(out, &cursor_cmpl, true),
        // if the previous is not a flag then it could be:
        // - one single cut-script? there shouldn't be anything after it
        _ if prior_args.len() <= 3 => false,
        _ => match prior_args.get(prior_args.len() - 2) {
            // - a post-f file
            Some(p) if p == "-f" => complete_cut_any_param(out, &cursor_cmpl, seen_b),
            // post-x script: TODO
            Some(p) if p == "-x" => false,
            // anything else: bad completion
            _ => false,
        },
    }
}

// check whether arg @s includes nil cursor marker, if so replace it with
// @comp_tok
fn complete_nil_arg_under_cursor(s: &str, comp_tok: Option<char>) -> (String, bool) {
    match s.contains("\0") {
        false => (s.to_string(), false),
        true => {
            // replace our injected nul at completion point
            match comp_tok {
                // TODO: for now we *ignore* the position within the
                // completion arg. We could get it via:
                // t.chars.position(|c| c == '\0')
                // ...but we'd somehow want to use it for partial-inner-word
                // completions(?)
                Some(t) => (s.replace("\0", &t.to_string()), true),
                None => {
                    let mut s = s.to_string();
                    assert_eq!(s.pop(), Some('\0'));
                    (s, true)
                }
            }
        }
    }
}

fn complete_rapido<W: io::Write>(out: &mut W, mut comp_line: String, comp_point: usize) -> bool {
    let mut comp_tok = comp_line.chars().nth(comp_point);

    #[cfg(debug_assertions)]
    eprintln!(
        "comp_point ({:?}@{}) in comp_line:\n{}\n{:─>width$}",
        comp_tok,
        comp_point,
        comp_line,
        "^",
        width = comp_point + 1
    );

    if comp_tok.is_some() {
        // Before whitespace split, record comp_point via nul to avoid loosing
        // position.
        let replacement = match comp_tok.unwrap().is_whitespace() {
            // avoid joining when the cursor sits on space between two words
            true => {
                // don't inject a space when we replace nul marker
                comp_tok = None;
                "\0 "
            }
            false => "\0",
        };
        comp_line.replace_range(comp_point..comp_point + 1, replacement);
    } else {
        // For end completion we still need to know whether we're completing an
        // existing or new parameter (space prior to completion). Track via...
        comp_line.push_str("\0");
    }

    // track completion word. replace "\0" with comp_tok, or remove it if None
    let mut args: Vec<String> = Vec::new();
    let mut seen_minus_b = false;
    for (i, s) in comp_line.split_whitespace().enumerate() {
        // TODO: '-x' completions currently unsupported:
        // To avoid tokenizing parameters like bash, we cheat for simplicity;
        // cut -x <script> is the only parameter which we handle as though it
        // may carry a space.
        if s == "-x" {
            return false;
        }
        // TODO: -f <path> names could potentially also carry spaces, which
        // would be broken by split_whitespace().

        let (arg, under_cursor) = complete_nil_arg_under_cursor(s, comp_tok);
        if under_cursor {
            if i == 0 {
                return false;
            } else if i == 1 {
                complete_filter(out, &RAPIDO_CMDS, &arg);
                return true;
            }
            match args.get(1).unwrap().as_ref() {
                "cut" => return complete_cut(out, &args, arg, seen_minus_b),
                // currently only "cut" takes parameters
                _ => return false,
            }
        }
        if arg == "-B" {
            seen_minus_b = true;
        }
        args.push(arg);
    }

    false
}

fn main() {
    // completion program first
    let mut args = env::args().into_iter();
    if args.next() == None {
        eprintln!("unexpected empty args");
        return;
    }

    // program whose args are being completed
    let prog_cmpl: String = match args.next() {
        Some(p) => p,
        None => return,
    };

    // These two parameters are unused for now, as we use COMP_LINE instead
    // word under current completion cursor:
    //let cursor_cmpl = args.next();
    // word before current cursor:
    //let pre_cursor_cmpl = args.next();

    // COMP_LINE
    // The current command line. This variable is available only in shell
    // functions and external commands invoked by the programmable completion
    // facilities (see Programmable Completion).
    let comp_line = match env::var("COMP_LINE") {
        Err(_) => return,
        Ok(l) => l,
    };
    // COMP_POINT
    // The index of the current cursor position relative to the beginning of
    // the current command. If the current cursor position is at the end of the
    // current command, the value of this variable is equal to ${#COMP_LINE}.
    // This variable is available only in shell functions and external commands
    // invoked by the programmable completion facilities (see Programmable
    // Completion).
    let comp_point = match env::var("COMP_POINT") {
        Err(_) => return,
        Ok(ps) => match ps.parse::<usize>() {
            Err(_) => return,
            Ok(p) => p,
        },
    };

    match prog_cmpl.as_str() {
        "rapido" | "./rapido" => match path::Path::new("rapido").is_file() {
            // don't complete for rapido (e.g. source) directories
            false => return,
            true => _ = complete_rapido(&mut io::stdout(), comp_line, comp_point),
        },
        _ => eprintln!("unknown program {} for completion", prog_cmpl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_completions() {
        let mut out = Vec::new();
        let lexp: &[(&str, &str)] = &[
            (
                "rapido ",
                "boot\ncut\nhelp\nlist\nsetup-network\nteardown-network\n",
            ),
            ("rapido cu", "cut\n"),
            ("rapido cut -", "-B\n-f\n-x\n"),
            ("rapido cut -B -", "-f\n-x\n"),
            ("rapido cut simple-e", "simple-example\n"),
            ("rapido cut -f ./whatever simple-e", "simple-example\n"),
        ];

        for (line, exp) in lexp {
            complete_rapido(&mut out, line.to_string(), line.len());
            assert_eq!(&str::from_utf8(&out).unwrap(), exp);
            out.clear();
        }
    }

    #[test]
    fn test_bad_completions() {
        let mut out = Vec::new();
        for bad_line in &["rapido qwer", "rapido cut -G", "rapido cut qwer"] {
            complete_rapido(&mut out, bad_line.to_string(), bad_line.len());
            assert!(out.is_empty());
            out.clear();
        }
    }
}
