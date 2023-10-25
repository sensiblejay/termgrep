extern crate hyperscan;
use hyperscan::prelude::*;
use hyperscan::HsError::ScanTerminated;

use avt::Vt;

use clap::{Parser, ValueEnum};

use std::fs;
use std::io::{self, BufRead, BufReader};

use chrono::{Local, TimeZone};
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use log::{debug, info, warn};

use std::io::IsTerminal;
use tracing::info as tracing_info;

// Annoying to have to do this but by god I need those colors in the help output
pub fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
        .header(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Yellow))),
        )
        .literal(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green))),
        )
        .placeholder(
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::White))),
        )
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
enum EntryKind {
    #[serde(rename = "i")]
    Input,
    #[serde(rename = "o")]
    Output,
    #[serde(rename = "m")]
    Mark,
    #[serde(rename = "r")]
    Resize,
    #[serde(rename = "f")]
    TermFlags,
}

#[derive(Serialize, Deserialize, Debug)]
struct V2Theme {
    fg: String,
    bg: String,
    palette: String,
}

// Environment variables
type Env = HashMap<String, String>;

// Header; e.g.:
// {"version": 2, "width": 179, "height": 50, "timestamp": 1696956471, "env": {"SHELL": "/bin/bash", "TERM": "screen-256color"}}
#[derive(Serialize, Deserialize, Debug)]
struct Header {
    version: u8,
    width: u16,
    height: u16,
    env: Option<Env>,
    timestamp: Option<u64>,
    command: Option<String>,
    idle_time_limit: Option<f64>,
    theme: Option<V2Theme>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    timestamp: f64,
    kind: EntryKind,
    data: String,
}

struct MatchData {
    filename: String,
    start_time: u64,
    start_frame: usize,
    end_frame: usize,
    start_ts: f64,
    end_ts: f64,
    last_frame_text: String,
    match_ranges: Vec<(usize, usize)>,
}

fn events(
    reader: impl BufRead,
    event_type: Option<EntryKind>,
) -> impl Iterator<Item = (f64, String)> {
    reader.lines().filter_map(move |line| {
        let line = line.ok()?;
        let entry: Entry = serde_json::from_str(&line).ok()?;
        if let Some(kind) = event_type {
            if entry.kind != kind {
                return None;
            }
        }
        Some((entry.timestamp, entry.data))
    })
}

fn stdout(reader: impl BufRead + 'static) -> impl Iterator<Item = (f64, String)> {
    events(reader, Some(EntryKind::Output))
}

fn stdin(reader: impl BufRead + 'static) -> impl Iterator<Item = (f64, String)> {
    events(reader, Some(EntryKind::Input))
}

pub fn frames(
    stream: impl Iterator<Item = (f64, String)>,
    is_stdin: bool,
) -> impl Iterator<Item = (f64, Vec<Vec<(char, avt::Pen)>>, Option<(usize, usize)>)> {
    // 1000 chars should be enough for anyone
    let mut vt = Vt::new(1000, 100);
    let mut prev_cursor = None;

    stream.filter_map(move |(time, data)| {
        // For stdin, we need to change \r to \r\n
        let data = if is_stdin {
            data.replace("\r", "\r\n")
        } else {
            data
        };
        let (changed_lines, _) = vt.feed_str(&data);
        let cursor: Option<(usize, usize)> = vt.cursor().into();

        if !changed_lines.is_empty() || cursor != prev_cursor {
            prev_cursor = cursor;

            let lines = vt
                .view()
                .iter()
                .map(|line| line.cells().collect())
                .collect();

            Some((time, lines, cursor))
        } else {
            prev_cursor = cursor;

            None
        }
    })
}

fn make_timestamp(start_time: u64, offset: f64) -> String {
    let ts = Local
        .timestamp_opt(
            start_time as i64 + offset as i64,
            (offset.fract() * 1e9) as u32,
        )
        .unwrap();
    ts.format("%Y-%m-%d %H:%M:%S").to_string()
}

const COLOR_RED: &str = "\x1b[31m";
const COLOR_RESET: &str = "\x1b[0m";

fn highlight_matches(matchdata: &MatchData, args: &Args) -> String {
    let use_color = match args.color {
        Color::Auto => {
            // Only use color if stdout is a terminal
            io::stdout().is_terminal()
        }
        Color::Always => true,
        Color::Never => false,
    };
    let mut result = String::new();
    for (i, ch) in matchdata.last_frame_text.chars().enumerate() {
        for (from, to) in matchdata.match_ranges.iter() {
            if use_color && i == *from {
                result.push_str(COLOR_RED);
            }
            if use_color && i == *to {
                result.push_str(COLOR_RESET);
            }
        }
        result.push(ch);
    }
    result
}

fn highlight_matchlines(matchdata: &MatchData, args: &Args) -> String {
    let use_color = match args.color {
        Color::Auto => {
            // Only use color if stdout is a terminal
            io::stdout().is_terminal()
        }
        Color::Always => true,
        Color::Never => false,
    };
    let mut result = String::new();
    // Iterate over lines in the frame; only add lines with matches (and highlight the matches)
    let mut pos = 0;
    for (i, line) in matchdata.last_frame_text.lines().enumerate() {
        let line_end = pos + line.len();
        let mut line_text = String::new();
        let mut line_pos = 0;
        for &(from, to) in matchdata.match_ranges.iter() {
            if from >= pos && to <= line_end {
                // This match is within the line
                line_text.push_str(&line[line_pos..(from - pos)]);
                if use_color {
                    line_text.push_str(COLOR_RED);
                }
                line_text.push_str(&line[(from - pos)..(to - pos)]);
                if use_color {
                    line_text.push_str(COLOR_RESET);
                }
                line_pos = to - pos;
            }
        }
        if line_pos != 0 {
            line_text.push_str(&line[line_pos..]);
        }
        if !line_text.is_empty() {
            if args.show_line_numbers {
                result.push_str(&format!("{:4}: ", i + 1));
            }
            result.push_str(&line_text);
            result.push('\n');
        }
        pos += line.len() + 1;
    }
    result
}

fn display_match(matchdata: &MatchData, args: &Args) {
    if args.list_only {
        println!("{}", matchdata.filename);
        return;
    }
    let start_timestamp = make_timestamp(matchdata.start_time, matchdata.start_ts);
    let end_timestamp = make_timestamp(matchdata.start_time, matchdata.end_ts);
    let nframes = matchdata.end_frame - matchdata.start_frame + 1;
    println!(
        "{}: Match found for {} in frames [{},{}] ({} frame{}): {} .. {}",
        matchdata.filename,
        args.pattern,
        matchdata.start_frame,
        matchdata.end_frame,
        nframes,
        if nframes == 1 { "" } else { "s" },
        start_timestamp,
        end_timestamp,
    );
    // Print the matching lines in the frame
    if args.show_full_frame {
        print!("{}", highlight_matches(&matchdata, &args));
    } else {
        print!("{}", highlight_matchlines(&matchdata, &args));
    }
}

fn search_file(pattern: &Pattern, file: &str, args: &Args) {
    tracing_info!("Searching file {}", file);
    let db: BlockDatabase = pattern.build().unwrap_or_else(|e| {
        eprintln!("Error building pattern {}: {}", pattern.expression, e);
        std::process::exit(1);
    });
    let scratch = db.alloc_scratch().unwrap();

    let mut reader = if file == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else if file.ends_with(".zst") {
        Box::new(BufReader::new(
            zstd::Decoder::new(fs::File::open(file).unwrap()).unwrap(),
        ))
    } else {
        Box::new(BufReader::new(fs::File::open(file).unwrap()))
    };

    // Read the header line of the input
    let mut header_line = String::new();
    reader.read_line(&mut header_line).unwrap();
    let header: Header = serde_json::from_str(&header_line).unwrap();

    // Print the header line
    debug!("{:?}", header);
    let start_time = header.timestamp.unwrap_or(0);

    // Count matches
    let mut match_count = 0;
    let max_matches = args.max_matches.unwrap_or(usize::MAX);

    // Collect matching frames
    let mut mi: Option<MatchData> = None;
    let target_is_stdin = args.event_type == "stdin";
    let event_stream = if target_is_stdin {
        stdin(reader)
    } else {
        stdout(reader)
    };

    let mut frame_text = String::new();
    for (i, (time, lines, _cursor)) in frames(event_stream, target_is_stdin).enumerate() {
        frame_text.clear();
        for chars in lines.iter() {
            let at = frame_text.len();
            frame_text.extend(chars.iter().map(|(ch, _)| *ch));
            frame_text.truncate(frame_text.trim_end().len());
            if frame_text.len() > at {
                frame_text.push('\n');
            }
        }
        let res = db.scan(&frame_text, &scratch, |_id, from: u64, to, _flags| {
            debug!("Match frame {} at {} from {} to {}", i, time, from, to);
            match_count += 1;
            if match_count > max_matches {
                warn!("Maximum number of matches reached; stopping");
                return Matching::Terminate;
            }
            match mi {
                None => {
                    mi = Some(MatchData {
                        filename: file.to_string(),
                        start_time,
                        start_frame: i,
                        end_frame: i,
                        start_ts: time,
                        end_ts: time,
                        last_frame_text: frame_text.clone(),
                        match_ranges: vec![(from as usize, to as usize)],
                    });
                    debug!(
                        "First matching frame found at {} {}",
                        i,
                        make_timestamp(start_time, time)
                    );
                }
                Some(ref mut mi) => {
                    if i == mi.end_frame + 1 {
                        // Contiguous
                        mi.end_frame = i;
                        mi.end_ts = time;
                        mi.last_frame_text.clear();
                        mi.last_frame_text.push_str(&frame_text);
                        mi.match_ranges.clear();
                        mi.match_ranges.push((from as usize, to as usize));
                        debug!("Extended matching frame range to {}", i);
                    } else if i == mi.end_frame {
                        // Same frame; add the match to the list
                        mi.match_ranges.push((from as usize, to as usize));
                        debug!("Additional match within the same frame; do nothing");
                    } else {
                        // Not contiguous; display the match. We use the last frame text.
                        // TODO: consider whether we should do something if there are multiple
                        // matches in the same frame; by the time we get to the last frame
                        // some of the matches may have disappeared...
                        display_match(mi, args);
                        mi.start_frame = i;
                        mi.end_frame = i;
                        mi.start_ts = time;
                        mi.end_ts = time;
                        mi.last_frame_text.clear();
                        mi.last_frame_text.push_str(&frame_text);
                        mi.match_ranges.clear();
                        mi.match_ranges.push((from as usize, to as usize));
                    }
                }
            }
            return Matching::Continue;
        });
        if let Err(e) = res {
            match e {
                hyperscan::Error::Hyperscan(ScanTerminated) => {
                    info!("Scan terminated");
                    break;
                }
                _ => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
    // Display the last match
    if let Some(mi) = mi {
        display_match(&mi, args);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Color {
    Auto,
    Always,
    Never,
}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, styles=get_styles())]
struct Args {
    // Pattern to search for
    #[arg(index = 1, help = "Pattern to search for")]
    pattern: String,

    // Input file to search
    #[arg(default_value = "-", index = 2, help = "Input file(s) to search")]
    files: Vec<String>,

    #[arg(short = 'i', long, help = "Make the search case-insensitive")]
    case_insensitive: bool,

    #[arg(short = 'm', long, help = "Set maximum number of matches to report")]
    max_matches: Option<usize>,

    #[arg(short = 'l', long, help = "Only list filenames; do not show matches")]
    list_only: bool,

    #[arg(short = 'n', long, help = "Show line numbers for matches")]
    show_line_numbers: bool,
    #[arg(
        long,
        value_enum,
        help = "Control color output",
        default_value = "auto"
    )]
    color: Color,

    #[arg(short = 'f', long, help = "Show full frame for matches")]
    show_full_frame: bool,

    #[arg(
        short = 't',
        long,
        default_value = "stdout",
        value_parser = clap::builder::PossibleValuesParser::new(["stdout", "stdin"]),
        help = "Select event type to search over"
    )]
    event_type: String,
}

fn main() {
    use tracing_chrome::ChromeLayerBuilder;
    use tracing_subscriber::{prelude::*, registry::Registry};

    let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
    tracing_subscriber::registry().with(chrome_layer).init();

    let mut args = Args::parse();

    // Validation: make sure that if "-" is specified, it is only used once
    let mut stdin_count = 0;
    for file in &args.files {
        if file == "-" {
            stdin_count += 1;
        }
        if stdin_count > 1 {
            eprintln!("Error: stdin specified more than once");
            std::process::exit(1);
        }
    }

    // If we're only listing filenames, we only need one match
    if args.list_only {
        args.max_matches = Some(1);
    }

    let pattern = pattern! {
        args.pattern.clone();
        CompileFlags::SOM_LEFTMOST | CompileFlags::UTF8 |
            if args.case_insensitive { CompileFlags::CASELESS } else { CompileFlags::empty() }
    };

    for file in &args.files {
        search_file(&pattern, file.as_str(), &args);
    }
}
