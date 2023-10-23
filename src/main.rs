extern crate hyperscan;
use hyperscan::prelude::*;

use avt::Vt;

use clap::Parser;

use std::fs;
use std::io::{self, BufReader, BufRead};

use serde::{Deserialize, Serialize};
use chrono::{Local, TimeZone};

use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum EntryKind {
    #[serde(rename = "i")]
    Input,
    #[serde(rename = "o")]
    Output,
    #[serde(rename = "m")]
    Mark,
    #[serde(rename = "r")]
    Resize,
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Pattern to search for
    #[arg(index = 1, help = "Pattern to search for")]
    pattern: String,

    // Input file to search
    #[arg(default_value = "-", index = 2, help = "Input file(s) to search")]
    files: Vec<String>,

    #[arg(short = 'i', long, help = "Make the search case-insensitive")]
    case_insensitive: bool,
}

fn trim_text(text: &mut Vec<String>) {
    println!("Before trim: {:?}", text);
    while !text.is_empty() && text[text.len() - 1].is_empty() {
        text.truncate(text.len() - 1);
    }
}

fn search_file(pattern: &Pattern, file: &str, args: &Args) {
    let db: StreamingDatabase = pattern.build().unwrap_or_else(|e| {
        eprintln!("Error building pattern {}: {}", pattern.expression, e);
        std::process::exit(1);
    });
    let scratch = db.alloc_scratch().unwrap();
    let st = db.open_stream().unwrap();

    // 1000 chars should be enough for anyone
    let mut vt = Vt::new(1000, 100);

    let mut reader: Box<dyn BufRead> = match file {
        "-" => Box::new(BufReader::new(io::stdin())),
        path => Box::new(BufReader::new(fs::File::open(path).unwrap())),
    };

    // Read the header line of the input
    let mut header_line = String::new();
    reader.read_line(&mut header_line).unwrap();
    let header: Header = serde_json::from_str(&header_line).unwrap();

    // Print the header line
    println!("{:?}", header);

    let start_time = header.timestamp.unwrap();

    let mut interval_start : u64 = 0;
    let mut current_line = 0;
    let mut current_line_timestamp : f64 = 0.0;
    let mut intervals : Vec<(u64,u64,f64,String)> = Vec::new();
    for (_entry_num, logline) in reader.lines().enumerate() {
        if let Err(_e) = logline {
            break;
        }
        let line = logline.unwrap();
        let entry: Entry = serde_json::from_str(&line).unwrap();
        if entry.kind == EntryKind::Input {
            continue;
        }

        println!("{:?}", entry);

        // Set the timestamp if not already set
        if current_line_timestamp == 0.0 {
            current_line_timestamp = entry.timestamp;
        }

        vt.feed_str(&entry.data);
        let mut vttext = vt.text();
        trim_text(&mut vttext);
        println!("Text after feeding: {:?}", vttext);
        let lines = vt.lines();
        if lines.len()-1 > current_line {
            println!("Now at {} lines", lines.len()-1);
            let mut combined = String::new();

            // Collect the text of the lines we haven't scanned yet; don't include the
            // last line because it might be partial
            for line in &vt.lines()[current_line..lines.len()-1] {
                let trim = line.text().trim_end().to_owned();
                if !trim.is_empty() {
                    combined.push_str(&trim);
                    combined.push('\n');
                }
            }

            // Update intervals
            let interval_end = interval_start + combined.len() as u64;
            intervals.push((interval_start, interval_end, current_line_timestamp, combined));
            println!("{:?}", intervals[intervals.len()-1]);
            interval_start = interval_end;
            current_line_timestamp = entry.timestamp;
            current_line = lines.len()-1;
        }
    }

    // Create the trailing interval
    println!("Processing trailing lines starting from line {}", current_line);
    let mut combined = String::new();
    for line in &vt.lines()[current_line..] {
        combined.push_str(&line.text().trim_end());
        combined.push('\n');
    }
    let interval_end = interval_start + combined.len() as u64;
    intervals.push((interval_start, interval_end, current_line_timestamp, combined));
    println!("{:?}", intervals[intervals.len()-1]);

    println!("VT text: {:?}", vt.text());

    for (_s, _e, _t, itext) in &intervals {
        // Scan the text we just collected
        st.scan(itext, &scratch, |_id, from: u64, to, _flags| {
            // println!("found pattern {} : {} @ [{}, {})", id, pattern.expression, from, to);
            // Search backward for the interval that contains the match start
            let mut match_start_interval_idx = 0;
            let mut start_timestamp = 0.0;
            for (i, (start, end, timestamp, _text)) in intervals.iter().enumerate().rev() {
                if from < *end && from >= *start {
                    // found the start interval
                    match_start_interval_idx = i;
                    start_timestamp = *timestamp;
                    break;
                }
            }
            let end_timestamp = current_line_timestamp;
            let num_intervals = intervals.len() - match_start_interval_idx;
            // Collect the text of the intervals that contain the match
            let interval_text = intervals[match_start_interval_idx..]
                .iter()
                .map(|(_s, _e, _ts, t)| t.to_owned())
                .collect::<Vec<String>>().join("");
            // Get a nice timestamp for each. Compute nsecs from the fractional part
            // of the timestamp
            let start_timestamp = Local.timestamp_opt(
                start_time as i64 + start_timestamp as i64,
                (start_timestamp.fract() * 1e9) as u32).unwrap();
            let end_timestamp = Local.timestamp_opt(
                start_time as i64 + end_timestamp as i64,
                (end_timestamp.fract() * 1e9) as u32).unwrap();

            println!("Match at [{},{}] spans {} interval{} from {} .. {}",
                from, to, num_intervals, if num_intervals == 1 {""} else {"s"},
                start_timestamp, end_timestamp);

            // Get the text of the line where the match occurs
            let match_line_start = interval_text[..(from as usize)]
                .rfind('\n').map(|i| i+1).unwrap_or(0);
            let match_line_end = interval_text[(to as usize)..]
                .find('\n').map(|i| i+to as usize).unwrap_or(interval_text.len());
            let match_line = &interval_text[match_line_start..match_line_end];
            println!("{}", match_line);

            Matching::Continue
        }).unwrap();
    }
}

fn main() {
    let args = Args::parse();

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

    let pattern = pattern! {
        args.pattern.clone();
        CompileFlags::SOM_LEFTMOST |
            if args.case_insensitive { CompileFlags::CASELESS } else { CompileFlags::empty() }
    };

    for file in &args.files {
        println!("{}:", file);
        search_file(&pattern, file.as_str(), &args);
    }
}
