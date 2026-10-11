use clap::{Parser, ValueEnum};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "List Windows processes or inspect and compare CSV snapshots"
)]
struct Args {
    #[arg(
        long,
        value_name = "FILE",
        help = "Read a CSV snapshot instead of live processes"
    )]
    input: Option<PathBuf>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Compare an earlier CSV snapshot with the current snapshot"
    )]
    compare: Option<PathBuf>,
    #[arg(long, help = "Keep only this exact PID")]
    pid: Option<u32>,
    #[arg(
        long,
        value_name = "PATTERN",
        help = "Filter image names without case sensitivity; * and ? are wildcards"
    )]
    image: Option<String>,
    #[arg(
        long,
        value_enum,
        default_value = "table",
        help = "Choose the output format; unavailable working sets are empty in CSV"
    )]
    format: Format,
    #[arg(
        long,
        value_enum,
        default_value = "pid",
        help = "Sort ascending, with unavailable working sets last and PID as a tie-breaker"
    )]
    sort: Sort,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
enum Sort {
    Pid,
    Image,
    WorkingSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Process {
    image: String,
    pid: u32,
    working_set: Option<u64>,
}

fn csv_records(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut state = 0;
    let mut pending = false;
    while let Some(ch) = chars.next() {
        pending = true;
        if state == 2 {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    state = 3;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            ',' => {
                fields.push(std::mem::take(&mut field));
                state = 0;
            }
            '\n' | '\r' => {
                if ch == '\r' && chars.next() != Some('\n') {
                    return Err(format!(
                        "CSV record {}: expected a newline after carriage return",
                        records.len() + 1
                    ));
                }
                fields.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut fields));
                state = 0;
                pending = false;
            }
            '"' if state == 0 => state = 2,
            _ if state == 3 || ch == '"' => {
                return Err(format!(
                    "CSV record {}: unexpected character outside a quoted field",
                    records.len() + 1
                ));
            }
            _ => {
                field.push(ch);
                state = 1;
            }
        }
    }
    if state == 2 {
        return Err(format!(
            "CSV record {}: unterminated quoted field",
            records.len() + 1
        ));
    }
    if pending {
        fields.push(field);
        records.push(fields);
    }
    Ok(records)
}

fn parse_snapshot(input: &str) -> Result<Vec<Process>, String> {
    let records = csv_records(input)?;
    let expected = ["image_name", "pid", "working_set_bytes"];
    if records
        .first()
        .map(|row| row.iter().map(String::as_str).collect::<Vec<_>>())
        != Some(expected.to_vec())
    {
        return Err("expected CSV header image_name,pid,working_set_bytes".into());
    }
    let mut processes = Vec::new();
    let mut pids = HashSet::new();
    for (index, row) in records.into_iter().enumerate().skip(1) {
        let record = index + 1;
        if row.len() != 3 {
            return Err(format!(
                "CSV record {record}: expected 3 fields, found {}",
                row.len()
            ));
        }
        if row[0].is_empty() {
            return Err(format!("CSV record {record}: image name is empty"));
        }
        let pid = parse_number::<u32>(&row[1], record, "PID")?;
        if !pids.insert(pid) {
            return Err(format!("CSV record {record}: duplicate PID {pid}"));
        }
        let working_set = if row[2].is_empty() {
            None
        } else {
            Some(parse_number::<u64>(&row[2], record, "working set size")?)
        };
        processes.push(Process {
            image: row[0].clone(),
            pid,
            working_set,
        });
    }
    Ok(processes)
}

fn parse_number<T: std::str::FromStr>(
    value: &str,
    record: usize,
    label: &str,
) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("CSV record {record}: invalid {label} {value:?}"));
    }
    value
        .parse()
        .map_err(|_| format!("CSV record {record}: invalid {label} {value:?}"))
}

fn read_snapshot(path: &Path) -> Result<Vec<Process>, String> {
    let input = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse_snapshot(&input).map_err(|error| format!("{}: {error}", path.display()))
}

fn image_matches(pattern: &str, image: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let image: Vec<char> = image.to_lowercase().chars().collect();
    let (mut p, mut i) = (0, 0);
    let mut star = None;
    let mut retry = 0;
    while i < image.len() {
        if p < pattern.len() && (pattern[p] == '?' || (pattern[p] != '*' && pattern[p] == image[i]))
        {
            p += 1;
            i += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = i;
        } else if let Some(position) = star {
            retry += 1;
            i = retry;
            p = position + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn changes<'a>(earlier: &'a [Process], current: &'a [Process]) -> Vec<(&'static str, &'a Process)> {
    let old: HashMap<_, _> = earlier
        .iter()
        .map(|process| (process.pid, process.image.to_lowercase()))
        .collect();
    let new: HashMap<_, _> = current
        .iter()
        .map(|process| (process.pid, process.image.to_lowercase()))
        .collect();
    let mut rows = Vec::new();
    for (label, source, other) in [("stopped", earlier, &new), ("started", current, &old)] {
        for process in source {
            if other.get(&process.pid) != Some(&process.image.to_lowercase()) {
                rows.push((label, process));
            }
        }
    }
    rows
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into()
    }
}

fn render(args: &Args, current: &[Process], earlier: Option<&[Process]>) -> String {
    let mut rows = if let Some(earlier) = earlier {
        changes(earlier, current)
    } else {
        current.iter().map(|process| ("", process)).collect()
    };
    rows.retain(|(_, process)| {
        args.pid.is_none_or(|pid| process.pid == pid)
            && args
                .image
                .as_ref()
                .is_none_or(|pattern| image_matches(pattern, &process.image))
    });
    rows.sort_by(|(a_label, a), (b_label, b)| {
        let order = match args.sort {
            Sort::Pid => a.pid.cmp(&b.pid),
            Sort::Image => a.image.to_lowercase().cmp(&b.image.to_lowercase()),
            Sort::WorkingSet => a
                .working_set
                .is_none()
                .cmp(&b.working_set.is_none())
                .then(a.working_set.cmp(&b.working_set)),
        };
        order
            .then(a.pid.cmp(&b.pid))
            .then(a.image.cmp(&b.image))
            .then(a_label.cmp(b_label))
    });
    let comparison = earlier.is_some();
    let mut output = String::new();
    match args.format {
        Format::Csv => {
            if comparison {
                output.push_str("change,");
            }
            output.push_str("image_name,pid,working_set_bytes\n");
            for (label, process) in rows {
                if comparison {
                    let _ = write!(output, "{label},");
                }
                let size = process
                    .working_set
                    .map(|size| size.to_string())
                    .unwrap_or_default();
                let _ = writeln!(
                    output,
                    "{},{},{size}",
                    csv_field(&process.image),
                    process.pid
                );
            }
        }
        Format::Table => {
            let names: Vec<_> = rows
                .iter()
                .map(|(_, process)| process.image.escape_default().to_string())
                .collect();
            let width = names.iter().map(String::len).max().unwrap_or(0).max(10);
            if comparison {
                output.push_str("Change   ");
            }
            let _ = writeln!(
                output,
                "{:<width$} {:>10} {:>17}",
                "Image name", "PID", "Working set bytes"
            );
            for ((label, process), name) in rows.into_iter().zip(names) {
                if comparison {
                    let _ = write!(output, "{label:<8} ");
                }
                let size = process
                    .working_set
                    .map(|size| size.to_string())
                    .unwrap_or_else(|| "unavailable".into());
                let _ = writeln!(output, "{name:<width$} {:>10} {size:>17}", process.pid);
            }
        }
    }
    output
}

#[cfg(not(windows))]
fn live_snapshot() -> Result<Vec<Process>, String> {
    Err(
        "live process enumeration is only available on Windows; use --input with a CSV snapshot"
            .into(),
    )
}

#[cfg(windows)]
mod windows {
    use super::Process;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};

    type Handle = *mut c_void;

    #[repr(C)]
    struct ProcessEntry {
        size: u32,
        usage: u32,
        pid: u32,
        heap: usize,
        module: u32,
        threads: u32,
        parent_pid: u32,
        priority: i32,
        flags: u32,
        image: [u16; 260],
    }

    #[repr(C)]
    struct MemoryCounters {
        size: u32,
        page_faults: u32,
        peak_working_set: usize,
        working_set: usize,
        peak_paged_pool: usize,
        paged_pool: usize,
        peak_nonpaged_pool: usize,
        nonpaged_pool: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn K32GetProcessMemoryInfo(
            process: Handle,
            counters: *mut MemoryCounters,
            size: u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct OwnedHandle(Handle);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn working_set(pid: u32) -> Option<u64> {
        unsafe {
            let handle = OpenProcess(0x0400 | 0x0010, 0, pid);
            if handle.is_null() {
                return None;
            }
            let handle = OwnedHandle(handle);
            let mut counters: MemoryCounters = zeroed();
            counters.size = size_of::<MemoryCounters>() as u32;
            if K32GetProcessMemoryInfo(handle.0, &mut counters, size_of::<MemoryCounters>() as u32)
                == 0
            {
                None
            } else {
                Some(counters.working_set as u64)
            }
        }
    }

    pub fn snapshot() -> Result<Vec<Process>, String> {
        unsafe {
            let handle = CreateToolhelp32Snapshot(0x00000002, 0);
            if handle == -1isize as Handle {
                return Err(format!(
                    "cannot enumerate processes: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let handle = OwnedHandle(handle);
            let mut entry: ProcessEntry = zeroed();
            entry.size = size_of::<ProcessEntry>() as u32;
            let mut success = Process32FirstW(handle.0, &mut entry);
            let mut processes = Vec::new();
            while success != 0 {
                let length = entry
                    .image
                    .iter()
                    .position(|&ch| ch == 0)
                    .unwrap_or(entry.image.len());
                let image = if length == 0 {
                    "unavailable".into()
                } else {
                    String::from_utf16_lossy(&entry.image[..length])
                };
                processes.push(Process {
                    image,
                    pid: entry.pid,
                    working_set: working_set(entry.pid),
                });
                success = Process32NextW(handle.0, &mut entry);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(18) {
                return Err(format!("cannot enumerate processes: {error}"));
            }
            Ok(processes)
        }
    }
}

#[cfg(windows)]
fn live_snapshot() -> Result<Vec<Process>, String> {
    windows::snapshot()
}

fn run(args: Args) -> Result<(), String> {
    let current = match &args.input {
        Some(path) => read_snapshot(path)?,
        None => live_snapshot()?,
    };
    let earlier = args.compare.as_deref().map(read_snapshot).transpose()?;
    let output = render(&args, &current, earlier.as_deref());
    match io::stdout().lock().write_all(output.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(format!("cannot write output: {error}")),
    }
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "image_name,pid,working_set_bytes\n";

    #[test]
    fn quoted_csv_round_trips_with_unavailable_details() {
        let input = format!("{HEADER}\"a,\"\"b\n.exe\",42,\r\nplain.exe,7,100\r\n");
        let processes = parse_snapshot(&input).unwrap();
        assert_eq!(processes[0].image, "a,\"b\n.exe");
        assert_eq!(processes[0].working_set, None);
        let args = Args::parse_from(["tasklist", "--format", "csv", "--sort", "pid"]);
        let output = render(&args, &processes, None);
        let parsed = parse_snapshot(&output).unwrap();
        assert_eq!(parsed[0], processes[1]);
        assert_eq!(parsed[1], processes[0]);
    }

    #[test]
    fn malformed_snapshots_are_rejected() {
        for row in [
            "a.exe,invalid,2",
            "a.exe,1,-2",
            "a.exe,1,18446744073709551616",
            "a.exe,4294967296,2",
            "a.exe,1,2,3",
            "a.exe,1",
            "a.exe,1,2\na.exe,1,3",
            "\"a.exe,1,2",
            "a\".exe,1,2",
            "\"a.exe\"x,1,2",
            ",1,2",
            "a.exe,,2",
        ] {
            assert!(parse_snapshot(&format!("{HEADER}{row}")).is_err(), "{row}");
        }
        assert!(parse_snapshot("pid,image_name,working_set_bytes\n").is_err());
        assert!(parse_snapshot("").is_err());
        assert!(parse_snapshot(HEADER).unwrap().is_empty());
    }

    #[test]
    fn wildcard_filters_are_case_insensitive_and_match_whole_names() {
        assert!(image_matches("*PAD.?XE", "Notepad.exe"));
        assert!(image_matches("a**?*c", "abbc"));
        assert!(image_matches("*a", "*ba"));
        assert!(!image_matches("pad", "notepad.exe"));
        assert!(!image_matches("a?c", "ac"));
        assert!(image_matches("*", ""));
    }

    #[test]
    fn comparisons_detect_reused_pids_and_ignore_memory_changes() {
        let earlier = parse_snapshot(&format!("{HEADER}old.exe,1,10\nstable.exe,2,20\n")).unwrap();
        let current = parse_snapshot(&format!(
            "{HEADER}new.exe,1,30\nSTABLE.EXE,2,40\nextra.exe,3,50\n"
        ))
        .unwrap();
        let rows = changes(&earlier, &current);
        assert_eq!(
            rows.iter()
                .map(|(label, process)| (*label, process.pid))
                .collect::<Vec<_>>(),
            [("stopped", 1), ("started", 1), ("started", 3)]
        );
    }
}
