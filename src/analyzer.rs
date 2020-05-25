use crate::analyzer::ThreatType::{FalsePositive, SuspectProcessInheritance};
use crate::parser::AuditRecord;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct Tree {
    pub pid_map: HashMap<u32, u32>,
    pub add_info: HashMap<u32, AddInfo>,
}

pub struct AddInfo {
    pub uid: u32,
    pub auid: u32,
    pub exe_path: String,
    pub audit_id: u64,
}

pub enum ThreatType {
    FalsePositive,
    SuspectProcessInheritance(AuditRecord),
}

impl Default for Tree {
    fn default() -> Self {
        Tree {
            pid_map: HashMap::new(),
            add_info: HashMap::new(),
        }
    }
}

fn get_installed_shells() -> std::io::Result<HashSet<String>> {
    let shells_file = File::open("/etc/shells")?;
    let reader = BufReader::new(shells_file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.starts_with('#'))
        .filter(|line| !line.is_empty())
        .map(|line| line.trim().to_string())
        .collect())
}

lazy_static! {
    pub static ref SHELLS_SET: HashSet<String> = match get_installed_shells() {
        Ok(a) => a,
        Err(e) => {
            println!("{}", e);
            vec!["bash", "sh", "zsh"]
                .into_iter()
                .map(|a| a.to_string())
                .collect()
        }
    };
}
impl Tree {
    pub fn new() -> Self {
        Tree {
            pid_map: HashMap::new(),
            add_info: HashMap::new(),
        }
    }
    fn (c)
    fn check_command(&self, record: &AuditRecord) -> ThreatType {
        let grand_parent = match self.pid_map.get(&record.ppid) {
            Some(a) => a,
            None => return FalsePositive,
        };
        let parent_exe = &self.add_info[grand_parent].exe_path;
        if SHELLS_SET.contains(parent_exe) {
            return FalsePositive;
        }
        if SHELLS_SET.contains(&record.exe_path) {
            return SuspectProcessInheritance(record.clone());
        }
        FalsePositive
    }
    pub fn insert_record(&mut self, record: AuditRecord) -> ThreatType {
        let result_of_check = self.check_command(&record);
        self.pid_map.insert(record.pid, record.ppid);
        self.add_info.insert(
            record.pid,
            AddInfo {
                uid: record.uid,
                auid: record.auid,
                exe_path: record.exe_path,
                audit_id: record.audit_id,
            },
        );
        result_of_check
    }
}
