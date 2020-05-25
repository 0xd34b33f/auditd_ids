use audisp_ids::analyzer::*;
use audisp_ids::parser::parse_record;
use std::io::BufReader;
use std::io::{BufRead, Error};
use std::{io, process};

fn main() -> Result<(), Error> {
    SHELLS_SET.iter().for_each(|a| println!("{}", a));
    let _term = unsafe { signal_hook::register(signal_hook::SIGTERM, || process::exit(0)) }?;
    let _hup = unsafe { signal_hook::register(signal_hook::SIGHUP, || process::exit(0)) }?;
    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut tree = Tree::new();

    reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|line| parse_record(&line))
        .filter_map(|rec| rec)
        .map(|record| tree.insert_record(record))
        .map(|suspect| match suspect {
            ThreatType::FalsePositive => None,
            ThreatType::SuspectProcessInheritance(a) => Some(a),
        })
        .filter_map(|check_candidate| check_candidate)
        .for_each(|threat| println!("{:#?}", threat));
    Ok(())
}
