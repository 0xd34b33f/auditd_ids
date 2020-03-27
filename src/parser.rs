
	use nom::bytes::complete::{tag, take, take_until, is_not, take_while};
	use nom::multi::count;
	use nom::IResult;
	use nom::character::{is_digit, is_space};
	
	
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
	
	fn get_status(i: &str) -> IResult<&str, &str> {
		get_after_equals(i)
	}
	
	
	fn get_after_equals(i: &str) -> IResult<&str, &str> {
		let (unparsed, _) = take_until("=")(i)?;
		let (unparsed, _) = take(1usize)(unparsed)?;
		take_while(|x: char| !is_space(x as u8))(unparsed)
	}
	fn get_ppid(i: &str)->IResult<&str, &str>{
		let (unparsed, _) = take_until("ppid")(i)?;
		dbg!(get_after_equals(unparsed))
	}
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
			Err(_) => return None
		};
		let  (unparsed, status) = match get_status(unparsed){
			Ok((unparsed, data))=>{
				let status =match data {
					"yes"=>true,
					"no"=>false,
					_=>false
				};
				(unparsed,status)
			},
			Err(e)=>{
				println!("{}", e);
				return None
			}
		};
		let (unparsed, ppid) = match get_ppid(unparsed) {
			Ok((unparsed, data)) => match data.parse::<u32>(){
				Ok(b)=>(unparsed, b),
				Err(e)=>{
					println!("{}:{}", e, data);
					return None
				}
			},
			Err(e) =>
				{
					println!("{}", e);
					return None;
				}
			
		};
		let (unparsed, pid) = match get_after_equals(i){
			Ok((unparsed, pid))=>{
				let pid = match pid.parse::<u32>(){
					Ok(a)=>a,
					Err(e)=>{
						println!("{}",e);
						return None;
					}
				};
				(unparsed, pid)
			},
			Err(e)=>{
				println!("{}",e);
				return None;
			}
		};
		dbg!(unparsed);
		None
	}