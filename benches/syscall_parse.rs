use audisp_ids::parser::parse_record;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
static DATA: &str = r##"type=SYSCALL msg=audit(1579395661.252:1103007): arch=c000003e syscall=59 success=yes exit=0 a0=7f79fb7fd3cd a1=7ffe55183980 a2=7f79fba00388 a3=2 items=2 ppid=10649 pid=10650 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="unix_chkpwd" exe="/usr/sbin/unix_chkpwd" subj=system_u:system_r:chkpwd_t:s0-s0:c0.c1023 key="rootcmd""##;
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("parse_syscall", |b| {
        b.iter(|| parse_record(black_box(DATA)))
    });
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
