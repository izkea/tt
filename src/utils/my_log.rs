extern crate log;
extern crate time;
extern crate colored;
use colored::*;

use log::{Log, Level,Metadata,Record,SetLoggerError};

struct SimpleLogger{
    level :Level
}

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_string = {
                match record.level() {
                    Level::Error => record.level().to_string().red(),
                    Level::Warn => record.level().to_string().yellow(),
                    Level::Info => record.level().to_string().white(),
                    Level::Debug => record.level().to_string().purple(),
                    Level::Trace => record.level().to_string().normal(),
                }
            };
            let target = if record.target().len() > 0 {
                record.target()
            } else {
                record.module_path().unwrap_or_default()
            };
            println!( "{} [{:<5}] [{}] {}",
//                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                time::now().strftime("%Y%m%d %T").unwrap().to_string(),
                level_string,
                target,
                record.args());
        }
    }

    fn flush(&self) {
    }
}

pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    log::set_boxed_logger(Box::new(SimpleLogger{ level }))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

#[allow(dead_code)]
pub fn init() -> Result<(), SetLoggerError> {
    init_with_level(Level::Trace)
}
