use chrono::Utc;
use tracing_core::field::{Field, Visit};
use tracing_core::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::{FmtContext, FormatEvent};
use tracing_subscriber::registry::LookupSpan;

pub struct OmniTimer;

impl tracing_subscriber::fmt::time::FormatTime for OmniTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00"))
    }
}

pub struct OmniFormatter;

struct OmniVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
    fatal: bool,
}

impl Visit for OmniVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let v = format!("{:?}", value);
        match field.name() {
            "message" => self.message = Some(v),
            "fatal" => self.fatal = v == "true",
            name => self.fields.push((name.to_string(), v)),
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = Some(value.to_string()),
            "fatal" => self.fatal = value == "true",
            name => self.fields.push((name.to_string(), quote(value))),
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        match field.name() {
            "fatal" => self.fatal = value,
            name => self.fields.push((name.to_string(), value.to_string())),
        }
    }
}

fn quote(s: &str) -> String {
    s.to_string()
}

impl<S, N> FormatEvent<S, N> for OmniFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let mut buf = String::new();
        {
            let mut timer_writer = Writer::new(&mut buf);
            OmniTimer.format_time(&mut timer_writer)?;
        }

        let mut visitor = OmniVisitor {
            message: None,
            fields: Vec::new(),
            fatal: false,
        };
        event.record(&mut visitor);

        let level = if visitor.fatal {
            "FATAL"
        } else {
            match *event.metadata().level() {
                Level::ERROR => "ERROR",
                Level::WARN => "WARN",
                Level::INFO => "INFO",
                Level::DEBUG => "DEBUG",
                Level::TRACE => "TRACE",
            }
        };

        write!(writer, "{} {} {}: ", buf, level, event.metadata().target())?;
        if let Some(msg) = &visitor.message {
            write!(writer, "{}", msg)?;
        }
        for (k, v) in &visitor.fields {
            write!(writer, " {}={}", k, v)?;
        }
        writeln!(writer)
    }
}
