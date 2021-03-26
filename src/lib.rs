#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_safety_doc)]

mod config;
mod fluentd;
mod matcher;
mod producer;
mod report;
mod session;

use crate::config::{Config, InputType, OutputType};
use crate::fluentd::SizedForwardMode;
use crate::matcher::Matcher;
use crate::report::Report;
use crate::session::Traffic;
pub use producer::Kafka as KafkaProducer;
use rmp_serde::Serializer;
use serde::Serialize;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use std::time::Duration;

#[no_mangle]
pub extern "C" fn config_default() -> *const Config {
    let config = Config::default();
    Box::into_raw(Box::new(config))
}

#[no_mangle]
pub unsafe extern "C" fn config_new(
    arg_count: c_int,
    mut arg_values: *const *const i8,
) -> *const Config {
    #[allow(clippy::cast_sign_loss)] // argc in C++ is non-negative.
    let mut arg_count = arg_count as usize;
    let mut args = Vec::with_capacity(arg_count);
    while arg_count > 0 {
        let arg = match CStr::from_ptr(*arg_values).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null(),
        };
        args.push(arg);
        arg_count -= 1;
        arg_values = arg_values.add(1);
    }

    let config = config::parse(&args);
    Box::into_raw(Box::new(config))
}

#[no_mangle]
pub unsafe extern "C" fn config_free(ptr: *mut Config) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn config_show(ptr: *const Config) {
    let config = &*ptr;
    println!("{}", config);
}

#[no_mangle]
pub unsafe extern "C" fn config_count_sent(ptr: *const Config) -> usize {
    let config = &*ptr;
    config.count_sent
}

#[no_mangle]
pub unsafe extern "C" fn config_count_skip(ptr: *const Config) -> usize {
    let config = &*ptr;
    config.count_skip
}

#[no_mangle]
pub unsafe extern "C" fn config_datasource_id(ptr: *const Config) -> u8 {
    let config = &*ptr;
    config.datasource_id
}

#[no_mangle]
pub unsafe extern "C" fn config_entropy_ratio(ptr: *const Config) -> f64 {
    let config = &*ptr;
    config.entropy_ratio
}

#[no_mangle]
pub unsafe extern "C" fn config_file_prefix(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.file_prefix.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_initial_seq_no(ptr: *const Config) -> u32 {
    let config = &*ptr;
    config.initial_seq_no
}

#[no_mangle]
pub unsafe extern "C" fn config_input(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.input.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_set_input(ptr: *mut Config, input: *const c_char) {
    let config = &mut *ptr;
    config.input = CStr::from_ptr(input).into();
}

#[no_mangle]
pub unsafe extern "C" fn config_input_type(ptr: *const Config) -> c_int {
    let config = &*ptr;
    match config.input_type {
        InputType::Pcap => 0,
        InputType::PcapNg => 1,
        InputType::Nic => 2,
        InputType::Log => 3,
        InputType::Dir => 4,
    }
}

#[no_mangle]
pub unsafe extern "C" fn config_set_input_type(ptr: *mut Config, input_type: c_int) {
    let config = &mut *ptr;
    config.input_type = match input_type {
        0 => InputType::Pcap,
        1 => InputType::PcapNg,
        2 => InputType::Nic,
        3 => InputType::Log,
        4 => InputType::Dir,
        _ => panic!(),
    };
}

#[no_mangle]
pub unsafe extern "C" fn config_kafka_broker(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.kafka_broker.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_set_kafka_broker(ptr: *mut Config, output: *const c_char) {
    let config = &mut *ptr;
    config.kafka_broker = CStr::from_ptr(output).into();
}

#[no_mangle]
pub unsafe extern "C" fn config_kafka_conf(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.kafka_conf.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_kafka_topic(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.kafka_topic.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_set_kafka_topic(ptr: *mut Config, output: *const c_char) {
    let config = &mut *ptr;
    config.kafka_topic = CStr::from_ptr(output).into();
}

#[no_mangle]
pub unsafe extern "C" fn config_mode_eval(ptr: *const Config) -> usize {
    let config = &*ptr;
    if config.mode_eval {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn config_mode_grow(ptr: *const Config) -> usize {
    let config = &*ptr;
    if config.mode_grow {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn config_mode_polling_dir(ptr: *const Config) -> usize {
    let config = &*ptr;
    if config.mode_polling_dir {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn config_offset_prefix(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.offset_prefix.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_output(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.output.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_set_output(ptr: *mut Config, output: *const c_char) {
    let config = &mut *ptr;
    config.output = CStr::from_ptr(output).into();
}

#[no_mangle]
pub unsafe extern "C" fn config_output_type(ptr: *const Config) -> c_int {
    let config = &*ptr;
    match config.output_type {
        OutputType::None => 0,
        OutputType::Kafka => 1,
        OutputType::File => 2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn config_set_output_type(ptr: *mut Config, output_type: c_int) {
    let config = &mut *ptr;
    config.output_type = match output_type {
        0 => OutputType::None,
        1 => OutputType::Kafka,
        2 => OutputType::File,
        _ => panic!(),
    };
}

#[no_mangle]
pub unsafe extern "C" fn config_packet_filter(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.packet_filter.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_pattern_file(ptr: *const Config) -> *const c_char {
    let config = &*ptr;
    config.pattern_file.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn config_queue_period(ptr: *const Config) -> usize {
    let config = &*ptr;
    config.queue_period
}

#[no_mangle]
pub unsafe extern "C" fn config_set_queue_period(ptr: *mut Config, period: usize) {
    let config = &mut *ptr;
    config.queue_period = period;
}

#[no_mangle]
pub unsafe extern "C" fn config_queue_size(ptr: *const Config) -> usize {
    let config = &*ptr;
    config.queue_size
}

#[no_mangle]
pub unsafe extern "C" fn config_set_queue_size(ptr: *mut Config, size: usize) {
    let config = &mut *ptr;
    config.queue_size = size;
}

#[no_mangle]
pub extern "C" fn forward_mode_new() -> *mut SizedForwardMode {
    Box::into_raw(Box::new(SizedForwardMode::default()))
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_free(ptr: *mut SizedForwardMode) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_size(ptr: *const SizedForwardMode) -> usize {
    assert!(!ptr.is_null());
    let forward_mode = &*ptr;
    forward_mode.len()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_serialized_len(ptr: *const SizedForwardMode) -> usize {
    assert!(!ptr.is_null());
    let forward_mode = &*ptr;
    forward_mode.serialized_len()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_set_tag(
    ptr: *mut SizedForwardMode,
    ctag: *const c_char,
) -> bool {
    assert!(!ptr.is_null());
    let forward_mode = &mut *ptr;
    assert!(!ctag.is_null());
    let ctag = CStr::from_ptr(ctag);
    let rstag = match ctag.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    forward_mode.set_tag(rstag.to_string()).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_append_raw(
    ptr: *mut SizedForwardMode,
    time: u64,
    key: *const c_char,
    value: *const u8,
    len: usize,
) -> bool {
    assert!(!ptr.is_null());
    let forward_mode = &mut *ptr;
    assert!(!key.is_null());
    let c_key = CStr::from_ptr(key);
    let rs_key = match c_key.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    assert!(!value.is_null());
    let value = slice::from_raw_parts(value, len);
    forward_mode.push_raw(time, rs_key, value).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_append_packet(
    ptr: *mut SizedForwardMode,
    time: u64,
    key: *const c_char,
    payload: *const u8,
    len: usize,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
) -> bool {
    assert!(!ptr.is_null());
    let forward_mode = &mut *ptr;
    assert!(!key.is_null());
    let c_key = CStr::from_ptr(key);
    let rs_key = match c_key.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    assert!(!payload.is_null());
    let payload = slice::from_raw_parts(payload, len);
    forward_mode
        .push_packet(
            time, rs_key, payload, src_ip, dst_ip, src_port, dst_port, proto,
        )
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_add_option(
    ptr: *mut SizedForwardMode,
    key: *const c_char,
    value: *const c_char,
) -> bool {
    assert!(!ptr.is_null());
    let forward_mode = &mut *ptr;
    assert!(!key.is_null());
    let c_key = CStr::from_ptr(key);
    let rs_key = match c_key.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    assert!(!value.is_null());
    let c_value = CStr::from_ptr(value);
    let rs_value = match c_value.to_str() {
        Ok(v) => v,
        Err(_) => return false,
    };
    forward_mode.push_option(rs_key, rs_value).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_clear(ptr: *mut SizedForwardMode) {
    assert!(!ptr.is_null());
    let forward_mode = &mut *ptr;
    forward_mode.clear();
}

#[no_mangle]
pub unsafe extern "C" fn forward_mode_serialize(
    ptr: *const SizedForwardMode,
    buf: *mut Vec<u8>,
) -> bool {
    assert!(!ptr.is_null());
    let forward_mode = &*ptr;
    assert!(!buf.is_null());
    let buf = &mut *buf;
    buf.clear();
    forward_mode
        .message
        .serialize(&mut Serializer::new(buf))
        .is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn kafka_producer_new(
    broker: *const c_char,
    topic: *const c_char,
    idle_timeout_ms: u32,
    ack_timeout_ms: u32,
) -> *mut KafkaProducer {
    let topic = match CStr::from_ptr(topic).to_str() {
        Ok(topic) => topic,
        Err(_) => return ptr::null_mut(),
    };
    let idle_timeout = Duration::new(
        (idle_timeout_ms / 1_000).into(),
        idle_timeout_ms % 1_000 * 1_000_000,
    );
    let ack_timeout = Duration::new(
        (ack_timeout_ms / 1_000).into(),
        ack_timeout_ms % 1_000 * 1_000_000,
    );
    let producer = match CStr::from_ptr(broker).to_str() {
        Ok(broker) => match KafkaProducer::new(broker, topic, idle_timeout, ack_timeout) {
            Ok(producer) => producer,
            Err(_) => return ptr::null_mut(),
        },
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new(producer))
}

#[no_mangle]
pub unsafe extern "C" fn kafka_producer_free(ptr: *mut KafkaProducer) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn kafka_producer_send(
    ptr: *mut KafkaProducer,
    msg: *const u8,
    len: usize,
) -> usize {
    let producer = &mut *ptr;
    if producer.send(slice::from_raw_parts(msg, len)).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn matcher_new(filename_ptr: *const c_char) -> *mut Matcher {
    let c_filename = CStr::from_ptr(filename_ptr);
    let filename = match c_filename.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let matcher = match Matcher::with_file(filename) {
        Ok(m) => m,
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new(matcher))
}

#[no_mangle]
pub unsafe extern "C" fn matcher_free(ptr: *mut Matcher) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn matcher_match(ptr: *mut Matcher, data: *const u8, len: usize) -> usize {
    let matcher = &mut *ptr;
    if matcher
        .scan(slice::from_raw_parts(data, len))
        .unwrap_or_default()
    {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn report_new(config: *const Config) -> *mut Report {
    Box::into_raw(Box::new(Report::new(config)))
}

#[no_mangle]
pub unsafe extern "C" fn report_free(ptr: *mut Report) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn report_start(ptr: *mut Report, id: u32) {
    let report = &mut *ptr;
    report.start(id)
}

#[no_mangle]
pub unsafe extern "C" fn report_process(ptr: *mut Report, bytes: usize) {
    let report = &mut *ptr;
    report.process(bytes)
}

#[no_mangle]
pub unsafe extern "C" fn report_skip(ptr: *mut Report, bytes: usize) {
    let report = &mut *ptr;
    report.skip(bytes)
}

#[no_mangle]
pub unsafe extern "C" fn report_end(ptr: *mut Report, id: u32) {
    let report = &mut *ptr;
    if report.end(id).is_err() {}
}

#[no_mangle]
pub extern "C" fn serialization_buffer_new() -> *mut Vec<u8> {
    Box::into_raw(Box::new(Vec::new()))
}

#[no_mangle]
pub unsafe extern "C" fn serialization_buffer_free(ptr: *mut Vec<u8>) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn serialization_buffer_data(buf: *const Vec<u8>) -> *const u8 {
    assert!(!buf.is_null());
    let buf = &*buf;
    buf.as_slice().as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn serialization_buffer_len(buf: *const Vec<u8>) -> usize {
    assert!(!buf.is_null());
    let buf = &*buf;
    buf.len()
}

#[no_mangle]
pub extern "C" fn traffic_new() -> *mut Traffic {
    Box::into_raw(Box::new(Traffic::default()))
}

#[no_mangle]
pub unsafe extern "C" fn traffic_free(ptr: *mut Traffic) {
    if ptr.is_null() {
        return;
    }
    Box::from_raw(ptr);
}

#[no_mangle]
pub unsafe extern "C" fn traffic_data_len(ptr: *const Traffic) -> usize {
    let traffic = &*ptr;
    traffic.data_len()
}

#[no_mangle]
pub unsafe extern "C" fn traffic_make_next_message(
    ptr: *mut Traffic,
    event_id: u64,
    msg: *mut SizedForwardMode,
    max_len: usize,
) -> u64 {
    let traffic = &mut *ptr;
    let msg = &mut *msg;
    traffic.make_next_message(event_id, msg, max_len)
}

#[no_mangle]
pub unsafe extern "C" fn traffic_session_count(ptr: *const Traffic) -> usize {
    let traffic = &*ptr;
    traffic.session_count()
}

#[no_mangle]
pub unsafe extern "C" fn traffic_set_entropy_ratio(ptr: *mut Traffic, ratio: f64) {
    let traffic = &mut *ptr;
    traffic.set_entropy_ratio(ratio);
}

#[no_mangle]
pub unsafe extern "C" fn traffic_update_session(
    ptr: *mut Traffic,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    data: *const u8,
    len: usize,
    event_id: u64,
) -> usize {
    let traffic = &mut *ptr;
    let data = slice::from_raw_parts(data, len);
    if traffic.update_session(
        src_addr, dst_addr, src_port, dst_port, proto, data, event_id,
    ) {
        1
    } else {
        0
    }
}
