mod fields;
mod packet;
mod statistics;
mod templates;

use anyhow::{bail, Result};
use chrono::DateTime;
use giganto_client::ingest::netflow::{Netflow5, Netflow9};
#[allow(clippy::module_name_repetitions)]
pub(super) use packet::{NetflowHeader, PktBuf};
pub(super) use statistics::{ProcessStats, Stats};
pub(super) use templates::TemplatesBox;
use tracing::{error, warn};

pub(super) trait ParseNetflowDatasets: Sized {
    fn parse_netflow_datasets(
        pkt_cnt: u64,
        templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>>;
}

impl ParseNetflowDatasets for Netflow5 {
    fn parse_netflow_datasets(
        _pkt_cnt: u64,
        _templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>> {
        let NetflowHeader::V5(header) = header else {
            bail!("invalid netflow v5 header");
        };
        let mut events = vec![];
        if let Ok(values) = input.parse_netflow_v5_datasets(header) {
            for v5 in values {
                events.push((
                    DateTime::from_timestamp(i64::from(header.unix_secs), *nanos)
                        .map_or(0, |t| t.timestamp_nanos_opt().unwrap_or_default()),
                    v5,
                ));
                *nanos += 1;
            }
            stats.add(ProcessStats::Events, usize::from(header.count));
        } else {
            stats.add(ProcessStats::InvalidNetflowPackets, 1);
            bail!("invalid netflow v5 pcap");
        }
        Ok(events)
    }
}

impl ParseNetflowDatasets for Netflow9 {
    fn parse_netflow_datasets(
        pkt_cnt: u64,
        templates: &mut TemplatesBox,
        header: &NetflowHeader,
        nanos: &mut u32,
        input: &mut PktBuf,
        stats: &mut Stats,
    ) -> Result<Vec<(i64, Self)>> {
        let NetflowHeader::V9(header) = header else {
            bail!("invalid netflow v9 header");
        };
        let Ok((flowset_id, flowset_length)) = input.parse_netflow_v9_flowset_header() else {
            stats.add(ProcessStats::InvalidNetflowPackets, 1);
            bail!("invalid netflow v9 pcap");
        };

        let mut events = vec![];
        match flowset_id {
            // Template
            0 => {
                let mut template_count = 0;
                for _i in 0..header.count {
                    let Ok(fds) = input.parse_netflow_template(flowset_length, header) else {
                        break;
                    };
                    templates.add(pkt_cnt, input.src_addr(), &fds);
                    template_count += fds.len();
                }
                stats.add(ProcessStats::V9Templates, template_count);
            }
            // Options Template
            1 => {
                let mut template_count = 0;
                for _i in 0..header.count {
                    let Ok(fds) = input.parse_netflow_options_template(flowset_length, header)
                    else {
                        break;
                    };
                    templates.add(pkt_cnt, input.src_addr(), &fds);
                    template_count += fds.len();
                }
                stats.add(ProcessStats::V9OptionsTemplate, template_count);
            }
            // Reserved flowset id
            2..=255 => {
                warn!(
                    "packet #{}: NETFLOW V9 reserved Flowset ID found!!",
                    pkt_cnt
                );
                stats.add(ProcessStats::ReservedFlowsetIDUsed, 1);
            }
            // Dataset
            _ => {
                let flow_key = (input.src_addr(), header.source_id, flowset_id);
                if let Some(template) = templates.get(&flow_key) {
                    let flows = input.parse_netflow_v9_datasets(template, header, flowset_id);
                    for v9 in flows {
                        events.push((
                            DateTime::from_timestamp(i64::from(header.unix_secs), *nanos)
                                .map_or(0, |t| t.timestamp_nanos_opt().unwrap_or_default()),
                            v9,
                        ));
                        *nanos += 1;
                    }
                    stats.add(ProcessStats::Events, usize::from(header.count));
                } else {
                    error!("no template for flow key ({:?})", flow_key);
                    stats.add(ProcessStats::TemplateNotFound, 1);
                }
            }
        }
        Ok(events)
    }
}
