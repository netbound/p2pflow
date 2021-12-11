use libbpf_rs::{Map, MapFlags};
use std::net::{Ipv4Addr, Ipv6Addr};
use termion::{input::MouseTerminal, raw::RawTerminal, screen::AlternateScreen};
use tui::{
    backend::TermionBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

use crate::{net::Resolver, App, PeerV4, PeerV6, ValueType};

fn gen_v4_rows<'a>(v4_peers: &'a Map, resolver: &Resolver) -> Vec<Row<'a>> {
    v4_peers
        .keys()
        .map(|k| {
            let mut key = PeerV4::default();
            let mut value = ValueType::default();

            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = v4_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

            let kb_in = value.bytes_in / 1024;
            let bytes_in_str = gen_bytes_str(kb_in);
            let kb_out = value.bytes_out / 1024;
            let bytes_out_str = gen_bytes_str(kb_out);

            let ip = Ipv4Addr::from(key.daddr.to_be());

            let entry = vec![
                format!("{}:{}", ip.to_string(), key.dport.to_string()),
                resolver.resolve_ip(ip.into()),
                bytes_in_str,
                bytes_out_str,
            ];

            let cells = entry.iter().map(|c| Cell::from(c.clone()));
            Row::new(cells).height(1)
        })
        .collect()
}

fn gen_v6_rows<'a>(v6_peers: &'a Map, resolver: &Resolver) -> Vec<Row<'a>> {
    v6_peers
        .keys()
        .map(|k| {
            let mut key = PeerV6::default();
            let mut value = ValueType::default();

            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = v6_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

            let kb_in = value.bytes_in / 1024;
            let bytes_in_str = gen_bytes_str(kb_in);

            let kb_out = value.bytes_out / 1024;
            let bytes_out_str = gen_bytes_str(kb_out);

            let ipv6 = Ipv6Addr::from(key.daddr.to_be());
            let ip = ipv6.to_ipv4().unwrap();

            let entry = vec![
                format!("{}:{}", ip.to_string(), key.dport.to_string()),
                resolver.resolve_ip(ip.into()),
                bytes_in_str,
                bytes_out_str,
            ];

            let cells = entry.iter().map(|c| Cell::from(c.clone()));
            Row::new(cells).height(1)
        })
        .collect()
}

pub fn draw_terminal(
    terminal: &mut Terminal<
        TermionBackend<AlternateScreen<MouseTerminal<RawTerminal<std::io::Stdout>>>>,
    >,
    app: &mut App,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let rects = Layout::default()
            .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
            .margin(1)
            .split(f.size());

        let selected_style = Style::default().add_modifier(Modifier::REVERSED);
        let normal_style = Style::default().add_modifier(Modifier::BOLD);
        let header_cells = ["Peer", "Name", "Total received", "Total sent"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells)
            .style(normal_style)
            .height(1)
            .bottom_margin(1);

        let mut rows = Vec::new();

        if let Some(v4_peers) = app.v4_peers {
            let mut v4_rows = gen_v4_rows(v4_peers, &app.resolver);
            rows.append(&mut v4_rows);
        }

        if let Some(v6_peers) = app.v6_peers {
            let mut v6_rows = gen_v6_rows(v6_peers, &app.resolver);
            rows.append(&mut v6_rows);
        }

        let peer_count = rows.len();

        let header_text = Span::styled(
            format!("Process: {} [{} peers]", app.process_name, peer_count),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let header_paragraph = Paragraph::new(header_text).alignment(Alignment::Left);

        let t = Table::new(rows.into_iter())
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Peer utilization"),
            )
            .highlight_style(selected_style)
            // .highlight_symbol("* ")
            .widths(&[
                Constraint::Percentage(20),
                Constraint::Percentage(40),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ]);

        f.render_widget(header_paragraph, rects[0]);
        f.render_stateful_widget(t, rects[1], &mut app.state);
    })?;

    Ok(())
}
// }

pub fn gen_bytes_str(kb: u64) -> String {
    let mut bytes_str = format!("{} kiB", kb);
    if kb >= 1024 {
        bytes_str = format!("{:.2} MiB", kb as f32 / 1024f32);
    }

    if kb >= 1024 * 1024 {
        bytes_str = format!("{:.2} GiB", kb as f32 / 1024f32 / 1024f32);
    }

    bytes_str
}
