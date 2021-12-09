use libbpf_rs::{Map, MapFlags};
use std::net::{Ipv4Addr, Ipv6Addr};
use termion::{input::MouseTerminal, raw::RawTerminal, screen::AlternateScreen};
use tui::{
    backend::TermionBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Terminal,
};

use crate::{App, PeerV4, PeerV6, ValueType};

pub fn gen_v4_rows(v4_peers: &Map) -> Vec<Row> {
    v4_peers
        .keys()
        .map(|k| {
            let mut key = PeerV4::default();
            let mut value = ValueType::default();

            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = v4_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

            let kb_in = value.bytes_in / 1024;
            let mut bytes_in_str = format!("{} kiB", kb_in);
            if kb_in >= 1024 {
                bytes_in_str = format!("{:.2} MiB", kb_in as f32 / 1024f32);
            }

            if kb_in >= 1024 * 1024 {
                bytes_in_str = format!("{:.2} GiB", kb_in as f32 / 1024f32 / 1024f32);
            }

            let kb_out = value.bytes_out / 1024;
            let mut bytes_out_str = format!("{} kiB", kb_out);
            if kb_out >= 1024 {
                bytes_out_str = format!("{:.2} MiB", kb_out as f32 / 1024f32);
            }

            if kb_out >= 1024 * 1024 {
                bytes_out_str = format!("{:.2} GiB", kb_out as f32 / 1024f32 / 1024f32);
            }

            let entry = vec![
                Ipv4Addr::from(key.daddr).to_string(),
                key.dport.to_string(),
                bytes_in_str,
                bytes_out_str
            ];

            let cells = entry.iter().map(|c| Cell::from(c.clone()));
            Row::new(cells).height(1)
        })
        .collect()
}

pub fn gen_v6_rows(v6_peers: &Map) -> Vec<Row> {
    v6_peers
        .keys()
        .map(|k| {
            let mut key = PeerV6::default();
            let mut value = ValueType::default();

            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = v6_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

            let kb_in = value.bytes_in / 1024;
            let mut bytes_in_str = format!("{} kiB", kb_in);
            if kb_in >= 1024 {
                bytes_in_str = format!("{:.2} MiB", kb_in as f32 / 1024f32);
            }

            if kb_in >= 1024 * 1024 {
                bytes_in_str = format!("{:.2} GiB", kb_in as f32 / 1024f32 / 1024f32);
            }

            let kb_out = value.bytes_out / 1024;
            let mut bytes_out_str = format!("{} kiB", kb_out);
            if kb_out >= 1024 {
                bytes_out_str = format!("{:.2} MiB", kb_out as f32 / 1024f32);
            }

            if kb_out >= 1024 * 1024 {
                bytes_out_str = format!("{:.2} GiB", kb_out as f32 / 1024f32 / 1024f32);
            }

            let entry = vec![
                Ipv6Addr::from(key.daddr).to_string(),
                key.dport.to_string(),
                bytes_in_str,
                bytes_out_str
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
            .constraints([Constraint::Percentage(100)].as_ref())
            .margin(1)
            .split(f.size());

        let selected_style = Style::default().add_modifier(Modifier::REVERSED);
        let normal_style = Style::default().add_modifier(Modifier::BOLD);
        let header_cells = ["IP address", "Port", "in", "out"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells)
            .style(normal_style)
            .height(1)
            .bottom_margin(1);

        let mut rows = Vec::new();

        if let Some(v4_peers) = app.v4_peers {
            let mut v4_rows = gen_v4_rows(v4_peers);
            rows.append(&mut v4_rows);
        }

        if let Some(v6_peers) = app.v6_peers {
            let mut v6_rows = gen_v6_rows(v6_peers);
            rows.append(&mut v6_rows);
        }

        let t = Table::new(rows.into_iter())
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Peers"))
            .highlight_style(selected_style)
            // .highlight_symbol("* ")
            .widths(&[
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ]);
        f.render_stateful_widget(t, rects[0], &mut app.state);
    })?;

    Ok(())
}
