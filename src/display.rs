use termion::{input::MouseTerminal, raw::RawTerminal, screen::AlternateScreen};
use tui::{
    backend::TermionBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

use crate::{app::Item, net::Resolver, App};

fn gen_rows<'a>(items: &Vec<Item>, resolver: &Resolver) -> Vec<Row<'a>> {
    let mut rows = Vec::new();
    for i in items {
        let v = if i.is_v4 { "v4" } else { "v6" };
        let entry = vec![
            format!("{}:{}", i.ip.to_string(), i.port.to_string()),
            v.to_owned(),
            resolver.resolve_ip(i.ip),
            format!("{}ps / {}ps", gen_bytes_str(i.tx_rate), gen_bytes_str(i.rx_rate)),
            format!("{} / {}", gen_bytes_str(i.tot_tx), gen_bytes_str(i.tot_rx))
        ];
        let cells = entry.iter().map(|c| Cell::from(c.clone()));
        rows.push(Row::new(cells).height(1));
    }

    rows
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
        let header_cells = ["Peer", "Type", "Name", "Rate tx / rx", "Total tx / rx"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
        let header = Row::new(header_cells)
            .style(normal_style)
            .height(1)
            .bottom_margin(1);

        let rows = gen_rows(&app.items.vec, &app.resolver);
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
            .widths(&[
                Constraint::Percentage(20),
                Constraint::Percentage(10),
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ]);

        f.render_widget(header_paragraph, rects[0]);
        f.render_stateful_widget(t, rects[1], &mut app.state);
    })?;

    Ok(())
}
// }

pub fn gen_bytes_str(bytes: u64) -> String {
    let mut bytes_str = format!("{} B", bytes);

    if bytes >= 1024 {
        bytes_str = format!("{:.2} KiB", bytes as f32 / 1024f32);
    }

    if bytes >= 1024 * 1024 {
        bytes_str = format!("{:.2} MiB", bytes as f32 / 1024f32 / 1024f32);
    }

    if bytes >= 1024 * 1024 * 1024 {
        bytes_str = format!("{:.2} GiB", bytes as f32 / 1024f32 / 1024f32 / 1024f32);
    }

    bytes_str
}
