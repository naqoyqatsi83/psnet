pub mod connections;
pub mod dashboard;
pub mod detail_popup;
pub mod packets;
pub mod packets_tab;
pub mod servers;
pub mod speed;
pub mod status;
pub mod title;
pub mod topology;
pub mod alerts;
pub mod devices;
pub mod firewall;
pub mod networks;
pub mod widgets;

use std::net::Ipv4Addr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::types::BottomTab;

/// Master draw function — lays out all panes.
pub fn draw(f: &mut Frame, app: &mut App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title bar
            Constraint::Length(11), // Speed section
            Constraint::Length(1),  // Tab menu
            Constraint::Min(10),   // Bottom pane (tab content)
            Constraint::Length(7),  // Wire preview (packet sniffer)
            Constraint::Length(1),  // Status bar (key hints)
        ])
        .split(f.area());

    title::draw_title_bar(f, main_layout[0], app);
    speed::draw_speed_section(f, main_layout[1], app);
    status::draw_tab_menu(f, main_layout[2], app);

    match app.bottom_tab {
        BottomTab::Dashboard => dashboard::draw_dashboard(f, main_layout[3], app),
        BottomTab::Connections => connections::draw_connections(f, main_layout[3], app),
        BottomTab::Servers => servers::draw_servers(f, main_layout[3], app),
        BottomTab::Packets => packets_tab::draw_packets_tab(f, main_layout[3], app),
        BottomTab::Topology => topology::draw_topology(f, main_layout[3], app),
        BottomTab::Alerts => alerts::draw_alerts(f, main_layout[3], app),
        BottomTab::Firewall => firewall::draw_firewall(f, main_layout[3], app),
        BottomTab::Devices => devices::draw_devices(f, main_layout[3], app),
        BottomTab::Networks => networks::draw_networks(f, main_layout[3], app),
    }

    packets::draw_packet_preview(f, main_layout[4], &app.sniffer);
    status::draw_key_hints(f, main_layout[5], app);

    // Status message toast — shown briefly after actions like copy/open
    if let Some((ref msg, _)) = app.status_message {
        let msg_width = (msg.len() as u16 + 4).min(f.area().width.saturating_sub(4));
        let area = f.area();
        let toast_area = Rect::new(
            area.x + (area.width.saturating_sub(msg_width)) / 2,
            area.y + area.height.saturating_sub(4),
            msg_width,
            3,
        );
        f.render_widget(Clear, toast_area);

        // Use orange styling for permission/firewall warnings.
        let is_warning = msg.contains("root") || msg.contains("permission")
            || msg.contains("sudo") || msg.contains("privileg")
            || msg.contains("Incognito");
        let (fg, border) = if is_warning {
            (Color::Rgb(255, 200, 100), Color::Rgb(200, 140, 40))
        } else {
            (Color::Rgb(200, 255, 200), Color::Rgb(80, 200, 120))
        };
        let toast = Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" {} ", msg),
                Style::default()
                    .fg(fg)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .style(Style::default().bg(Color::Rgb(15, 30, 20))),
        );
        f.render_widget(toast, toast_area);
    }

    // Detail popup overlay — drawn last so it appears on top of everything
    detail_popup::draw_detail_popup(f, app);

    // Interface selection popup
    if let Some(ref state) = app.interface_select_popup {
        let w = 74u16.min(f.area().width.saturating_sub(4));
        let h = (state.interfaces.len() as u16 + 7).min(22).max(9);
        let area = Rect {
            x: f.area().x + (f.area().width - w) / 2,
            y: f.area().y + (f.area().height - h) / 2,
            width: w,
            height: h,
        };
        f.render_widget(Clear, area);
        draw_interface_select_popup(f, area, state);
    }
}

fn mask_to_cidr(ip: Ipv4Addr, mask: Ipv4Addr) -> String {
    let network = u32::from(ip) & u32::from(mask);
    let prefix = u32::from(mask).leading_ones();
    format!("{}/{}", Ipv4Addr::from(network), prefix)
}

fn draw_interface_select_popup(f: &mut Frame, area: Rect, state: &crate::app::InterfaceSelectState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(60, 100, 180)))
        .style(Style::default().bg(Color::Rgb(10, 14, 28)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Title
    lines.push(Line::from(Span::styled(
        "  Sweep Interface Selection",
        Style::default()
            .fg(Color::Rgb(200, 220, 255))
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        Style::default().fg(Color::Rgb(35, 50, 80)),
    )));

    // Interface rows
    for (i, (ip, mask, name)) in state.interfaces.iter().enumerate() {
        let checked = state.selected.get(i).copied().unwrap_or(false);
        let is_cursor = i == state.cursor;
        let cidr = mask_to_cidr(*ip, *mask);
        let checkbox_color = if checked {
            Color::Rgb(80, 200, 120)
        } else {
            Color::Rgb(80, 85, 100)
        };
        let cb = if checked { "[x]" } else { "[ ]" };
        let fg = if is_cursor {
            Color::Rgb(255, 200, 80)
        } else {
            Color::Rgb(170, 185, 210)
        };
        let row_mod = if is_cursor { Modifier::BOLD } else { Modifier::empty() };
        let prefix = if is_cursor { " \u{25b6} " } else { "    " };
        lines.push(Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::Rgb(255, 200, 80))),
            Span::styled(format!(" {}  ", cb), Style::default().fg(checkbox_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:20}  ", cidr), Style::default().fg(fg).add_modifier(row_mod)),
            Span::styled(format!("{:20}  ", name), Style::default().fg(Color::Rgb(140, 180, 240)).add_modifier(row_mod)),
            Span::styled(ip.to_string(), Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(row_mod)),
        ]));
    }

    // Footer hint
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [ Space: toggle  Enter: confirm  Esc: cancel ]",
        Style::default().fg(Color::Rgb(65, 80, 110)).add_modifier(Modifier::ITALIC),
    )));

    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(Color::Rgb(10, 14, 28))),
        inner,
    );
}
