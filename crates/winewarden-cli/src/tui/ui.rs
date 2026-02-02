//! TUI UI Rendering
//!
//! Renders the various screens and widgets using ratatui.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Gauge, Paragraph, Row, Sparkline, Table, TableState, Tabs, Wrap,
    },
    Frame,
};

use crate::tui::app::{App, ProcessStatus, Screen};

/// Main render function
pub fn render(frame: &mut Frame, app: &mut App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

    render_header(frame, app, main_layout[0]);
    render_main_content(frame, app, main_layout[1]);
    render_footer(frame, app, main_layout[2]);
}

/// Renders the header with tabs
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = vec![
        Screen::Dashboard,
        Screen::Trust,
        Screen::Network,
        Screen::Processes,
        Screen::Events,
    ]
    .iter()
    .map(|screen| {
        let title = screen.title();
        let style = if *screen == app.current_screen {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        Line::from(Span::styled(format!(" {} ", title), style))
    })
    .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" WineWarden Monitor ")
                .title_style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .highlight_style(Style::default().fg(Color::Green))
        .select(app.current_screen as usize);

    frame.render_widget(tabs, area);
}

/// Renders the main content area based on current screen
fn render_main_content(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.current_screen {
        Screen::Dashboard => render_dashboard(frame, app, area),
        Screen::Trust => render_trust(frame, app, area),
        Screen::Network => render_network(frame, app, area),
        Screen::Processes => render_processes(frame, app, area),
        Screen::Events => render_events(frame, app, area),
    }
}

/// Renders the dashboard screen
fn render_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Stats row
            Constraint::Length(12), // Trust graph
            Constraint::Min(0),     // Recent events
        ])
        .split(area);

    // Stats row
    let stats_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(layout[0]);

    render_stat_card(
        frame,
        "Session",
        &app.session_duration(),
        Color::Blue,
        stats_layout[0],
    );
    render_stat_card(
        frame,
        "Trust Tier",
        &format!("{:?}", app.trust_tier),
        trust_tier_color(app.trust_tier),
        stats_layout[1],
    );
    render_stat_card(
        frame,
        "Events/sec",
        &format!("{:.1}", app.events_per_second()),
        Color::Yellow,
        stats_layout[2],
    );
    render_stat_card(
        frame,
        "Denied",
        &format!("{:.1}%", app.denial_rate() * 100.0),
        if app.denial_rate() > 0.1 {
            Color::Red
        } else {
            Color::Green
        },
        stats_layout[3],
    );

    // Trust score gauge
    if let Some(score) = &app.trust_score {
        let trust_gauge = Gauge::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Trust Score: {} ", score.score)),
            )
            .gauge_style(Style::default().fg(trust_score_color(score.score)))
            .percent(score.score as u16);
        frame.render_widget(trust_gauge, layout[1]);
    } else {
        let no_score = Paragraph::new("No trust score available yet")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Trust Score "),
            )
            .alignment(Alignment::Center);
        frame.render_widget(no_score, layout[1]);
    }

    // Recent events table
    render_recent_events(frame, app, layout[2]);
}

/// Renders a stat card
fn render_stat_card(frame: &mut Frame, title: &str, value: &str, color: Color, area: Rect) {
    let card = Paragraph::new(value)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", title))
                .border_style(Style::default().fg(color)),
        )
        .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center);
    frame.render_widget(card, area);
}

/// Renders the trust score screen with history graph
fn render_trust(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    // Trust score display
    if let Some(score) = &app.trust_score {
        let trust_text = format!(
            "Current Score: {}\nRecommended Tier: {:?}\n\nAssessment:\n{}\n",
            score.score, score.recommended_tier, score.assessment
        );

        let trust_info = Paragraph::new(trust_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Trust Score Details ")
                    .border_style(Style::default().fg(trust_score_color(score.score))),
            )
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        frame.render_widget(trust_info, layout[0]);

        // History graph
        let data: Vec<u64> = app
            .trust_history
            .iter()
            .map(|(_, score)| *score as u64)
            .collect();
        let sparkline = Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Trust Score History "),
            )
            .data(&data)
            .style(Style::default().fg(Color::Cyan))
            .max(100);
        frame.render_widget(sparkline, layout[1]);
    } else {
        let no_data = Paragraph::new("No trust score data available")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Trust Score "),
            )
            .alignment(Alignment::Center);
        frame.render_widget(no_data, area);
    }
}

/// Renders the network screen
fn render_network(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Connections table
    let connections_header = Row::new(vec!["Host", "Port", "Proto", "Count"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let connections_rows: Vec<Row> = app
        .connections
        .iter()
        .map(|conn| {
            Row::new(vec![
                Cell::from(conn.host.clone()),
                Cell::from(conn.port.to_string()),
                Cell::from(conn.protocol.clone()),
                Cell::from(conn.connection_count.to_string()),
            ])
        })
        .collect();

    let connections_table = Table::new(
        connections_rows,
        [
            Constraint::Percentage(50),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
        ],
    )
    .header(connections_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Connections ({}) ", app.connections.len())),
    );
    frame.render_widget(connections_table, layout[0]);

    // DNS queries table
    let dns_header = Row::new(vec!["Domain", "Queries", "Resolved IPs"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let dns_rows: Vec<Row> = app
        .dns_queries
        .iter()
        .map(|dns| {
            Row::new(vec![
                Cell::from(dns.domain.clone()),
                Cell::from(dns.query_count.to_string()),
                Cell::from(dns.resolved_ips.join(", ")),
            ])
        })
        .collect();

    let dns_table = Table::new(
        dns_rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(15),
            Constraint::Percentage(45),
        ],
    )
    .header(dns_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" DNS Queries ({}) ", app.dns_queries.len())),
    );
    frame.render_widget(dns_table, layout[1]);
}

/// Renders the processes screen
fn render_processes(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Status", "PID", "Name", "Runtime"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|proc| {
            let runtime = format_duration(proc.started_at.elapsed());
            let status_color = match proc.status {
                ProcessStatus::Running => Color::Green,
                ProcessStatus::Suspended => Color::Yellow,
                ProcessStatus::Terminated => Color::Red,
            };

            Row::new(vec![
                Cell::from(proc.status.as_str()).style(Style::default().fg(status_color)),
                Cell::from(proc.pid.to_string()),
                Cell::from(proc.name.clone()),
                Cell::from(runtime),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Percentage(50),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Processes ({}) ", app.processes.len())),
    );
    frame.render_widget(table, area);
}

/// Renders the events screen with scrolling
fn render_events(frame: &mut Frame, app: &mut App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Filter input
    let filter_block = Paragraph::new(app.event_filter.clone())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Filter (type to filter events) "),
        )
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(filter_block, layout[0]);

    // Events table
    let header = Row::new(vec!["Time", "Kind", "Target", "Note"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let filtered_events = app.filtered_events();
    let rows: Vec<Row> = filtered_events
        .iter()
        .map(|event| {
            let time = event
                .timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            let kind = format!("{:?}", event.kind);
            let target = format!("{:?}", event.target);
            let note = event.note.clone().unwrap_or_default();

            Row::new(vec![
                Cell::from(time),
                Cell::from(kind),
                Cell::from(target),
                Cell::from(note),
            ])
        })
        .collect();

    let mut table_state = TableState::default();
    if app.auto_scroll && !filtered_events.is_empty() {
        table_state.select(Some(filtered_events.len() - 1));
    } else if !filtered_events.is_empty() {
        table_state.select(Some(app.selected_event.min(filtered_events.len() - 1)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(25),
            Constraint::Length(10),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(format!(
        " Events ({}/{}) ",
        filtered_events.len(),
        app.total_events
    )))
    .row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_stateful_widget(table, layout[1], &mut table_state);
}

/// Renders recent events on dashboard
fn render_recent_events(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "Kind", "Target"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let recent: Vec<Row> = app
        .events
        .iter()
        .rev()
        .take(10)
        .map(|event| {
            let time = event
                .timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            let kind = format!("{:?}", event.kind);
            let target = format!("{:?}", event.target);

            Row::new(vec![
                Cell::from(time),
                Cell::from(kind),
                Cell::from(target.chars().take(50).collect::<String>()),
            ])
        })
        .collect();

    let table = Table::new(
        recent,
        [
            Constraint::Length(25),
            Constraint::Length(10),
            Constraint::Percentage(70),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent Events "),
    );
    frame.render_widget(table, area);
}

/// Renders the footer with help text
fn render_footer(frame: &mut Frame, _app: &App, area: Rect) {
    let help_text = "Tab/→:Next | Shift+Tab/←:Prev | Q:Quit | P:Pause | ↑↓:Scroll | /:Filter";
    let help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Gray))
        .alignment(Alignment::Center);
    frame.render_widget(help, area);
}

/// Helper function to get color for trust tier
fn trust_tier_color(tier: winewarden_core::trust::TrustTier) -> Color {
    match tier {
        winewarden_core::trust::TrustTier::Green => Color::Green,
        winewarden_core::trust::TrustTier::Yellow => Color::Yellow,
        winewarden_core::trust::TrustTier::Red => Color::Red,
    }
}

/// Helper function to get color for trust score
fn trust_score_color(score: u32) -> Color {
    match score {
        0..=25 => Color::Red,
        26..=50 => Color::Yellow,
        51..=75 => Color::Cyan,
        76..=100 => Color::Green,
        _ => Color::Gray,
    }
}

/// Formats a duration as HH:MM:SS
fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}
