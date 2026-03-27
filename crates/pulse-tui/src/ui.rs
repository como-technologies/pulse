use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::app::{App, ConnectField, Screen};

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),    // Main content
            Constraint::Length(10), // Log panel
            Constraint::Length(1),  // Status bar
        ])
        .split(frame.area());

    // Main content area
    match app.screen {
        Screen::Connect => render_connect(frame, app, chunks[0]),
        Screen::Login => render_login(frame, app, chunks[0]),
        Screen::Questions => render_questions(frame, app, chunks[0]),
        Screen::Token => render_token(frame, app, chunks[0]),
        Screen::Respond => render_respond(frame, app, chunks[0]),
        Screen::Submit => render_submit(frame, app, chunks[0]),
    }

    // Log panel
    render_log(frame, app, chunks[1]);

    // Status bar
    render_status_bar(frame, app, chunks[2]);
}

fn render_connect(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Connect to Pulse Server ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    let id_style = if app.connect_field == ConnectField::IdentityUrl {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };
    let sig_style = if app.connect_field == ConnectField::SignalUrl {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    };

    frame.render_widget(
        Paragraph::new("Identity Zone URL:").style(id_style),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(app.identity_url.as_str())
            .block(Block::default().borders(Borders::ALL).style(id_style)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new("Signal Zone URL:").style(sig_style),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(app.signal_url.as_str())
            .block(Block::default().borders(Borders::ALL).style(sig_style)),
        chunks[3],
    );
}

fn render_login(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Authenticate ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new("API Key / Employee ID:").style(Style::default().fg(Color::Yellow)),
        chunks[0],
    );

    let cursor = if app.login_status.is_none() {
        "█"
    } else {
        ""
    };
    frame.render_widget(
        Paragraph::new(format!("{}{}", app.api_key, cursor)).block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::Yellow)),
        ),
        chunks[1],
    );

    if let Some(ref status) = app.login_status {
        let color = if status.starts_with("Error") {
            Color::Red
        } else {
            Color::Green
        };
        frame.render_widget(
            Paragraph::new(status.as_str()).style(Style::default().fg(color)),
            chunks[2],
        );
    }
}

fn render_questions(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Questions ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.questions.is_empty() {
        frame.render_widget(
            Paragraph::new("No questions assigned.").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let items: Vec<ListItem> = app
        .questions
        .iter()
        .enumerate()
        .map(|(i, q)| {
            let style = if i == app.selected_question {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if i == app.selected_question {
                "▸ "
            } else {
                "  "
            };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(q.question_text.0.clone(), style),
                Span::styled(
                    format!("  [{:?}]", q.response_type),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn render_token(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Token Acquisition ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Phase 1: ", Style::default().fg(Color::Cyan)),
            Span::raw("Identity-Aware Channel"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Construct TokenPayload (nonce, batch, segments)"),
        ]),
        Line::from(vec![
            Span::styled("  2. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Blind token (hide contents from Token Issuer)"),
        ]),
        Line::from(vec![
            Span::styled("  3. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Request blind signature from Identity Zone"),
        ]),
        Line::from(vec![
            Span::styled("  4. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Unblind signature (verify locally)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Status: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                app.token_status.as_str(),
                Style::default().fg(if app.token_status.contains("Error") {
                    Color::Red
                } else if app.token_status.contains("ready") {
                    Color::Green
                } else {
                    Color::White
                }),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_respond(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Respond ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let question = &app.questions[app.selected_question];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(question.question_text.0.as_str())
            .style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .wrap(Wrap { trim: true }),
        chunks[0],
    );

    frame.render_widget(
        Paragraph::new(format!("Response type: {:?}", question.response_type))
            .style(Style::default().fg(Color::DarkGray)),
        chunks[1],
    );

    match question.response_type {
        pulse_protocol::messages::ResponseType::Scale5 => {
            let scale_display: Vec<Span> = (1..=5)
                .map(|i| {
                    if i == app.scale_value {
                        Span::styled(
                            format!(" [{i}] "),
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::styled(format!("  {i}  "), Style::default().fg(Color::DarkGray))
                    }
                })
                .collect();

            let lines = vec![
                Line::from("Use ←/→ or Up/Down to select, Enter to submit:"),
                Line::from(""),
                Line::from(scale_display),
            ];
            frame.render_widget(Paragraph::new(lines), chunks[2]);
        }
        _ => {
            frame.render_widget(
                Paragraph::new(format!("{}█", app.text_response)).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Your response "),
                ),
                chunks[2],
            );
        }
    }
}

fn render_submit(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Submit Response ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Phase 2: ", Style::default().fg(Color::Cyan)),
            Span::raw("Anonymous Channel (via Signal Zone)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Derive anonymous pseudonym (HMAC-SHA256)"),
        ]),
        Line::from(vec![
            Span::styled("  2. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Encrypt response payload (AES-256-GCM)"),
        ]),
        Line::from(vec![
            Span::styled("  3. ", Style::default().fg(Color::DarkGray)),
            Span::raw("Submit to Signal Zone (NO auth, NO identity)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Status: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                app.submit_status.as_str(),
                Style::default().fg(if app.submit_status.contains("Error") {
                    Color::Red
                } else if app.submit_status.contains("successfully") {
                    Color::Green
                } else {
                    Color::White
                }),
            ),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_log(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Protocol Log ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Show last N log entries that fit
    let max_lines = inner.height as usize;
    let start = app.log.len().saturating_sub(max_lines);
    let items: Vec<ListItem> = app.log[start..]
        .iter()
        .map(|entry| {
            let style = if entry.starts_with("[Identity Zone]") {
                Style::default().fg(Color::Blue)
            } else if entry.starts_with("[Signal Zone]") {
                Style::default().fg(Color::Magenta)
            } else if entry.starts_with("[Client]") {
                Style::default().fg(Color::Green)
            } else if entry.starts_with("Error") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(Line::from(Span::styled(entry.as_str(), style)))
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let screen_name = match app.screen {
        Screen::Connect => "CONNECT",
        Screen::Login => "LOGIN",
        Screen::Questions => "QUESTIONS",
        Screen::Token => "TOKEN",
        Screen::Respond => "RESPOND",
        Screen::Submit => "SUBMIT",
    };

    let nav_hint = match app.screen {
        Screen::Connect => "Tab: switch field | Enter: connect | Ctrl+C: quit",
        Screen::Login => "Enter: authenticate | Esc: back",
        Screen::Questions => "↑↓: select | Enter: get token | Esc: back",
        Screen::Token => "Esc: back (waiting for token...)",
        Screen::Respond => "↑↓: change value | Enter: submit | Esc: back",
        Screen::Submit => "Esc: back to questions",
    };

    let bar = Line::from(vec![
        Span::styled(
            format!(" {screen_name} "),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {nav_hint}"), Style::default().fg(Color::DarkGray)),
    ]);

    frame.render_widget(Paragraph::new(bar), area);
}
