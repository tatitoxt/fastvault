use crate::app::{Tab, TuiApp};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fastvault_core::error::Result;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, Tabs},
    Terminal,
};
use std::io;

pub fn run_tui(mut app: TuiApp) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = main_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn main_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if app.is_searching {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => app.is_searching = false,
                        KeyCode::Backspace => {
                            app.search_query.pop();
                        }
                        KeyCode::Char(c) => {
                            app.search_query.push(c);
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => app.should_quit = true,
                        KeyCode::Char('m') => app.toggle_mask(),
                        KeyCode::Char('/') | KeyCode::Char('s') => app.is_searching = true,
                        KeyCode::Char('1') => app.active_tab = Tab::Secrets,
                        KeyCode::Char('2') => app.active_tab = Tab::AuditLog,
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous(),
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn draw_ui(f: &mut ratatui::Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    let titles = vec![" [1] Secrets ", " [2] Audit Trail ", " [3] Sync "];
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" FastVault TUI "),
        )
        .select(match app.active_tab {
            Tab::Secrets => 0,
            Tab::AuditLog => 1,
            Tab::SyncStatus => 2,
        })
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(chunks[1]);

    let filtered = app.filtered_secrets();
    let rows: Vec<Row> = filtered
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == app.selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Row::new(vec![
                s.namespace.clone(),
                s.name.clone(),
                format!("{:?}", s.secret_type),
            ])
            .style(style)
        })
        .collect();

    let table_title = if app.is_searching {
        format!(" Secrets (Search: {}_) ", app.search_query)
    } else {
        " Secrets ".to_string()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(45),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(vec!["Namespace", "Name", "Type"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(Block::default().borders(Borders::ALL).title(table_title));

    f.render_widget(table, main_chunks[0]);

    let detail_text = if let Some(secret) = app.selected_secret() {
        let val_display = if app.mask_secrets {
            "••••••••••••••••".to_string()
        } else {
            secret.value.as_str().to_string()
        };

        format!(
            "ID: {}\nName: {}\nNamespace: {}\nType: {:?}\nValue: {}\nCreated: {}\nTags: {}\nDescription: {}",
            secret.id,
            secret.name,
            secret.namespace,
            secret.secret_type,
            val_display,
            secret.created_at.format("%Y-%m-%d %H:%M:%S"),
            secret.tags.join(", "),
            secret.description.as_deref().unwrap_or("N/A")
        )
    } else {
        "No secret selected".to_string()
    };

    let detail_paragraph = Paragraph::new(detail_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Secret Metadata "),
    );
    f.render_widget(detail_paragraph, main_chunks[1]);

    let footer = Paragraph::new(app.status_message.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Controls "));
    f.render_widget(footer, chunks[2]);
}
