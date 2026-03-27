use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use tokio::sync::mpsc;

use crate::action::Action;

/// Polls crossterm events and translates them to Actions.
/// Also receives async protocol results via the channel.
pub async fn event_loop(
    action_tx: mpsc::UnboundedSender<Action>,
    mut protocol_rx: mpsc::UnboundedReceiver<Action>,
) {
    loop {
        // Check for protocol results (non-blocking)
        while let Ok(action) = protocol_rx.try_recv() {
            if action_tx.send(action).is_err() {
                return;
            }
        }

        // Poll for terminal events with a short timeout
        if event::poll(Duration::from_millis(50)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
        {
            let action = match (key.code, key.modifiers) {
                (KeyCode::Char('c'), KeyModifiers::CONTROL) => Action::Quit,
                (KeyCode::Char('q'), _) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    Action::Quit
                }
                (KeyCode::Esc, _) => Action::Back,
                (KeyCode::Tab, _) => Action::NextField,
                (KeyCode::BackTab, _) => Action::PrevField,
                (KeyCode::Enter, _) => Action::Submit,
                (KeyCode::Up, _) => Action::SelectUp,
                (KeyCode::Down, _) => Action::SelectDown,
                (KeyCode::Left, _) => Action::ScaleDown,
                (KeyCode::Right, _) => Action::ScaleUp,
                (KeyCode::Backspace, _) => Action::Backspace,
                (KeyCode::Char(c), _) => Action::CharInput(c),
                _ => continue,
            };
            if action_tx.send(action).is_err() {
                return;
            }
        }
    }
}
