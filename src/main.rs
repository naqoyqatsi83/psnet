#![allow(dead_code)]

mod app;
mod network;
mod types;
mod ui;
mod utils;

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind, KeyCode, KeyModifiers, EnableMouseCapture, DisableMouseCapture, MouseEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::Terminal;

use app::App;

fn main() -> io::Result<()> {
    // Attempt to raise CAP_NET_ADMIN as an ambient capability so child
    // processes (e.g. `ss`) inherit it and can resolve process info for
    // all users.  This is a no-op if the binary lacks the capability or
    // the kernel doesn't support ambient caps.
    #[cfg(target_os = "linux")]
    raise_ambient_cap_net_admin();

    // Setup terminal
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    io::stdout().execute(EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Pre-warm OUI + GeoIP databases in background threads immediately
    // so they're ready before first device/connection display.
    std::thread::spawn(|| { crate::network::oui::warm(); });
    std::thread::spawn(|| { crate::network::geoip::warm(); });

    // Init sysinfo Networks (fast — just enumerates adapters)
    let mut networks = sysinfo::Networks::new_with_refreshed_list();
    let mut app = App::new(&networks);

    // Draw FIRST frame immediately — before any heavy update()
    terminal.draw(|f| {
        app.last_frame_size = f.area();
        ui::draw(f, &mut app);
    })?;

    let tick_rate = Duration::from_millis(1000);
    let fast_poll_interval = Duration::from_millis(200);
    // Set last_tick to zero so first loop iteration triggers update() immediately
    let mut last_tick = Instant::now() - tick_rate;

    // Track active tab to detect switches
    let mut last_tab = app.bottom_tab;

    // Event loop
    let mut needs_redraw = true;

    loop {
        if needs_redraw {
            if app.bottom_tab != last_tab {
                terminal.clear()?;
                last_tab = app.bottom_tab;
            }
            terminal.draw(|f| {
                app.last_frame_size = f.area();
                ui::draw(f, &mut app);
            })?;
            needs_redraw = false;
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO)
            .min(fast_poll_interval);

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && (key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C'))
                        {
                            break;
                        }
                        if app.handle_key(key.code) {
                            break;
                        }
                        needs_redraw = true;
                    }
                }
                Event::Mouse(mouse) => {
                    match mouse.kind {
                        MouseEventKind::Moved | MouseEventKind::Drag(_) => {}
                        _ => {
                            if app.handle_mouse(mouse.kind, mouse.column, mouse.row) {
                                break;
                            }
                            needs_redraw = true;
                        }
                    }
                }
                Event::Resize(_, _) => {
                    needs_redraw = true;
                }
                _ => {}
            }
        }

        // Fast poll: drain streaming scanner buffers every 200ms
        if app.fast_poll() {
            needs_redraw = true;
        }

        // Drain deferred init results
        if app.poll_deferred_init() {
            needs_redraw = true;
        }

        if last_tick.elapsed() >= tick_rate {
            app.update(&mut networks);
            last_tick = Instant::now();
            needs_redraw = true;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(DisableMouseCapture)?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

/// Raise `CAP_NET_ADMIN` as an ambient capability so child processes
/// (like `ss -tunp`) inherit the capability and can resolve process
/// information for all users.
///
/// This is a best-effort call — silently ignored when the binary
/// hasn't been granted the capability or the kernel is too old.
#[cfg(target_os = "linux")]
fn raise_ambient_cap_net_admin() {
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
    const CAP_NET_ADMIN: libc::c_ulong = 12;

    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0);
    }
}
