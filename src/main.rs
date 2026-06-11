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

/// Raise `CAP_NET_ADMIN` and `CAP_NET_RAW` as ambient capabilities so child
/// processes (like `ss -tunp` and `nft`) inherit them.
///
/// To actually succeed, the binary must have `CAP_SETPCAP` in its effective
/// set (granted via `setcap cap_setpcap+ep`).  With CAP_SETPCAP we first
/// use the `capset` syscall to add CAP_NET_ADMIN / CAP_NET_RAW to our
/// inheritable set, then raise them as ambient via `prctl`.
///
/// When `CAP_SETPCAP` is not available, or the kernel doesn't support
/// ambient capabilities, this is a best-effort no-op and nftables.rs will
/// fall back to `sudo -n nft`.
#[cfg(target_os = "linux")]
fn raise_ambient_cap_net_admin() {
    // V3 capability format — 2 × 32-bit struct for caps 0-31 and 32-63.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_NET_RAW: u32 = 13;
    // CAP_SETPCAP is bit 4 in the capability mask
    const CAP_SETPCAP_BIT: u32 = 4;

    // Check if we have CAP_SETPCAP in our effective set before proceeding.
    if !capability_bit_from_proc("CapEff", CAP_SETPCAP_BIT) {
        return;
    }

    let mut header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];

    // Read current capabilities via capget(2).
    // Having CAP_SETPCAP lets us modify the inheritable set and the
    // permitted set (as long as new values are subsets of the current
    // permitted set).
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget as libc::c_long,
            &mut header as *mut CapHeader,
            &mut data as *mut CapData,
        )
    };
    if ret != 0 {
        return;
    }

    // Add CAP_NET_ADMIN and CAP_NET_RAW to the inheritable set.
    // These are already in our permitted set (via setcap +ep).
    data[0].inheritable |= (1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW);

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset as libc::c_long,
            &mut header as *mut CapHeader,
            &mut data as *mut CapData,
        )
    };
    if ret != 0 {
        return;
    }

    // Now both caps are in our permitted AND inheritable sets, satisfying
    // the requirement for PR_CAP_AMBIENT_RAISE.
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;

    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN as libc::c_ulong, 0, 0);
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW as libc::c_ulong, 0, 0);
    }
}

/// Helper: read a single capability bit from `/proc/self/status`.
/// `bit` is the 0-based capability number (e.g. CAP_SETPCAP = 4).
#[cfg(target_os = "linux")]
fn capability_bit_from_proc(field: &str, bit: u32) -> bool {
    let data = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in data.lines() {
        if line.starts_with(field) && line.len() > field.len() + 1 {
            if let Some(hex) = line[field.len()..].trim().split_whitespace().next() {
                let mask = u64::from_str_radix(hex, 16).unwrap_or(0);
                if bit < 64 && (mask & (1u64 << bit)) != 0 {
                    return true;
                }
            }
        }
    }
    false
}
