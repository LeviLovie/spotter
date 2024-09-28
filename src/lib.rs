use libc::{sigaction, sigemptyset, siginfo_t, SIGBUS, SIGFPE, SIGILL, SIGSEGV};
use std::sync::atomic::{AtomicBool, Ordering};
use colored::Colorize;
use std::{env, panic, thread};

fn log_backtrace() {
    if let Ok(backtrace_enabled) = env::var("RUST_BACKTRACE") {
        if backtrace_enabled != "0" {
            println!("{}", "Backtrace:".yellow().bold());
            let backtrace = std::backtrace::Backtrace::capture();
            for line in backtrace.to_string().lines() {
                println!("{}", line);
            }
        } else {
            println!("{}\n", "Backtrace not enabled.".yellow().bold());
        }
    } else {
        println!("{}\n", "Backtrace not enabled.".yellow().bold());
    }
}

pub fn init_panic_hook() {
    panic::set_hook(Box::new(|info| {
        print!("{}", "A panic has occured: ".red().bold());
        println!("{}", info.to_string().blue().bold());

        log_backtrace();
    }));
}

static HANDLED: AtomicBool = AtomicBool::new(false);

// The signal handler function
extern "C" fn handle_signal(sig: libc::c_int, info: *mut siginfo_t, context: *mut libc::c_void) {
    if HANDLED.swap(true, Ordering::SeqCst) {
        return; // Prevent re-entrant signal handling
    }

    match sig {
        SIGSEGV => println!("{}", "Segmentation fault".red().bold()),
        SIGILL => println!("{}", "Illegal instruction".red().bold()),
        SIGFPE => println!("{}", "Floating point exception".red().bold()),
        SIGBUS => println!("{}", "Bus error".red().bold()),
        _ => println!("{}", "Unknown signal".red().bold()),
    }

    unsafe {
        if !info.is_null() {
            let info = &*info;

            println!(
                "{:17}{:p}",
                "Fault address:".yellow().bold(),
                info.si_addr()
            );
        }

        if !context.is_null() {
            let ucontext = &*(context as *mut libc::ucontext_t);

            #[cfg(target_arch = "x86_64")]
            {
                println!(
                    "{}: {:016x}",
                    "RIP".yellow().bold(),
                    (*ucontext.uc_mcontext).gregs[libc::REG_RIP as usize]
                );
                println!(
                    "{}: {:016x}",
                    "RSP".yellow().bold(),
                    (*ucontext.uc_mcontext).gregs[libc::REG_RSP as usize]
                );
            }

            #[cfg(target_os = "macos")]
            {
                let mcontext = (*ucontext).uc_mcontext;

                println!(
                    "{:17}0x{:x}",
                    "Programm conter:".yellow().bold(),
                    (*mcontext).__ss.__pc
                );

                println!(
                    "{:17}0x{:x}",
                    "Programm status:".yellow().bold(),
                    (*mcontext).__ss.__cpsr
                );

                println!(
                    "{:17}0x{:x}",
                    "Stack pointer:".yellow().bold(),
                    (*mcontext).__ss.__sp
                );

                println!(
                    "{:17}0x{:x}",
                    "Frame pointer:".yellow().bold(),
                    (*mcontext).__ss.__fp
                );

                println!(
                    "{:17}0x{:x}",
                    "Link register:".yellow().bold(),
                    (*mcontext).__ss.__lr
                );
            }
        }
    }

    log_backtrace();

    std::process::exit(1);
}

pub fn register_signal_handlers() -> std::io::Result<()> {
    unsafe {
        let mut sig_action: sigaction = std::mem::zeroed();
        sigemptyset(&mut sig_action.sa_mask);
        sig_action.sa_flags = sigaction as libc::c_ulong as libc::c_int;
        sig_action.sa_sigaction = handle_signal as usize;

        for &signal in &[SIGSEGV, SIGILL, SIGFPE, SIGBUS] {
            if sigaction(signal, &sig_action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

pub fn init() {
    init_panic_hook();
    if let Err(e) = register_signal_handlers() {
        eprintln!("Failed to register signal handlers: {}", e);
    }
}
