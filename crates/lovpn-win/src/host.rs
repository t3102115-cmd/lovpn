//! Service Control Manager integration and the install/uninstall commands.
use lovpn_win::daemon::{self, Paths, ServiceConfig, Signals};
use std::{
    ffi::OsString,
    process::ExitCode,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        PowerEventParam, ServiceAccess, ServiceAction, ServiceActionType, ServiceControl,
        ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const NAME: &str = "LoVPNClient";

define_windows_service!(ffi_service_main, service_main);

pub fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("service") => match service_dispatcher::start(NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("could not start under the Service Control Manager: {e}");
                ExitCode::FAILURE
            }
        },
        Some("run") => run_foreground(),
        Some("install") => install(
            args.next()
                .as_deref()
                .filter(|a| *a == "--owner-sid")
                .and_then(|_| args.next()),
        ),
        Some("uninstall") => uninstall(),
        Some("release") => release(),
        _ => {
            eprintln!(
                "usage: lovpn-service service | run | install [--owner-sid SID] | uninstall | release"
            );
            ExitCode::from(2)
        }
    }
}

fn run_foreground() -> ExitCode {
    let paths = match Paths::discover() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match daemon::run(&paths, Arc::new(Signals::default())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lovpn-service: {e}");
            ExitCode::FAILURE
        }
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let signals = Arc::new(Signals::default());
    let handler_signals = Arc::clone(&signals);
    let status_handle =
        match service_control_handler::register(NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_signals.stop.store(true, Ordering::SeqCst);
                // Wake the blocked pipe accept so the loop can notice the stop flag.
                let _ = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(lovpn_win::pipe::DEFAULT_PIPE);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend,
            ) => {
                handler_signals.resumed.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate | ServiceControl::PowerEvent(_) => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(h) => h,
            Err(_) => return,
        };
    let status = |state: ServiceState, exit: u32, accept: ServiceControlAccept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = status_handle.set_service_status(status(
        ServiceState::StartPending,
        0,
        ServiceControlAccept::empty(),
    ));
    let accept = ServiceControlAccept::STOP
        | ServiceControlAccept::SHUTDOWN
        | ServiceControlAccept::POWER_EVENT;
    let _ = status_handle.set_service_status(status(ServiceState::Running, 0, accept));
    let result = match Paths::discover() {
        Ok(paths) => daemon::run(&paths, signals),
        Err(e) => Err(e.to_string()),
    };
    let exit = u32::from(result.is_err());
    let _ = status_handle.set_service_status(status(
        ServiceState::Stopped,
        exit,
        ServiceControlAccept::empty(),
    ));
}

/// The SID of the user running this (elevated) process: the controlling user.
fn current_user_sid() -> Option<String> {
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()
        .ok()?;
    let sid = String::from_utf8(output.stdout).ok()?.trim().to_string();
    sid.starts_with("S-1-").then_some(sid)
}

fn install(owner_sid: Option<String>) -> ExitCode {
    let Some(owner_sid) = owner_sid.or_else(current_user_sid) else {
        eprintln!("could not determine the controlling user; pass --owner-sid SID");
        return ExitCode::FAILURE;
    };
    let paths = match Paths::discover() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = daemon::write_config(&paths.state_dir, &ServiceConfig { owner_sid }) {
        eprintln!("could not write the service configuration (run as Administrator): {e}");
        return ExitCode::FAILURE;
    }
    let result = (|| -> windows_service::Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "LoVPN Client".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: paths.service_exe.clone(),
            launch_arguments: vec!["service".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager.create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )?;
        service
            .set_description("LoVPN local VPN client: tunnel, kill switch and DNS protection.")?;
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(30),
                },
            ]),
        })?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!("Service installed. Start it with: sc start {NAME}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not install the service (run as Administrator): {e}");
            ExitCode::FAILURE
        }
    }
}

/// Offline recovery: remove LoVPN's firewall filters without the service (Administrator).
fn release() -> ExitCode {
    let paths = match Paths::discover() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    match daemon::release_offline(&paths) {
        Ok(()) => {
            println!("LoVPN firewall filters removed. Normal networking is restored.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not release the kill switch (run as Administrator): {e}");
            ExitCode::FAILURE
        }
    }
}

fn uninstall() -> ExitCode {
    let result = (|| -> windows_service::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            NAME,
            ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )?;
        let _ = service.stop();
        service.delete()
    })();
    match result {
        Ok(()) => {
            println!(
                "Service removed. Firewall rules persist until `lovpn reset` or `lovpn disconnect --release-kill-switch`."
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not remove the service (run as Administrator): {e}");
            ExitCode::FAILURE
        }
    }
}
