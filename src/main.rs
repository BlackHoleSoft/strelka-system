// Copyright (c) 2017, The MesaLock Linux Contributors
// All rights reserved.
// 
// This work is licensed under the terms of the BSD 3-Clause License.
// For a copy, see the LICENSE file.

extern crate libc;
extern crate nix;
extern crate framebuffer;

use nix::unistd;
use nix::mount;

use framebuffer::{Framebuffer, KdMode};

use libc::{waitpid, sigprocmask, sigfillset, sigset_t, signal};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::mem;
use std::ptr;
use std::ffi::CString;
use std::fs;

fn draw() {
    let mut framebuffer = Framebuffer::new("/dev/fb0").unwrap();
    println!("Framebuffer initialized");

    let w = framebuffer.var_screen_info.xres as usize;
    let h = framebuffer.var_screen_info.yres as usize;
    let line_length = framebuffer.fix_screen_info.line_length as usize;
    let bytespp = (framebuffer.var_screen_info.bits_per_pixel / 8) as usize;

    let mut frame = vec![0u8; line_length * h];

    println!("Setting fb mode");

    let _ = Framebuffer::set_kd_mode(KdMode::Graphics).unwrap();

    let mut i = 0;
    while i < w * bytespp * 4 {
        frame[i * bytespp + 0] = 255u8;
        frame[i * bytespp + 1] = 255u8;
        frame[i * bytespp + 2] = 127u8;

        i = i+1;
    }
    

    let _ = framebuffer.write_frame(&frame);

    let _ = std::io::stdin().read_line(&mut String::new());

    frame = vec![0u8; line_length * h];

    i = 0;
    while i < line_length * h - 3 {
        frame[i * bytespp + 0] = 255u8;
        frame[i * bytespp + 1] = 0;
        frame[i * bytespp + 2] = 127u8;

        i = i+1;

        if i % 100 == 0 {
            let _ = framebuffer.write_frame(&frame);
        }
    }    

    let _ = std::io::stdin().read_line(&mut String::new());

    frame = vec![0u8; line_length * h];

    i = 100 * bytespp;
    while i < 800 * bytespp {
        let mut j = 100 * bytespp;
        while j < 500 {
            frame[line_length * j + i + 0] = 255u8;
            frame[line_length * j + i + 1] = 120u8;
            frame[line_length * j + i + 2] = 180u8;
            j += 1;
            
        }

        i += bytespp;

        let _ = framebuffer.write_frame(&frame);
    }
    let _ = framebuffer.write_frame(&frame);

    let _ = std::io::stdin().read_line(&mut String::new());
    let _ = Framebuffer::set_kd_mode(KdMode::Text).unwrap();
}


/*fn run(line: &str) {
    println!("[+] init: run {}", line);
    let mut args = line.split(' ').map(|arg| {arg.to_string()});

    if let Some(cmd) = args.next() {
        match cmd.as_str() {
            _ => {
                let mut command = Command::new(cmd);
                for arg in args {
                    command.arg(arg);
                }

                match command.before_exec(|| {
                    unsafe { reset_sighandlers_and_unblock_sigs() }
                    // TODO: Open the new terminal device
                    Ok(())
                }).spawn() {
                    Ok(mut child) => match child.wait() {
                        Ok(_status) => {
                            println!("[+] init: {} exit", line);
                            unsafe { sigprocmask_allsigs(libc::SIG_UNBLOCK); }
                        },
                        Err(err) => println!("[-] init: failed to wait: {}", err)
                    },
                    Err(err) => println!("[-] init: failed to execute: {}", err)
                }
            }
        }

    }
}

unsafe fn sigprocmask_allsigs(how: libc::c_int) {
    let mut sigset = mem::uninitialized::<sigset_t>();
    sigfillset(&mut sigset as *mut sigset_t);
    sigprocmask(how, &sigset as *const sigset_t, ptr::null_mut() as *mut sigset_t);
}


unsafe fn reset_sighandlers_and_unblock_sigs() {
    signal(libc::SIGUSR1, libc::SIG_DFL);
    signal(libc::SIGUSR2, libc::SIG_DFL);
    signal(libc::SIGTERM, libc::SIG_DFL);
    signal(libc::SIGQUIT, libc::SIG_DFL);
    signal(libc::SIGINT, libc::SIG_DFL);
    signal(libc::SIGHUP, libc::SIG_DFL);
    signal(libc::SIGTSTP, libc::SIG_DFL);
    signal(libc::SIGSTOP, libc::SIG_DFL);
    sigprocmask_allsigs(libc::SIG_UNBLOCK);
}*/

fn main() {
    println!("init");
    unistd::setsid().expect("setsid failed");    
    unsafe {
        libc::putenv(CString::new("HOME=/").unwrap().into_raw());
        libc::putenv(CString::new("PATH=/sbin:/bin:/usr/sbin:/usr/bin").unwrap().into_raw());
        libc::putenv(CString::new("SHELL=/bin/sh").unwrap().into_raw());

        println!("try call libc");
        let fp = libc::abs(-10);  
        println!("Result: {}", fp);
    }

    println!("try syscall");
    let pid = unistd::getpid();
    println!("called successful");
    println!("Value: {}", pid);

    println!("try read file via rust lib");
    let contents = fs::read_to_string("/home/anton/test.txt")
        .expect("Something went wrong reading the file");
    println!("file contents:\n{}", contents);
    
    draw();

    // TODO: setup signal handler
    /*
    // mount -n -t proc proc /proc
    let proc_mount_flags = mount::MS_NOSUID | mount::MS_NODEV | mount::MS_NOEXEC | mount::MS_RELATIME;
    let _ = mount::mount(Some("proc"), "/proc", Some("proc"), proc_mount_flags, Some("mode=0555")).expect("mount proc failed");

    // mount -n -t devtmpfs devtmpfs /dev
    let dev_mount_flags = mount::MS_NOSUID | mount::MS_RELATIME;
    let _ = mount::mount(Some("dev"), "/dev", Some("devtmpfs"), dev_mount_flags, Some("mode=0755")).expect("mount tmp failed");

    // mount -n -t sysfs sysfs /sys
    let sys_mount_flags = mount::MS_NOSUID | mount::MS_NODEV | mount::MS_NOEXEC | mount::MS_RELATIME;
    let _ = mount::mount(Some("sysfs"), "/sys", Some("sysfs"), sys_mount_flags, Some("mode=0555")).expect("mount sys failed");

    run("mknod -m 600 /dev/console c 5 1");
    run("mknod -m 620 /dev/tty1 c 4 1");
    run("mknod -m 666 /dev/tty c 5 0");
    run("mknod -m 666 /dev/null c 1 3");
    run("mknod -m 660 /dev/kmsg c 1 11");
*/
    //println!("starting loop");
    loop {
        
    }
}
