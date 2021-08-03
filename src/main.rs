// Copyright (c) 2017, The MesaLock Linux Contributors
// All rights reserved.
// 
// This work is licensed under the terms of the BSD 3-Clause License.
// For a copy, see the LICENSE file.

extern crate libc;
extern crate nix;
extern crate framebuffer;

use nix::unistd;

use framebuffer::{Framebuffer, KdMode};

use std::ffi::CString;
use std::fs;

use image::io::Reader as ImageReader;

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

    //let img = graphics::image("strelka.jpg");
    let img = ImageReader::open("/strelka/assets/strelka.jpg").decode();

    for i in 0..img.width() {
        for j in 0..img.height() {
            let px = img.get_pixel(i, j);
            frame[j*img.width()*bytespp + i * bytespp + 0] = px.0;
            frame[j*img.width()*bytespp + i * bytespp + 1] = px.1;
            frame[j*img.width()*bytespp + i * bytespp + 2] = px.2;
        }
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
}*/



fn main() {
    println!("init");
    unistd::setsid().expect("setsid failed");    
    unsafe {
        libc::putenv(CString::new("HOME=/").unwrap().into_raw());
        libc::putenv(CString::new("PATH=/sbin:/bin:/usr/sbin:/usr/bin").unwrap().into_raw());
        libc::putenv(CString::new("SHELL=/bin/sh").unwrap().into_raw());
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
