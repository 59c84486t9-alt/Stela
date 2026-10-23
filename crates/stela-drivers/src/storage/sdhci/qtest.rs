//! Opt-in real paused QEMU SDHCI PIO qualification. Uses an authored sparse
//! card image; no guest CPU or operating system is executed by this fixture.
extern crate std;
use super::*;
use crate::bus::dma::RegionAllocator;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Wire {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    log: File,
}
impl Wire {
    fn exchange(&mut self, request: &str) -> String {
        writeln!(self.log, "> {request}").unwrap();
        writeln!(self.writer, "{request}").unwrap();
        self.writer.flush().unwrap();
        let mut reply = String::new();
        self.reader.read_line(&mut reply).unwrap();
        writeln!(self.log, "< {}", reply.trim()).unwrap();
        assert!(reply.starts_with("OK"), "{request}: {reply}");
        reply
    }
    fn read(&mut self, command: &str, address: u64) -> u64 {
        let reply = self.exchange(&format!("{command} {address:#x}"));
        u64::from_str_radix(
            reply
                .split_whitespace()
                .nth(1)
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap()
    }
    fn write(&mut self, command: &str, address: u64, value: u64) {
        self.exchange(&format!("{command} {address:#x} {value:#x}"));
    }
}
struct Port {
    wire: Rc<RefCell<Wire>>,
    base: u64,
}
impl Registers for Port {
    fn read8(&mut self, at: usize) -> u8 {
        self.wire.borrow_mut().read("readb", self.base + at as u64) as u8
    }
    fn read16(&mut self, at: usize) -> u16 {
        self.wire.borrow_mut().read("readw", self.base + at as u64) as u16
    }
    fn read32(&mut self, at: usize) -> u32 {
        self.wire.borrow_mut().read("readl", self.base + at as u64) as u32
    }
    fn write8(&mut self, at: usize, value: u8) {
        self.wire
            .borrow_mut()
            .write("writeb", self.base + at as u64, u64::from(value));
    }
    fn write16(&mut self, at: usize, value: u16) {
        self.wire
            .borrow_mut()
            .write("writew", self.base + at as u64, u64::from(value));
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.wire
            .borrow_mut()
            .write("writel", self.base + at as u64, u64::from(value));
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires a caller-authorized paused64MiB QEMU SDHCI fixture"]
fn real_paused_qemu_sd_card_runs_native_initialization_pio_and_durable_io() {
    let binary = std::env::var_os("STELA_SDHCI_QEMU").expect("set STELA_SDHCI_QEMU");
    let output = PathBuf::from(
        std::env::var_os("STELA_SDHCI_QTEST_OUTPUT")
            .expect("set STELA_SDHCI_QTEST_OUTPUT to fresh directory"),
    );
    std::fs::create_dir(&output).unwrap();
    let image = output.join("card.img");
    let image_file = File::create(&image).unwrap();
    image_file.set_len(4 * 1024 * 1024 * 1024).unwrap();
    drop(image_file);
    let socket = output.join("qtest.sock");
    // Authored standard capabilities: v3,3.3V,100MHz,high-speed,PIO. The
    // emulator's actual register advertises this profile; no driver read is
    // rewritten. ADMA remains independently modeled, outside this PIO receipt.
    let arguments = vec![
        String::from("-machine"),
        "q35".into(),
        "-accel".into(),
        "tcg,thread=single".into(),
        "-m".into(),
        "64M".into(),
        "-S".into(),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        "-qtest".into(),
        format!("unix:{},server=on,wait=off", socket.display()),
        "-device".into(),
        "sdhci-pci,id=sdhci,addr=06.0,sd-spec-version=3,capareg=0x01206480".into(),
        "-drive".into(),
        format!("if=none,id=card,format=raw,file={}", image.display()),
        "-device".into(),
        "sd-card,drive=card".into(),
    ];
    std::fs::write(
        output.join("arguments.txt"),
        format!(
            "binary={}\n{}\n",
            PathBuf::from(&binary).display(),
            arguments.join("\n")
        ),
    )
    .unwrap();
    let mut process = Process(
        Command::new(binary)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                File::create(output.join("stdout.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(output.join("stderr.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let writer = loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => break stream,
            Err(error) => {
                assert!(Instant::now() < deadline, "QEMU qtest socket: {error}");
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "QEMU startup failed; inspect stderr.log"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    writer
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writer
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let reader = BufReader::new(writer.try_clone().unwrap());
    let wire = Rc::new(RefCell::new(Wire {
        reader,
        writer,
        log: File::create(output.join("protocol.log")).unwrap(),
    }));
    let pci = |wire: &Rc<RefCell<Wire>>, offset: u32, value: Option<u32>| -> u32 {
        let mut wire = wire.borrow_mut();
        wire.write("outl", 0xcf8, u64::from(0x8000_0000 | 6 << 11 | offset));
        if let Some(value) = value {
            wire.write("outl", 0xcfc, u64::from(value));
            value
        } else {
            wire.read("inl", 0xcfc) as u32
        }
    };
    let identity = pci(&wire, 0, None);
    assert_ne!(identity, u32::MAX);
    assert_eq!(pci(&wire, 8, None) >> 8, 0x080501);
    let base = 0xe000_0000;
    pci(&wire, 0x10, Some(base));
    pci(&wire, 4, Some(6));
    let actual_capabilities = wire
        .borrow_mut()
        .read("readl", u64::from(base) + CAPABILITIES as u64);
    assert_eq!(actual_capabilities, 0x01206480);
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: PIO profile never lets QEMU DMA into this native fixture RAM.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let mut host = Host::new(
        Box::new(Port {
            wire: wire.clone(),
            base: u64::from(base),
        }),
        Clock {
            ticks_per_microsecond: 10_000,
        },
        "real paused QEMU SDHCI".into(),
        &mut dma,
        Profile::Standard,
    )
    .unwrap();
    let mut card = host.poll().unwrap().unwrap();
    assert_eq!(card.identity().blocks, 4 * 1024 * 1024 * 1024 / 512);
    let mut poison = vec![0xa5; 2 * 512];
    card.read(0, &mut poison).unwrap();
    assert_eq!(poison, vec![0; 1024]);
    let data: Vec<u8> = (0..1024).map(|i| (i ^ (i >> 3)) as u8).collect();
    card.write(33, &data).unwrap();
    card.flush().unwrap();
    poison.fill(0xa5);
    card.read(33, &mut poison).unwrap();
    assert_eq!(poison, data);
    let receipt = format!(
        "identity={:?}\ninfo={:?}\ncapabilities={:?}\nPIO read_zero=1024 write_lba=33 write_bytes=1024 flush=ack readback=equal guest_cpu=paused ram=64MiB\n",
        card.identity(),
        card.info(),
        host.info()
    );
    std::fs::write(output.join("receipt.txt"), receipt).unwrap();
    drop(card);
    drop(host);
    drop(wire);
    drop(process);
    let mut file = OpenOptions::new().read(true).open(image).unwrap();
    file.seek(SeekFrom::Start(33 * 512)).unwrap();
    let mut actual = vec![0; 1024];
    file.read_exact(&mut actual).unwrap();
    assert_eq!(actual, data);
}
