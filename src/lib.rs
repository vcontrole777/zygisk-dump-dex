use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info, trace};
use nix::{fcntl::OFlag, sys::stat::Mode};
use std::arch::naked_asm;
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};

struct MyModule {
    api: Api,
    env: JNIEnv<'static>,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni::sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("dump_dex"),
        );
        unsafe { GLOBAL_ENV = env as usize; }
        let env = unsafe { JNIEnv::from_raw(env).unwrap() };
        Self { api, env }
    }
    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let mut inner = || -> anyhow::Result<()> {
            let package_name = self
                .env
                .get_string(&unsafe { jni::objects::JString::from_raw(*args.nice_name) })?
                .to_string_lossy()
                .to_string();
            trace!("pre_app_specialize: package_name: {}", package_name);
            let module_dir = self
                .api
                .get_module_dir()
                .ok_or_else(|| anyhow::anyhow!("get_module_dir error"))?;
            let mut list_file = unsafe {
                File::from_raw_fd(nix::fcntl::openat(
                    Some(module_dir.as_raw_fd()),
                    "list.txt",
                    OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?)
            };
            let mut file_content = String::new();
            list_file.read_to_string(&mut file_content)?;

            let find: bool = file_content
                .split("\n")
                .any(|item| item.trim() == package_name);
            unsafe { std::ptr::addr_of_mut!(PKG_MATCH).write(find); }

            if !find {
                self.api
                    .set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
                return Ok(());
            }
            flog(&format!("DUMP-MATCH {}", package_name));
            info!("dump {}", package_name);
            let open_common = dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader10OpenCommonENSt3__110shared_ptrINS_16DexFileContainerEEEPKhmRKNS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS1_8optionalIjEEPKNS_10OatDexFileEbbPSC_PNS_22DexFileLoaderErrorCodeE")
                .ok_or_else(|| anyhow::anyhow!("resolve symbol error"))?;
            flog(&format!("ARM oc1(libdexfile) @{:x}", open_common as usize));
            unsafe {
                OLD_OPEN_COMMON =
                    dobby_rs::hook(open_common, new_open_common_wrapper as Address)? as usize
            };
            // segunda sobrecarga: OpenCommon(base, size, cdex_base, cdex_size, ...) —
            // ABI limpa: x0=this, x1=base, x2=size
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE") {
                Some(oc2) => {
                    flog(&format!("ARM oc2(libdexfile) @{:x}", oc2 as usize));
                    unsafe {
                        OLD_OPEN_COMMON2 =
                            dobby_rs::hook(oc2, new_open_common2_wrapper as Address)? as usize
                    };
                }
                None => flog("FAIL resolve oc2"),
            }
            // CreateMemoryDexStorage(base, size) — x0=this, x1=base, x2=size
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader22CreateMemoryDexStorageEPKhm") {
                Some(cmds) => {
                    flog(&format!("ARM cmds_sz(libdexfile) @{:x}", cmds as usize));
                    unsafe {
                        OLD_CMDS_SZ =
                            dobby_rs::hook(cmds, new_cmds_sz_wrapper as Address)? as usize
                    };
                }
                None => flog("FAIL resolve cmds_sz"),
            }
            // CreateMemoryDexStorage(begin, end) — x0=this, x1=begin, x2=end
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader22CreateMemoryDexStorageEPKhS2_") {
                Some(cmdp) => {
                    flog(&format!("ARM cmds_ptr(libdexfile) @{:x}", cmdp as usize));
                    unsafe {
                        OLD_CMDS_PTR =
                            dobby_rs::hook(cmdp, new_cmds_ptr_wrapper as Address)? as usize
                    };
                }
                None => flog("FAIL resolve cmds_ptr"),
            }
            Ok(())
        };
        if let Err(e) = inner() {
            flog(&format!("pre_app error: {:?}", e));
            error!("pre_app_specialize error: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _args: &AppSpecializeArgs) {
        // SÓ no pacote-alvo (o gate do pre gravou PKG_MATCH). Sem isso o hook
        // patcheava a vtable JNI em TODOS os processos (SystemUI crash-loop —
        // bug da run7). Contexto app completo: logs gravam, e ainda é antes do
        // attachBaseContext do DP.
        let m = unsafe { std::ptr::addr_of!(PKG_MATCH).read() };
        if m { hook_jni_define_class(); }
    }

    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}

    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);
static mut GLOBAL_ENV: usize = 0;
static mut PKG_MATCH: bool = false;
static mut OLD_OPEN_COMMON: usize = 0;
static mut OLD_OPEN_COMMON2: usize = 0;
static mut OLD_CMDS_SZ: usize = 0;
static mut OLD_CMDS_PTR: usize = 0;

#[unsafe(naked)]
pub extern "C" fn new_cmds_sz_wrapper() {
    naked_asm!(
        r#"
            sub sp, sp, 0x280
            stp x29, x30, [sp, #0]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            stp x4, x5, [sp, #0x30]
            stp x6, x7, [sp, #0x40]
            stp x8, x9, [sp, #0x50]

            mov x0, x1
            mov x1, x2
            bl {new_open_common}

            ldp x29, x30, [sp, #0]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            ldp x4, x5, [sp, #0x30]
            ldp x6, x7, [sp, #0x40]
            ldp x8, x9, [sp, #0x50]
            add sp, sp, #0x280
            adrp x16, {old}
            ldr x16, [x16, #:lo12:{old}]
            br x16"#,
        new_open_common = sym new_open_common,
        old = sym OLD_CMDS_SZ,
    );
}

#[unsafe(naked)]
pub extern "C" fn new_cmds_ptr_wrapper() {
    naked_asm!(
        r#"
            sub sp, sp, 0x280
            stp x29, x30, [sp, #0]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            stp x4, x5, [sp, #0x30]
            stp x6, x7, [sp, #0x40]
            stp x8, x9, [sp, #0x50]

            mov x0, x1
            sub x1, x2, x1
            bl {new_open_common}

            ldp x29, x30, [sp, #0]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            ldp x4, x5, [sp, #0x30]
            ldp x6, x7, [sp, #0x40]
            ldp x8, x9, [sp, #0x50]
            add sp, sp, #0x280
            adrp x16, {old}
            ldr x16, [x16, #:lo12:{old}]
            br x16"#,
        new_open_common = sym new_open_common,
        old = sym OLD_CMDS_PTR,
    );
}

#[unsafe(naked)]
pub extern "C" fn new_open_common2_wrapper() {
    naked_asm!(
        r#"
            sub sp, sp, 0x280
            stp x29, x30, [sp, #0]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            stp x4, x5, [sp, #0x30]
            stp x6, x7, [sp, #0x40]
            stp x8, x9, [sp, #0x50]

            mov x0, x1
            mov x1, x2
            bl {new_open_common}

            ldp x29, x30, [sp, #0]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            ldp x4, x5, [sp, #0x30]
            ldp x6, x7, [sp, #0x40]
            ldp x8, x9, [sp, #0x50]
            add sp, sp, #0x280
            adrp x16, {old_open_common2}
            ldr x16, [x16, #:lo12:{old_open_common2}]
            br x16"#,
        new_open_common = sym new_open_common,
        old_open_common2 = sym OLD_OPEN_COMMON2,
    );
}

#[unsafe(naked)]
pub extern "C" fn new_open_common_wrapper() {
    naked_asm!(
        r#"
            sub sp, sp, 0x280
            stp x29, x30, [sp, #0]
            stp x0, x1, [sp, #0x10]
            stp x2, x3, [sp, #0x20]
            stp x4, x5, [sp, #0x30]
            stp x6, x7, [sp, #0x40]
            stp x8, x9, [sp, #0x50]

            mov x0, x1
            mov x1, x2
            bl {new_open_common}

            ldp x29, x30, [sp, #0]
            ldp x0, x1, [sp, #0x10]
            ldp x2, x3, [sp, #0x20]
            ldp x4, x5, [sp, #0x30]
            ldp x6, x7, [sp, #0x40]
            ldp x8, x9, [sp, #0x50]
            add sp, sp, 0x280
            adrp x16, {old_open_common}
            ldr x16, [x16, #:lo12:{old_open_common}]
            br x16"#,
        new_open_common = sym new_open_common,
        old_open_common = sym OLD_OPEN_COMMON,
    );
}

// log em ARQUIVO — o logcat não mostra nada deste módulo (WHY ainda unknown)
fn flog(msg: &str) {
    use std::io::Write;
    let pkg = std::fs::read_to_string("/proc/self/cmdline")
        .unwrap_or_default()
        .split('\0')
        .next()
        .unwrap_or("unknown")
        .to_string();
    let _ = std::fs::create_dir_all(format!("/data/data/{}/dexes", pkg));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("/data/data/{}/dexes/module.log", pkg))
    {
        let _ = writeln!(f, "{}", msg);
    }
}

static mut STATUS_DUMPED: bool = false;

extern "C" fn new_open_common(base: usize, size: usize) {
    unsafe {
        if !std::ptr::addr_of!(STATUS_DUMPED).read() {
            std::ptr::addr_of_mut!(STATUS_DUMPED).write(true);
            let dc = std::ptr::addr_of!(OLD_DEFINE_CLASS).read();
            let ndb = std::ptr::addr_of!(OLD_NDB).read();
            let oc1 = std::ptr::addr_of!(OLD_OPEN_COMMON).read();
            flog(&format!("STATUS: oc1={:x} dc_hook={:x} ndb_hook={:x}", oc1, dc, ndb));
        }
    }
    flog(&format!("find dex: base=0x{:x} size=0x{:x}", base, size));

    // só despeja buffers que são DEX/CompactDEX de verdade (guarda contra ABI errada)
    let head = unsafe { std::slice::from_raw_parts(base as *const u8, 4.min(size)) };
    if head != b"dex\n" && head != b"cdex" {
        flog(&format!("skip: magic {:02x?} base=0x{:x}", head, base));
        return;
    }

    let dex_data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    let package = match std::fs::read_to_string("/proc/self/cmdline") {
        Ok(cmdline) => cmdline,
        Err(e) => {
            error!("read cmdline error: {:?}", e);
            return;
        }
    };
    if package.is_empty() {
        error!("package name is empty");
        return;
    }
    let Some(package) = package.split('\0').next() else {
        error!("package name split by zero error: {}", package);
        return;
    };

    let dir = format!("/data/data/{}/dexes", package);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!("create dir error: {:?}", e);
        return;
    }

    let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
    let mut digest = crc.digest();
    digest.update(dex_data);

    let file_name = format!("/data/data/{}/dexes/{:08x}.dex", package, digest.finalize());
    if let Err(e) = std::fs::write(file_name, dex_data) {
        error!("write file error: {:?}", e);
    }
}

// ================= JNI DefineClass hook (vtable slot 5) =================
// DexProtector define classes individualmente via env->DefineClass com mini-dexes.
// Slot 5 da JNIEnv function table = DefineClass.
use std::ffi::{c_char, c_void, CStr};

static mut OLD_DEFINE_CLASS: usize = 0;
static mut OLD_NDB: usize = 0;

fn hook_jni_define_class() {
    unsafe {
        let e = std::ptr::addr_of!(GLOBAL_ENV).read() as *mut *mut *mut c_void;
        if e.is_null() { flog("defineclass: sem env"); return; }
        let tbl = *e; // functions
        if tbl.is_null() { flog("defineclass: table null"); return; }
        let slot = tbl.add(5);
        // página RW pra escrever na table (normalmente RO em libart .data/.rodata? é .data do gJniNativeInterface — pode ser RO)
        let page = (tbl as usize) & !0xfff;
        let r = libc::mprotect(page as *mut c_void, 0x4000, libc::PROT_READ | libc::PROT_WRITE);
        flog(&format!("defineclass: tbl={:p} slot5={:p} mprotect={}", tbl, *slot, r));
        if r != 0 { return; }
        let oldv = *slot as usize;
        std::ptr::addr_of_mut!(OLD_DEFINE_CLASS).write(oldv);
        *slot = my_define_class as *mut c_void;
        flog(&format!("defineclass: HOOKED (old={:x})", oldv));
        // slot 227 = NewDirectByteBuffer(env, addr, cap)
        let slot227 = tbl.add(227);
        let old227 = *slot227 as usize;
        std::ptr::addr_of_mut!(OLD_NDB).write(old227);
        *slot227 = my_new_direct_buffer as *mut c_void;
        flog(&format!("newdirectbb: HOOKED (old={:x})", old227));
    }
}

extern "C" fn my_define_class(
    env: *mut c_void,
    name: *const c_char,
    loader: *mut c_void,
    buf: *const u8,
    len: i32,
) -> *mut c_void {
    unsafe {
        let nm = if name.is_null() { "null".to_string() } else {
            CStr::from_ptr(name).to_string_lossy().to_string()
        };
        if len > 4 && !buf.is_null() {
            let head = std::slice::from_raw_parts(buf, 4);
            if head == b"dex\n" || head == b"cdex" {
                flog(&format!("DEFINECLASS dex: {} len={}", nm, len));
                dump_buf(buf, len as usize, &nm);
            } else {
                flog(&format!("DEFINECLASS nãodex: {} len={} magic={:02x?}", nm, len, head));
            }
        } else {
            flog(&format!("DEFINECLASS degenerate: {} len={}", nm, len));
        }
        let orig: extern "C" fn(*mut c_void, *const c_char, *mut c_void, *const u8, i32) -> *mut c_void =
            std::mem::transmute(std::ptr::addr_of!(OLD_DEFINE_CLASS).read());
        orig(env, name, loader, buf, len)
    }
}

fn dump_buf(buf: *const u8, len: usize, tag: &str) {
    unsafe {
        let data = std::slice::from_raw_parts(buf, len);
        let pkg = std::fs::read_to_string("/proc/self/cmdline")
            .unwrap_or_default().split('\0').next().unwrap_or("unknown").to_string();
        let dir = format!("/data/data/{}/dexes", pkg);
        let _ = std::fs::create_dir_all(&dir);
        let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
        let mut dg = crc.digest();
        dg.update(data);
        let fname = format!("{}/dc_{:08x}_{}.dex", dir, dg.finalize(), tag.replace('/', "_"));
        if std::path::Path::new(&fname).exists() { return; }
        if let Err(e) = std::fs::write(&fname, data) {
            flog(&format!("dump err: {}", e));
        }
    }
}

extern "C" fn my_new_direct_buffer(env: *mut c_void, addr: *mut c_void, cap: i64) -> *mut c_void {
    unsafe {
        if !addr.is_null() && cap > 4 {
            let b = addr as *const u8;
            let head = std::slice::from_raw_parts(b, 4);
            if head == b"dex\n" || head == b"cdex" {
                flog(&format!("NDB-DEX: addr={:p} cap={:x}", addr, cap));
                dump_buf(b, cap as usize, "ndb");
            }
        }
        let orig: extern "C" fn(*mut c_void, *mut c_void, i64) -> *mut c_void =
            std::mem::transmute(std::ptr::addr_of!(OLD_NDB).read());
        orig(env, addr, cap)
    }
}
