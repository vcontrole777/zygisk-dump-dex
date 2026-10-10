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

            if !find {
                self.api
                    .set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
                return Ok(());
            }
            info!("dump {}", package_name);
            let open_common = dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader10OpenCommonENSt3__110shared_ptrINS_16DexFileContainerEEEPKhmRKNS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS1_8optionalIjEEPKNS_10OatDexFileEbbPSC_PNS_22DexFileLoaderErrorCodeE")
                .ok_or_else(|| anyhow::anyhow!("resolve symbol error"))?;
            info!("open_common addr: {:x}", open_common as usize);
            unsafe {
                OLD_OPEN_COMMON =
                    dobby_rs::hook(open_common, new_open_common_wrapper as Address)? as usize
            };
            // segunda sobrecarga: OpenCommon(base, size, cdex_base, cdex_size, ...) —
            // ABI limpa: x0=this, x1=base, x2=size
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE") {
                Some(oc2) => {
                    info!("open_common2 addr: {:x}", oc2 as usize);
                    unsafe {
                        OLD_OPEN_COMMON2 =
                            dobby_rs::hook(oc2, new_open_common2_wrapper as Address)? as usize
                    };
                }
                None => error!("open_common2 não resolvido — seguindo só com overload 1"),
            }
            // CreateMemoryDexStorage(base, size) — x0=this, x1=base, x2=size
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader22CreateMemoryDexStorageEPKhm") {
                Some(cmds) => {
                    info!("cmds_sz addr: {:x}", cmds as usize);
                    unsafe {
                        OLD_CMDS_SZ =
                            dobby_rs::hook(cmds, new_cmds_sz_wrapper as Address)? as usize
                    };
                }
                None => error!("CreateMemoryDexStorage(size) não resolvido"),
            }
            // CreateMemoryDexStorage(begin, end) — x0=this, x1=begin, x2=end
            match dobby_rs::resolve_symbol("libdexfile.so", "_ZN3art13DexFileLoader22CreateMemoryDexStorageEPKhS2_") {
                Some(cmdp) => {
                    info!("cmds_ptr addr: {:x}", cmdp as usize);
                    unsafe {
                        OLD_CMDS_PTR =
                            dobby_rs::hook(cmdp, new_cmds_ptr_wrapper as Address)? as usize
                    };
                }
                None => error!("CreateMemoryDexStorage(end) não resolvido"),
            }

            Ok(())
        };
        if let Err(e) = inner() {
            error!("pre_app_specialize error: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _args: &AppSpecializeArgs) {}

    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}

    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);
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

extern "C" fn new_open_common(base: usize, size: usize) {
    info!("find dex: base=0x{:x}, size=0x{:x}", base, size);

    // só despeja buffers que são DEX/CompactDEX de verdade (guarda contra ABI errada)
    let head = unsafe { std::slice::from_raw_parts(base as *const u8, 4.min(size)) };
    if head != b"dex\n" && head != b"cdex" {
        info!("skip: magic inválida ({:02x?})", head);
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
