use std::{
    ffi::c_void,
    sync::{Mutex, Once},
};

use log::{error, info};
use mhw_toolkit::{
    game::{
        address,
        hooks::{CallbackPosition, HookHandle},
    },
    game_util::{self, SystemMessageColor},
};
use windows::Win32::{
    Foundation::{BOOL, TRUE},
    System::{
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
    },
};

mod logger {
    use log::LevelFilter;
    use mhw_toolkit::logger::MHWLogger;
    use once_cell::sync::Lazy;

    static LOGGER: Lazy<MHWLogger> = Lazy::new(|| MHWLogger::new(env!("CARGO_PKG_NAME")));

    pub fn init_log() {
        log::set_logger(&*LOGGER).unwrap();
        log::set_max_level(LevelFilter::Debug);
    }
}

static MAIN_THREAD_ONCE: Once = Once::new();

// .text:0000000141CC51B0 48 83 EC 68                                sub     rsp, 68h
// .text:0000000141CC51B4 83 B9 80 22 01 00 0F                       cmp     dword ptr [rcx+12280h], 0Fh
// .text:0000000141CC51BB 75 59                                      jnz     short loc_141CC5216  ; nop there or reverse the condition to force behemoth damage display
// .text:0000000141CC51BD 8B 84 24 B0 00 00 00                       mov     eax, [rsp+68h+arg_40]
// .text:0000000141CC51C4 C6 44 24 50 00                             mov     [rsp+68h+var_18], 0
// .text:0000000141CC51C9 C7 44 24 48 00 00 00 00                    mov     [rsp+68h+var_20], 0
// .text:0000000141CC51D1 89 44 24 40                                mov     [rsp+68h+var_28], eax
// .text:0000000141CC51D5 0F B6 84 24 A8 00 00 00                    movzx   eax, [rsp+68h+arg_38]
// .text:0000000141CC51DD 88 44 24 38                                mov     [rsp+68h+var_30], al
// .text:0000000141CC51E1 8B 84 24 98 00 00 00                       mov     eax, [rsp+68h+arg_28]
// .text:0000000141CC51E8 89 44 24 30                                mov     [rsp+68h+var_38], eax
// .text:0000000141CC51EC 8B 84 24 90 00 00 00                       mov     eax, [rsp+68h+arg_20]
// .text:0000000141CC51F3 89 44 24 28                                mov     [rsp+68h+var_40], eax
// .text:0000000141CC51F7 44 89 4C 24 20                             mov     [rsp+68h+var_48], r9d
// .text:0000000141CC51FC 4D 8B C8                                   mov     r9, r8
// .text:0000000141CC51FF 44 8B C2                                   mov     r8d, edx
// .text:0000000141CC5202 48 8B D1                                   mov     rdx, rcx
// .text:0000000141CC5205 48 8B 0D F4 D1 4F 03                       mov     rcx, cs:qword_1451C2400
// .text:0000000141CC520C E8 FF D3 E1 FF                             call    DrawBehemothDamage
// .text:0000000141CC5211 48 83 C4 68                                add     rsp, 68h
// .text:0000000141CC5215 C3                                         retn
// .text:0000000141CC5216                            ; ---------------------------------------------------------------------------
// .text:0000000141CC5216
// .text:0000000141CC5216                            loc_141CC5216:                          ; CODE XREF: DrawDamage+B↑j
// .text:0000000141CC5216 48 83 C4 68                                add     rsp, 68h
// .text:0000000141CC521A E9 21 00 00 00                             jmp     DrawGeneralDamage
// .text:0000000141CC521A                            DrawDamage      endp
// .text:0000000141CC521A
// .text:0000000141CC521A                            ; ---------------------------------------------------------------------------

/// VirtualProtect RAII object
struct VirtualProtectGuard {
    old_protect: PAGE_PROTECTION_FLAGS,
    new_protect: PAGE_PROTECTION_FLAGS,
    ptr: *const c_void,
    dwsize: usize,
}

impl Drop for VirtualProtectGuard {
    fn drop(&mut self) {
        if let Err(e) = self.reset_protect() {
            error!("Failed to reset memory protection: {}", e);
        }
    }
}

impl VirtualProtectGuard {
    pub fn new(
        ptr: *const c_void,
        dwsize: usize,
        new_protect: PAGE_PROTECTION_FLAGS,
    ) -> Result<Self, String> {
        let mut this = Self {
            old_protect: PAGE_PROTECTION_FLAGS::default(),
            new_protect,
            ptr,
            dwsize,
        };
        this.set_protect()
            .map_err(|e| format!("Failed to set memory protection: {}", e))?;

        Ok(this)
    }

    fn set_protect(&mut self) -> Result<(), String> {
        unsafe {
            VirtualProtect(
                self.ptr as *const _,
                self.dwsize,
                self.new_protect,
                &mut self.old_protect,
            )
        }
        .map_err(|e| e.to_string())
    }

    fn reset_protect(&self) -> Result<(), String> {
        unsafe {
            VirtualProtect(
                self.ptr as *const _,
                self.dwsize,
                self.old_protect,
                &mut PAGE_PROTECTION_FLAGS::default(),
            )
        }
        .map_err(|e| e.to_string())
    }
}

struct BehemothDamage {
    pub enabled: bool,
    patch_addr: usize,
}

impl BehemothDamage {
    pub fn new() -> Result<Self, String> {
        let draw_dmg_func_addr = address::AddressRepository::get_instance()
            .lock()
            .unwrap()
            .get_address(address::player::DrawDamage)?;
        let patch_addr = draw_dmg_func_addr + 11;

        Ok(Self {
            enabled: false,
            patch_addr,
        })
    }

    pub fn enable(&mut self) -> Result<(), String> {
        let patch_ptr = self.patch_addr as *mut u8;
        let _p_guard = VirtualProtectGuard::new(patch_ptr as *const _, 2, PAGE_EXECUTE_READWRITE)?;

        let jmp_bytes = unsafe { std::slice::from_raw_parts_mut(patch_ptr, 2) };
        if jmp_bytes[0] == 0x74 {
            // already changed, skip
            return Ok(());
        }
        if jmp_bytes[0] != 0x75 {
            return Err(format!(
                "Expected JNZ opcode at patch address 0x{:X}, found {:X}",
                patch_ptr as usize, jmp_bytes[0]
            ));
        }

        jmp_bytes[0] = 0x74; // JNZ -> JE
        self.enabled = true;

        Ok(())
    }

    pub fn disable(&mut self) -> Result<(), String> {
        let patch_ptr = self.patch_addr as *mut u8;
        let _p_guard = VirtualProtectGuard::new(patch_ptr as *const _, 2, PAGE_EXECUTE_READWRITE)?;

        let jmp_bytes = unsafe { std::slice::from_raw_parts_mut(patch_ptr, 2) };
        if jmp_bytes[0] == 0x75 {
            // already changed, skip
            return Ok(());
        }
        if jmp_bytes[0] != 0x74 {
            return Err(format!(
                "Expected JE opcode at patch address 0x{:X}, found {:X}",
                patch_ptr as usize, jmp_bytes[0]
            ));
        }

        jmp_bytes[0] = 0x75; // JE -> JNZ
        self.enabled = false;

        Ok(())
    }

    pub fn switch(&mut self) -> Result<(), String> {
        if self.enabled {
            self.disable()
        } else {
            self.enable()
        }
    }
}

#[inline]
fn show_primary_info_msg(msg: &str) {
    info!("{}", msg);
    game_util::show_system_message(msg, SystemMessageColor::Purple)
}

fn main_entry() -> Result<(), String> {
    logger::init_log();

    info!(
        "Behemoth Damage plugin version: {}",
        env!("CARGO_PKG_VERSION")
    );

    let behemoth_damage = Mutex::new(BehemothDamage::new()?);
    // enable at start
    behemoth_damage.lock().unwrap().enable()?;

    // user input
    mhw_toolkit::game::hooks::InputDispatchHook::new()
        .set_hook(CallbackPosition::Before, move |input| {
            if !input.starts_with("/behemoth") {
                return;
            }

            let args = input.split_whitespace().collect::<Vec<_>>();
            if args.len() == 1 {
                let mut _behemoth_damage = behemoth_damage.lock().unwrap();
                if let Err(e) = _behemoth_damage.switch() {
                    error!("Failed to switch behemoth damage mode: {}", e);
                } else if _behemoth_damage.enabled {
                    show_primary_info_msg("Behemoth damage mode on");
                } else {
                    show_primary_info_msg("Behemoth damage mode off");
                }
            } else if args.len() >= 2 {
                let cmd = args[1];
                match cmd {
                    "on" | "enable" => {
                        if let Err(e) = behemoth_damage.lock().unwrap().enable() {
                            error!("Failed to enable behemoth damage mode: {}", e);
                        } else {
                            show_primary_info_msg("Behemoth damage mode on");
                        }
                    }
                    "off" | "disable" => {
                        if let Err(e) = behemoth_damage.lock().unwrap().disable() {
                            error!("Failed to disable behemoth damage mode: {}", e);
                        } else {
                            show_primary_info_msg("Behemoth damage mode off");
                        }
                    }
                    _ => {
                        error!("Invalid command: {}", cmd);
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_: usize, call_reason: u32, _: usize) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            MAIN_THREAD_ONCE.call_once(|| {
                if let Err(e) = main_entry() {
                    error!("{}", e);
                }
            });
        }
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    TRUE
}
