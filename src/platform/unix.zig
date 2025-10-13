//! Unix/macOS OS Abstraction Layer
//!
//! Provides Unix/POSIX system primitives for the SoftEther VPN client:
//! - Thread synchronization (locks, events, thread management)
//! - File I/O operations
//! - Time and memory utilities
//! - Atomic operations
//!
//! This module replaces unix_bridge.c with type-safe Zig implementations
//! while maintaining C FFI compatibility through exported functions.

const std = @import("std");
const builtin = @import("builtin");

// Forward declare SoftEther types we need (they'll be provided at link time)
pub const LOCK = extern struct {
    pData: ?*anyopaque,
    Ready: bool,
};

pub const EVENT = extern struct {
    pData: ?*anyopaque,
};

pub const THREAD = extern struct {
    ref: ?*anyopaque,
    thread_proc: ?*const fn (?*THREAD, ?*anyopaque) callconv(.c) void,
    param: ?*anyopaque,
    pData: ?*anyopaque,
};

pub const SYSTEMTIME = extern struct {
    wYear: c_ushort,
    wMonth: c_ushort,
    wDayOfWeek: c_ushort = 0,
    wDay: c_ushort,
    wHour: c_ushort,
    wMinute: c_ushort,
    wSecond: c_ushort,
    wMilliseconds: c_ushort,
};

pub const UINT = c_uint;
pub const UINT64 = c_ulonglong;

// External SoftEther functions we need
extern "C" fn ZeroMalloc(size: usize) ?*anyopaque;
extern "C" fn Free(ptr: ?*anyopaque) void;
extern "C" fn NewRef() ?*anyopaque;
extern "C" fn AddRef(ref: ?*anyopaque) void;

// C standard library functions
extern "C" fn malloc(size: usize) ?*anyopaque;
extern "C" fn realloc(ptr: ?*anyopaque, size: usize) ?*anyopaque;
extern "C" fn free(ptr: ?*anyopaque) void;
extern "C" fn fopen(filename: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern "C" fn fclose(stream: *anyopaque) c_int;
extern "C" fn fwrite(ptr: *const anyopaque, size: usize, nmemb: usize, stream: *anyopaque) usize;
extern "C" fn fread(ptr: *anyopaque, size: usize, nmemb: usize, stream: *anyopaque) usize;
extern "C" fn fflush(stream: *anyopaque) c_int;
extern "C" fn ftell(stream: *anyopaque) c_long;
extern "C" fn fseek(stream: *anyopaque, offset: c_long, whence: c_int) c_int;
extern "C" fn unlink(path: [*:0]const u8) c_int;
extern "C" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern "C" fn rmdir(path: [*:0]const u8) c_int;
extern "C" fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern "C" fn usleep(usec: c_uint) c_int;
extern "C" fn gettimeofday(tv: *timeval, tz: ?*anyopaque) c_int;
extern "C" fn time(tloc: ?*c_long) c_long;
extern "C" fn localtime_r(timep: *const c_long, result: *tm) ?*tm;
extern "C" fn pthread_mutex_init(mutex: *pthread_mutex_t, attr: ?*const anyopaque) c_int;
extern "C" fn pthread_mutex_lock(mutex: *pthread_mutex_t) c_int;
extern "C" fn pthread_mutex_unlock(mutex: *pthread_mutex_t) c_int;
extern "C" fn pthread_mutex_destroy(mutex: *pthread_mutex_t) c_int;
extern "C" fn pthread_cond_init(cond: *pthread_cond_t, attr: ?*const anyopaque) c_int;
extern "C" fn pthread_cond_broadcast(cond: *pthread_cond_t) c_int;
extern "C" fn pthread_cond_wait(cond: *pthread_cond_t, mutex: *pthread_mutex_t) c_int;
extern "C" fn pthread_cond_timedwait(cond: *pthread_cond_t, mutex: *pthread_mutex_t, abstime: *const timespec) c_int;
extern "C" fn pthread_cond_destroy(cond: *pthread_cond_t) c_int;
extern "C" fn pthread_create(thread: *pthread_t, attr: ?*const anyopaque, start_routine: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, arg: ?*anyopaque) c_int;
extern "C" fn pthread_join(thread: pthread_t, retval: ?*?*anyopaque) c_int;
extern "C" fn pthread_self() pthread_t;

// POSIX types
const pthread_mutex_t = extern struct {
    __sig: c_long = 0,
    __opaque: [56]u8 = undefined,
};

const pthread_cond_t = extern struct {
    __sig: c_long = 0,
    __opaque: [40]u8 = undefined,
};

const pthread_t = *anyopaque;

const timeval = extern struct {
    tv_sec: c_long,
    tv_usec: c_long,
};

const timespec = extern struct {
    tv_sec: c_long,
    tv_nsec: c_long,
};

const tm = extern struct {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: ?[*:0]const u8,
};

const FILE = anyopaque;
const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;
const ETIMEDOUT: c_int = 60; // errno value for timeout

// ============================================================================
// Lock Implementation (pthread mutex wrapper)
// ============================================================================

/// Create a new lock (mutex)
pub fn newLock() ?*LOCK {
    // Allocate LOCK structure using SoftEther's allocator
    const lock_mem = ZeroMalloc(@sizeOf(LOCK)) orelse return null;
    const lock_ptr: *LOCK = @ptrCast(@alignCast(lock_mem));

    // Allocate pthread mutex
    const mutex = malloc(@sizeOf(pthread_mutex_t)) orelse {
        Free(lock_mem);
        return null;
    };
    const mutex_ptr: *pthread_mutex_t = @ptrCast(@alignCast(mutex));

    // Initialize mutex
    const result = pthread_mutex_init(mutex_ptr, null);
    if (result != 0) {
        free(mutex);
        Free(lock_mem);
        return null;
    }

    lock_ptr.pData = mutex;
    lock_ptr.Ready = true;
    return lock_ptr;
}

/// Lock a mutex (blocking)
pub fn lock(lock_ptr: ?*LOCK) bool {
    const l = lock_ptr orelse return false;
    if (l.pData == null) return false;

    const mutex: *pthread_mutex_t = @ptrCast(@alignCast(l.pData));
    _ = pthread_mutex_lock(mutex);
    return true;
}

/// Unlock a mutex
pub fn unlock(lock_ptr: ?*LOCK) void {
    const l = lock_ptr orelse return;
    if (l.pData == null) return;

    const mutex: *pthread_mutex_t = @ptrCast(@alignCast(l.pData));
    _ = pthread_mutex_unlock(mutex);
}

/// Delete a lock and free resources
pub fn deleteLock(lock_ptr: ?*LOCK) void {
    const l = lock_ptr orelse return;

    if (l.pData) |mutex_ptr| {
        const mutex: *pthread_mutex_t = @ptrCast(@alignCast(mutex_ptr));
        _ = pthread_mutex_destroy(mutex);
        free(mutex_ptr);
    }

    Free(l);
}

// ============================================================================
// Event Implementation (pthread condition variable wrapper)
// ============================================================================

const PthreadEvent = extern struct {
    mutex: pthread_mutex_t,
    cond: pthread_cond_t,
    signaled: bool,
};

/// Initialize an event object
pub fn initEvent(event: ?*EVENT) void {
    const e = event orelse return;

    const pthread_event = malloc(@sizeOf(PthreadEvent)) orelse return;
    const pe: *PthreadEvent = @ptrCast(@alignCast(pthread_event));

    _ = pthread_mutex_init(&pe.mutex, null);
    _ = pthread_cond_init(&pe.cond, null);
    pe.signaled = false;

    e.pData = pthread_event;
}

/// Set an event to signaled state
pub fn setEvent(event: ?*EVENT) void {
    const e = event orelse return;
    const pe: *PthreadEvent = @ptrCast(@alignCast(e.pData orelse return));

    _ = pthread_mutex_lock(&pe.mutex);
    pe.signaled = true;
    _ = pthread_cond_broadcast(&pe.cond);
    _ = pthread_mutex_unlock(&pe.mutex);
}

/// Reset an event to non-signaled state
pub fn resetEvent(event: ?*EVENT) void {
    const e = event orelse return;
    const pe: *PthreadEvent = @ptrCast(@alignCast(e.pData orelse return));

    _ = pthread_mutex_lock(&pe.mutex);
    pe.signaled = false;
    _ = pthread_mutex_unlock(&pe.mutex);
}

/// Wait for an event to be signaled with optional timeout
/// Returns true if event was signaled, false if timeout
pub fn waitEvent(event: ?*EVENT, timeout_ms: UINT) bool {
    const e = event orelse return false;
    const pe: *PthreadEvent = @ptrCast(@alignCast(e.pData orelse return false));

    _ = pthread_mutex_lock(&pe.mutex);

    if (timeout_ms == 0xFFFFFFFF) {
        // Infinite wait
        while (!pe.signaled) {
            _ = pthread_cond_wait(&pe.cond, &pe.mutex);
        }
        _ = pthread_mutex_unlock(&pe.mutex);
        return true;
    } else {
        // Timed wait - match C implementation exactly
        var tv: timeval = undefined;
        _ = gettimeofday(&tv, null);

        var ts: timespec = undefined;
        ts.tv_sec = tv.tv_sec + @as(i64, @intCast(timeout_ms / 1000));

        // Calculate nanoseconds - use wrapping to avoid Zig's overflow detection
        const usec_i64: i64 = @intCast(tv.tv_usec);
        const timeout_ms_rem: i64 = @intCast(timeout_ms % 1000);
        const usec_ns: i64 = usec_i64 *% 1000;
        const timeout_ns: i64 = timeout_ms_rem *% 1000000;
        var total_ns: i64 = usec_ns +% timeout_ns;

        // Handle nanosecond overflow
        if (total_ns >= 1000000000) {
            ts.tv_sec += 1;
            total_ns -= 1000000000;
        }
        ts.tv_nsec = @intCast(total_ns);
        while (!pe.signaled) {
            const ret = pthread_cond_timedwait(&pe.cond, &pe.mutex, &ts);
            if (ret == ETIMEDOUT) {
                _ = pthread_mutex_unlock(&pe.mutex);
                return false;
            }
            // If any other error, also break out to avoid infinite loop
            if (ret != 0) {
                _ = pthread_mutex_unlock(&pe.mutex);
                return false;
            }
        }
        _ = pthread_mutex_unlock(&pe.mutex);
        return true;
    }
}

/// Free an event object and its resources
pub fn freeEvent(event: ?*EVENT) void {
    const e = event orelse return;
    const pe: *PthreadEvent = @ptrCast(@alignCast(e.pData orelse return));

    _ = pthread_mutex_destroy(&pe.mutex);
    _ = pthread_cond_destroy(&pe.cond);
    free(pe);
    e.pData = null;
}

// ============================================================================
// Thread Management
// ============================================================================

fn threadStartWrapper(param: ?*anyopaque) callconv(.c) ?*anyopaque {
    const thread: *THREAD = @ptrCast(@alignCast(param orelse return null));
    if (thread.thread_proc) |proc| {
        proc(thread, thread.param);
    }
    return null;
}

/// Initialize and start a thread
pub fn initThread(thread: ?*THREAD) bool {
    const t = thread orelse return false;

    // Initialize reference counter if needed
    if (t.ref == null or @intFromPtr(t.ref) < 0x10000) {
        t.ref = NewRef();
        if (t.ref == null) return false;
    }

    // Add reference for the thread
    AddRef(t.ref);

    // Allocate pthread_t
    const pthread_ptr = malloc(@sizeOf(pthread_t)) orelse return false;
    const pthread: *pthread_t = @ptrCast(@alignCast(pthread_ptr));

    // Create thread
    const result = pthread_create(pthread, null, threadStartWrapper, t);
    if (result != 0) {
        free(pthread_ptr);
        return false;
    }

    t.pData = pthread_ptr;
    return true;
}

/// Wait for a thread to complete
pub fn waitThread(thread: ?*THREAD) bool {
    const t = thread orelse return false;
    const pthread: *pthread_t = @ptrCast(@alignCast(t.pData orelse return false));

    _ = pthread_join(pthread.*, null);
    return true;
}

/// Free thread resources
pub fn freeThread(thread: ?*THREAD) void {
    const t = thread orelse return;

    if (t.pData) |pthread_ptr| {
        free(pthread_ptr);
        t.pData = null;
    }
}

/// Get current thread ID
pub fn threadId() UINT {
    const pthread = pthread_self();
    // Hash the pointer to get a UINT
    return @as(UINT, @intCast(@intFromPtr(pthread) & 0xFFFFFFFF));
}

// ============================================================================
// Time Functions
// ============================================================================

/// Get system tick count in milliseconds
pub fn getTick() UINT {
    var tv: timeval = undefined;
    _ = gettimeofday(&tv, null);
    return @as(UINT, @intCast(tv.tv_sec * 1000 + @divTrunc(tv.tv_usec, 1000)));
}

/// Get current system time
pub fn getSystemTime(system_time: ?*SYSTEMTIME) void {
    const st = system_time orelse return;

    const now = time(null);
    var tm_info: tm = undefined;
    _ = localtime_r(&now, &tm_info);

    st.wYear = @as(c_ushort, @intCast(tm_info.tm_year + 1900));
    st.wMonth = @as(c_ushort, @intCast(tm_info.tm_mon + 1));
    st.wDay = @as(c_ushort, @intCast(tm_info.tm_mday));
    st.wHour = @as(c_ushort, @intCast(tm_info.tm_hour));
    st.wMinute = @as(c_ushort, @intCast(tm_info.tm_min));
    st.wSecond = @as(c_ushort, @intCast(tm_info.tm_sec));
    st.wMilliseconds = 0;
}

/// Sleep for specified milliseconds
pub fn sleep(milliseconds: UINT) void {
    _ = usleep(milliseconds * 1000);
}

// ============================================================================
// Atomic Operations
// ============================================================================

/// Atomically increment a 32-bit value
pub fn inc32(value: ?*UINT) void {
    const v = value orelse return;
    _ = @atomicRmw(UINT, v, .Add, 1, .seq_cst);
}

/// Atomically decrement a 32-bit value
pub fn dec32(value: ?*UINT) void {
    const v = value orelse return;
    _ = @atomicRmw(UINT, v, .Sub, 1, .seq_cst);
}

// ============================================================================
// Memory Management (simple wrappers)
// ============================================================================

pub fn memoryAlloc(size: UINT) ?*anyopaque {
    return malloc(size);
}

pub fn memoryReAlloc(addr: ?*anyopaque, size: UINT) ?*anyopaque {
    return realloc(addr, size);
}

pub fn memoryFree(addr: ?*anyopaque) void {
    free(addr);
}

// ============================================================================
// File I/O Operations
// ============================================================================

/// Open a file
pub fn fileOpen(name: ?[*:0]u8, write_mode: bool, read_lock: bool) ?*anyopaque {
    _ = read_lock; // Unused parameter
    const n = name orelse return null;
    const mode: [*:0]const u8 = if (write_mode) "r+b" else "rb";
    const fp = fopen(n, mode);
    return @ptrCast(fp);
}

/// Create a new file
pub fn fileCreate(name: ?[*:0]u8) ?*anyopaque {
    const n = name orelse return null;
    const fp = fopen(n, "w+b");
    return @ptrCast(fp);
}

/// Write to a file
pub fn fileWrite(pData: ?*anyopaque, buf: ?*anyopaque, size: UINT) bool {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return false));
    const buffer = buf orelse return false;
    return fwrite(buffer, 1, size, fp) == size;
}

/// Read from a file
pub fn fileRead(pData: ?*anyopaque, buf: ?*anyopaque, size: UINT) bool {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return false));
    const buffer = buf orelse return false;
    return fread(buffer, 1, size, fp) == size;
}

/// Close a file
pub fn fileClose(pData: ?*anyopaque, no_flush: bool) void {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return));
    if (!no_flush) {
        _ = fflush(fp);
    }
    _ = fclose(fp);
}

/// Flush file buffers
pub fn fileFlush(pData: ?*anyopaque) void {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return));
    _ = fflush(fp);
}

/// Get file size
pub fn fileSize(pData: ?*anyopaque) UINT64 {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return 0));
    const current = ftell(fp);
    _ = fseek(fp, 0, SEEK_END);
    const size = ftell(fp);
    _ = fseek(fp, current, SEEK_SET);
    return @intCast(size);
}

/// Seek in a file
pub fn fileSeek(pData: ?*anyopaque, mode: UINT, offset: c_int) bool {
    const fp: *FILE = @ptrCast(@alignCast(pData orelse return false));
    const whence: c_int = switch (mode) {
        0 => SEEK_SET,
        1 => SEEK_CUR,
        else => SEEK_END,
    };
    return fseek(fp, offset, whence) == 0;
}

/// Delete a file
pub fn fileDelete(name: ?[*:0]u8) bool {
    const n = name orelse return false;
    return unlink(n) == 0;
}

/// Create a directory
pub fn makeDir(name: ?[*:0]u8) bool {
    const n = name orelse return false;
    return mkdir(n, 0o755) == 0;
}

/// Delete a directory
pub fn deleteDir(name: ?[*:0]u8) bool {
    const n = name orelse return false;
    return rmdir(n) == 0;
}

/// Rename a file
pub fn fileRename(old_name: ?[*:0]u8, new_name: ?[*:0]u8) bool {
    const old = old_name orelse return false;
    const new = new_name orelse return false;
    return rename(old, new) == 0;
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Yield CPU time slice
pub fn yield() void {
    _ = usleep(1000);
}

// ============================================================================
// C FFI Exports
// ============================================================================

// Lock functions
export fn stub_NewLock() callconv(.c) ?*LOCK {
    return newLock();
}

export fn stub_Lock(lock_ptr: ?*LOCK) callconv(.c) bool {
    return lock(lock_ptr);
}

export fn stub_Unlock(lock_ptr: ?*LOCK) callconv(.c) void {
    unlock(lock_ptr);
}

export fn stub_DeleteLock(lock_ptr: ?*LOCK) callconv(.c) void {
    deleteLock(lock_ptr);
}

// Event functions
export fn stub_InitEvent(event: ?*EVENT) callconv(.c) void {
    initEvent(event);
}

export fn stub_SetEvent(event: ?*EVENT) callconv(.c) void {
    setEvent(event);
}

export fn stub_ResetEvent(event: ?*EVENT) callconv(.c) void {
    resetEvent(event);
}

export fn stub_WaitEvent(event: ?*EVENT, timeout: UINT) callconv(.c) bool {
    return waitEvent(event, timeout);
}

export fn stub_FreeEvent(event: ?*EVENT) callconv(.c) void {
    freeEvent(event);
}

// Thread functions
export fn stub_InitThread(thread: ?*THREAD) callconv(.c) bool {
    return initThread(thread);
}

export fn stub_WaitThread(thread: ?*THREAD) callconv(.c) bool {
    return waitThread(thread);
}

export fn stub_FreeThread(thread: ?*THREAD) callconv(.c) void {
    freeThread(thread);
}

export fn stub_ThreadId() callconv(.c) UINT {
    return threadId();
}

// Time functions
export fn stub_GetTick() callconv(.c) UINT {
    return getTick();
}

export fn stub_GetSystemTime(system_time: ?*SYSTEMTIME) callconv(.c) void {
    getSystemTime(system_time);
}

export fn stub_Sleep(time_ms: UINT) callconv(.c) void {
    sleep(time_ms);
}

// Atomic operations
export fn stub_Inc32(value: ?*UINT) callconv(.c) void {
    inc32(value);
}

export fn stub_Dec32(value: ?*UINT) callconv(.c) void {
    dec32(value);
}

// Memory management
export fn stub_MemoryAlloc(size: UINT) callconv(.c) ?*anyopaque {
    return memoryAlloc(size);
}

export fn stub_MemoryReAlloc(addr: ?*anyopaque, size: UINT) callconv(.c) ?*anyopaque {
    return memoryReAlloc(addr, size);
}

export fn stub_MemoryFree(addr: ?*anyopaque) callconv(.c) void {
    memoryFree(addr);
}

// File I/O functions
export fn stub_FileOpen(name: ?[*:0]u8, write_mode: bool, read_lock: bool) callconv(.c) ?*anyopaque {
    return fileOpen(name, write_mode, read_lock);
}

export fn stub_FileCreate(name: ?[*:0]u8) callconv(.c) ?*anyopaque {
    return fileCreate(name);
}

export fn stub_FileWrite(pData: ?*anyopaque, buf: ?*anyopaque, size: UINT) callconv(.c) bool {
    return fileWrite(pData, buf, size);
}

export fn stub_FileRead(pData: ?*anyopaque, buf: ?*anyopaque, size: UINT) callconv(.c) bool {
    return fileRead(pData, buf, size);
}

export fn stub_FileClose(pData: ?*anyopaque, no_flush: bool) callconv(.c) void {
    fileClose(pData, no_flush);
}

export fn stub_FileFlush(pData: ?*anyopaque) callconv(.c) void {
    fileFlush(pData);
}

export fn stub_FileSize(pData: ?*anyopaque) callconv(.c) UINT64 {
    return fileSize(pData);
}

export fn stub_FileSeek(pData: ?*anyopaque, mode: UINT, offset: c_int) callconv(.c) bool {
    return fileSeek(pData, mode, offset);
}

export fn stub_FileDelete(name: ?[*:0]u8) callconv(.c) bool {
    return fileDelete(name);
}

export fn stub_MakeDir(name: ?[*:0]u8) callconv(.c) bool {
    return makeDir(name);
}

export fn stub_DeleteDir(name: ?[*:0]u8) callconv(.c) bool {
    return deleteDir(name);
}

export fn stub_FileRename(old_name: ?[*:0]u8, new_name: ?[*:0]u8) callconv(.c) bool {
    return fileRename(old_name, new_name);
}

// Utility functions
export fn stub_Yield() callconv(.c) void {
    yield();
}

// No-op stubs for functions not implemented
export fn stub_Init() callconv(.c) void {}
export fn stub_Free() callconv(.c) void {}

// ============================================================================
// Additional Unix-specific stub functions (not used by client, but needed for linking)
// ============================================================================

// OS Dispatch Table structure (must match OS_DISPATCH_TABLE from OS.h)
const OS_DISPATCH_TABLE = extern struct {
    Init: ?*const fn () callconv(.c) void,
    Free: ?*const fn () callconv(.c) void,
    MemoryAlloc: ?*const fn (UINT) callconv(.c) ?*anyopaque,
    MemoryReAlloc: ?*const fn (?*anyopaque, UINT) callconv(.c) ?*anyopaque,
    MemoryFree: ?*const fn (?*anyopaque) callconv(.c) void,
    GetTick: ?*const fn () callconv(.c) UINT,
    GetSystemTime: ?*const fn (?*SYSTEMTIME) callconv(.c) void,
    Inc32: ?*const fn (?*UINT) callconv(.c) void,
    Dec32: ?*const fn (?*UINT) callconv(.c) void,
    Sleep: ?*const fn (UINT) callconv(.c) void,
    NewLock: ?*const fn () callconv(.c) ?*LOCK,
    Lock: ?*const fn (?*LOCK) callconv(.c) bool,
    Unlock: ?*const fn (?*LOCK) callconv(.c) void,
    DeleteLock: ?*const fn (?*LOCK) callconv(.c) void,
    InitEvent: ?*const fn (?*EVENT) callconv(.c) void,
    SetEvent: ?*const fn (?*EVENT) callconv(.c) void,
    ResetEvent: ?*const fn (?*EVENT) callconv(.c) void,
    WaitEvent: ?*const fn (?*EVENT, UINT) callconv(.c) bool,
    FreeEvent: ?*const fn (?*EVENT) callconv(.c) void,
    WaitThread: ?*const fn (?*THREAD) callconv(.c) bool,
    FreeThread: ?*const fn (?*THREAD) callconv(.c) void,
    InitThread: ?*const fn (?*THREAD) callconv(.c) bool,
    ThreadId: ?*const fn () callconv(.c) UINT,
    FileOpen: ?*const fn (?[*:0]u8, bool, bool) callconv(.c) ?*anyopaque,
    FileOpenW: ?*const fn (?[*:0]c_ushort, bool, bool) callconv(.c) ?*anyopaque,
    FileCreate: ?*const fn (?[*:0]u8) callconv(.c) ?*anyopaque,
    FileCreateW: ?*const fn (?[*:0]c_ushort) callconv(.c) ?*anyopaque,
    FileWrite: ?*const fn (?*anyopaque, ?*anyopaque, UINT) callconv(.c) bool,
    FileRead: ?*const fn (?*anyopaque, ?*anyopaque, UINT) callconv(.c) bool,
    FileClose: ?*const fn (?*anyopaque, bool) callconv(.c) void,
    FileFlush: ?*const fn (?*anyopaque) callconv(.c) void,
    FileSize: ?*const fn (?*anyopaque) callconv(.c) UINT64,
    FileSeek: ?*const fn (?*anyopaque, UINT, c_int) callconv(.c) bool,
    FileDelete: ?*const fn (?[*:0]u8) callconv(.c) bool,
    FileDeleteW: ?*const fn (?[*:0]c_ushort) callconv(.c) bool,
    MakeDir: ?*const fn (?[*:0]u8) callconv(.c) bool,
    MakeDirW: ?*const fn (?[*:0]c_ushort) callconv(.c) bool,
    DeleteDir: ?*const fn (?[*:0]u8) callconv(.c) bool,
    DeleteDirW: ?*const fn (?[*:0]c_ushort) callconv(.c) bool,
    GetCallStack: ?*const fn () callconv(.c) ?*anyopaque,
    GetCallStackSymbolInfo: ?*const fn (?*anyopaque) callconv(.c) bool,
    FileRename: ?*const fn (?[*:0]u8, ?[*:0]u8) callconv(.c) bool,
    FileRenameW: ?*const fn (?[*:0]c_ushort, ?[*:0]c_ushort) callconv(.c) bool,
    Run: ?*const fn (?[*:0]u8, ?[*:0]u8, bool, bool) callconv(.c) bool,
    RunW: ?*const fn (?[*:0]c_ushort, ?[*:0]c_ushort, bool, bool) callconv(.c) bool,
    IsSupportedOs: ?*const fn () callconv(.c) bool,
    GetOsInfo: ?*const fn (?*anyopaque) callconv(.c) void,
    Alert: ?*const fn (?[*:0]u8, ?[*:0]u8) callconv(.c) void,
    AlertW: ?*const fn (?[*:0]c_ushort, ?[*:0]c_ushort) callconv(.c) void,
    GetProductId: ?*const fn () callconv(.c) ?[*:0]u8,
    SetHighPriority: ?*const fn () callconv(.c) void,
    RestorePriority: ?*const fn () callconv(.c) void,
    NewSingleInstance: ?*const fn (?[*:0]u8) callconv(.c) ?*anyopaque,
    FreeSingleInstance: ?*const fn (?*anyopaque) callconv(.c) void,
    GetMemInfo: ?*const fn (?*anyopaque) callconv(.c) void,
    Yield: ?*const fn () callconv(.c) void,
};

// Wide character file operation stubs
fn stub_FileOpenW(name: ?[*:0]c_ushort, write_mode: bool, read_lock: bool) callconv(.c) ?*anyopaque {
    _ = name;
    _ = write_mode;
    _ = read_lock;
    return null;
}

fn stub_FileCreateW(name: ?[*:0]c_ushort) callconv(.c) ?*anyopaque {
    _ = name;
    return null;
}

fn stub_FileDeleteW(name: ?[*:0]c_ushort) callconv(.c) bool {
    _ = name;
    return false;
}

fn stub_MakeDirW(name: ?[*:0]c_ushort) callconv(.c) bool {
    _ = name;
    return false;
}

fn stub_DeleteDirW(name: ?[*:0]c_ushort) callconv(.c) bool {
    _ = name;
    return false;
}

fn stub_FileRenameW(old_name: ?[*:0]c_ushort, new_name: ?[*:0]c_ushort) callconv(.c) bool {
    _ = old_name;
    _ = new_name;
    return false;
}

fn stub_Run(filename: ?[*:0]u8, arg: ?[*:0]u8, hide: bool, wait: bool) callconv(.c) bool {
    _ = filename;
    _ = arg;
    _ = hide;
    _ = wait;
    return false;
}

fn stub_RunW(filename: ?[*:0]c_ushort, arg: ?[*:0]c_ushort, hide: bool, wait: bool) callconv(.c) bool {
    _ = filename;
    _ = arg;
    _ = hide;
    _ = wait;
    return false;
}

fn stub_IsSupportedOs() callconv(.c) bool {
    return true;
}

fn stub_GetOsInfo(info: ?*anyopaque) callconv(.c) void {
    _ = info;
}

fn stub_Alert(msg: ?[*:0]u8, caption: ?[*:0]u8) callconv(.c) void {
    _ = msg;
    _ = caption;
}

fn stub_AlertW(msg: ?[*:0]c_ushort, caption: ?[*:0]c_ushort) callconv(.c) void {
    _ = msg;
    _ = caption;
}

fn stub_GetProductId() callconv(.c) ?[*:0]u8 {
    const empty: [*:0]const u8 = "";
    return @constCast(empty);
}

fn stub_SetHighPriority() callconv(.c) void {}
fn stub_RestorePriority() callconv(.c) void {}

fn stub_NewSingleInstance(instance_name: ?[*:0]u8) callconv(.c) ?*anyopaque {
    _ = instance_name;
    return null;
}

fn stub_FreeSingleInstance(data: ?*anyopaque) callconv(.c) void {
    _ = data;
}

fn stub_GetMemInfo(info: ?*anyopaque) callconv(.c) void {
    _ = info;
}

fn stub_GetCallStack() callconv(.c) ?*anyopaque {
    return null;
}

fn stub_GetCallStackSymbolInfo(s: ?*anyopaque) callconv(.c) bool {
    _ = s;
    return false;
}

// Static dispatch table instance
var unix_dispatch_table = OS_DISPATCH_TABLE{
    .Init = stub_Init,
    .Free = stub_Free,
    .MemoryAlloc = stub_MemoryAlloc,
    .MemoryReAlloc = stub_MemoryReAlloc,
    .MemoryFree = stub_MemoryFree,
    .GetTick = stub_GetTick,
    .GetSystemTime = stub_GetSystemTime,
    .Inc32 = stub_Inc32,
    .Dec32 = stub_Dec32,
    .Sleep = stub_Sleep,
    .NewLock = stub_NewLock,
    .Lock = stub_Lock,
    .Unlock = stub_Unlock,
    .DeleteLock = stub_DeleteLock,
    .InitEvent = stub_InitEvent,
    .SetEvent = stub_SetEvent,
    .ResetEvent = stub_ResetEvent,
    .WaitEvent = stub_WaitEvent,
    .FreeEvent = stub_FreeEvent,
    .WaitThread = stub_WaitThread,
    .FreeThread = stub_FreeThread,
    .InitThread = stub_InitThread,
    .ThreadId = stub_ThreadId,
    .FileOpen = stub_FileOpen,
    .FileOpenW = stub_FileOpenW,
    .FileCreate = stub_FileCreate,
    .FileCreateW = stub_FileCreateW,
    .FileWrite = stub_FileWrite,
    .FileRead = stub_FileRead,
    .FileClose = stub_FileClose,
    .FileFlush = stub_FileFlush,
    .FileSize = stub_FileSize,
    .FileSeek = stub_FileSeek,
    .FileDelete = stub_FileDelete,
    .FileDeleteW = stub_FileDeleteW,
    .MakeDir = stub_MakeDir,
    .MakeDirW = stub_MakeDirW,
    .DeleteDir = stub_DeleteDir,
    .DeleteDirW = stub_DeleteDirW,
    .GetCallStack = stub_GetCallStack,
    .GetCallStackSymbolInfo = stub_GetCallStackSymbolInfo,
    .FileRename = stub_FileRename,
    .FileRenameW = stub_FileRenameW,
    .Run = stub_Run,
    .RunW = stub_RunW,
    .IsSupportedOs = stub_IsSupportedOs,
    .GetOsInfo = stub_GetOsInfo,
    .Alert = stub_Alert,
    .AlertW = stub_AlertW,
    .GetProductId = stub_GetProductId,
    .SetHighPriority = stub_SetHighPriority,
    .RestorePriority = stub_RestorePriority,
    .NewSingleInstance = stub_NewSingleInstance,
    .FreeSingleInstance = stub_FreeSingleInstance,
    .GetMemInfo = stub_GetMemInfo,
    .Yield = stub_Yield,
};

export fn UnixGetDispatchTable() callconv(.c) *OS_DISPATCH_TABLE {
    return &unix_dispatch_table;
}

export fn UnixDisableCoreDump() callconv(.c) void {}
export fn UnixSetResourceLimit(id: UINT, value: UINT64) callconv(.c) void {
    _ = id;
    _ = value;
}
export fn UnixSetHighOomScore() callconv(.c) void {}
export fn UnixIgnoreSignalForThread(sig: c_int) callconv(.c) void {
    _ = sig;
}
export fn UnixSetEnableKernelEspProcessing(b: bool) callconv(.c) void {
    _ = b;
}
export fn UnixCloseIO() callconv(.c) void {}
export fn UnixGetNumberOfCpuInner() callconv(.c) UINT {
    return 1;
}
export fn UnixIsInVm() callconv(.c) bool {
    return false;
}

// Directory/File stubs (not needed for client)
export fn UnixCheckExecAccessW(name: ?[*:0]c_ushort) callconv(.c) bool {
    _ = name;
    return false;
}
export fn UnixGetCurrentDir(dir: ?[*:0]u8, size: UINT) callconv(.c) void {
    _ = size;
    if (dir) |d| d[0] = 0;
}
export fn UnixGetCurrentDirW(dir: ?[*:0]c_ushort, size: UINT) callconv(.c) void {
    _ = size;
    if (dir) |d| d[0] = 0;
}
export fn UnixGetDiskFree(path: ?[*:0]u8, free_size: ?*UINT64, used_size: ?*UINT64, total_size: ?*UINT64) callconv(.c) bool {
    _ = path;
    _ = free_size;
    _ = used_size;
    _ = total_size;
    return false;
}
export fn UnixGetDiskFreeW(path: ?[*:0]c_ushort, free_size: ?*UINT64, used_size: ?*UINT64, total_size: ?*UINT64) callconv(.c) bool {
    _ = path;
    _ = free_size;
    _ = used_size;
    _ = total_size;
    return false;
}
export fn UnixEnumDirExW(dirname: ?[*:0]c_ushort, compare: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = dirname;
    _ = compare;
    return null;
}
export fn UnixExec(cmd: ?[*:0]u8) callconv(.c) ?*anyopaque {
    _ = cmd;
    return null;
}

// VLan/TAP stubs (not needed for client)
export fn UnixVLanInit() callconv(.c) void {}
export fn UnixVLanCreate(name: ?[*:0]u8, mac_address: ?[*]u8) callconv(.c) bool {
    _ = name;
    _ = mac_address;
    return false;
}
export fn UnixVLanDelete(name: ?[*:0]u8) callconv(.c) void {
    _ = name;
}
export fn UnixVLanFree(vlan: ?*anyopaque) callconv(.c) void {
    _ = vlan;
}
export fn VLanGetPacketAdapter() callconv(.c) ?*anyopaque {
    return null;
}
export fn VLanPutPacket(v: ?*anyopaque, buf: ?*anyopaque, size: UINT) callconv(.c) bool {
    _ = v;
    _ = buf;
    _ = size;
    return false;
}
export fn FreeTap(tap: ?*anyopaque) callconv(.c) void {
    _ = tap;
}

// HTTP/URL stubs (minimal implementations)
export fn ParseUrl(data: ?*anyopaque, str: ?[*:0]u8, is_post: bool, referrer: ?[*:0]u8) callconv(.c) bool {
    _ = data;
    _ = str;
    _ = is_post;
    _ = referrer;
    return false;
}
export fn HttpRequestEx(
    data: ?*anyopaque,
    setting: ?*anyopaque,
    timeout_connect: UINT,
    timeout_comm: UINT,
    error_code: ?*UINT,
    check_ssl_trust: bool,
    post_data: ?[*:0]u8,
    recv_callback: ?*anyopaque,
    recv_callback_param: ?*anyopaque,
    sha1_cert_hash: ?*anyopaque,
    cancel: ?*bool,
    max_recv_size: UINT,
) callconv(.c) ?*anyopaque {
    _ = data;
    _ = setting;
    _ = timeout_connect;
    _ = timeout_comm;
    _ = error_code;
    _ = check_ssl_trust;
    _ = post_data;
    _ = recv_callback;
    _ = recv_callback_param;
    _ = sha1_cert_hash;
    _ = cancel;
    _ = max_recv_size;
    return null;
}
export fn HttpRequestEx3(
    data: ?*anyopaque,
    setting: ?*anyopaque,
    timeout_connect: UINT,
    timeout_comm: UINT,
    error_code: ?*UINT,
    check_ssl_trust: bool,
    post_data: ?[*:0]u8,
    recv_callback: ?*anyopaque,
    recv_callback_param: ?*anyopaque,
    sha1_cert_hash: ?*anyopaque,
    num_hashes: UINT,
    cancel: ?*bool,
    max_recv_size: UINT,
    header_name: ?[*:0]u8,
    header_value: ?[*:0]u8,
) callconv(.c) ?*anyopaque {
    _ = data;
    _ = setting;
    _ = timeout_connect;
    _ = timeout_comm;
    _ = error_code;
    _ = check_ssl_trust;
    _ = post_data;
    _ = recv_callback;
    _ = recv_callback_param;
    _ = sha1_cert_hash;
    _ = num_hashes;
    _ = cancel;
    _ = max_recv_size;
    _ = header_name;
    _ = header_value;
    return null;
}

// WPC (Windows Proxy Configuration) stubs - not used on Unix
export fn WpcCall(
    url: ?[*:0]u8,
    setting: ?*anyopaque,
    timeout_connect: UINT,
    timeout_comm: UINT,
    function_name: ?[*:0]u8,
    pack: ?*anyopaque,
    cert: ?*anyopaque,
    key: ?*anyopaque,
    sha1_cert_hash: ?*anyopaque,
) callconv(.c) ?*anyopaque {
    _ = url;
    _ = setting;
    _ = timeout_connect;
    _ = timeout_comm;
    _ = function_name;
    _ = pack;
    _ = cert;
    _ = key;
    _ = sha1_cert_hash;
    return null;
}
export fn WpcCallEx2(
    url: ?[*:0]u8,
    setting: ?*anyopaque,
    timeout_connect: UINT,
    timeout_comm: UINT,
    function_name: ?[*:0]u8,
    pack: ?*anyopaque,
    cert: ?*anyopaque,
    key: ?*anyopaque,
    sha1_cert_hash: ?*anyopaque,
    num_hashes: UINT,
    cancel: ?*bool,
    max_recv_size: UINT,
    additional_header_name: ?[*:0]u8,
    additional_header_value: ?[*:0]u8,
    sni_string: ?[*:0]u8,
) callconv(.c) ?*anyopaque {
    _ = url;
    _ = setting;
    _ = timeout_connect;
    _ = timeout_comm;
    _ = function_name;
    _ = pack;
    _ = cert;
    _ = key;
    _ = sha1_cert_hash;
    _ = num_hashes;
    _ = cancel;
    _ = max_recv_size;
    _ = additional_header_name;
    _ = additional_header_value;
    _ = sni_string;
    return null;
}
export fn WpcSockConnect2(
    hostname: ?[*:0]u8,
    port: UINT,
    t: ?*anyopaque,
    error_code: ?*UINT,
    timeout: UINT,
) callconv(.c) ?*anyopaque {
    _ = hostname;
    _ = port;
    _ = t;
    _ = error_code;
    _ = timeout;
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "lock: create, lock, unlock, delete" {
    const lock_ptr = newLock();
    try std.testing.expect(lock_ptr != null);

    const success = lock(lock_ptr);
    try std.testing.expect(success);

    unlock(lock_ptr);
    deleteLock(lock_ptr);
}

test "event: create, signal, wait" {
    var event: EVENT = undefined;
    initEvent(&event);
    try std.testing.expect(event.pData != null);

    // Signal the event
    setEvent(&event);

    // Wait should return immediately since event is signaled
    const result = waitEvent(&event, 100);
    try std.testing.expect(result);

    freeEvent(&event);
}

test "event: timeout" {
    var event: EVENT = undefined;
    initEvent(&event);

    // Don't signal the event, wait should timeout
    const result = waitEvent(&event, 10); // 10ms timeout
    try std.testing.expect(!result);

    freeEvent(&event);
}

test "thread: threadId returns non-zero" {
    const id = threadId();
    try std.testing.expect(id != 0);
}

test "time: getTick returns non-zero" {
    const tick = getTick();
    try std.testing.expect(tick > 0);
}

test "time: sleep actually sleeps" {
    const before = getTick();
    sleep(50); // 50ms
    const after = getTick();
    try std.testing.expect(after >= before + 40); // Allow some tolerance
}

test "atomic: inc32" {
    var value: UINT = 0;
    inc32(&value);
    try std.testing.expectEqual(@as(UINT, 1), value);
    inc32(&value);
    try std.testing.expectEqual(@as(UINT, 2), value);
}

test "atomic: dec32" {
    var value: UINT = 10;
    dec32(&value);
    try std.testing.expectEqual(@as(UINT, 9), value);
    dec32(&value);
    try std.testing.expectEqual(@as(UINT, 8), value);
}

test "memory: alloc, realloc, free" {
    const ptr = memoryAlloc(100);
    try std.testing.expect(ptr != null);

    const ptr2 = memoryReAlloc(ptr, 200);
    try std.testing.expect(ptr2 != null);

    memoryFree(ptr2);
}

test "file: create, write, read, delete" {
    const test_file = "/tmp/zig_unix_test.txt";

    // Create file
    const fp = fileCreate(test_file);
    try std.testing.expect(fp != null);

    // Write data
    const data = "Hello, Zig!";
    const write_ok = fileWrite(fp, @constCast(@as(*const anyopaque, @ptrCast(data.ptr))), data.len);
    try std.testing.expect(write_ok);

    // Close
    fileClose(fp, false);

    // Open for reading
    const fp2 = fileOpen(test_file, false, false);
    try std.testing.expect(fp2 != null);

    // Read data
    var buffer: [100]u8 = undefined;
    const read_ok = fileRead(fp2, &buffer, data.len);
    try std.testing.expect(read_ok);

    // Verify
    try std.testing.expectEqualSlices(u8, data, buffer[0..data.len]);

    // Close and delete
    fileClose(fp2, false);
    const delete_ok = fileDelete(test_file);
    try std.testing.expect(delete_ok);
}

test "file: size and seek" {
    const test_file = "/tmp/zig_unix_size_test.txt";

    const fp = fileCreate(test_file);
    try std.testing.expect(fp != null);

    // Write 10 bytes
    const data = "0123456789";
    _ = fileWrite(fp, @constCast(@as(*const anyopaque, @ptrCast(data.ptr))), data.len);

    // Get size
    const size = fileSize(fp);
    try std.testing.expectEqual(@as(UINT64, 10), size);

    // Seek to position 5
    const seek_ok = fileSeek(fp, 0, 5);
    try std.testing.expect(seek_ok);

    fileClose(fp, false);
    _ = fileDelete(test_file);
}

test "directory: create and delete" {
    const test_dir = "/tmp/zig_unix_dir_test";

    const create_ok = makeDir(test_dir);
    try std.testing.expect(create_ok);

    const delete_ok = deleteDir(test_dir);
    try std.testing.expect(delete_ok);
}

test "file: rename" {
    const old_name = "/tmp/zig_unix_rename_old.txt";
    const new_name = "/tmp/zig_unix_rename_new.txt";

    // Create file
    const fp = fileCreate(old_name);
    try std.testing.expect(fp != null);
    fileClose(fp, false);

    // Rename
    const rename_ok = fileRename(old_name, new_name);
    try std.testing.expect(rename_ok);

    // Clean up
    _ = fileDelete(new_name);
}

// ============================================================================
// Zig-prefixed exports for dual-mode compatibility layer
// ============================================================================

export fn zig_NewLock() callconv(.c) ?*LOCK {
    return newLock();
}

export fn zig_Lock(lock_ptr: ?*LOCK) callconv(.c) bool {
    return lock(lock_ptr);
}

export fn zig_Unlock(lock_ptr: ?*LOCK) callconv(.c) void {
    unlock(lock_ptr);
}

export fn zig_DeleteLock(lock_ptr: ?*LOCK) callconv(.c) void {
    deleteLock(lock_ptr);
}

export fn zig_InitEvent(event: ?*EVENT) callconv(.c) void {
    initEvent(event);
}

export fn zig_SetEvent(event: ?*EVENT) callconv(.c) void {
    setEvent(event);
}

export fn zig_ResetEvent(event: ?*EVENT) callconv(.c) void {
    resetEvent(event);
}

export fn zig_WaitEvent(event: ?*EVENT, timeout: UINT) callconv(.c) bool {
    return waitEvent(event, timeout);
}

export fn zig_FreeEvent(event: ?*EVENT) callconv(.c) void {
    freeEvent(event);
}

export fn zig_InitThread(thread: ?*THREAD) callconv(.c) bool {
    return initThread(thread);
}

export fn zig_WaitThread(thread: ?*THREAD) callconv(.c) bool {
    return waitThread(thread);
}

export fn zig_FreeThread(thread: ?*THREAD) callconv(.c) void {
    freeThread(thread);
}

export fn zig_ThreadId() callconv(.c) UINT {
    return threadId();
}

export fn zig_GetTick() callconv(.c) UINT {
    return getTick();
}

export fn zig_GetSystemTime(system_time: ?*SYSTEMTIME) callconv(.c) void {
    getSystemTime(system_time);
}

export fn zig_Sleep(milliseconds: UINT) callconv(.c) void {
    sleep(milliseconds);
}

export fn zig_Inc32(value: ?*UINT) callconv(.c) void {
    inc32(value);
}

export fn zig_Dec32(value: ?*UINT) callconv(.c) void {
    dec32(value);
}

export fn zig_GetDispatchTable() callconv(.c) *OS_DISPATCH_TABLE {
    return &unix_dispatch_table;
}
