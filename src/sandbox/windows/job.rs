#[cfg(windows)]
#[derive(Default)]
struct JobMetrics {
    peak_memory_bytes: Option<u64>,
    cpu_time_ms: Option<u64>,
}

#[cfg(windows)]
type JobHandle = windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
fn attach_job(child: &Child, config: &Config) -> Result<Option<JobHandle>> {
    use std::os::windows::io::AsRawHandle;
    Ok(Some(attach_job_handle(child.as_raw_handle() as _, config)?))
}

#[cfg(windows)]
fn attach_job_handle(process: JobHandle, config: &Config) -> Result<JobHandle> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOB_OBJECT_LIMIT_PROCESS_TIME, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("failed to create analysis Job Object");
    }
    let mut info = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.BasicLimitInformation.PerProcessUserTimeLimit =
        config.limits.child_cpu_time_ms.saturating_mul(10_000) as i64;
    info.ProcessMemoryLimit = config.limits.child_committed_memory_bytes as usize;
    info.JobMemoryLimit = config.limits.child_committed_memory_bytes as usize;
    let set_ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if set_ok == 0 {
        close_job(job);
        return Err(std::io::Error::last_os_error()).context("failed to configure Job Object");
    }
    let assign_ok = unsafe { AssignProcessToJobObject(job, process) };
    if assign_ok == 0 {
        close_job(job);
        return Err(std::io::Error::last_os_error())
            .context("failed to assign child to Job Object");
    }
    Ok(job)
}

#[cfg(windows)]
fn query_job_metrics(job: JobHandle) -> JobMetrics {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::JobObjects::{
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };
    let mut extended = unsafe { zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    let mut accounting = unsafe { zeroed::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() };
    let ext_ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut extended as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    let acct_ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    JobMetrics {
        peak_memory_bytes: (ext_ok != 0).then_some(extended.PeakProcessMemoryUsed as u64),
        cpu_time_ms: (acct_ok != 0).then_some(
            (accounting.TotalUserTime as u64 + accounting.TotalKernelTime as u64) / 10_000,
        ),
    }
}

#[cfg(windows)]
fn terminate_job(child: &Child) {
    // The wait timeout path kills the process directly. Kill-on-close in the
    // Job Object ensures any descendant that might exist is also terminated
    // when the job handle is closed.
    let _ = child.id();
}

#[cfg(windows)]
fn close_job(job: JobHandle) {
    use windows_sys::Win32::Foundation::CloseHandle;
    unsafe {
        CloseHandle(job);
    }
}

