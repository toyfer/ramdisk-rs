use clap::{Parser, ValueEnum};
use ctrlc;
use memmap::MmapMut;
use std::ffi::OsStr;
use std::fs::{OpenOptions, remove_file};
use std::os::windows::ffi::OsStrExt; 
use std::os::windows::prelude::AsRawHandle;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};  // 共有するためのArcとMutexを追加
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::fileapi::{CreateFileW, FindFirstVolumeW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winbase::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OVERLAPPED,
    FILE_FLAG_WRITE_THROUGH,
};
use winapi::um::winioctl::{
    CREATE_VIRTUAL_DISK_PARAMETERS, CREATE_VIRTUAL_DISK_VERSION_2, DISK_GEOMETRY,
    FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME, IOCTL_DISK_GET_DRIVE_GEOMETRY,
    VIRTUAL_DISK_ACCESS_NONE, VIRTUAL_STORAGE_TYPE_DEVICE_RAM,
};
use winapi::um::winnt::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};

#[derive(Parser, Debug)]
#[clap::command(author, version, about, long_about = None)]
struct Args {
    /// ramdiskのサイズをMB単位で指定
    #[clap(arg(short, long, default_value_t = 100))]
    size: u64,

    /// ファイルシステムのフォーマット (例: FAT32, NTFS)
    #[clap(arg(short, long, value_enum, default_value_t = Format::NTFS))]
    format: Format,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Format {
    FAT32,
    NTFS,
}

fn create_virtual_disk(file_handle: &dyn AsRawHandle, size_bytes: u64) -> Result<(), std::io::Error> {
    let mut params: CREATE_VIRTUAL_DISK_PARAMETERS = unsafe { std::mem::zeroed() };
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Version2.MaximumSize = size_bytes;
    params.Version2.SectorSizeInBytes = 512;

    let mut geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    geometry.BytesPerSector = params.Version2.SectorSizeInBytes;
    geometry.Cylinders.QuadPart = (size_bytes / (geometry.BytesPerSector * 63)) as i64; 
    geometry.TracksPerCylinder = 255; 
    geometry.SectorsPerTrack = 63;

    let mut returned_size: DWORD = 0;
    let result = unsafe {
        DeviceIoControl(
            file_handle.as_raw_handle() as LPVOID,
            winapi::um::winioctl::CREATE_VIRTUAL_DISK,
            &params as *const _ as LPVOID,
            std::mem::size_of_val(&params) as DWORD,
            std::ptr::null_mut(),
            0,
            &mut returned_size,
            std::ptr::null_mut(),
        )
    };

    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn format_virtual_disk(disk_path: &Path, format: Format) -> Result<(), std::io::Error> {
    let format_arg = match format {
        Format::FAT32 => "/FS:FAT32",
        Format::NTFS => "/FS:NTFS",
    };

    let output = Command::new("format.com")
        .arg(disk_path)
        .arg(format_arg)
        .arg("/Q")
        .arg("/V:RAMDISK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("仮想ディスクのフォーマットに失敗しました: {}", stderr),
        ));
    }

    Ok(())
}

fn mount_virtual_disk(disk_path: &Path) -> Result<String, std::io::Error> {
    let mut volume_name_buf = [0u16; 256];
    let find_handle = unsafe {
        FindFirstVolumeW(volume_name_buf.as_mut_ptr(), volume_name_buf.len() as u32)
    };

    if find_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let volume_guid_path = OsStr::from_wide(&volume_name_buf)
        .to_string_lossy()
        .trim_matches(char::from(0))
        .to_string();

    let volume_handle = unsafe {
        CreateFileW(
            volume_guid_path.encode_wide().collect::<Vec<_>>().as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if volume_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut drive_letter = 'Z';
    loop {
        let drive_name = format!("{}:", drive_letter);
        let drive_handle = unsafe {
            CreateFileW(
                drive_name.encode_wide().collect::<Vec<_>>().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        if drive_handle == INVALID_HANDLE_VALUE {
            break;
        } else {
            unsafe { CloseHandle(drive_handle) };
            drive_letter = std::char::from_u32(drive_letter as u32 - 1).unwrap();
        }

        if drive_letter < 'A' {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "利用可能なドライブレターがありません",
            ));
        }
    }

    Ok(format!("{}:", drive_letter))
}

fn unmount_virtual_disk(drive_letter: &str) -> Result<(), std::io::Error> {
    let drive_path = format!("\\\\.\\{}:", drive_letter.trim_end_matches(':'));
    let drive_handle = unsafe {
        CreateFileW(
            drive_path.encode_wide().collect::<Vec<_>>().as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if drive_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut bytes_returned: DWORD = 0;
    let lock_result = unsafe {
        DeviceIoControl(
            drive_handle as LPVOID,
            FSCTL_LOCK_VOLUME,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if lock_result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let dismount_result = unsafe {
        DeviceIoControl(
            drive_handle as LPVOID,
            FSCTL_DISMOUNT_VOLUME,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if dismount_result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    unsafe { CloseHandle(drive_handle) };

    Ok(())
}

fn main() {
    let args = Args::parse();
    let size_bytes = args.size * 1024 * 1024;

    let temp_file_path = Path::new("C:\\path\\to\\temp_ramdisk_file.img");

    // ファイルの生成とオープン
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(temp_file_path)
        .expect("一時ファイルの作成に失敗しました");

    // 仮想ディスクの作成
    create_virtual_disk(&file, size_bytes).expect("仮想ディスクの作成に失敗しました");

    // フォーマット
    format_virtual_disk(temp_file_path, args.format).expect("ディスクのフォーマットに失敗しました");

    // マウント
    let drive_letter = mount_virtual_disk(temp_file_path).expect("ディスクのマウントに失敗しました");

    // Ctrl+Cハンドラの設定
    let drive_letter_shared = Arc::new(Mutex::new(drive_letter.clone()));
    let temp_file_shared = Arc::new(Mutex::new(temp_file_path.to_path_buf()));

    ctrlc::set_handler(move || {
        let drive_letter = drive_letter_shared.lock().unwrap();
        let temp_file_path = temp_file_shared.lock().unwrap();

        unmount_virtual_disk(&drive_letter).expect("仮想ディスクのアンマウントに失敗しました");
        remove_file(&*temp_file_path).expect("一時ファイルの削除に失敗しました");
        println!("Ctrl+C を受け取りました。クリーンアップを実行しました。");
        std::process::exit(0);
    })
    .expect("Ctrl+C ハンドラの設定に失敗しました");

    // 仮想ディスクを使用中...
    println!("仮想ディスクが {} にマウントされました", drive_letter);
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
