use clap::{Parser, ValueEnum};
use ctrlc;
use memmap::MmapMut;
use std::ffi::OsStr;
use std::fs::{OpenOptions, remove_file};
use std::os::windows::ffi::OsStrExt; // OsStrExtトレイトのインポート
use std::os::windows::prelude::AsRawHandle;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID, TRUE};
use winapi::um::fileapi::{CreateFileW, FindFirstVolumeW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winbase::{
    DRIVE_FIXED, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OVERLAPPED,
    FILE_FLAG_WRITE_THROUGH,
};
use winapi::um::winioctl::{
    CREATE_VIRTUAL_DISK_PARAMETERS, CREATE_VIRTUAL_DISK_VERSION_2, DISK_GEOMETRY,
    FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME, GET_DISK_ATTRIBUTES, IOCTL_DISK_GET_DRIVE_GEOMETRY,
    MOUNTMGR_MOUNT_POINT, VIRTUAL_DISK_ACCESS_NONE, VIRTUAL_STORAGE_TYPE_DEVICE_RAM,
};
use winapi::um::winnt::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};

#[derive(Parser, Debug)]
#[clap::command(author, version, about, long_about = None)] // clap::commandを使用
struct Args {
    /// ramdiskのサイズをMB単位で指定
    #[clap::arg(short, long, default_value_t = 100)] // clap::argを使用
    size: u64,

    /// ファイルシステムのフォーマット (例: FAT32, NTFS)
    #[clap::arg(short, long, value_enum, default_value_t = Format::NTFS)] // clap::argを使用
    format: Format,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Format {
    FAT32,
    NTFS,
}

fn create_virtual_disk(file_handle: &dyn AsRawHandle, size_bytes: u64) -> Result<(), std::io::Error> { // dyn AsRawHandleを使用
    let mut params: CREATE_VIRTUAL_DISK_PARAMETERS = unsafe { std::mem::zeroed() };
    params.Version = CREATE_VIRTUAL_DISK_VERSION_2;
    params.Version2.UniqueId = unsafe { std::mem::zeroed() };
    params.Version2.MaximumSize = size_bytes;
    params.Version2.BlockSizeInBytes = 0; // デフォルトのブロックサイズ
    params.Version2.SectorSizeInBytes = 512;
    params.Version2.ParentPath = std::ptr::null_mut();
    params.Version2.SourcePath = std::ptr::null_mut();

    let mut geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    geometry.BytesPerSector = params.Version2.SectorSizeInBytes;
    geometry.Cylinders.QuadPart = (size_bytes / (geometry.BytesPerSector * 63)) as i64; // 1トラックあたり63セクターと仮定
    geometry.TracksPerCylinder = 255; // 1シリンダーあたり255トラックと仮定
    geometry.SectorsPerTrack = 63;

    params.Version2.ResiliencyGuid = unsafe { std::mem::zeroed() };
    params.Version2.StorageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_RAM;
    params.Version2.StorageType.VendorId = unsafe { std::mem::zeroed() };

    let mut returned_size: DWORD = 0;
    let result = unsafe {
        DeviceIoControl(
            file_handle.as_raw_handle() as LPVOID,
            winioctl::CREATE_VIRTUAL_DISK, // winioctl::CREATE_VIRTUAL_DISKを使用
            ¶ms as *const _ as LPVOID,
            std::mem::size_of_val(¶ms) as DWORD,
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
        .arg("/Q") // クイックフォーマット
        .arg("/V:RAMDISK") // ボリュームラベル
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
    // 仮想ディスクのボリュームGUIDパスを探す
    let mut volume_name_buf = [0u16; 256];
    let find_handle = unsafe {
        FindFirstVolumeW(volume_name_buf.as_mut_ptr(), volume_name_buf.len() as u32)
    };

    if find_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    // ボリュームGUIDパスを抽出する
    let volume_guid_path = OsStr::from_wide(&volume_name_buf) // OsStr::from_wideを使用
        .to_string_lossy() // 不正なUTF-16文字を処理するためにto_string_lossyを使用
        .trim_matches(char::from(0))
        .to_string();

    // マウントするためにボリュームを開く
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

    // ドライブレターを割り当てる（最初に利用可能なドライブレターを探す）
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
            // ドライブレターが利用可能
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

    // ボリュームをマウントする
    let mut mount_point: MOUNTMGR_MOUNT_POINT = unsafe { std::mem::zeroed() };
    mount_point.SymbolicLinkNameLength = (drive_letter.to_string().len() * 2) as u16; // バイト単位の長さ (Unicode)
    mount_point.SymbolicLinkName =
        drive_letter.to_string().encode_wide().collect::<Vec<_>>().as_mut_ptr();
    mount_point.UniqueIdOffset = 0;
    mount_point.UniqueIdLength = 0;
    mount_point.DeviceNameOffset = 0;
    mount_point.DeviceNameLength = 0;

    let result = unsafe {
        DeviceIoControl(
            volume_handle as LPVOID,
            winioctl::IOCTL_MOUNTMGR_CREATE_POINT, // winioctl::IOCTL_MOUNTMGR_CREATE_POINTを使用
            &mut mount_point as *mut _ as LPVOID,
            std::mem::size_of_val(&mut mount_point) as DWORD,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 割り当てられたドライブレターを返す
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

    // ボリュームをロックする
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
        unsafe { CloseHandle(drive_handle) };
        return Err(std::io::Error::last_os_error());
    }

    // ボリュームをアンマウントする
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

    unsafe { CloseHandle(drive_handle) };

    if dismount_result == 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    // ramdiskのサイズをバイト単位で計算
    let size_bytes = args.size * 1024 * 1024;

    // メモリマップファイルのための一時ファイルを作成
    let temp_file_path = Path::new("ramdisk.img");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(temp_file_path)
        .expect("一時ファイルの作成に失敗しました");

    // ファイルサイズを設定
    file.set_len(size_bytes).expect("ファイルサイズの設定に失敗しました");

    // メモリマップを作成
    let mmap = unsafe { MmapMut::map_mut(&file).expect("メモリマップの作成に失敗しました") };

    // 仮想ディスク作成用の適切なフラグを指定して一時ファイルを開く
    let vhd_file = CreateFileW(
        temp_file_path.as_os_str().encode_wide().collect::<Vec<_>>().as_ptr(), // Use encode_wide
        winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE,
        winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS
            | FILE_FLAG_WRITE_THROUGH
            | FILE_FLAG_NO_BUFFERING
            | FILE_FLAG_OVERLAPPED,
        std::ptr::null_mut(),
    );

    if vhd_file == INVALID_HANDLE_VALUE {
        panic!(
            "仮想ディスク作成用のファイルを開けませんでした: {}",
            std::io::Error::last_os_error()
        );
    }

    // 仮想ディスクを作成
    create_virtual_disk(&vhd_file, size_bytes).expect("仮想ディスクの作成に失敗しました");

    // ファイルハンドルを閉じる
    unsafe { CloseHandle(vhd_file) };

    // 仮想ディスクをフォーマットする
    format_virtual_disk(temp_file_path, args.format).expect("仮想ディスクのフォーマットに失敗しました");

    // 仮想ディスクをマウントする
    let drive_letter = mount_virtual_disk(temp_file_path).expect("仮想ディスクのマウントに失敗しました");

    println!("Ramdiskが{}としてマウントされました", drive_letter);

    // 正常なアンマウントとクリーンアップのためにCtrl+Cハンドラーを設定する
    ctrlc::set_handler(move || {
        if let Err(e) = unmount_virtual_disk(&drive_letter) {
            eprintln!("ramdiskのアンマウントに失敗しました: {}", e);
        }
        if let Err(e) = remove_file(temp_file_path) {
            eprintln!("一時ファイルの削除に失敗しました: {}", e);
        }
        std::process::exit(0);
    })
    .expect("Ctrl+Cハンドラーの設定エラー");

    // Ctrl+Cが押されるまでプログラムを実行し続ける
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}