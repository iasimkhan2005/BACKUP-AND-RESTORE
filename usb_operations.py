# usb_operations.py
import os
import sys
import platform

# --- Platform-specific USB Detection Libraries ---
PYUDEV_AVAILABLE = False
if platform.system() == 'Linux':
    try:
        import pyudev
        PYUDEV_AVAILABLE = True
    except ImportError:
        print("Warning: 'pyudev' not found. USB detection for Linux will be unavailable. Please install it using 'pip install pyudev'.")
    except Exception as e:
        print(f"Error loading pyudev: {e}. USB detection for Linux will be unavailable.")

PYWIN32_AVAILABLE = False
if platform.system() == 'Windows':
    try:
        import win32api
        import win32file
        import pythoncom
        import wmi
        PYWIN32_AVAILABLE = True
    except ImportError:
        print("Warning: 'pywin32' not found. USB detection for Windows will be unavailable. Please install it using 'pip install pywin32'.")
    except Exception as e:
        print(f"Error loading pywin32: {e}. USB detection for Windows will be unavailable.")

# --- USB Detection Functions ---

def get_usb_devices():
    """
    Detects and returns a list of potential USB drive paths.
    Returns a list of strings (e.g., ['/media/user/USB', 'D:\\']).
    Returns an empty list if no USB devices are found or detection fails due to missing libs.
    """
    usb_paths = []
    print("DEBUG: Entering get_usb_devices() function.")

    if platform.system() == 'Linux':
        if PYUDEV_AVAILABLE:
            try:
                context = pyudev.Context()
                for device in context.list_devices(subsystem='block', DRIVER='sd'):
                    if 'ID_FS_UUID' in device and 'ID_BUS' in device and device['ID_BUS'] == 'usb':
                        mount_point = find_mount_point_linux(device.device_node)
                        if mount_point:
                            usb_paths.append(mount_point)
                        else:
                            print(f"DEBUG: Found Linux USB device {device.device_node} but could not determine its mount point.")
            except Exception as e:
                print(f"ERROR: Exception during Linux USB detection: {e}")
        else:
            print("DEBUG: Skipping Linux USB detection because 'pyudev' is not available.")
    
    elif platform.system() == 'Windows':
        if PYWIN32_AVAILABLE:
            try:
                pythoncom.CoInitialize() 
                print("DEBUG: pythoncom.CoInitialize() called.")

                print("DEBUG: Initializing WMI for Windows USB detection.")
                c = wmi.WMI()
                
                for disk in c.Win32_DiskDrive():
                    print(f"DEBUG: Checking DiskDrive: Caption='{disk.Caption}', DeviceID='{disk.DeviceID}', InterfaceType='{disk.InterfaceType}'")
                    if 'USB' in str(disk.Caption).upper() or 'USB' in str(disk.DeviceID).upper() or \
                       (disk.InterfaceType and str(disk.InterfaceType).upper() == 'USB'):
                        print(f"DEBUG: Potential USB DiskDrive identified: {disk.Caption}")
                        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                            print(f"DEBUG: Checking Partition: Name='{partition.Name}'")
                            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                                print(f"DEBUG: Checking LogicalDisk: Caption='{logical_disk.Caption}', DriveType='{logical_disk.DriveType}'")
                                if logical_disk.DriveType == 2:
                                    usb_paths.append(logical_disk.Caption + "\\")
                                    print(f"DEBUG: Added USB drive to list: {logical_disk.Caption}\\")
            except pythoncom.com_error as e:
                print(f"ERROR: WMI Error during Windows USB detection: {e}. Ensure pywin32 is properly installed and COM initialized. Run your terminal as Administrator for installation if needed.")
            except Exception as e:
                print(f"ERROR: General exception during Windows USB detection: {e}")
            finally:
                pythoncom.CoUninitialize()
                print("DEBUG: pythoncom.CoUninitialize() called.")
        else:
            print("DEBUG: Skipping Windows USB detection because 'pywin32' is not available.")
    
    else:
        print(f"DEBUG: USB detection not implemented for OS: {platform.system()}")

    print(f"DEBUG: Exiting get_usb_devices(). Found USB paths: {usb_paths}")
    return usb_paths

def find_mount_point_linux(device_node):
    """
    Helper function to find the mount point of a Linux block device.
    Reads /etc/mtab (or /proc/mounts) to find the mount point.
    """
    try:
        with open('/etc/mtab', 'r') as f:
            for line in f:
                if device_node in line:
                    parts = line.split()
                    return parts[1]
    except FileNotFoundError:
        print("Warning: /etc/mtab not found. Cannot determine mount points easily on Linux.")
    except Exception as e:
        print(f"Error reading mount points on Linux: {e}")
    return None

def generate_directory_tree(start_path, output_file_path):
    """
    Traverses the directory structure from start_path and writes it to output_file_path
    in a tree-like format.
    """
    print(f"DEBUG: Entering generate_directory_tree() for path: {start_path}, output: {output_file_path}")
    if not os.path.exists(start_path):
        print(f"ERROR: Start path for directory tree not found: '{start_path}'")
        raise FileNotFoundError(f"Start path for directory tree not found: '{start_path}'")
    
    output_dir = os.path.dirname(output_file_path)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            print(f"DEBUG: Created output directory for tree file: {output_dir}")
        except OSError as e:
            print(f"ERROR: Could not create output directory '{output_dir}': {e}")
            raise

    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"Directory structure of: {start_path}\n\n")
            
            for root, dirs, files in os.walk(start_path):
                relative_root = os.path.relpath(root, start_path)
                
                level = 0
                if relative_root != '.':
                    level = relative_root.count(os.sep) + 1 

                indent = ' ' * 4 * level
                
                f.write(f'{indent}{os.path.basename(root)}/\n')
                
                subindent = ' ' * 4 * (level + 1)
                for file in files:
                    f.write(f'{subindent}{file}\n')
        print(f"DEBUG: Directory tree successfully written to: {output_file_path}")
    except Exception as e:
        print(f"ERROR: Exception while writing directory tree to '{output_file_path}': {e}")
        raise
    print("DEBUG: Exiting generate_directory_tree() function.")

