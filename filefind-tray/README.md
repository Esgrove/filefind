# filefind-tray

System tray application for easily controlling the filefind daemon when it is running in the background.

This application provides a convenient graphical interface for managing the filefind background indexing service from the Windows system tray.

## Features

- **Status indicator**: Tray icon color shows daemon state
    - 🟢 Green: Running
    - 🟠 Orange: Scanning
    - ⚫ Gray: Stopped
- **Tooltip**: Shows indexed file and directory counts
- **Quick controls**: Start, stop, and rescan from the tray menu

## Usage

Simply run the application:

```shell
filefind-tray
```

The application will appear in the system tray. Right-click the icon to access the menu.

### Menu Options

| Option           | Description                                  |
| ---------------- | -------------------------------------------- |
| **Status**       | Shows current daemon state and file count    |
| **Start daemon** | Start the filefind daemon                    |
| **Stop daemon**  | Stop the running daemon                      |
| **Rescan**       | Trigger a full rescan of all indexed volumes |
| **About**        | Show application information                 |
| **Quit**         | Exit the tray application                    |

## Auto-start on Login

To have the tray application start automatically when you log in:

### Using Task Scheduler

1. Open Task Scheduler (`taskschd.msc`)
2. Click "Create Basic Task..."
3. Name: `filefind tray`
4. Trigger: "When I log on"
5. Action: "Start a program"
6. Program: `C:\Users\<username>\.cargo\bin\filefind-tray.exe`
7. Finish

### Using PowerShell

```powershell
$action = New-ScheduledTaskAction -Execute "$env:USERPROFILE\.cargo\bin\filefind-tray.exe"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "filefind tray" -Action $action -Trigger $trigger -Settings $settings
```

## Architecture

The tray application:

1. Creates a system tray icon using the `tray-icon` crate
2. Periodically polls the daemon status via IPC (named pipes)
3. Updates the icon color and tooltip based on daemon state
4. Handles menu events to control the daemon

### IPC Communication

The tray app uses the same IPC client as the CLI to communicate with the daemon:

- Connects to named pipe `\\.\pipe\filefind`
- Sends commands: start, stop, rescan, status
- Receives status updates with file/directory counts
