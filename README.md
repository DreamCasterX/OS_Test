
**OS_Test** is a repository containing a PowerShell script and auxiliary binaries designed for operating system testing, diagnostics, and information gathering. This tool aims to provide a streamlined way to assess system health, collect sensor data, and perform various checks, making it valuable for quality assurance, troubleshooting, and system maintenance tasks, particularly in Windows environments.

## Key Features & Benefits
*   **Automated System Diagnostics**: Execute a series of checks to evaluate the operating system's state.
*   **Sensor Information Collection**: Utilize `ssc_sensor_info.exe` to gather detailed sensor data from the system.
*   **Diagnostic Logging**: Leverage `qcdiaglogging.dll` for robust diagnostic logging capabilities, aiding in issue identification.
*   **PowerShell Scripting**: Easy-to-understand and extendable script for custom testing scenarios.
*   **Streamlined Troubleshooting**: Quickly pinpoint potential issues by automating information gathering.
*   **QA and Validation**: Useful for validating system configurations and performance post-deployment or during manufacturing.

## Prerequisites & Dependencies
To run `OS_Test`, you will need:

*   **Operating System**: Windows 7 or newer (due to PowerShell and binary dependencies).
*   **PowerShell**: Version 5.1 or newer.
    *   You can check your PowerShell version by running `$PSVersionTable.PSVersion` in a PowerShell console.
*   **Administrative Privileges**: Some diagnostic checks or sensor data collection might require elevated permissions.

## Installation & Setup Instructions
Follow these steps to get a copy of the project up and running on your local machine.

### 1. Clone the Repository
```bash
git clone https://github.com/DreamCasterX/OS_Test.git
cd OS_Test
```

### 2. Configure PowerShell Execution Policy
By default, PowerShell might prevent scripts from running. You might need to adjust your execution policy.
**Caution**: Be aware of the security implications before changing your execution policy.
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
You can revert this setting later with `Set-ExecutionPolicy Restricted -Scope CurrentUser`.

### 3. Verify Project Structure
Ensure the `bin` directory and its contents (`qcdiaglogging.dll`, `ssc_sensor_info.exe`) are present alongside the main PowerShell script (`OS_Test_v1.6.ps1`).

## Usage Examples
To run the `OS_Test` script:

### Basic Execution
Navigate to the `OS_Test` directory in your PowerShell console and execute the script:
```powershell
.\OS_Test_v1.6.ps1
```

### Interpreting Output
The script will output various system information and diagnostic results directly to the console. Depending on its internal logic, it might also generate log files through `qcdiaglogging.dll` or output sensor data using `ssc_sensor_info.exe`. Review the console output and any generated log files for test results and system status.



*   Thanks to the PowerShell community for countless resources and inspiration.
*   Credit to the developers of `ssc_sensor_info.exe` and `qcdiaglogging.dll` for providing essential diagnostic capabilities.
