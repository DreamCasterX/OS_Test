$_creator = "Mike Lu (lu.mike@inventec.com)"
$_version = 1.0
$_changedate = 11/06/2025


# Set-ExecutionPolicy RemoteSigned

$Configurations = @{
    "CashmereQ" = @{
        SensorList = @{
            "iob" = "iob"
            "color" = "tcs3530"
            "ambient_light" = "tcs3530"
            "st_wkmp" = "lsm6dso16is"
            "st_intransport" = "lsm6dso16is"
            "st_pickup" = "lsm6dso16is"
            "st_otd" = "lsm6dso16is"
            "st_oob" = "lsm6dso16is"
            "st_ib" = "lsm6dso16is"
            "sensor_temperature" = "lsm6dso16is"
            "gyro" = "lsm6dso16is"
            "accel" = "lsm6dso16is"
        }
    }
    "Dolcelatte" = @{
        SensorList = @{
            "human_presence_detect" = "human_presence_detect"
        }
    }
    # Add more configurations here in the future, for example:
    # "NewConfig" = @{
    #     SensorList = @{
    #         "sensor1" = "expected_value1"
    #         "sensor2" = "expected_value2"
    #     }
    # }
}

function Show-ConfigurationMenu {
    Write-Host ""
    Write-Host "=================="
    
    $configNames = $Configurations.Keys | Sort-Object
    $index = 1
    foreach ($configName in $configNames) {
        Write-Host " [$index] $configName" 
        $index++
    }
    Write-Host "==================" 
    Write-Host ""

    
    do {
        $selection = Read-Host "Select a SUT"
        try {
            $choiceIndex = [int]$selection - 1
            if ($choiceIndex -ge 0 -and $choiceIndex -lt $configNames.Count) {
                $selectedConfigName = $configNames[$choiceIndex]
                return $selectedConfigName
            } else {
                continue
            }
        } catch {
            continue
        }
    } while ($true)
}

# Let user select configuration
$selectedConfigName = Show-ConfigurationMenu
$selectedConfig = $Configurations[$selectedConfigName]
$sensorList = $selectedConfig.SensorList

# ============================================================================
# Common Settings (can be customized per configuration if needed)
# ============================================================================
$product_id = "8480"
$CVA_OS = "W11A"
$CVA_filePath = Join-Path -Path $PSScriptRoot -ChildPath "CVA_info.txt"
$infFileName_ADSP = "qcsubsys_ext_adsp$product_id.inf"
$mbnFileName_ADSP = "qcadsp$product_id.mbn"
$infFileName_ABD = "qcabd$product_id.inf"
$exeFilePath = ".\Version.exe"
$OpenAdspFolders = $false

# Display selected configuration
Write-Host "Running with config: " -NoNewline
Write-Host "$selectedConfigName" -ForegroundColor Yellow
Write-Host ""

# ============================================================================
# Common Functions
# ============================================================================

# Func to safely read current file content 
function Get-SafeFileContent {
    param($FilePath)
    if (Test-Path $FilePath) {
        try {
            $content = Get-Content $FilePath -Raw
            return if ($content) { $content } else { "" }
        } catch {
            return ""
        }
    }
    return ""
}

# Func to safely write file content 
function Add-ContentSafely {
    param($FilePath, $Content, $Description = "")
    
    try {
        $Content | Add-Content -Path $FilePath -Encoding UTF8
    } catch {
        if ($Description) {
            Write-Host "Write fail $Description : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Func to check specific title in the file content
function Test-SectionExists {
    param($FilePath, $SectionTitle)
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    try {
        $result = Select-String -Path $FilePath -Pattern [regex]::Escape($SectionTitle) -SimpleMatch
        return $null -ne $result
    } catch {
        $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
        if ($content) {
            return $content -like "*$SectionTitle*"
        }
        return $false
    }
}

# Check if the file is empty or only has null strings
function Test-FileIsEmpty {
    param($FilePath)
    
    if (-not (Test-Path $FilePath)) { return $true }
    try {
        $item = Get-Item -Path $FilePath -ErrorAction Stop
        if ($item.Length -gt 0) { return $false }
        $hit = Select-String -Path $FilePath -Pattern '\\S' -ErrorAction SilentlyContinue
        return $null -eq $hit
    } catch {
        return $true
    }
}

# Inlined replacement for ChangeAdspPermission1/2.cmd
function Invoke-ChangeAdspPermission {
    param([bool]$OpenFolders = $false)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Admin rights required for permission changes. Please run PowerShell as Administrator." -ForegroundColor Yellow
        return
    }

    $targetRoot = 'C:\Windows\System32\DriverStore\FileRepository'
    try {
        $dirs = Get-ChildItem -Path $targetRoot -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'qcsubsys_ext_adsp' }
    } catch {
        $dirs = @()
    }

    foreach ($dir in $dirs) {
        try {
            & takeown /F $dir.FullName /R /A | Out-Null
            # Use icacls (cacls is deprecated)
            & icacls $dir.FullName /T /grant Everyone:F /C | Out-Null
            if ($OpenFolders) { Start-Process explorer.exe $dir.FullName }
        } catch {
            Write-Host "Failed to update permission on $($dir.FullName): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

# Display system info
$BIOS_ver = (Get-CimInstance -ClassName Win32_BIOS).Name
$OS_build = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
$OS_ver = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
Write-Host ""
Write-Host "==== System Information ===="
Write-Host "BIOS: " -NoNewline
Write-Host "$BIOS_ver" -ForegroundColor 'Green'
Write-Host "OS: " -NoNewline
Write-Host "$OS_ver Build $OS_build" -ForegroundColor 'Green'
Write-Host "============================"
Write-Host ""


# Launch MS Camera app
try {
    Write-Host "Launching MS Camera app..." 
    Start-Process -FilePath "microsoft.windows.camera:" -ErrorAction Stop
    Write-Host "Done" 
    Write-Host ""
    Write-Host ""
} catch {
    Write-Host "Failed to open Camera！" -ForegroundColor Red
    Write-Host "Error：" -ForegroundColor Yellow
    Write-Host $_.Exception.Message -ForegroundColor Red
}


# Show device YB
Write-Host "Checking YB (error status) on DM..." 
$errorDevices = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' }
$counter = 1
$show_YB = $errorDevices | 
    Select-Object @{Name="No."; Expression={ $script:counter; $script:counter++ }},
    @{Name="Class"; Expression={ if ($_.Class) { $_.Class } else { "Unknown" } }}, 
    @{Name="FriendlyName"; Expression={ if ($_.FriendlyName) { $_.FriendlyName } else { if ($_.Name) { $_.Name } else { "Unknown Device" } } }}, 
    @{Name="InfName"; Expression={
        try {
            $inf = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath' -ErrorAction SilentlyContinue
            if ($inf.Data) { Split-Path $inf.Data -Leaf } else { "N/A" }
        } catch { "N/A" }
    }}, 
    @{Name="HardwareID"; Expression={
        try {
            $hwid = Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue
            if ($hwid.Data -and $hwid.Data.Count -gt 0) { $hwid.Data[0] } else { "N/A" }
        } catch { "N/A" }
    }} | Format-Table -AutoSize | Out-String
Write-Host $show_YB -ForegroundColor 'Yellow'


# Check installed ADSP folder
Write-Host "Changing ADSP permission..."
Invoke-ChangeAdspPermission -OpenFolders:$OpenAdspFolders

$infFileFound = Get-ChildItem -Path C:\Windows\System32\DriverStore\FileRepository -Filter $infFileName_ADSP -Recurse
$mbnFileFound = Get-ChildItem -Path C:\Windows\System32\DriverStore\FileRepository -Filter $mbnFileName_ADSP -Recurse

if ($infFileFound) {
    # Get the full path of the found file
    $infFileFullPath = $infFileFound.FullName
    Write-Host "INF file found at: " -NoNewline 
    Write-Host "$infFileFullPath" -ForegroundColor 'White'
}

if ($mbnFileFound) {
    # Get the full path of the found file
    $mbnFileFullPath = $mbnFileFound.FullName
    Write-Host "MBN file found at: " -NoNewline 
    Write-Host "$mbnFileFullPath" -ForegroundColor 'White'

    # Initialize OEM Build Version variable
    $oemBuildVer = $null

    # Extract OEM Build Version from MBN file
    try {
        # Read the file as byte array
        $bytes = [System.IO.File]::ReadAllBytes($mbnFileFullPath)
        
        # Convert bytes to ASCII string (ignoring non-printable characters)
        $content = [System.Text.Encoding]::ASCII.GetString($bytes)
        
        # Search for OEM_IMAGE_VERSION_STRING pattern and extract version number
        $pattern = 'OEM_IMAGE_VERSION_STRING=(\d+)'
        $match = [regex]::Match($content, $pattern)
        
        if ($match.Success) {
            $oemBuildVer = $match.Groups[1].Value
        }

    } catch {
        # Fallback: Use cmd findstr method
        try {
            $findResult = & cmd /c "findstr /C:`"OEM_IMAGE_VERSION_STRING`" `"$mbnFileFullPath`"" 2>$null
            
            if ($findResult) {
                # Extract version number from the result
                $versionMatch = [regex]::Match($findResult, 'OEM_IMAGE_VERSION_STRING=(\d+)')
                if ($versionMatch.Success) {
                    $oemBuildVer = $versionMatch.Groups[1].Value
                }
            }
        } catch {
            # Keep $oemBuildVer as $null if both methods fail
        }
    }

    # Display ADSP Information
    try {
        # Read the file content and use Select-String to find the required strings
        $fileContent = Get-Content -Path $infFileFullPath

        $extensionId = $fileContent | Select-String -Pattern 'ExtensionId\s*=\s*({[^}]+})'
        $driverVer = $fileContent | Select-String -Pattern 'DriverVer\s*=\s*(\d{2}\/\d{2}\/\d{4},[\w\d\.]+)'

        # Display the captured information
        Write-Host "`n==== ADSP Information ===="
        if ($extensionId) {
            Write-Host "ExtensionId: " -NoNewline
            Write-Host "$($extensionId.Matches.Groups[1].Value)" -ForegroundColor 'Blue'
        } else {
            Write-Host "ExtensionId: " -NoNewline
            Write-Host "Not found" -ForegroundColor 'Red'
        }

        if ($driverVer) {
            Write-Host "DriverVer: " -NoNewline
            Write-Host "$($driverVer.Matches.Groups[1].Value)" -ForegroundColor 'Blue'
        } else {
            Write-Host "DriverVer: " -NoNewline
            Write-Host "Not found" -ForegroundColor 'Red'
        }

        # Display OEM Build Version
        if ($oemBuildVer) {
            Write-Host "OEM Build Ver: " -NoNewline
            Write-Host "$oemBuildVer" -ForegroundColor 'Blue'
        } else {
            Write-Host "OEM Build Ver: " -NoNewline
            Write-Host "Not found" -ForegroundColor 'Red'
        }

        Write-Host "=========================="

    } catch {
        Write-Host "Error reading the INF file. You may need to run the ChangeAdspPermission1.cmd manually to grant permissions." -ForegroundColor 'Red'
    }

} else {
    Write-Host "Error: The INF file '$infFileName_ADSP' was not found in the DriverStore." -ForegroundColor 'Red'
    Write-Host "Error: The MBN file '$mbnFileName_ADSP' was not found in the DriverStore." -ForegroundColor 'Red'
}

Write-Host ""
Write-Host ""

# Create CVA_info file
if (-not (Test-Path $CVA_filePath)) {
    New-Item -Path $CVA_filePath -ItemType File -Force | Out-Null
}

# Check Version.exe info
if (Test-Path $exeFilePath) {
	try {
		$exeItem = Get-Item $exeFilePath
		# More robust version retrieval
		$exeVersionString = $null
		try {
			$exeVersionString = $exeItem.VersionInfo.FileVersion
		} catch {}
		if (-not $exeVersionString) {
			try {
				$verInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path $exeFilePath))
				$exeVersionString = $verInfo.FileVersion
			} catch {}
		}

		# Convert version to hex: extract numeric parts, pad to 4 with zeros
		$exeHexVersion = "N/A"
		if ($exeVersionString) {
			$exeVersionParts = @([regex]::Matches($exeVersionString, '\d+')) | ForEach-Object { $_.Value }
			while ($exeVersionParts.Count -lt 4) { $exeVersionParts += '0' }
			$exeVersionParts = $exeVersionParts[0..3]
			$exeHexVersion = "0x{0:X4},0x{1:X4},0x{2:X4},0x{3:X4}" -f [int]$exeVersionParts[0], [int]$exeVersionParts[1], [int]$exeVersionParts[2], [int]$exeVersionParts[3]
		}

		# Display the captured information header (BSP)
		$BSP_sub = "`n==== BSP CVA Information ===="
		Write-Host $BSP_sub
		Write-Host "File Version: " -NoNewline
		Write-Host "$exeVersionString" -ForegroundColor 'Blue'

		# Signature info (can be slow on some systems due to revocation checks)
		try {
			$sig = Get-AuthenticodeSignature -FilePath $exeFilePath
			if ($sig) {
				$signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unknown signer" }
				$status = $sig.Status
                                $color = if ($status -eq 'Valid') { 'Blue' } else { 'Red' }
				Write-Host "Signature: " -NoNewline
				Write-Host "$status - $signer" -BackgroundColor $color
			} else {
				Write-Host "Signature: Not available" -ForegroundColor 'Yellow'
			}
		} catch {
			Write-Host "Signature: Skipped (error during signature check)" -ForegroundColor Yellow
		}

		# Display and persist the formatted line
		$exe_info = "Version.exe=<DRIVERS>,$exeHexVersion,$CVA_OS"
		Write-Host $exe_info -ForegroundColor 'Green'
		Write-Host "============================="
	        Write-Host ""
                Write-Host ""

		# Check if CVA_info.txt has specific string
		$hasBSPInfo = Test-SectionExists $CVA_filePath "BSP CVA Information"
		if (-not $hasBSPInfo) {
			Add-ContentSafely $CVA_filePath $BSP_sub "BSP Header"
			Add-ContentSafely $CVA_filePath $exe_info "Version.exe Info"
		}

	} catch {
		Write-Host "Error: Failed to read Version.exe details." -ForegroundColor 'Red'
	}
} else {
	Write-Host "Error: Version.exe not found in the current directory" -ForegroundColor 'Red'
}

# Check installed ABD folder path
$repo = 'C:\Windows\System32\DriverStore\FileRepository'
$abdDir = Get-ChildItem $repo -Directory | Where-Object { $_.Name -like "qcabd$product_id.inf_*" } | Select-Object -First 1
if ($abdDir) {
	$infFileFullPath = Join-Path $abdDir.FullName "qcabd$product_id.inf"
} else {
	# Fallback to original recursive search
	$infFileFound = Get-ChildItem -Path $repo -Filter $infFileName_ABD -Recurse
	if ($infFileFound) { $infFileFullPath = $infFileFound.FullName }
}
if ($infFileFullPath) {
	try {
        # Read the file content and use Select-String to find the required strings
        $fileContent = Get-Content -Path $infFileFullPath
        $driverVer = $fileContent | Select-String -Pattern 'DriverVer\s*=\s*(\d{2}\/\d{2}\/\d{4},[\w\d\.]+)'

        # Display the captured information
		$WinPE_sub = "`n==== WinPE CVA Information ===="
		Write-Host $WinPE_sub
		
        if ($driverVer) {
            Write-Host "DriverVer: " -NoNewline
			Write-Host "$($driverVer.Matches.Groups[1].Value)"
            
            # Parse version and convert to hex format
            $versionString = $driverVer.Matches.Groups[1].Value -replace '.*,'
            $versionParts = $versionString -split '\.'
            if ($versionParts.Count -ge 4) {
                $hexVersion = "0x{0:X4},0x{1:X4},0x{2:X4},0x{3:X4}" -f [int]$versionParts[0], [int]$versionParts[1], [int]$versionParts[2], [int]$versionParts[3]
            } else {
                $hexVersion = "N/A"
            }
            
            # Get directory name from the full path
            $directoryName = Split-Path (Split-Path $infFileFullPath -Parent) -Leaf
            
            # Display the formatted line
			$WinPE_info = "qcabd$product_id.sys=<WINSYSDIR>\DriverStore\FileRepository\$directoryName,$hexVersion,$CVA_OS" 
            Write-Host $WinPE_info -ForegroundColor 'Green'
			
			$hasWinPEInfo = Test-SectionExists $CVA_filePath "WinPE CVA Information"
			if (-not $hasWinPEInfo) {
				Add-ContentSafely $CVA_filePath $WinPE_sub "WinPE Header"
				Add-ContentSafely $CVA_filePath $WinPE_info "WinPE Info"
			}
			
        } else {
			Write-Host "DriverVer: " -NoNewline
            Write-Host "Not found" -ForegroundColor 'Red'
        }
        Write-Host "==============================="

    } catch {
        Write-Host "Error reading the INF file. You may need to run the ChangeAdspPermission1.cmd manually to grant permissions." -ForegroundColor 'Red'
    }

	
} else {
    Write-Host "Error: The INF file '$infFileName_ABD' was not found in the DriverStore." -ForegroundColor 'Red'
}
Write-Host ""
Write-Host ""
pause


# Init counter for summary
$totalSensors = $sensorList.Count
$nameNotFoundCount = 0
$nameMatchCount = 0
$nameMismatchCount = 0


# Run sensor tool
$sscFilePath = Join-Path -Path $PSScriptRoot -ChildPath "ssc_sensor_info.exe"
if (-not (Test-Path $sscFilePath)) {
    Write-Host "ERROR: ssc_sensor_info.exe not found！" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host ""
Write-Host "Running sensor tool..."
foreach ($sensorName in $sensorList.Keys) {
    Write-Host "Checking sensor: $sensorName" -ForegroundColor Cyan
    Write-Host "------------------------------"
    $output = & $sscFilePath -sensor="$sensorName" *>&1
    $typeFound = $false

    $lines = $output -split "`n"
    foreach ($line in $lines) {
        if ($line.Trim().StartsWith("NAME ")) {
            $nameValue = $line.Trim() -replace "^NAME\s*=\s*", ""
            $nameValue = $nameValue.Trim()
            
            $expectedName = $sensorList[$sensorName]
            
            if ($expectedName -and $nameValue -eq $expectedName) {
                Write-Host $line -ForegroundColor Green
                $nameMatchCount++
            } elseif ($expectedName) {
                Write-Host $line -ForegroundColor Red
                Write-Host "Expected: $expectedName, but found: $nameValue" -ForegroundColor Yellow
                $nameMismatchCount++
            } else {
                Write-Host $line -ForegroundColor Yellow
                Write-Host "Warning: No expected value defined for sensor '$sensorName'" -ForegroundColor Yellow
                $nameMismatchCount++
            }
            $typeFound = $true
        } else {
            Write-Host $line
        }
    }
    
    if (-not $typeFound) {
        Write-Host "NAME not found!" -ForegroundColor Red
        $nameNotFoundCount++
    }

    Write-Host ""
    Write-Host ""
}

# Display detailed summary
Write-Host "=================================" 
Write-Host "           SUMMARY" 
Write-Host "=================================" 
Write-Host "Configuration: $selectedConfigName"
Write-Host "Total sensors checked: $totalSensors" 
Write-Host "NAME matched: $nameMatchCount"
Write-Host "NAME mismatched: $nameMismatchCount" 
Write-Host "NAME not found: $nameNotFoundCount" 
Write-Host "---------------------------------" 

# Determine PASS/FAIL based on criteria
if ($nameNotFoundCount -eq 0) {
    Write-Host "Result: PASSED" -ForegroundColor Green -BackgroundColor Black
} else {
    Write-Host "Result: FAILED" -ForegroundColor Red -BackgroundColor Black
}

Write-Host "---------------------------------" -ForegroundColor White
Write-Host ""
Write-Host ""
Write-Host ""
pause

