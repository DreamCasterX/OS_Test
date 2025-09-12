$_creator = "Mike Lu (lu.mike@inventec.com)"
$_changedate = 9/12/2025


$product_id = "8480"
$CVA_OS = "W11A"
$CVA_filePath = Join-Path -Path $PSScriptRoot -ChildPath "CVA_info.txt"
$infFileName_ADSP = "qcsubsys_ext_adsp$product_id.inf"
$mbnFileName_ADSP = "qcadsp$product_id.mbn"
$infFileName_ABD = "qcabd$product_id.inf"
$batFilePath = ".\ChangeAdspPermission1.cmd"
$exeFilePath = ".\Version.exe"
$sensorList = @{
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


# Display system info
$BIOS_ver = (Get-CimInstance -ClassName Win32_BIOS).Name
$OS_build = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
$OS_ver = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
Write-Host ""
Write-Host "==== System Information ===="
Write-Host "BIOS: " -NoNewline
Write-Host "$BIOS_ver" -ForegroundColor 'Blue'
Write-Host "OS: " -NoNewline
Write-Host "$OS_ver Build $OS_build" -ForegroundColor 'Blue'
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
Write-Host "Changing ADSP permission and opening the directory..."
& $batFilePath > $null 2>&1

$infFileFound = Get-ChildItem -Path C:\Windows\System32\DriverStore\FileRepository -Filter $infFileName_ADSP -Recurse -ErrorAction SilentlyContinue
$mbnFileFound = Get-ChildItem -Path C:\Windows\System32\DriverStore\FileRepository -Filter $mbnFileName_ADSP -Recurse -ErrorAction SilentlyContinue

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
        $fileContent = Get-Content -Path $infFileFullPath -ErrorAction SilentlyContinue

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
		$exeItem = Get-Item $exeFilePath -ErrorAction SilentlyContinue
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
			$sig = Get-AuthenticodeSignature -FilePath $exeFilePath -ErrorAction SilentlyContinue
			if ($sig) {
				$signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unknown signer" }
				Write-Host "Signature: " -NoNewline
				Write-Host "$($sig.Status) - $signer" -ForegroundColor 'Blue'
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

		# Load existing CVA_info.txt content
		$existingContent = ""
		if (Test-Path $CVA_filePath) {
			try { $existingContent = Get-Content $CVA_filePath -ErrorAction SilentlyContinue -Raw } catch { $existingContent = "" }
		}

		# Append header if not present
		if ($existingContent -notmatch [regex]::Escape($BSP_sub)) {
			try { $BSP_sub | Add-Content -Path $CVA_filePath -ErrorAction SilentlyContinue } catch { Write-Host "Warning: Could not write BSP header to CVA file" -ForegroundColor Yellow }
		}

		# Append info line if not present
		if ($existingContent -notmatch [regex]::Escape($exe_info)) {
			try { $exe_info | Add-Content -Path $CVA_filePath -ErrorAction SilentlyContinue } catch { Write-Host "Warning: Could not write Version.exe info to CVA file" -ForegroundColor Yellow }
		}

	} catch {
		Write-Host "Error: Failed to read Version.exe details." -ForegroundColor 'Red'
	}
} else {
	Write-Host "Error: Version.exe not found in the current directory" -ForegroundColor 'Red'
}

# Check installed ABD folder path
$repo = 'C:\Windows\System32\DriverStore\FileRepository'
$abdDir = Get-ChildItem $repo -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "qcabd$product_id.inf_*" } | Select-Object -First 1
if ($abdDir) {
	$infFileFullPath = Join-Path $abdDir.FullName "qcabd$product_id.inf"
} else {
	# Fallback to original recursive search
	$infFileFound = Get-ChildItem -Path $repo -Filter $infFileName_ABD -Recurse -ErrorAction SilentlyContinue
	if ($infFileFound) { $infFileFullPath = $infFileFound.FullName }
}
if ($infFileFullPath) {
	try {
        # Read the file content and use Select-String to find the required strings
        $fileContent = Get-Content -Path $infFileFullPath -ErrorAction SilentlyContinue
        $driverVer = $fileContent | Select-String -Pattern 'DriverVer\s*=\s*(\d{2}\/\d{2}\/\d{4},[\w\d\.]+)'

        # Display the captured information
		$WinPE_sub = "`n==== WinPE CVA Information ===="
		Write-Host $WinPE_sub
		
		# Load and write CVA_info.txt
        $existingContent = ""
        if (Test-Path $CVA_filePath) {
            try {
                $existingContent = Get-Content $CVA_filePath -ErrorAction SilentlyContinue -Raw
            } catch {
                $existingContent = ""
            }
        }
        
		if ($existingContent -notmatch [regex]::Escape($WinPE_sub)) {
			try {
                $WinPE_sub | Add-Content -Path $CVA_filePath -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Warning: Could not write to CVA file" -ForegroundColor Yellow
            }
		}
		
        if ($driverVer) {
            Write-Host "DriverVer: " -NoNewline
			Write-Host "$($driverVer.Matches.Groups[1].Value)" -ForegroundColor Blue
            
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
			
			# Load and write CVA_info.txt
            if ($existingContent -notmatch [regex]::Escape($WinPE_info)) {
                try {
                    $WinPE_info | Add-Content -Path $CVA_filePath -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "Warning: Could not write WinPE info to CVA file" -ForegroundColor Yellow
                }
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