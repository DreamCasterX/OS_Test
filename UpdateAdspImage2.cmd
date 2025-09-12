@echo off
echo.======== Current qcadsp8480.mbn vesion ========
forfiles /P C:\Windows\System32\DriverStore\FileRepository /S /M qcadsp8480.mbn /C "cmd /C find \"OEM_IMAGE_VERSION_STRING\" @path"
echo.
echo.
echo.
echo.
echo.
set LocalDateTime=%date:~10,4%%date:~4,2%%date:~7,2%%time:~0,2%%time:~3,2%%time:~6,2%
set LocalDateTime=%LocalDateTime: =0%


rename qcadsp8480.mbn qcadsp8480_%LocalDateTime%.mbn
copy %~dp0\qcadsp8480.mbn %CD%
copy %~dp0\adsp_dtbs.elf %CD%

echo.======== Copy qcadsp8480.mbn to %CD% ========
echo.
echo.
echo.
echo.
echo.========      Check new Version      ========
forfiles /P C:\Windows\System32\DriverStore\FileRepository /S /M qcadsp8480.mbn /C "cmd /C find \"OEM_IMAGE_VERSION_STRING\" @path"


pause