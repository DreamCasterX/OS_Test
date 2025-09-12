@echo off
forfiles /P C:\Windows\System32\DriverStore\FileRepository /S /M ADSP /C "cmd /c call %~dp0\UpdateADSPImage2"