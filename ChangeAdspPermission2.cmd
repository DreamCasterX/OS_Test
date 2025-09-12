takeown /F %CD% /R /A
echo y| cacls %CD% /T /E /G Everyone:F
:START %CD%
