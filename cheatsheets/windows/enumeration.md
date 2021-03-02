### Find file in current and subdirectories
`dir /s SEARCH_NAME`

### Restart a service
`net stop SERVICE_NAME && net start SERVICE_NAME`

- Restart all depending services
`net stop /y`  

Alternative: `sc stop|start SERVICE_NAME` 
PowerShell: `Restart-Service SERVICE_NAME`

### Show running processes including User
`tasklist /v`


### Download files
`powershell -c "(new-object System.Net.WebClient).DownloadFile('TARGET_URL','LOCAL_TARGET_FILE')"`