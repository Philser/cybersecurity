#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
	pid=`ps aux | grep brainpan.exe | grep -v grep`
	if [[ ! -z $pid ]]; then
		kill -9 $pid
		killall wineserver
		killall winedevice.exe
	fi
	/usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
	pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
	if [[ ! -z $pid ]]; then
		kill -9 $pid
	fi
	cd /home/puck/web
	/usr/bin/python -m SimpleHTTPServer 10000
fi 
