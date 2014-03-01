#!/bin/sh

sudo launchctl stop com.fsb.logKext
sudo launchctl unload /Library/LaunchDaemons/logKext.plist
sudo /Library/Application\ Support/logKext/logKextKeyGen remove
sudo rm -f /Library/LaunchDaemons/logKext.plist
sudo rm -rf /System/Library/Extensions/logKext.kext
sudo rm -rf /Library/Application\ Support/logKext
sudo rm -rf /Library/Receipts/logKext*
if [ -z "`sudo defaults read com.fsb.logKext Pathname | grep 'does not exist'`" ];
then
sudo rm "`sudo defaults read com.fsb.logKext Pathname`"
fi;
sudo rm -f /usr/bin/logKextClient
sudo rm -f /LogKext\ Readme.html
sudo defaults delete com.fsb.logKext
sudo rm -f /LogKextUninstall.command
sudo kextunload -b com.fsb.kext.logKext
