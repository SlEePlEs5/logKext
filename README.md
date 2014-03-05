logKext
=======

###Introduction
logKext v2.4

Release Date: 2014-03-01

Summary: LogKext is an open source keylogger for Mac OS X, a product of FSB software.

Requirements: Mac OS X 10.7.x - 10.9.x  
(older versions can be found on the [downloads](https://github.com/SlEePlEs5/logKext/releases) page.)

###Details
How to get started: Control and usage of logKext is through logKextClient. LogKextClient runs through the Mac OS X Terminal.

####Step 1: Finding the Terminal

Locate the Terminal Application (`/Applications/Utilities/Terminal`)

####Step 2: Using the Terminal

The window that pops up will have a command prompt that looks something like this: `Bill's-Computer:~ bill$ `  
At the prompt type the following command and press return:

    sudo logKextClient

You will be prompted for your account password (you must be an administrator). Enter it. You will not see the password echoed to the screen as you type it.

Next, logKext will prompt you for your logKext password:

    logKext password:

Type in your logKext password. The default password is "logKext". You will not see the password echoed to the screen as you type it.

####Step 3: Operating logKextClient

LogKextClient is an interactive client that allows you to change preference values that will change the behavior of your keylogger. Type `help` to get the help screen.

Most likely, you will want to see the logfile! To do this, use the `open` command. It will save the decrypted logfile to your desktop, and open it in a text editor. If you haven't yet typed 100 characters, you will not yet have a logfile. Come back later and try again.

####Uninstalling logKextClient

A standalone script has been installed in your computer's root directory that will uninstall logKext. It is called `LogKextUninstall.command`. Double-click it to run.



####Most Frequently Asked Question: Why is my logfile all gibberish?

If you have changed your password or turned encryption on or off, you must delete the logfile before these changes take effect; otherwise your client will try to decrypt using a different password than your daemon is encrypting: this results in "gibberish".

Use the logKextClient `list` command to see where your logfile is, then quit logKextClient. Find the logfile using the path, and throw it in the trash. If you try to empty the trash, don't worry if it says: `The operation can't be completed because the item "com.fsb.logKext" is in use`.  
After a while, you will be able to delete it.

You can also delete the logfile from the terminal if you know how ( `sudo rm -f <path>` ). You will need to enter your administrator password.

**Note: For security reasons, it is recommended that you change your password from the default setting.**
