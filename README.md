msf_dropbox_scanner
===================

An MSF module for dropbox detection.  This can complement nmap or orther port scanning software.

==Installation ==

Clone this file:
    git clone https://github.com/dagorim/msf_dropbox_scanner.git

Create a folder under your MSF custom module directory:
    mkdir /root/.msf4/modules/auxiliary/scanner/misc/

Copy the file downloaded from step one into the directory from step 2:
    cp msf_dropbox_scanner/dropbox.rb /root/.msf4/modules/auxiliary/scanner/misc/

Now you can search for and use the module from within Metasploit:
    msf> use auxiliary/scanner/misc/dropbox