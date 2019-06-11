# Burp Sub domains extension

A very simple, straightforward extension to export sub domains from Burp using a context menu option. 

![](http://g.recordit.co/qnpcbcsJH6.gif)

Unbestown to many, Burp has amazing passive gathering capabilities that allows to easily discover sub domains related to a target you're assessing. These often only come up after browsing and using the target features extensively. Some of them are only linked - i.e. are not necessarily requested, which make them even more interesting for recon purposes.

## Install

1. Make sure you have Jython configured under Extender -> Options -> Python Environment. For further instructions, check PortSwigger official instructions at their [support page](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite).
2. `git clone git@github.com:Regala/burp-subdomains.git`
3. Import [main_release.py](main_release.py) in Extender - Extender -> Extensions -> Add -> Select Python -> Select [main_release.py](main_release.py)


