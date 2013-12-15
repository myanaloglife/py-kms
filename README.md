# History
py-kms is a port of node-kms by [markedsword](http://forums.mydigitallife.info/members/183074-markedsword), which is a port of either the C#, C++, or .NET implementations of KMSEmulator, of which the original version was written by [CODYQX4](http://forums.mydigitallife.info/members/89933-CODYQX4) and is derived from the reverse-engineered code of Microsoft's official KMS.

# Features
- Responds to V4, V5, and V6 KMS requests.
- Supports activating Windows 7/8/8.1/2008R2/2012/2012R2 and Office 2010/2013.
- It's written in Python.

# Dependencies
- Python 2.7.x or Python 2.6.x with the "argparse" module installed.
- If the "pytz" module is installed, the "Request Time" in the verbose output will be converted into local time. Otherwise, it will be in UTC.

# Usage
- To start the server, execute `python server.py [listen_address] [port]`. The default listening address is `0.0.0.0` (all interfaces) and the default port is `1688`.
- To run the client, use `python client.py server_address [port]`. The default port is `1688`.