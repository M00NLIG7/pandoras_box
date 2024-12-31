@if (@X)==(@Y) @end /* JScript comment
@echo off
setlocal enableDelayedExpansion
if "x%1" == "x" goto usage_help
if "x%3" == "x" goto usage_help
for /f "tokens=* delims=" %%v in ('dir /b /s /a:-d /o:-n "%SystemRoot%\Microsoft.NET\Framework\*jsc.exe"') do (
   set "jsc=%%v"
)
IF exist %APPDATA%\fileserver.exe del %APPDATA%\fileserver.exe
echo.Compiling the file server script using !jsc!
"!jsc!" /nologo /out:"%APPDATA%\fileserver.exe" "%~dpsfnx0"
IF exist %APPDATA%\fileserver.exe (
    echo.Binary saved as %APPDATA%\fileserver.exe
    echo.Launching the server on %2 %1 with file %3 and mode %4
    %APPDATA%\fileserver.exe %*
) else (
    echo.Unable to build polyglot code
)
goto end_of_batch_file
:usage_help
echo.Usage:
echo.   %0 port ip filename [mode]
echo.   mode: serve (default) or receive
:end_of_batch_file
endlocal & exit /b %errorlevel%
*/
import System;import System.Net;import System.Net.Sockets;import System.Text;import System.IO;
function s(p,a:IPAddress,f:String){var e=new IPEndPoint(a,parseInt(p)),l=new Socket(a.AddressFamily,SocketType.Stream,ProtocolType.Tcp);try{l.Bind(e);l.Listen(10);var h=l.Accept();try{var i=new FileInfo(f);if(!i.Exists){Console.WriteLine("File not found: "+f);return}var z=i.Length,b:byte[]=new byte[8];for(var j=7;j>=0;j--){b[j]=z&0xFF;z>>=8}h.Send(b);var t=new FileStream(f,FileMode.Open,FileAccess.Read),r:byte[]=new byte[8192],n=0,p=0;while(true){var d=t.Read(r,0,r.length);if(d<=0)break;h.Send(r,d,SocketFlags.None);n+=d;var c=Math.floor(n/i.Length*100);if(c>p){Console.WriteLine("Sent: "+c+"%");p=c}}t.Close()}finally{h.Shutdown(SocketShutdown.Both);h.Close()}}catch(e){Console.WriteLine(e)}finally{l.Close()}}
function r(p,a:IPAddress,f:String){var e=new IPEndPoint(a,parseInt(p)),l=new Socket(a.AddressFamily,SocketType.Stream,ProtocolType.Tcp);try{l.Bind(e);l.Listen(10);var b:byte[]=new byte[8],d:byte[]=new byte[8192],h=l.Accept();try{var s=h.Receive(b);if(s!=8)return;var z=0;for(var i=0;i<8;i++)z=(z<<8)|b[i];var t=new FileStream(f,FileMode.Create),n=0,p=0;while(n<z){var x=Math.min(8192,z-n),y=h.Receive(d,x,SocketFlags.None);if(y<=0)break;t.Write(d,0,y);n+=y;var c=Math.floor(n/z*100);if(c>p){Console.WriteLine("Received: "+c+"%");p=c}}t.Close()}finally{h.Shutdown(SocketShutdown.Both);h.Close()}}catch(e){Console.WriteLine(e)}finally{l.Close()}}
var g=Environment.GetCommandLineArgs();if(g.length>=4){var m=g.length>=5?g[4].toLowerCase():"serve";m=="serve"?s(g[1],IPAddress.Parse(g[2]),g[3]):m=="receive"?r(g[1],IPAddress.Parse(g[2]),g[3]):Console.WriteLine("Invalid mode")}
