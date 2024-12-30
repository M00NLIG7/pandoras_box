@if (@X)==(@Y) @end /* JScript comment
@echo off
setlocal enableDelayedExpansion

if "x%1" == "x" goto usage_help
if "x%3" == "x" goto usage_help

for /f "tokens=* delims=" %%v in ('dir /b /s /a:-d /o:-n "%SystemRoot%\Microsoft.NET\Framework\*jsc.exe"') do (
   set "jsc=%%v"
)

IF exist %APPDATA%\listener.exe del %APPDATA%\listener.exe

echo.Compiling the listener script using !jsc!
"!jsc!" /nologo /out:"%APPDATA%\listener.exe" "%~dpsfnx0"

IF exist %APPDATA%\listener.exe (
    echo.Binary saved as %APPDATA%\listener.exe
    echo.Launching the listener on %2 %1 with output to %3
    %APPDATA%\listener.exe %*
) else (
    echo.Unable to build polyglot code
)

goto end_of_batch_file

:usage_help
echo.Usage:
echo.   %0 port ip filename

:end_of_batch_file
endlocal & exit /b %errorlevel%

*/
import System;
import System.Net;
import System.Net.Sockets;
import System.Text;
import System.IO;

function StartListening(port, ipAddress:IPAddress, filename:String) {
   var localEndPoint = new IPEndPoint(ipAddress, parseInt(port));  
   var listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);  

   try {  
       listener.Bind(localEndPoint);  
       listener.Listen(10);  

       var headerBuf:byte[] = new byte[8];
       var data:byte[] = new byte[8192];
       
       Console.WriteLine("Waiting for a TCP connection on {0}:{1}...", ipAddress, port);  
       var handler = listener.Accept();  
       Console.WriteLine("Connected to {0}", handler.RemoteEndPoint);  

       try {
           var sizeRead = handler.Receive(headerBuf);
           if (sizeRead != 8) {
               Console.WriteLine("Invalid header size");
               return;
           }
           
           var fileSize = 0;
           for (var i = 0; i < 8; i++) {
               fileSize = (fileSize << 8) | headerBuf[i];
           }
           
           Console.WriteLine("Expecting file of size: " + fileSize + " bytes");
           Console.WriteLine("Will save to: " + filename);

           var fileStream = new FileStream(filename, FileMode.Create);
           var totalReceived = 0;
           var lastPercent = 0;

           while (totalReceived < fileSize) {
               var toRead = Math.min(8192, fileSize - totalReceived);
               var bytesRec = handler.Receive(data, toRead, SocketFlags.None);
               if (bytesRec <= 0) break;
               
               fileStream.Write(data, 0, bytesRec);
               totalReceived += bytesRec;
               
               var percent = Math.floor((totalReceived / fileSize) * 100);
               if (percent > lastPercent) {
                   Console.WriteLine("Received: " + percent + "%");
                   lastPercent = percent;
               }
           }

           fileStream.Close();
           Console.WriteLine("File saved as: " + filename);

       } finally {
           Console.WriteLine("\nDisconnected\n");
           handler.Shutdown(SocketShutdown.Both);  
           handler.Close();
       }
       
       listener.Close();

   } catch (e) {  
       Console.WriteLine(e.ToString());  
   }  
}

function GetThisHostIPv4Address() {
   var ipAddress = IPAddress.Parse("127.0.0.1");
   var ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());  

   for(var i=0; i<ipHostInfo.AddressList.length; ++i) {
       if (ipHostInfo.AddressList[i].AddressFamily == AddressFamily.InterNetwork) {
          ipAddress = ipHostInfo.AddressList[i];
          break;
        }
   }

   return ipAddress;
}

var arguments:String[] = Environment.GetCommandLineArgs();

if (arguments.length == 4) {
    StartListening(arguments[1], IPAddress.Parse(arguments[2]), arguments[3]);
} else {
    Console.WriteLine("Usage: listener port ip filename");
}
