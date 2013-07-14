using System;
using System.Collections.Generic;
using System.IO;
using CommandLine.Utility;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace OpenMetaverse.TestClient
{
    public class CommandLineArgumentsException : Exception
    {
    }

    public class TrustLindenLabCertificatePolicy : ICertificatePolicy
    {
        public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem)
        {
            return false;
        }

        public static byte[] lindenlabcacert;
        public static X509ChainPolicy policy;

        private static bool CheckChain(X509Certificate2 cert)
        {
            if (cert == null || policy == null) return false;
            X509Chain chain = new X509Chain();

            chain.ChainPolicy = policy;

            chain.Build(cert);

            if (chain.ChainStatus.Length == 1 && chain.ChainStatus[0].Status == X509ChainStatusFlags.UntrustedRoot)
            {
                var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;

                return root.Thumbprint == "FA1AF1C586013830CD0E67F9B07EF59152C139B5";
            }
            if (chain.ChainStatus.Length == 0) return true;

            return false;
        }

        public static bool TestLindenLabCertificateAuthorityHandler(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
            {
                return CheckChain(certificate as X509Certificate2);
            }

            return false;
        }
    }

    public class Program
    {
        public static string LoginURI;

        private static void Usage()
        {
            Console.WriteLine("Usage: " + Environment.NewLine +
                    "TestClient.exe [--first firstname --last lastname --pass password] [--file userlist.txt] [--loginuri=\"uri\"] [--startpos \"sim/x/y/z\"] [--master \"master name\"] [--masterkey \"master uuid\"] [--gettextures] [--scriptfile \"filename\"]");
        }

        static void Main(string[] args)
        {
            Arguments arguments = new Arguments(args);

            List<LoginDetails> accounts = new List<LoginDetails>();
            LoginDetails account;
            bool groupCommands = false;
            string masterName = String.Empty;
            UUID masterKey = UUID.Zero;
            string file = String.Empty;
            bool getTextures = false;
            bool noGUI = false; // true if to not prompt for input
            string scriptFile = String.Empty;

            if (arguments["groupcommands"] != null)
                groupCommands = true;

            if (arguments["masterkey"] != null)
                masterKey = UUID.Parse(arguments["masterkey"]);

            if (arguments["master"] != null)
                masterName = arguments["master"];

            if (arguments["loginuri"] != null)
                LoginURI = arguments["loginuri"];
            if (String.IsNullOrEmpty(LoginURI))
                LoginURI = Settings.AGNI_LOGIN_SERVER;
            Logger.Log("Using login URI " + LoginURI, Helpers.LogLevel.Info);

            if (arguments["gettextures"] != null)
                getTextures = true;

            if (arguments["nogui"] != null)
                noGUI = true;

            if (arguments["scriptfile"] != null)
            {
                scriptFile = arguments["scriptfile"];
                if (!File.Exists(scriptFile))
                {
                    Logger.Log(String.Format("File {0} Does not exist", scriptFile), Helpers.LogLevel.Error);
                    return;
                }
            }

            if (arguments["file"] != null)
            {
                file = arguments["file"];

                if (!File.Exists(file))
                {
                    Logger.Log(String.Format("File {0} Does not exist", file), Helpers.LogLevel.Error);
                    return;
                }

                // Loading names from a file
                try
                {
                    using (StreamReader reader = new StreamReader(file))
                    {
                        string line;
                        int lineNumber = 0;

                        while ((line = reader.ReadLine()) != null)
                        {
                            lineNumber++;
                            string[] tokens = line.Trim().Split(new char[] { ' ', ',' });

                            if (tokens.Length >= 3)
                            {
                                account = new LoginDetails();
                                account.FirstName = tokens[0];
                                account.LastName = tokens[1];
                                account.Password = tokens[2];

                                if (tokens.Length >= 4) // Optional starting position
                                {
                                    char sep = '/';
                                    string[] startbits = tokens[3].Split(sep);
                                    account.StartLocation = NetworkManager.StartLocation(startbits[0], Int32.Parse(startbits[1]),
                                        Int32.Parse(startbits[2]), Int32.Parse(startbits[3]));
                                }

                                accounts.Add(account);
                            }
                            else
                            {
                                Logger.Log("Invalid data on line " + lineNumber +
                                    ", must be in the format of: FirstName LastName Password [Sim/StartX/StartY/StartZ]",
                                    Helpers.LogLevel.Warning);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log("Error reading from " + args[1], Helpers.LogLevel.Error, ex);
                    return;
                }
            }
            else if (arguments["first"] != null && arguments["last"] != null && arguments["pass"] != null)
            {
                // Taking a single login off the command-line
                account = new LoginDetails();
                account.FirstName = arguments["first"];
                account.LastName = arguments["last"];
                account.Password = arguments["pass"];

                accounts.Add(account);
            }
            else if (arguments["help"] != null)
            {
                Usage();
                return;
            }

            using (var stream = System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream("TestClient.lindenlab.cer"))
            {
                TrustLindenLabCertificatePolicy.lindenlabcacert = new byte[stream.Length];
                stream.Read(TrustLindenLabCertificatePolicy.lindenlabcacert, 0, (int)stream.Length);
            }
            TrustLindenLabCertificatePolicy.policy = new X509ChainPolicy();
            TrustLindenLabCertificatePolicy.policy.RevocationMode = X509RevocationMode.NoCheck;
            TrustLindenLabCertificatePolicy.policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            TrustLindenLabCertificatePolicy.policy.ExtraStore.Add(new X509Certificate2(TrustLindenLabCertificatePolicy.lindenlabcacert));
            System.Net.ServicePointManager.ServerCertificateValidationCallback = TrustLindenLabCertificatePolicy.TestLindenLabCertificateAuthorityHandler;

            foreach (LoginDetails a in accounts)
            {
                a.GroupCommands = groupCommands;
                a.MasterName = masterName;
                a.MasterKey = masterKey;
                a.URI = LoginURI;

                if (arguments["startpos"] != null)
                {
                    char sep = '/';
                    string[] startbits = arguments["startpos"].Split(sep);
                    a.StartLocation = NetworkManager.StartLocation(startbits[0], Int32.Parse(startbits[1]),
                            Int32.Parse(startbits[2]), Int32.Parse(startbits[3]));
                }
            }

            // Login the accounts and run the input loop
            ClientManager.Instance.Start(accounts, getTextures);

            if (!String.IsNullOrEmpty(scriptFile))
                ClientManager.Instance.DoCommandAll("script " + scriptFile, UUID.Zero);

            // Then Run the ClientManager normally
            ClientManager.Instance.Run(noGUI);
        }
    }
}
