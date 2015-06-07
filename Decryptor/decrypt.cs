using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using StringDLLProtection;

namespace Dotwall_deobfuscator.Decryptor
{
    internal class decrypt
    {
        public static Stream BnnFeasJ;
        public static string resourcename;
        public static string filename;
        static decrypt()
        {
            filename = Form1.filename;
            resourcename = Form1.resourcename;
            int arg_27_0 = 2;
            while (true)
            {
                switch (arg_27_0)
                {
                    case 0:
                    {
                        return;
                    }
                    case 1:
                    {
                        BnnFeasJ = Assembly.LoadFile(filename)
                            .GetManifestResourceStream(resourcename);
                        arg_27_0 = 0;
                        break;
                    }
                    case 2:
                    {
                        if (BnnFeasJ != null)
                        {
                            return;
                        }
                        arg_27_0 = 1;
                        break;
                    }
                    default:
                    {
                        int num = 0;
                        arg_27_0 = num;
                        break;
                    }
                }
            }
        }

        public static string decryptor(int A7LzUKtY, string resourcename, string filename)
        {
            resourcename = resourcename;
            filename = filename;
            return zY8S2HDn(A7LzUKtY);
        }

        internal static string zY8S2HDn(int z7lFCNSX)
        {
            return b64decrypt(new BinaryReader(BnnFeasJ)
            {
                BaseStream =
                {
                    Position = (long) z7lFCNSX
                }
            }.ReadString());
        }

        internal static string b64decrypt(string Ph04hwrl)
        {
            byte[] bytes = Convert.FromBase64String(Ph04hwrl);
            return Encoding.UTF8.GetString(bytes);
        }


    }
}

