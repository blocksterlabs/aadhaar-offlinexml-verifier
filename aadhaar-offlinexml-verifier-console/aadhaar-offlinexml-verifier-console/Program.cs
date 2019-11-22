using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace aadhaar_offlinexml_verifier_console
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            string XMLFilePath = "D:\\Amit\\netAadhar\\offlineaadhaar20191121011352794.xml";
            string KeyFilePath = "D:\\Amit\\netAadhar\\uidai_offline_publickey_19062019.cer";
            XmlDocument ObjXmlDocument = new XmlDocument();
            ObjXmlDocument.Load(XMLFilePath);
            // XmlElement a = ObjXmlDocument.DocumentElement;            
            // XmlNodeList b = a.ChildNodes;
            string signatureValue = ObjXmlDocument.DocumentElement.ChildNodes[1].ChildNodes[1].InnerXml;
            XmlNode childElement = ObjXmlDocument.DocumentElement.ChildNodes[1];
            ObjXmlDocument.DocumentElement.RemoveChild(childElement);

            /*----------------Read and parse the public key as string-----------------------*/
            X509Certificate2 ObjX509Certificate2 = new X509Certificate2(KeyFilePath, "public"); //Initialize the public ket certificate file        
            Org.BouncyCastle.X509.X509Certificate objX509Certificate;
            X509CertificateParser objX509CertificateParser = new X509CertificateParser();
            objX509Certificate = objX509CertificateParser.ReadCertificate(ObjX509Certificate2.GetRawCertData());
            /*----------------End-----------------------*/


            /* Init alg */
            ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");


            /* Populate key */
            signer.Init(false, objX509Certificate.GetPublicKey());

            Console.WriteLine(signatureValue);
            Console.WriteLine("\n\n\n");
            Console.WriteLine(ObjXmlDocument.InnerXml);


            /* Get the signature into bytes */
            var expectedSig = Convert.FromBase64String(signatureValue);

            Console.WriteLine("\n\n\n\n  expectedSig");
            Console.WriteLine(Convert.ToString(expectedSig));
            Console.WriteLine("\n\n\n\n");

            /* Get the bytes to be signed from the string */
            var msgBytes = Encoding.UTF8.GetBytes(ObjXmlDocument.InnerXml);

            /* Calculate the signature and see if it matches */
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);

            bool Flag = signer.VerifySignature(expectedSig);
            Console.WriteLine("\n\n\n");
            if (Flag)
            {
                Console.WriteLine("XML Validate Successfully");
            }
            else
            {
                Console.WriteLine("XML Validation Failed");
            }


            Console.ReadKey();
        }
    }
}
