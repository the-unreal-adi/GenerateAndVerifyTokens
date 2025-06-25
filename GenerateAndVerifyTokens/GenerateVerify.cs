using System.Security.Cryptography;
using System.Text;

namespace GenerateAndVerifyTokens
{
    public static class GenerateVerify
    {
        public static string GenerateToken(string key, string messageText)
        {
            string signature = "";

            byte[] privBytesIn = Convert.FromBase64String(key);
            using ECDsa slotKeyLoaded = ECDsa.Create();
            slotKeyLoaded.ImportPkcs8PrivateKey(privBytesIn, out _);

            DateTime today = DateTime.UtcNow.Date;
            DateTime now = DateTime.UtcNow;
            DateTime midnight = now.Date;
            double minsSince = (now - midnight).TotalMinutes;
            int intervalId = (int)(minsSince / 2);
            string date = today.ToString("yyyy-MM-dd");
            byte[] message = Encoding.UTF8.GetBytes($"{messageText}:slot:{date:yyyy-MM-dd}:{intervalId}");

            // 4) Sign some data
            byte[] signatureBytes = slotKeyLoaded.SignData(
                message,
                HashAlgorithmName.SHA256
            );

            signature = Convert.ToBase64String(signatureBytes);
            return signature;
        }

        public static bool VerifyToken(string key, string messageText, string signatureBase64)
        {
            bool isVerified = false;

            byte[] pubBytesIn = Convert.FromBase64String(key);
            using ECDsa pubOnly = ECDsa.Create();
            pubOnly.ImportSubjectPublicKeyInfo(pubBytesIn, out _);

            DateTime today = DateTime.UtcNow.Date;
            DateTime now = DateTime.UtcNow;
            DateTime midnight = now.Date;
            double minsSince = (now - midnight).TotalMinutes;
            int intervalId = (int)(minsSince / 2);

            string date = today.ToString("yyyy-MM-dd");
            byte[] message = Encoding.UTF8.GetBytes($"{messageText}:slot:{date:yyyy-MM-dd}:{intervalId}");

            byte[] signature = Convert.FromBase64String(signatureBase64);

            isVerified = pubOnly.VerifyData(
                message,
                signature,
                HashAlgorithmName.SHA256
            );

            return isVerified;
        }
    }
}
