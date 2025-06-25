using System.Security.Cryptography;
using System.Text;

namespace KeyRotationDerivation
{
    class GenerateKeypair
    {
        static void Main()
        {
            // --- 1) Derive the slot key as before ---
            byte[] rootSeed = Convert.FromBase64String("mZ7x9Gc2jKpQiR4u5T6v7W8xY9zA0bCdeF1Gh2Ij3KL=");
            var kds = new KeyDerivationService(rootSeed);
            DateTime today = DateTime.UtcNow.Date;
            int intervalDuration = 5;
            using ECDsa slotKey = kds.DeriveSlotKey(today, intervalDuration);

            // --- 2) Export to standard blobs ---
            byte[] privBytes = slotKey.ExportPkcs8PrivateKey();       // PKCS#8 DER
            byte[] pubBytes = slotKey.ExportSubjectPublicKeyInfo(); // X.509/SPKI DER

            // Optionally Base64‐encode for storage
            string privB64 = Convert.ToBase64String(privBytes);
            string pubB64 = Convert.ToBase64String(pubBytes);

            // Persist to disk (or database) separately
            File.WriteAllText("slot.private.b64.txt", privB64);
            File.WriteAllText("slot.public.b64.txt", pubB64);

            Console.WriteLine("Keys saved.");

            // --- 3) Later: re-import them ---

            // Read back Base64
            string privB64In = File.ReadAllText("slot.private.b64.txt");
            string pubB64In = File.ReadAllText("slot.public.b64.txt");

            byte[] privBytesIn = Convert.FromBase64String(privB64In);
            byte[] pubBytesIn = Convert.FromBase64String(pubB64In);

            // Reconstruct ECDsa instances
            using ECDsa slotKeyLoaded = ECDsa.Create();
            slotKeyLoaded.ImportPkcs8PrivateKey(privBytesIn, out _);

            using ECDsa pubOnly = ECDsa.Create();
            pubOnly.ImportSubjectPublicKeyInfo(pubBytesIn, out _);

            DateTime now = DateTime.UtcNow;
            DateTime midnight = now.Date;
            double minsSince = (now - midnight).TotalMinutes;
            int intervalId = (int)(minsSince / 3);

            string date = today.ToString("yyyy-MM-dd");
            string text = "Hello, world!";

            byte[] message = Encoding.UTF8.GetBytes($"{text}:slot:{date:yyyy-MM-dd}:{intervalId}");
            byte[] sig = slotKeyLoaded.SignData(message, HashAlgorithmName.SHA256);
            bool ok = pubOnly.VerifyData(message, sig, HashAlgorithmName.SHA256);

            Console.WriteLine($"Re-imported key works: {ok}");
        }
    }
}
