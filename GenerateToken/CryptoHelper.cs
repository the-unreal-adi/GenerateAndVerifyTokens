using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GenerateToken
{
    internal class CryptoHelper
    {
        private static readonly Dictionary<string, DateTime> _validPrivateKeys = [];

        private static string GeneratePrivateKey(string root, string salt)
        { 
            try
            {
                lock (_validPrivateKeys)
                {
                    var signEntries = _validPrivateKeys
                        .Where(kvp => kvp.Key.StartsWith("sign-" + root + ":"))
                        .ToList();

                    foreach (var kvp in signEntries)
                    {
                        if (kvp.Value <= DateTime.UtcNow)
                        {
                            _validPrivateKeys.Remove(kvp.Key);
                        }
                        else
                        {
                            return kvp.Key.Split(":")[1];
                        }
                    }
                }

                DateTime now = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, DateTime.UtcNow.Day, DateTime.UtcNow.Hour, 0, 0, DateTimeKind.Utc);
                string rootHex = BitConverter.ToString(SHA256.HashData(Encoding.UTF8.GetBytes($"{root}|MDRiMjk0ODAyMzNmNGRlZjVjODc1ODc1YjZiZGMzYjE=|{now}"))).Replace("-", "").ToLowerInvariant();
                byte[] rootSeed = Encoding.UTF8.GetBytes(rootHex);
                var kds = new KeyDerivationService(rootSeed);
                DateTime today = DateTime.UtcNow.Date;
                int intervalDuration = 60;
                string saltHex = BitConverter.ToString(SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}|MDRiMjk0ODAyMzNmNGRlZjVjODc1ODc1YjZiZGMzYjE=|{now}"))).Replace("-", "").ToLowerInvariant();
                using ECDsa slotKey = kds.DeriveSlotKey(today, intervalDuration, saltHex);

                byte[] privBytes = slotKey.ExportPkcs8PrivateKey();
                string privateKey = Convert.ToBase64String(privBytes);

                lock (_validPrivateKeys)
                {
                    if (!_validPrivateKeys.ContainsKey("sign-" + root + ":" + privateKey))
                    {
                        DateTime expiry = now.AddHours(1);
                        _validPrivateKeys["sign-" + root + ":" + privateKey] = expiry;
                    }
                }

                return privateKey;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating private key: {ex.Message}", ex);
            }
        }

        public static string GenerateToken(string origin, string root, string salt)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(origin))
                {
                    throw new ArgumentException("Origin cannot be null or empty.", nameof(origin));
                }

                string privateKey = GeneratePrivateKey(root, salt);

                byte[] privBytesIn = Convert.FromBase64String(privateKey);
                using ECDsa slotKeyLoaded = ECDsa.Create();
                slotKeyLoaded.ImportPkcs8PrivateKey(privBytesIn, out _);

                DateTime today = DateTime.UtcNow.Date;
                DateTime now = DateTime.UtcNow;
                DateTime midnight = now.Date;
                double minsSince = (now - midnight).TotalMinutes;
                int intervalId = (int)(minsSince / 2);
                string date = today.ToString("yyyy-MM-dd");
                byte[] message = Encoding.UTF8.GetBytes($"{origin}:slot:{date:yyyy-MM-dd}:{intervalId}");

                // 4) Sign some data
                byte[] tokenBytes = slotKeyLoaded.SignData(
                    message,
                    HashAlgorithmName.SHA256
                );

                return Convert.ToBase64String(tokenBytes);


            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating token: {ex.Message}", ex);
            }
        }
    }

    internal static class Hkdf
    {
        public static byte[] Extract(byte[]? salt, byte[] ikm)
        {
            using var hmac = new HMACSHA256(salt ?? new byte[32]);
            return hmac.ComputeHash(ikm);
        }

        public static byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            int hashLen = 32;  
            int n = (int)Math.Ceiling((double)outputLength / hashLen);
            var okm = new byte[outputLength];
            var t = new byte[0];
            int pos = 0;

            for (int i = 1; i <= n; i++)
            {
                using var hmac = new HMACSHA256(prk);
                byte[] data = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, data, 0, t.Length);
                Buffer.BlockCopy(info, 0, data, t.Length, info.Length);
                data[data.Length - 1] = (byte)i;

                t = hmac.ComputeHash(data);
                int toCopy = Math.Min(hashLen, outputLength - pos);
                Buffer.BlockCopy(t, 0, okm, pos, toCopy);
                pos += toCopy;
            }

            return okm;
        }

        public static byte[] DeriveKey(byte[] ikm, byte[] info, byte[]? salt = null, int length = 32)
        {
            byte[] prk = Extract(salt, ikm);
            return Expand(prk, info, length);
        }
    }

    internal class KeyDerivationService
    {
        private readonly byte[] _rootSeed;

        public KeyDerivationService(byte[] rootSeed)
        {
            if (rootSeed == null || rootSeed.Length < 32)
                throw new ArgumentException("Root seed must be at least 32 bytes of randomness.");

            _rootSeed = rootSeed;
        }

        public byte[] DeriveDailyMaster(DateTime date)
        {
            var info = Encoding.UTF8.GetBytes($"daily:{date:yyyy-MM-dd}");
            return Hkdf.DeriveKey(_rootSeed, info);
        }

        public ECDsa DeriveSlotKey(DateTime date, int intervalDuration, string saltHex)
        {
            DateTime now = DateTime.UtcNow;
            DateTime midnight = now.Date;
            double minsSince = (now - midnight).TotalMinutes;
            int intervalId = (int)(minsSince / intervalDuration);
            byte[] daily = DeriveDailyMaster(date);
            byte[] info = Encoding.UTF8.GetBytes($"slot:{date:yyyy-MM-dd}:{intervalId}");
            byte[] salt = Encoding.UTF8.GetBytes(saltHex);
            byte[] keyMaterial = Hkdf.DeriveKey(daily, info, salt);

            // Use P-256 curve
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keyMaterial
            };

            // Derive public Q from D
            using var ecdsaTemp = ECDsa.Create(ecParams);
            ecParams.Q = ecdsaTemp.ExportParameters(false).Q;

            var ecdsa = ECDsa.Create(ecParams);
            return ecdsa;
        }
    }
}

