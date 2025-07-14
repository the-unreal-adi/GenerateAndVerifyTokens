namespace GenerateToken
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.Error.WriteLine("Usage: GenerateToken <origin> <clientId> <version>");
                return 1;
            }

            string origin = args[0];
            string clientId = args[1];
            string version = args[2];

            try
            {
                string token = CryptoHelper.GenerateToken(origin, clientId, version);
                Console.WriteLine(token);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error generating token: {ex.Message}");
                return 2;
            }
        }
    }
}

