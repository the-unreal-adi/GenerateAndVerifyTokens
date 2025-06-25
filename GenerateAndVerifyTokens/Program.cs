namespace GenerateAndVerifyTokens
{
    class Program
    {
        static void Main(string[] args)
        {
            bool exit = false;
            string privateKey = "", publicKey = "", messageText = "Hello, world!";

            privateKey = File.ReadAllText("slot.private.b64.txt");
            publicKey = File.ReadAllText("slot.public.b64.txt");

            while (!exit)
            {
                Console.Clear();
                Console.WriteLine("=== Token Management Console ===");
                Console.WriteLine("1. Generate Token");
                Console.WriteLine("2. Verify Token");
                Console.WriteLine("3. Exit");
                Console.Write("Select an option: ");

                var choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        string token = GenerateVerify.GenerateToken(privateKey, messageText);
                        Console.WriteLine($"Generated Token: {token}");
                        File.WriteAllText("token.b64.txt", token);
                        break;
                    case "2":
                        string tokenF = File.ReadAllText("token.b64.txt");
                        bool isValid = GenerateVerify.VerifyToken(publicKey, messageText, tokenF);
                        Console.WriteLine($"Token verification result: {isValid}");
                        break;
                    case "3":
                        exit = true;
                        Console.WriteLine("Exiting application. Goodbye!");
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Please select 1, 2, or 3.");
                        break;
                }

                if (!exit)
                {
                    Console.WriteLine("\nPress any key to return to the menu...");
                    Console.ReadKey();
                }
            }
        }
    }
}
