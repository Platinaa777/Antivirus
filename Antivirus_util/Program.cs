using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;

class Program
{
    public static void Main(string[] args)
    {
        HttpClient client = new HttpClient();
        // запускаем с консоли
        client.BaseAddress = new Uri("http://localhost:5000/scan/");

        if (args.Length <= 1 || args.Length >= 3)
        {
            Console.WriteLine("Неправильное количество параметров");
            return;
        }
        
        if (args[0] == "scan")
        {
            string value = JsonSerializer.Serialize(args[1]);
            
            HttpContent content = new StringContent(value, Encoding.UTF8, "application/json");
            try
            {
                var response = client.PostAsync($"run-scan", content).Result;
                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"Scan task was created with ID: {response.Content.ReadAsStringAsync().Result}");
                }
            }
            catch
            {
                Console.WriteLine("Ошибка! К сервису нельзя подключиться");
            }

        } else if (args[0] == "status")
        {
            string value = args[1];
            HttpContent content = new StringContent(value, Encoding.UTF8, "application/json");

            var isValid = int.TryParse(value, out int taskId);

            if (!isValid)
            {
                Console.WriteLine("Некорректный параметр");
                return;
            }

            try
            {
                var response = client.GetAsync($"get-status/{taskId}");

                if (response.Result.IsSuccessStatusCode)
                {
                    Console.WriteLine(response.Result.Content.ReadAsStringAsync().Result);
                }
                else
                {
                    Console.WriteLine(response.Result.Content.ReadAsStringAsync().Result);
                }
            }
            catch
            {
                Console.WriteLine("Ошибка! К сервису нельзя подключиться");
            }
        }

    }
}