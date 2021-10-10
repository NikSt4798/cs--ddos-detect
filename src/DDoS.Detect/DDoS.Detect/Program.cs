using DDoS.Core;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DDoS.Detect
{
	class Program
	{
        const int port = 8888; // порт для прослушивания подключений

        static INotificationService _notificationService;

		static void Main(string[] args)
		{
			Console.WriteLine("Start DDoS check...");

            TcpListener server = null;
            try
            {
                IPAddress localAddr = IPAddress.Parse("127.0.0.1");
                server = new TcpListener(localAddr, port);

                // запуск слушателя
                server.Start();

                while (true)
                {
                    Console.WriteLine("Ожидание подключений... ");

                    // получаем входящее подключение
                    TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Подключен клиент. Выполнение запроса...");

                    var endPoint = client.Client.RemoteEndPoint as IPEndPoint;

                    if (DdosDetector.CheckDdos(endPoint?.Address.ToString()))
					{
                        Console.WriteLine("Слишком много запросов, угроза DDoS атаки");

                        //Отправляем сообщение о возможной атаке любым удобным способом
                        _notificationService?.Notify($"Угроза DDoS атаки с ip адреса {endPoint?.Address.ToString()}");
                        // закрываем подключение
                        client.Close();
                        continue;
                    }

                    // получаем сетевой поток для чтения и записи
                    NetworkStream stream = client.GetStream();

                    // сообщение для отправки клиенту
                    string response = "Привет мир";
                    // преобразуем сообщение в массив байтов
                    byte[] data = Encoding.UTF8.GetBytes(response);

                    // отправка сообщения
                    stream.Write(data, 0, data.Length);
                    Console.WriteLine("Отправлено сообщение: {0}", response);
                    // закрываем поток
                    stream.Close();
                    // закрываем подключение
                    client.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                if (server != null)
                    server.Stop();
            }
		}
	}
}
