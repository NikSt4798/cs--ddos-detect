using DDoS.Core;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

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

            while (true)
			{
				var result = DdosCheck();

				if (!string.IsNullOrEmpty(result))
				{
					_notificationService.Notify(result);
					return;
				}

				Thread.Sleep(60000);
			}
		}

		public static string DdosCheck()
		{


			return string.Empty;
		}
	}
}
