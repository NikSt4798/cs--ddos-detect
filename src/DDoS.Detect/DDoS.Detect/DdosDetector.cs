using System;
using System.Collections.Generic;
using System.Linq;

namespace DDoS.Detect
{
	static class DdosDetector
	{
		//Список разрешенных адресов
		private static readonly string[] _ipWhiteList = new[]
		{
			"127.0.0.1",
		};

		//Период проверки в миллисекундах
		private static readonly int _requestFrequency = 60000;

		//Максимальная частота запросов за период
		private static readonly int _requestThreshold = 1000;

		private static Dictionary<string, List<DateTime>> _ipHistory = new Dictionary<string, List<DateTime>>();

		public static bool CheckDdos(string ip)
		{
			//Проверка, находится ли адрес в списке разрешенных
			if(_ipWhiteList.Contains(ip))
				return false;

			//Проверка, совершал ли этот адрес запросы
			if (_ipHistory.ContainsKey(ip))
			{
				_ipHistory[ip].Add(DateTime.Now);
			}
			else
			{
				_ipHistory[ip] = new List<DateTime>
				{
					DateTime.Now
				};
			}

			//Выбираем запросы за указанный период
			var requests = _ipHistory[ip].Where(time => time > DateTime.Now.AddMilliseconds(-_requestFrequency));

			//Если количество запросов за указанный период времени превышает ограничение, сообщаем о возможной атаке
			if(requests.Count() > _requestThreshold) 
				return true;

			return false;
		}
	}
}
