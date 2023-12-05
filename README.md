Задание сделано в сложной версии.

Реализовано API, которая сканирует файлы определенной директории, и утилита, отправляющая запросы на сервисное приложение.

Если хотите протестировать через IDE, используя Swagger (добавил endpoint - '/'), Postman, Insomnia и тд, то приложение будет уже запускаться на url: http://localhost:5221/ (решил написать, просто если был бы отправлен запрос через утилиту, то была бы ошибка с сервисом).

Чтобы все работало, надо перед этим запустить сервисное приложение. (./Antivirus_api + нажать Enter как просить приложение для запуска)

API:
Имеет 2 эндпоинта:
1) Запуск сканирования директории (POST) - /scan/run-scan
2) Проверка статуса задачи (GET) - /scan/get-status/{id}

Подозрительные файлы:
1) .js, содержащий строку <script>evil_script()</script>
2) содержит rm -rf %userprofile%\Documents, где %username% путь к директории текущего пользователя Windows (на Linux обычно /home/denis - написал по моему случаю).
3) содержит Rundll32 sys.dll SysEntry

API работает в асинхронном режиме, пользователь не брокируется, когда ждет результат, а получает id задачи, по которому может получить уже информацию, когда задача будет выполнена.

Ответ от API, при готовой задаче:

====== Scan result ======
Directory: /home/denis/Testing-antiviruses
Processed files: 196
JS detects: 47
rm -rf detects: 3
Rundll32 detects: 48
Errors: 2
Execution time: 0:00:00.3011799
=========================

Также API в многопоточном режиме обрабатывает все файлы определенной директории и далее уже рекурсивно проходится по всем подпапкам, собирая информацию о вредоносных файлах

Утилита:
1) Отправка запроса на сканирование:
   linux: ./Antivirus_util scan [path-to-directory]
   windows: ./Antivirus_util.exe scan [path-to-directory]

2) Получение ответа от api: 
   linux: ./Antivirus_util status [task-id]
   windows: ./Antivirus_util.exe status [task-id]

Выполнил: Мирошниченко Денис @platina_777

Если приложение не хочет запускаться с данными exe, выполните команду dotnet build (создаться подходящий вашей ОС исполняемый файл).

Если есть желание оставить отзыв о работе, можно написать по этим контактам (хотелось бы просто знать, что делаю неправильно и дальше двигаться вперед):
тг - @platina_777
почта - miroshnichenkodenis2004@mail.ru
