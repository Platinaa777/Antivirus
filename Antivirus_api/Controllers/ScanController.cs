using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus_api;

[ApiController]
[Route("[controller]")]
public class ScanController : ControllerBase
{
    private static readonly Dictionary<int, Task<string>> _tasks = new Dictionary<int, Task<string>>();
    
    
    /// <summary>
    /// Запустить асинхронно задачу на сканирование
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    [HttpPost("run-scan")]
    public async Task<IActionResult> LaunchScan([FromBody] string path)
    {
        var task = Task.Run(() => RunScan(path));
        _tasks.Add(task.Id, task);
        
        return Ok(task.Id);
    }

    private string RunScan(string path)
    {
        DateTime creationTime = DateTime.Now;
        var infoStats = new InformationAboutScanning();

        // проверяем есть ли у нас в входной строке пользователя ОС
        // Нормализуем его, если имеется
        if (path.Contains("%userprofile%"))
        {
            path = NormalizeStringIfUserProfileExist(path);
        }

        if (!Directory.Exists(path))
        {
            return "Несуществующий путь";
        }
        
        var currentDirectory = new DirectoryInfo(path);

        var files = currentDirectory.GetFiles();
        
        // проходимся по всем файлом текущей директории
        foreach (var file in files)
        {
            infoStats = infoStats + AnalyzeFile(file.FullName);
        }
        
        // запускаем сканирование других подпапок
        infoStats = infoStats + SearchingInfo(currentDirectory, new InformationAboutScanning());

        var duration = DateTime.Now - creationTime;
        string totalInfo = "====== Scan result ======\n" +
                           $"Directory: {currentDirectory.FullName}\n" +
                           $"Processed files: {infoStats.CountFiles}\n" +
                           $"JS detects: {infoStats.CountJSfiles}\n" +
                           $"rm -rf detects: {infoStats.CountRmDetecs}\n" +
                           $"Rundll32 detects: {infoStats.CountRundll32Detecs}\n" +
                           $"Errors: {infoStats.CountOtherErrors}\n" +
                           $"Execution time: {duration:g}\n" +
                           "=========================";
        
        return totalInfo;
    }
    
    /// <summary>
    /// Рекурсивнивная функция подсчета вредоносных файлов
    /// </summary>
    /// <param name="currentDirectory"></param>
    /// <param name="info"></param>
    /// <returns></returns>
    private InformationAboutScanning SearchingInfo(DirectoryInfo currentDirectory, InformationAboutScanning info)
    {
        // получаем все подпапки текущей папки
        var directories = currentDirectory.GetDirectories();

        var currentInformation = new InformationAboutScanning();
    
        // проходимся по всем подпапкам синхронно
        foreach (var dir in directories)
        {
            // получаем все файлы
            var files = dir.GetFiles();

            // создаем список задач для асинхронной обработки файлов данной подпапки
            var tasks = new List<Task<InformationAboutScanning>>();
        
            // проходимся по всем файлам данной подпапки и добавляем задачи в список
            foreach (var file in files)
            {
                var fullName = file.FullName;
            
                // запускаем анализирование файла асинхронно
                tasks.Add(Task.Run(() => AnalyzeFile(fullName)));
            }
        
            // ждем когда все файлы проанализируются
            Task.WaitAll(tasks.ToArray());
        
            // суммируем результаты вредоносных файлов
            foreach (var task in tasks)
            {
                currentInformation = currentInformation + task.Result;
            }
        
            // рекурсивно обрабатываем случай для других подпапок для данной подпапки
            currentInformation = currentInformation + SearchingInfo(dir, new InformationAboutScanning());
        }

        return currentInformation;
    }

    /// <summary>
    /// Получаем корректную строку если введен пользователь ОС
    /// </summary>
    /// <param name="path"></param>
    /// <returns></returns>
    private string NormalizeStringIfUserProfileExist(string path)
    {
        // получаем пользователя системы
        string userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        // находим последний элемент %
        int lastSymbolOfUserProfile = path.LastIndexOf('%');

        StringBuilder pathAfterUserProfile = new StringBuilder();

        // создаем путь который идет после пользователя системы
        for (int i = lastSymbolOfUserProfile + 1; i < path.Length; ++i)
        {
            pathAfterUserProfile.Append(path[i]);
        }
        // возвращаем абсолютный путь (без %userprofile%)
        return userProfilePath + pathAfterUserProfile;
    }
    
    /// <summary>
    /// Аназирование файла на наличие вредоносных файлов
    /// </summary>
    /// <param name="fullName"></param>
    /// <returns></returns>
    private InformationAboutScanning AnalyzeFile(string fullName)
    {
        InformationAboutScanning info = new InformationAboutScanning();
        info.CountFiles = 1;
        var textInFile = "";

        // проверка на то что нет каких-либо других ошибок (например: запрет на чтение файла)
        try
        {
            textInFile = System.IO.File.ReadAllText(fullName);
        }
        catch
        {
            info.CountOtherErrors = 1;
            return info;
        }
        
        // проверка на js ошибки
        if (fullName.Length > 3 && fullName.EndsWith(".js") && textInFile.Contains("<script>evil_script()</script>"))
        {
            info.CountJSfiles = 1;
            return info;
        }
        
        // получаем текущего пользователя операционной системы
        string userProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var rmString = $"rm -rf {userProfilePath}\\Documents";
        if (textInFile.Contains(rmString))
        {
            info.CountRmDetecs = 1;
            return info;
        }

        if (textInFile.Contains("Rundll32 sys.dll SysEntry"))
        {
            info.CountRundll32Detecs = 1;
            return info;
        }

        // файл чистый
        return info;
    }

    /// <summary>
    /// Проверка статуса задачи
    /// </summary>
    /// <param name="taskId">Номер задачи</param>
    /// <returns></returns>
    [HttpGet("get-status/{taskId:int}")]
    public IActionResult GetStatus(int taskId)
    {
        // если нет ключа, то задача не была создана
        if (!_tasks.ContainsKey(taskId))
        {
            return NotFound("Scan is not found");
        }
        
        // задача еще выполняется
        if (_tasks[taskId].Status == TaskStatus.Running)
        {
            return Ok("Scan task in progress, please wait");
        }
        
        // возвращаем результат задачи
        var result = _tasks[taskId].Result;
        _tasks.Remove(taskId);
        return Ok(result);
    }
}