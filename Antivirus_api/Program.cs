var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Logging.ClearProviders();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
        options.RoutePrefix = string.Empty;
    });
}

app.MapControllers();
bool isFirstTime = false;

while (!isFirstTime)
{
    Console.Write("Scan service was started.\nPress <Enter> to exit...");
    var key = Console.ReadKey();
    if (key.Key == ConsoleKey.Enter)
    {
        isFirstTime = true;
    }
}

app.Run();