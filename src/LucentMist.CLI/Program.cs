using LucentMist.CLI;

// Redirected REPL input follows the same UTF-8 contract as JSON/transcripts.
// Windows' legacy code page otherwise corrupts Chinese follow-up questions.
if (Console.IsInputRedirected)
    Console.InputEncoding = System.Text.Encoding.UTF8;

var app = new CliApp();
return await app.RunAsync(args);
