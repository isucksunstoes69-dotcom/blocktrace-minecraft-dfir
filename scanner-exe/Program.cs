using System.Windows.Forms;

namespace BlockTraceRuleScanner;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new ScannerForm());
    }
}
