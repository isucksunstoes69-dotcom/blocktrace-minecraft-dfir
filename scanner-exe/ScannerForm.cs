using System.Text.RegularExpressions;

namespace BlockTraceRuleScanner;

public sealed class ScannerForm : Form
{
    private readonly TextBox _input = new() { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, AcceptsTab = true };
    private readonly ListView _findings = new() { View = View.Details, FullRowSelect = true, GridLines = false };
    private readonly Label _source = new();
    private readonly Label _queue = new();
    private Label _ruleCount = new();
    private Label _hitCount = new();
    private Label _stringCount = new();
    private readonly ProgressBar _progress = new();
    private readonly FlowLayoutPanel _targets = new();
    private readonly HashSet<string> _activeTargets = new(StringComparer.OrdinalIgnoreCase);
    private readonly string[] _indicators = ["dnscache", "lsass.exe", "javaw.exe", "dcom", "SysMain", "PcaSvc", "Bam", "Schedule", "EventLog", "DusmSvc", "DPS", "CDPSvc"];
    private const string Ink = "#D8E8DA";
    private const string Panel = "#111B17";
    private const string Edge = "#274536";
    private const string Green = "#A6D76D";

    public ScannerForm()
    {
        Text = "BlockTrace — YARA Signature Console";
        MinimumSize = new Size(1040, 700);
        Size = new Size(1220, 790);
        BackColor = ColorTranslator.FromHtml("#0A100D");
        Font = new Font("Segoe UI", 9.5F);
        BuildUi();
        foreach (var indicator in _indicators) _activeTargets.Add(indicator);
        RenderTargets();
        TryLoadBundledRules();
    }

    private void BuildUi()
    {
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), BackColor = BackColor, ColumnCount = 1, RowCount = 5 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(root);

        var title = new Label { AutoSize = true, Text = "BLOCKTRACE  /  SIGNATURE CONSOLE", ForeColor = ColorTranslator.FromHtml(Green), Font = new Font("Consolas", 11F, FontStyle.Bold), Margin = new Padding(0, 0, 0, 5) };
        var subtitle = new Label { AutoSize = true, Text = "YARA rule text scanner · Javaw-style target queue and findings workflow", ForeColor = ColorTranslator.FromHtml(Ink), Font = new Font("Segoe UI", 20F, FontStyle.Bold), Margin = new Padding(0, 0, 0, 16) };
        var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        header.Controls.Add(title); header.Controls.Add(subtitle); root.Controls.Add(header, 0, 0);

        var status = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Margin = new Padding(0, 0, 0, 12) };
        for (var i = 0; i < 3; i++) status.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333F));
        status.Controls.Add(StatusCard("TARGET PROFILE", "12 ACTIVE TARGETS", "Click a target chip to include or exclude it"), 0, 0);
        status.Controls.Add(StatusCard("RULE SOURCE", _source, "rules\\minecraft-dfir-rules.md"), 1, 0);
        status.Controls.Add(StatusCard("SIGNATURE QUEUE", _queue, "Ready to parse"), 2, 0);
        _source.Text = "NOT LOADED"; _queue.Text = "IDLE";
        root.Controls.Add(status, 0, 1);

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, BackColor = ColorTranslator.FromHtml(Panel), Padding = new Padding(10), Margin = new Padding(0, 0, 0, 0) };
        toolbar.Controls.Add(ActionButton("LOAD RULE TEXT", (_, _) => LoadFromPicker()));
        toolbar.Controls.Add(ActionButton("LOAD INCLUDED RULES", (_, _) => TryLoadBundledRules()));
        toolbar.Controls.Add(ActionButton("CLEAR", (_, _) => ClearScan()));
        toolbar.Controls.Add(new Label { Text = "  Default: rules\\minecraft-dfir-rules.md", ForeColor = ColorTranslator.FromHtml("#91A393"), AutoSize = true, Padding = new Padding(8, 7, 0, 0), Font = new Font("Consolas", 8.5F) });
        root.Controls.Add(toolbar, 0, 2);

        var body = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = ColorTranslator.FromHtml(Edge), Padding = new Padding(1) };
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 53)); body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 47));
        var left = BuildInputPane(); var right = BuildResultsPane(); body.Controls.Add(left, 0, 0); body.Controls.Add(right, 1, 0); root.Controls.Add(body, 0, 3);
        root.Controls.Add(new Label { AutoSize = true, Text = "LOCAL TEXT ANALYSIS ONLY  ·  parses selected rule text; it does not read process memory", ForeColor = ColorTranslator.FromHtml("#708573"), Font = new Font("Consolas", 8.5F), Padding = new Padding(0, 12, 0, 0) }, 0, 4);
    }

    private Control BuildInputPane()
    {
        var pane = Pane();
        var head = Caption("SIGNATURE INPUT", "PASTE OR LOAD READABLE RULE TEXT");
        _targets.Dock = DockStyle.Top; _targets.AutoSize = true; _targets.Padding = new Padding(0, 0, 0, 8); _targets.BackColor = ColorTranslator.FromHtml(Panel);
        _input.Dock = DockStyle.Fill; _input.BackColor = ColorTranslator.FromHtml("#09100C"); _input.ForeColor = ColorTranslator.FromHtml("#CBE8C7"); _input.BorderStyle = BorderStyle.FixedSingle; _input.Font = new Font("Consolas", 9F); _input.Margin = new Padding(0, 8, 0, 10);
        _progress.Dock = DockStyle.Bottom; _progress.Height = 7; _progress.Style = ProgressBarStyle.Continuous;
        var scan = ActionButton("RUN SIGNATURE QUEUE  →", (_, _) => RunScan()); scan.Dock = DockStyle.Bottom; scan.Height = 36; scan.Margin = new Padding(0, 8, 0, 0);
        pane.Controls.Add(_input); pane.Controls.Add(scan); pane.Controls.Add(_progress); pane.Controls.Add(_targets); pane.Controls.Add(head); return pane;
    }

    private Control BuildResultsPane()
    {
        var pane = Pane();
        _findings.Dock = DockStyle.Fill; _findings.BackColor = ColorTranslator.FromHtml("#0C130F"); _findings.ForeColor = ColorTranslator.FromHtml(Ink); _findings.BorderStyle = BorderStyle.FixedSingle; _findings.Font = new Font("Consolas", 9F);
        _findings.Columns.Add("Finding", 280); _findings.Columns.Add("Type", 100); _findings.Columns.Add("Count", 70);
        var stats = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 3, Height = 68, BackColor = ColorTranslator.FromHtml("#0C130F"), Padding = new Padding(8), Margin = new Padding(0, 0, 0, 8) };
        for (var i = 0; i < 3; i++) stats.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.333F));
        _ruleCount = Stat("0", "RULES PARSED"); _hitCount = Stat("0", "INDICATOR HITS"); _stringCount = Stat("0", "STRINGS INDEXED"); stats.Controls.Add(_ruleCount, 0, 0); stats.Controls.Add(_hitCount, 1, 0); stats.Controls.Add(_stringCount, 2, 0);
        pane.Controls.Add(_findings); pane.Controls.Add(stats); pane.Controls.Add(Caption("FINDINGS", "RULE DECLARATIONS · ACTIVE TARGET MATCHES")); return pane;
    }

    private Panel Pane() => new() { Dock = DockStyle.Fill, BackColor = ColorTranslator.FromHtml(Panel), Padding = new Padding(16) };
    private Label Caption(string a, string b) => new() { Dock = DockStyle.Top, AutoSize = true, Text = a + "   /   " + b, ForeColor = ColorTranslator.FromHtml(Green), Font = new Font("Consolas", 8.5F, FontStyle.Bold), Padding = new Padding(0, 0, 0, 10) };
    private Label Stat(string value, string label) => new() { Dock = DockStyle.Fill, Text = value + "\n" + label, ForeColor = ColorTranslator.FromHtml(Ink), Font = new Font("Consolas", 9F, FontStyle.Bold), TextAlign = ContentAlignment.MiddleCenter };
    private Control StatusCard(string title, string value, string detail) { var v = new Label(); v.Text = value; return StatusCard(title, v, detail); }
    private Control StatusCard(string title, Label value, string detail) { var p = new Panel { Dock = DockStyle.Fill, Height = 76, BackColor = ColorTranslator.FromHtml(Panel), Padding = new Padding(13), Margin = new Padding(0, 0, 8, 0) }; var h = new Label { Text = title, AutoSize = true, ForeColor = ColorTranslator.FromHtml("#789477"), Font = new Font("Consolas", 8F) }; value.AutoSize = true; value.ForeColor = ColorTranslator.FromHtml(Ink); value.Font = new Font("Segoe UI", 11F, FontStyle.Bold); value.Top = 22; var d = new Label { Text = detail, AutoSize = true, ForeColor = ColorTranslator.FromHtml("#769078"), Font = new Font("Segoe UI", 8F), Top = 48 }; p.Controls.Add(h); p.Controls.Add(value); p.Controls.Add(d); return p; }
    private Button ActionButton(string text, EventHandler action) { var b = new Button { Text = text, AutoSize = true, FlatStyle = FlatStyle.Flat, BackColor = ColorTranslator.FromHtml("#1E3827"), ForeColor = ColorTranslator.FromHtml("#D6EEC8"), Font = new Font("Consolas", 8.5F, FontStyle.Bold), Padding = new Padding(10, 6, 10, 6), Margin = new Padding(0, 0, 8, 0) }; b.FlatAppearance.BorderColor = ColorTranslator.FromHtml("#4C7954"); b.Click += action; return b; }

    private void RenderTargets()
    {
        _targets.Controls.Clear(); _targets.Controls.Add(new Label { Text = "TARGETS", AutoSize = true, ForeColor = ColorTranslator.FromHtml("#789477"), Font = new Font("Consolas", 8F), Padding = new Padding(0, 7, 8, 0) });
        foreach (var name in _indicators) { var chip = ActionButton(name, (_, _) => { if (!_activeTargets.Add(name)) _activeTargets.Remove(name); RenderTargets(); }); chip.BackColor = ColorTranslator.FromHtml(_activeTargets.Contains(name) ? "#31543A" : "#1B251E"); chip.Padding = new Padding(6, 3, 6, 3); _targets.Controls.Add(chip); }
    }

    private void LoadFromPicker()
    {
        using var dialog = new OpenFileDialog { Filter = "Rule text|*.txt;*.md;*.json;*.yml;*.yaml;*.yar;*.yara|All readable files|*.*", Title = "Select a readable YARA rule text file" };
        if (dialog.ShowDialog() == DialogResult.OK) { _input.Text = File.ReadAllText(dialog.FileName); _source.Text = "LOADED"; _queue.Text = Path.GetFileName(dialog.FileName); }
    }

    private void TryLoadBundledRules()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "rules", "minecraft-dfir-rules.md");
        if (File.Exists(path)) { _input.Text = File.ReadAllText(path); _source.Text = "INCLUDED RULES"; _queue.Text = "READY"; } else { _source.Text = "NOT FOUND"; _queue.Text = "SELECT SOURCE"; }
    }

    private void ClearScan() { _input.Clear(); _findings.Items.Clear(); _ruleCount.Text = "0\nRULES PARSED"; _hitCount.Text = "0\nINDICATOR HITS"; _stringCount.Text = "0\nSTRINGS INDEXED"; _progress.Value = 0; _source.Text = "NOT LOADED"; _queue.Text = "IDLE"; }

    private void RunScan()
    {
        var text = _input.Text; if (string.IsNullOrWhiteSpace(text)) { _queue.Text = "LOAD SOURCE"; return; }
        _queue.Text = "PARSING"; _progress.Value = 30; _findings.Items.Clear();
        var rules = Regex.Matches(text, @"^\s*(?:private\s+|global\s+)?rule\s+([A-Za-z0-9_]+)", RegexOptions.Multiline | RegexOptions.IgnoreCase).Select(m => m.Groups[1].Value).ToList();
        var strings = Regex.Matches(text, @"^\s*(\$[A-Za-z0-9_]+)\s*=", RegexOptions.Multiline).Count;
        foreach (var rule in rules) AddFinding(rule, "RULE", "1");
        var hits = 0; foreach (var indicator in _activeTargets) { var count = Regex.Matches(text, Regex.Escape(indicator), RegexOptions.IgnoreCase).Count; if (count > 0) { AddFinding(indicator, "TARGET", count.ToString()); hits += count; } }
        _ruleCount.Text = rules.Count + "\nRULES PARSED"; _hitCount.Text = hits + "\nINDICATOR HITS"; _stringCount.Text = strings + "\nSTRINGS INDEXED"; _progress.Value = 100; _queue.Text = "COMPLETE";
    }
    private void AddFinding(string name, string type, string count) { var item = new ListViewItem(name); item.SubItems.Add(type); item.SubItems.Add(count); _findings.Items.Add(item); }
}
