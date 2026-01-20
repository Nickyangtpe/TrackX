using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

#region Configuration & Models

public class MonitorConfig
{
    public string ExePath { get; set; } = "";
    public string OutputFile { get; set; } = "proc_report.json";
    public string ArtifactZipPath { get; set; } = "";
    public bool Verbose { get; set; }
    public bool RunAsAdmin { get; set; }
    public bool EnableFilter { get; set; } = true;
    public bool EnableAlpc { get; set; }
    public bool Paranoid { get; set; }
    public bool EnableMapView { get; set; }
}

public class ReportRoot
{
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public TargetInfo? TargetMetadata { get; set; }
    public int TotalActions { get; set; }
    public List<ProcessRecord> Processes { get; set; } = new();
}

public class TargetInfo
{
    public string Path { get; set; } = "";
    public long SizeBytes { get; set; }
    public DateTime CreatedTime { get; set; }
    public DateTime ModifiedTime { get; set; }
    public string Owner { get; set; } = "";
    public string Permissions { get; set; } = "";
}

public class ProcessRecord
{
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public string Name { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public DateTime? StartTime { get; set; }
    public List<ActionRecord> Actions { get; set; } = new();

    [JsonIgnore]
    public ConcurrentDictionary<string, ActionRecord> ActionMap { get; } = new();
}

public class ActionRecord
{
    public string Type { get; set; } = "";
    public object Detail { get; set; } = new();
    public int Count { get; set; } = 1;
    public List<string> Times { get; set; } = new();
}

public class ArtifactMapping
{
    public string ZipEntry { get; set; } = "";
    public string OriginalPath { get; set; } = "";
    public long SizeBytes { get; set; }
    public DateTime CaptureTime { get; set; }
}

#endregion

#region Main Program

class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var config = ParseArguments(args);
        if (config == null) return 1;

        ConsoleHelper.Header(config);

        if (!IsAdministrator() && !config.RunAsAdmin)
            ConsoleHelper.Warn("Not running as Admin. ETW API tracing will be disabled.");

        if (!File.Exists(config.ExePath))
        {
            ConsoleHelper.Error($"Executable '{config.ExePath}' not found.");
            return 2;
        }

        var monitor = new ProcessMonitor(config);
        Console.CancelKeyPress += (s, e) => {
            e.Cancel = true;
            ConsoleHelper.Info("Stopping monitor (Ctrl+C)...");
            monitor.Stop();
        };

        try { await monitor.RunAsync(); }
        catch (Exception ex) { ConsoleHelper.Error($"Fatal: {ex.Message}"); }

        return 0;
    }

    static bool IsAdministrator()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static MonitorConfig? ParseArguments(string[] args)
    {
        if (args.Length == 0) { PrintHelp(); return null; }

        var config = new MonitorConfig();
        var loose = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i].ToLowerInvariant();
            switch (arg)
            {
                case "-v":
                case "--verbose":
                    config.Verbose = true;
                    break;
                case "--admin":
                    config.RunAsAdmin = true;
                    break;
                case "--no-filter":
                    config.EnableFilter = false;
                    break;
                case "--alpc":
                    config.EnableAlpc = true;
                    break;
                case "--mapview":
                    config.EnableMapView = true;
                    break;
                case "--paranoid":
                    config.Paranoid = true;
                    break;
                case "-a":
                case "--artifacts":
                    if (i + 1 < args.Length) config.ArtifactZipPath = args[++i];
                    break;
                case "-o":
                case "--output":
                    if (i + 1 < args.Length) config.OutputFile = args[++i];
                    break;
                default:
                    if (!arg.StartsWith("-")) loose.Add(args[i]);
                    break;
            }
        }

        if (loose.Count > 0) config.ExePath = loose[0];
        if (string.IsNullOrEmpty(config.ExePath)) { PrintHelp(); return null; }

        return config;
    }

    static void PrintHelp()
    {
        Console.WriteLine("Usage: TrackX.exe <path-to-exe> [options]");
        Console.WriteLine("Options:");
        Console.WriteLine("  -o <file.json>  Output JSON report");
        Console.WriteLine("  -a <file.zip>   Backup artifacts");
        Console.WriteLine("  -v              Verbose mode");
        Console.WriteLine("  --alpc          Enable ALPC (IPC monitoring)");
        Console.WriteLine("  --paranoid      Enable HANDLES & AMSI (Extremely Detailed!)");
        Console.WriteLine("  --mapview       Enable File MapView events (Very Noisy!)");
        Console.WriteLine("  --no-filter     Capture ALL events");
        Console.WriteLine("  --admin         Run as Administrator");
    }
}

#endregion

#region Event Aggregator

class EventAggregator
{
    private readonly ConcurrentDictionary<int, ProcessRecord> _processes = new();
    private readonly ConcurrentDictionary<int, ActionRecord> _lastActionByPid = new();
    private readonly DateTime _startTime = DateTime.Now;
    private readonly TargetInfo _targetInfo;

    public EventAggregator(string targetPath)
    {
        _targetInfo = GetTargetMetadata(targetPath);
    }

    private TargetInfo GetTargetMetadata(string path)
    {
        var info = new TargetInfo { Path = Path.GetFullPath(path) };
        try
        {
            var fi = new FileInfo(path);
            info.SizeBytes = fi.Length;
            info.CreatedTime = fi.CreationTime;
            info.ModifiedTime = fi.LastWriteTime;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var fs = fi.GetAccessControl();
                info.Owner = fs.GetOwner(typeof(NTAccount))?.ToString() ?? "Unknown";
                info.Permissions = fs.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
            }
        }
        catch { info.Permissions = "Access Denied"; }

        return info;
    }

    public void RegisterProcess(int pid, int parentPid, string name, string cmd)
    {
        _processes.TryAdd(pid, new ProcessRecord
        {
            Pid = pid,
            ParentPid = parentPid,
            Name = name,
            CommandLine = cmd,
            StartTime = DateTime.Now
        });
    }

    public void AddAction(int pid, string type, object detail)
    {
        var procRec = _processes.GetOrAdd(pid, new ProcessRecord
        {
            Pid = pid,
            Name = "Unknown/Existing",
            StartTime = DateTime.Now
        });

        string timeStr = DateTime.UtcNow.ToString("HH:mm:ss.fff");
        string detailJson = JsonSerializer.Serialize(detail);
        string key = $"{type}|{detailJson}";

        if (_lastActionByPid.TryGetValue(pid, out var lastAction))
        {
            string lastDetailJson = JsonSerializer.Serialize(lastAction.Detail);
            if (lastAction.Type == type && lastDetailJson == detailJson)
            {
                lock (lastAction)
                {
                    lastAction.Count++;
                    if (lastAction.Times.Count < 10)
                        lastAction.Times.Add(timeStr);
                    else
                        lastAction.Times[^1] = timeStr + " (Last)";
                }
                return;
            }
        }

        var newAction = new ActionRecord
        {
            Type = type,
            Detail = detail,
            Count = 1,
            Times = new List<string> { timeStr }
        };

        procRec.ActionMap.AddOrUpdate(key, newAction, (k, existing) => {
            lock (existing)
            {
                existing.Count++;
                if (existing.Times.Count < 10)
                    existing.Times.Add(timeStr);
                else
                    existing.Times[^1] = timeStr;
            }
            return existing;
        });

        _lastActionByPid[pid] = newAction;
    }

    public async Task SaveReportAsync(string path)
    {
        int totalActions = 0;
        var processList = new List<ProcessRecord>();

        foreach (var kvp in _processes.OrderBy(p => p.Value.StartTime))
        {
            var proc = kvp.Value;
            proc.Actions = proc.ActionMap.Values
                .OrderBy(a => a.Times.FirstOrDefault())
                .ToList();

            totalActions += proc.Actions.Count;
            processList.Add(proc);
        }

        var report = new ReportRoot
        {
            StartTime = _startTime,
            EndTime = DateTime.Now,
            TargetMetadata = _targetInfo,
            TotalActions = totalActions,
            Processes = processList
        };

        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        await using var fs = File.Create(path);
        await JsonSerializer.SerializeAsync(fs, report, opts);
    }
}

#endregion

#region Artifact Manager

class ArtifactManager : IDisposable
{
    private readonly BlockingCollection<string> _workQueue = new();
    private readonly ConcurrentDictionary<string, bool> _captured = new();
    private readonly HashSet<string> _zipEntryNames = new();
    private readonly List<ArtifactMapping> _fileMappings = new();
    private readonly Task _workerTask;
    private readonly string _zipPath;
    private readonly bool _enabled;
    private readonly string _monitorExePath;

    private FileStream? _zipFileStream;
    private ZipArchive? _archive;

    public ArtifactManager(string zipPath)
    {
        _enabled = !string.IsNullOrEmpty(zipPath);
        _zipPath = zipPath;
        _monitorExePath = Environment.ProcessPath ?? "";

        if (_enabled)
        {
            try
            {
                if (File.Exists(_zipPath)) File.Delete(_zipPath);
                _zipFileStream = new FileStream(_zipPath, FileMode.Create, FileAccess.Write, FileShare.Read);
                _archive = new ZipArchive(_zipFileStream, ZipArchiveMode.Create, leaveOpen: true);
            }
            catch (Exception ex)
            {
                ConsoleHelper.Error($"Init Zip Failed: {ex.Message}");
                _enabled = false;
            }
        }
        _workerTask = Task.Run(ProcessQueue);
    }

    public void Capture(string sourcePath)
    {
        if (!_enabled || string.IsNullOrEmpty(sourcePath) || _workQueue.IsAddingCompleted) return;

        try
        {
            string fullPath = Path.GetFullPath(sourcePath);

            if (fullPath.Equals(Path.GetFullPath(_zipPath), StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrEmpty(_monitorExePath) && fullPath.Equals(Path.GetFullPath(_monitorExePath), StringComparison.OrdinalIgnoreCase)) ||
                sourcePath.EndsWith("proc_report.json", StringComparison.OrdinalIgnoreCase) ||
                IsNoisyPath(fullPath))
                return;

            if (_captured.TryAdd(fullPath, true))
                _workQueue.Add(fullPath);
        }
        catch { }
    }

    private static bool IsNoisyPath(string path)
    {
        return path.Contains(@"\AppData\Local\D3DSCache", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\AppData\LocalLow\Intel\ShaderCache", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\Windows\Fonts", StringComparison.OrdinalIgnoreCase);
    }

    private void ProcessQueue()
    {
        if (!_enabled || _archive == null) return;

        foreach (var path in _workQueue.GetConsumingEnumerable())
        {
            try
            {
                if (!File.Exists(path)) continue;

                using var fsSource = OpenFileWithRetry(path, 5000);
                if (fsSource == null) continue;

                string entryName = GetUniqueEntryName(Path.GetFileName(path));
                var entry = _archive.CreateEntry(entryName, CompressionLevel.Fastest);

                using var fsDest = entry.Open();
                fsSource.CopyTo(fsDest);

                _fileMappings.Add(new ArtifactMapping
                {
                    ZipEntry = entryName,
                    OriginalPath = path,
                    SizeBytes = fsSource.Length,
                    CaptureTime = DateTime.Now
                });

                ConsoleHelper.Debug($"Saved: {entryName} ({fsSource.Length} bytes)");
            }
            catch (InvalidOperationException) { break; }
            catch (Exception ex) { ConsoleHelper.Debug($"Artifact Err: {ex.Message}"); }
        }
    }

    private string GetUniqueEntryName(string originalFileName)
    {
        lock (_zipEntryNames)
        {
            string entryName = originalFileName;
            int counter = 1;
            string nameNoExt = Path.GetFileNameWithoutExtension(originalFileName);
            string ext = Path.GetExtension(originalFileName);

            while (_zipEntryNames.Contains(entryName))
            {
                counter++;
                entryName = $"{nameNoExt}_{counter}{ext}";
            }
            _zipEntryNames.Add(entryName);
            return entryName;
        }
    }

    private FileStream? OpenFileWithRetry(string path, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (!File.Exists(path)) return null;
            try
            {
                var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length == 0)
                {
                    fs.Dispose();
                    Thread.Sleep(100);
                    continue;
                }
                return fs;
            }
            catch (IOException) { Thread.Sleep(50); }
            catch (UnauthorizedAccessException) { return null; }
        }
        return null;
    }

    public void FinalizeZip()
    {
        if (!_enabled) return;
        _workQueue.CompleteAdding();

        try
        {
            _workerTask.Wait(TimeSpan.FromSeconds(5));

            if (_archive != null && _fileMappings.Count > 0)
            {
                var entry = _archive.CreateEntry("README_Files.json");
                using var stream = entry.Open();
                using var writer = new StreamWriter(stream);
                var opts = new JsonSerializerOptions { WriteIndented = true };
                writer.Write(JsonSerializer.Serialize(_fileMappings, opts));
            }
        }
        catch { }

        Dispose();
        ConsoleHelper.Info($"Artifacts saved to: {_zipPath}");
    }

    public void Dispose()
    {
        try { _archive?.Dispose(); } catch { }
        try { _zipFileStream?.Dispose(); } catch { }
    }
}

#endregion

#region Helpers

static class ConsoleHelper
{
    public static void Header(MonitorConfig c)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[*] Target: {c.ExePath}");
        Console.WriteLine($"[*] Output: {c.OutputFile}");
        if (!string.IsNullOrEmpty(c.ArtifactZipPath))
            Console.WriteLine($"[*] Backup: {c.ArtifactZipPath}");
        Console.ResetColor();
        Console.WriteLine(new string('-', 50));
    }

    public static void Info(string msg) => Write(ConsoleColor.Gray, "[INFO] " + msg);
    public static void Warn(string msg) => Write(ConsoleColor.Yellow, "[WARN] " + msg);
    public static void Error(string msg) => Write(ConsoleColor.Red, "[ERR ] " + msg);
    public static void Debug(string msg) { }

    public static void LiveEvent(string type, string detail)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"[{DateTime.Now:HH:mm:ss}] ");

        Console.ForegroundColor = type switch
        {
            var t when t.StartsWith("File") => ConsoleColor.Magenta,
            var t when t.StartsWith("Net") => ConsoleColor.Cyan,
            var t when t.StartsWith("Reg") => ConsoleColor.Yellow,
            "ProcessExited" => ConsoleColor.Red,
            "ProcessStarted" => ConsoleColor.Green,
            _ => ConsoleColor.Green
        };

        Console.Write(type.PadRight(15));
        Console.ResetColor();

        if (detail.Length > 60) detail = detail[..57] + "...";
        Console.WriteLine(" " + detail);
    }

    private static void Write(ConsoleColor c, string msg)
    {
        Console.ForegroundColor = c;
        Console.WriteLine(msg);
        Console.ResetColor();
    }
}

static class FilterHelper
{
    private static readonly string[] NoisyExtensions = {
        ".dll", ".nls", ".nlx", ".mun", ".sdb", ".ttf", ".ttc", ".dat", ".res", ".icu"
    };

    private static readonly string[] NoisyPaths = {
        @"\Windows\System32", @"\Windows\SysWOW64", @"\Windows\WinSxS",
        @"\Windows\Fonts", @"\Windows\Globalization", @"\Microsoft.Net",
        @"\AppData\Local\D3DSCache", @"\AppData\LocalLow\Intel\ShaderCache",
        @"\AppData\LocalLow\Microsoft\CryptnetFlushCache",
        @"\AppData\Local\Microsoft\Windows\INetCache",
        @"\AppData\Local\Microsoft\Windows\History",
        @"\AppData\Local\IconCache.db", "TrackX_"
    };

    private static readonly string[] NoisyRegistryPaths = {
        @"\Cryptography", @"\EnterpriseCertificates", @"\Services\Crypt32",
        @"\Direct3D", @"\DirectX", @"\Avalon.Graphics", @"\Control\Nls",
        @"\International", @"\MUI\Settings", @"\Microsoft\Input",
        @"\Microsoft\CTF", @"\CLSID\", @"\Interface\", @"\TypeLib\"
    };

    public static bool IsNoisy(string val)
    {
        if (string.IsNullOrEmpty(val)) return true;

        if (NoisyExtensions.Any(ext => val.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (NoisyPaths.Any(path => val.Contains(path, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (NoisyRegistryPaths.Any(path => val.Contains(path, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (val.StartsWith("1.3.6.1") || val.StartsWith("2.16.840"))
            return true;

        if (val.Length > 30 && val.All(c => char.IsAsciiHexDigit(c) || c == '-'))
            return true;

        return false;
    }
}

#endregion

#region DNS-IP Correlator

public class DnsIpCorrelator
{
    private readonly ConcurrentDictionary<string, DnsRecord> _dnsCache = new();
    private readonly ConcurrentDictionary<string, List<DomainEntry>> _ipToDomain = new();

    private class DnsRecord
    {
        public string Domain { get; set; } = "";
        public List<string> IPs { get; set; } = new();
        public DateTime QueryTime { get; set; }
        public int TTL { get; set; } = 300;
    }

    private class DomainEntry
    {
        public string Domain { get; set; } = "";
        public DateTime AddedTime { get; set; }
        public int Confidence { get; set; } = 100;
    }

    public void RecordDnsQuery(int pid, string domain, string[] resolvedIPs, int ttl = 300)
    {
        if (string.IsNullOrEmpty(domain) || resolvedIPs == null || resolvedIPs.Length == 0)
            return;

        var record = new DnsRecord
        {
            Domain = domain.TrimEnd('.'),
            IPs = resolvedIPs.ToList(),
            QueryTime = DateTime.UtcNow,
            TTL = ttl
        };

        _dnsCache[domain] = record;

        foreach (var ip in resolvedIPs)
        {
            var domains = _ipToDomain.GetOrAdd(ip, _ => new List<DomainEntry>());
            lock (domains)
            {
                domains.RemoveAll(d => d.Domain == domain);
                domains.Insert(0, new DomainEntry
                {
                    Domain = domain,
                    AddedTime = DateTime.UtcNow,
                    Confidence = 100
                });

                if (domains.Count > 10)
                    domains.RemoveRange(10, domains.Count - 10);
            }
        }

        CleanupExpiredRecords();
    }

    public string? GetDomainForIP(string ip, DateTime connectionTime)
    {
        if (!_ipToDomain.TryGetValue(ip, out var domains))
            return null;

        lock (domains)
        {
            var candidate = domains
                .Where(d => d.AddedTime <= connectionTime.AddSeconds(5))
                .OrderByDescending(d => d.Confidence)
                .ThenBy(d => Math.Abs((connectionTime - d.AddedTime).TotalSeconds))
                .FirstOrDefault();

            return candidate?.Domain;
        }
    }

    private void CleanupExpiredRecords()
    {
        var now = DateTime.UtcNow;

        foreach (var kvp in _dnsCache.ToArray())
        {
            if ((now - kvp.Value.QueryTime).TotalSeconds > kvp.Value.TTL)
            {
                _dnsCache.TryRemove(kvp.Key, out _);
                foreach (var ip in kvp.Value.IPs)
                {
                    if (_ipToDomain.TryGetValue(ip, out var domains))
                    {
                        lock (domains)
                        {
                            domains.RemoveAll(d => d.Domain == kvp.Key);
                        }
                    }
                }
            }
        }

        foreach (var kvp in _ipToDomain.ToArray())
        {
            if (_ipToDomain.TryGetValue(kvp.Key, out var domains))
            {
                lock (domains)
                {
                    domains.RemoveAll(d => (now - d.AddedTime).TotalHours > 1);
                    if (domains.Count == 0)
                        _ipToDomain.TryRemove(kvp.Key, out _);
                }
            }
        }
    }

    public string GetStats() =>
        $"DNS Cache: {_dnsCache.Count} domains, IP Mappings: {_ipToDomain.Count} IPs";
}

#endregion

#region Process Monitor

class ProcessMonitor
{
    private readonly MonitorConfig _config;
    private readonly CancellationTokenSource _cts = new();
    private readonly EventAggregator _aggregator;
    private readonly ArtifactManager _artifacts;
    private readonly ConcurrentDictionary<int, bool> _monitoredPids = new();
    private readonly ConcurrentDictionary<string, DateTime> _consoleFloodGuard = new();
    private readonly DnsIpCorrelator _dnsCorrelator = new();
    private Process? _proc;
    private bool _isStopping;

    public ProcessMonitor(MonitorConfig config)
    {
        _config = config;
        _artifacts = new ArtifactManager(config.ArtifactZipPath);
        _aggregator = new EventAggregator(config.ExePath);
    }

    public void Stop() => _cts.Cancel();

    public async Task RunAsync()
    {
        var psi = new ProcessStartInfo(_config.ExePath)
        {
            WorkingDirectory = Path.GetDirectoryName(_config.ExePath) ?? Environment.CurrentDirectory,
            UseShellExecute = _config.RunAsAdmin,
            RedirectStandardOutput = !_config.RunAsAdmin,
            RedirectStandardError = !_config.RunAsAdmin,
            CreateNoWindow = !_config.RunAsAdmin
        };

        if (_config.RunAsAdmin) psi.Verb = "runas";

        _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _proc.Exited += (s, e) => {
            Log(_proc.Id, "ProcessExited", new { Code = _proc.ExitCode });
            _cts.Cancel();
        };

        try { if (!_proc.Start()) throw new Exception("Failed to start."); }
        catch (System.ComponentModel.Win32Exception w32)
        {
            throw new Exception($"Launch failed: {w32.Message}");
        }

        int mainPid = _proc.Id;
        _monitoredPids.TryAdd(mainPid, true);
        _aggregator.RegisterProcess(mainPid, 0, Path.GetFileName(_config.ExePath), "Target");
        Log(mainPid, "ProcessStarted", _config.ExePath);

        var tasks = new List<Task>
        {
            Task.Run(() => MonitorMetrics(_cts.Token)),
            Task.Run(() => MonitorNet(_cts.Token)),
            Task.Run(() => MonitorEtw(_cts.Token))
        };

        if (!_config.RunAsAdmin)
        {
            _ = Task.Run(async () => {
                try
                {
                    while (!_proc.StandardOutput.EndOfStream)
                    {
                        var line = await _proc.StandardOutput.ReadLineAsync();
                        if (line != null) Log(mainPid, "StdOut", line);
                    }
                }
                catch { }
            });

            _ = Task.Run(async () => {
                try
                {
                    while (!_proc.StandardError.EndOfStream)
                    {
                        var line = await _proc.StandardError.ReadLineAsync();
                        if (line != null) Log(mainPid, "StdErr", line);
                    }
                }
                catch { }
            });
        }

        try { await Task.WhenAll(tasks); }
        catch (OperationCanceledException) { }

        if (!_isStopping)
        {
            _isStopping = true;
            if (!_proc.HasExited)
            {
                try { _proc.Kill(); }
                catch { }
            }

            ConsoleHelper.Info("Process finished. Saving data...");
            await _aggregator.SaveReportAsync(_config.OutputFile);
            ConsoleHelper.Info($"Report saved: {_config.OutputFile}");
            _artifacts.FinalizeZip();
        }
    }

    private void Log(int pid, string type, object detail)
    {
        if (_isStopping) return;

        _aggregator.AddAction(pid, type, detail);

        if (_config.Verbose)
        {
            string detailStr = detail is string s ? s : JsonSerializer.Serialize(detail);
            string key = $"{pid}|{type}|{detailStr}";

            bool shouldPrint = true;
            if (_consoleFloodGuard.TryGetValue(key, out var lastTime))
            {
                if ((DateTime.Now - lastTime).TotalMilliseconds < 500)
                    shouldPrint = false;
            }

            if (shouldPrint)
            {
                _consoleFloodGuard[key] = DateTime.Now;
                ConsoleHelper.LiveEvent($"{type}({pid})", detailStr);
            }
        }
    }

    private async Task MonitorMetrics(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(2000, token);
            foreach (var pid in _monitoredPids.Keys)
            {
                try
                {
                    using var p = Process.GetProcessById(pid);
                    if (p.WorkingSet64 > 10 * 1024 * 1024)
                        Log(pid, "ProcessMetric", new
                        {
                            CPU = p.TotalProcessorTime.TotalSeconds,
                            RAM = p.WorkingSet64
                        });
                }
                catch { }
            }
        }
    }

    private async Task MonitorNet(CancellationToken token)
    {
        var seen = new HashSet<string>();
        while (!token.IsCancellationRequested)
        {
            foreach (var pid in _monitoredPids.Keys)
            {
                var conns = NetworkHelper.GetTcpConnections(pid);
                foreach (var c in conns)
                {
                    string k = $"{pid}:{c.Remote}:{c.State}";
                    if (!seen.Contains(k))
                    {
                        seen.Add(k);
                        Log(pid, "NetConnect", new
                        {
                            Dest = c.Remote.ToString(),
                            State = c.State.ToString()
                        });
                    }
                }
            }
            await Task.Delay(1000, token);
        }
    }

    private void FlushDns()
    {
        try
        {
            var psi = new ProcessStartInfo("ipconfig", "/flushdns")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            };
            Process.Start(psi)?.WaitForExit();
        }
        catch { }
    }

    private async Task MonitorEtw(CancellationToken token)
    {
        if (!IsAdministrator()) return;
        FlushDns();

        string modeMsg = _config.Paranoid ? "PARANOID (Handles/AMSI/PowerShell/Mem/Net)" :
                        _config.EnableAlpc ? "IPC/ALPC Enhanced" : "Standard";

        ConsoleHelper.Info($"Starting ETW Session: {modeMsg}...");

        await Task.Run(() => {
            try
            {
                using var session = new TraceEventSession("TrackX_Agg_" + Guid.NewGuid());
                using var reg = token.Register(() => session.Stop());

                var kernelFlags = KernelTraceEventParser.Keywords.Process |
                                  KernelTraceEventParser.Keywords.Thread |
                                  KernelTraceEventParser.Keywords.ImageLoad |
                                  KernelTraceEventParser.Keywords.VirtualAlloc |
                                  KernelTraceEventParser.Keywords.NetworkTCPIP |
                                  KernelTraceEventParser.Keywords.FileIO |
                                  KernelTraceEventParser.Keywords.FileIOInit |
                                  KernelTraceEventParser.Keywords.Registry;

                if (_config.EnableAlpc)
                    kernelFlags |= KernelTraceEventParser.Keywords.AdvancedLocalProcedureCalls;

                if (_config.Paranoid)
                    session.EnableKernelProvider(kernelFlags, KernelTraceEventParser.Keywords.All);
                else
                    session.EnableKernelProvider(kernelFlags);

                EnableProviders(session);
                AttachEventHandlers(session);

                _ = Task.Run(async () => {
                    while (!token.IsCancellationRequested)
                    {
                        await Task.Delay(TimeSpan.FromMinutes(5), token);
                        ConsoleHelper.Debug(_dnsCorrelator.GetStats());
                    }
                }, token);

                session.Source.Process();
            }
            catch (Exception ex)
            {
                ConsoleHelper.Error($"ETW Error: {ex.Message}");
            }
        }, token);
    }

    private void EnableProviders(TraceEventSession session)
    {
        var providers = new[]
        {
            ("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D", "DNS"),
            ("43D1A55C-76D6-4F7E-995C-64C711E5CAFE", "WinINet"),
            ("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa", "WMI"),
            ("6ad52b32-d609-4a9e-aece-9560b74306e2", "RPC"),
            ("DD5EF90A-6398-47A4-AD34-4DCECDEF795F", "HTTP.sys"),
            ("7D44233D-3055-4B9C-BA64-0D47CA40A232", "WinHTTP"),
            ("bdd9a83e-1929-5482-0d73-2edc5e1e7ef0", ".NET HTTP Client"),
            ("a9f9e4e4-0cf5-5005-b530-3d667cf2e3ca", ".NET Sockets"),
            ("1F678132-5938-4686-9FDC-C8FF68F15C85", "Schannel"),
            ("314DE49F-CE63-4779-BA2B-D616F6963A88", "NCSI")
        };

        foreach (var (guid, name) in providers)
        {
            session.EnableProvider(new Guid(guid), TraceEventLevel.Verbose, 0xFFFFFFFFFFFFFFFF);
        }

        if (_config.Paranoid)
        {
            session.EnableProvider(new Guid("2A576553-F74E-4F34-9914-FC18D87291EA"),
                TraceEventLevel.Verbose, 0xFFFFFFFFFFFFFFFF);
            session.EnableProvider(new Guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A"),
                TraceEventLevel.Informational, 0xFFFFFFFFFFFFFFFF);
        }
    }

    private void AttachEventHandlers(TraceEventSession session)
    {
        session.Source.Kernel.ProcessStart += d => {
            if (_monitoredPids.ContainsKey(d.ParentID))
            {
                if (_monitoredPids.TryAdd(d.ProcessID, true))
                {
                    _aggregator.RegisterProcess(d.ProcessID, d.ParentID, d.ProcessName, d.CommandLine);
                    Log(d.ProcessID, "ProcessStarted", d.CommandLine);
                }
            }
        };

        session.Source.Kernel.ThreadStart += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID))
            {
                string extra = d.ProcessID != d.ParentProcessID ?
                    $" (Remote by PID:{d.ParentProcessID})" : "";
                Log(d.ProcessID, "API:CreateThread", $"TID:{d.ThreadID}{extra}");
            }
        };

        session.Source.Kernel.VirtualMemAlloc += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) && d.EventDataLength > 4096)
                Log(d.ProcessID, "API:VirtualAlloc",
                    $"Size:{d.EventDataLength} Flags:0x{d.Flags:X}");
        };

        if (_config.EnableMapView)
        {
            session.Source.Kernel.FileIOMapFile += d => {
                if (_monitoredPids.ContainsKey(d.ProcessID))
                    Log(d.ProcessID, "API:MapView",
                        $"0x{d.ViewBase:X} Size:{d.ViewSize}");
            };
        }

        if (_config.Paranoid)
        {
            session.Source.Kernel.All += d => {
                if (!_monitoredPids.ContainsKey(d.ProcessID)) return;

                if ((int)d.ID == 32)
                {
                    try
                    {
                        long objAddr = (long)d.PayloadValue(0);
                        Log(d.ProcessID, "API:OpenHandle", $"ObjAddr:0x{objAddr:X}");
                    }
                    catch { }
                }
                else if ((int)d.ID == 34)
                {
                    try
                    {
                        int targetPid = (int)d.PayloadValue(2);
                        Log(d.ProcessID, "API:DupHandle", $"TargetPID:{targetPid}");
                    }
                    catch { }
                }
            };
        }

        AttachFileHandlers(session);
        AttachRegistryHandlers(session);
        AttachNetworkHandlers(session);
        AttachImageLoadHandlers(session);
        AttachAlpcHandlers(session);
        AttachDynamicHandlers(session);
    }

    private void AttachFileHandlers(TraceEventSession session)
    {
        session.Source.Kernel.FileIOCreate += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) && !string.IsNullOrEmpty(d.FileName))
            {
                if (!_config.EnableFilter || !FilterHelper.IsNoisy(d.FileName))
                {
                    Log(d.ProcessID, "API:CreateFile", d.FileName);
                    _artifacts.Capture(d.FileName);
                }
            }
        };

        session.Source.Kernel.FileIORename += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) && !string.IsNullOrEmpty(d.FileName))
                Log(d.ProcessID, "API:MoveFile", d.FileName);
        };

        session.Source.Kernel.FileIODelete += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) && !string.IsNullOrEmpty(d.FileName))
                if (!_config.EnableFilter || !FilterHelper.IsNoisy(d.FileName))
                    Log(d.ProcessID, "API:DeleteFile", d.FileName);
        };
    }

    private void AttachRegistryHandlers(TraceEventSession session)
    {
        session.Source.Kernel.RegistryCreate += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) &&
                (!_config.EnableFilter || !FilterHelper.IsNoisy(d.KeyName)))
                Log(d.ProcessID, "API:RegCreateKey", d.KeyName);
        };

        session.Source.Kernel.RegistrySetValue += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) &&
                (!_config.EnableFilter || !FilterHelper.IsNoisy(d.KeyName)))
                Log(d.ProcessID, "API:RegSetValue", d.KeyName);
        };
    }

    private void AttachNetworkHandlers(TraceEventSession session)
    {
        session.Source.Kernel.TcpIpConnect += d => {
            if (!_monitoredPids.ContainsKey(d.ProcessID)) return;

            string destIp = d.daddr.ToString();
            int destPort = (int)d.dport;
            string? domain = _dnsCorrelator.GetDomainForIP(destIp, DateTime.UtcNow);

            if (domain != null)
            {
                string protocol = destPort == 443 ? "https" : "http";
                string url = $"{protocol}://{domain}";
                Log(d.ProcessID, "TCP:Connect", new
                {
                    URL = url,
                    IP = destIp,
                    Port = destPort,
                    Confidence = "DNS-Correlated"
                });
            }
            else
            {
                Log(d.ProcessID, "TCP:Connect", new
                {
                    IP = destIp,
                    Port = destPort,
                    Note = "No DNS record found"
                });
            }
        };

        session.Source.Kernel.UdpIpSend += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID))
                if (d.daddr.ToString() != "127.0.0.1" && d.daddr.ToString() != "::1")
                    Log(d.ProcessID, "API:SendTo(UDP)", $"{d.daddr}:{d.dport}");
        };
    }

    private void AttachImageLoadHandlers(TraceEventSession session)
    {
        session.Source.Kernel.ImageLoad += d => {
            if (_monitoredPids.ContainsKey(d.ProcessID) && !string.IsNullOrEmpty(d.FileName))
            {
                if (!_config.EnableFilter || !FilterHelper.IsNoisy(d.FileName))
                {
                    string eventType = d.FileName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)
                        ? "API:LoadDriver" : "API:LoadLibrary";
                    Log(d.ProcessID, eventType, d.FileName);
                }
            }
        };
    }

    private void AttachAlpcHandlers(TraceEventSession session)
    {
        if (_config.EnableAlpc)
        {
            session.Source.Kernel.ALPCSendMessage += d => {
                if (_monitoredPids.ContainsKey(d.ProcessID))
                    Log(d.ProcessID, "API:ALPC_Send",
                        $"MsgID:{d.MessageID} Name:{d.ProcessName}");
            };
        }
    }

    private void AttachDynamicHandlers(TraceEventSession session)
    {
        session.Source.Dynamic.All += d => {
            if (!_monitoredPids.ContainsKey(d.ProcessID)) return;

            HandleAmsiEvents(d);
            HandlePowerShellEvents(d);
            HandleWmiEvents(d);
            HandleRpcEvents(d);
            HandleWinInetEvents(d);
            HandleDnsEvents(d);
            HandleWinHttpEvents(d);
            HandleHttpSysEvents(d);
            HandleSchannelEvents(d);
            HandleDotNetHttpEvents(d);
        };
    }

    private void HandleAmsiEvents(TraceEvent d)
    {
        if (!_config.Paranoid || d.ProviderGuid != new Guid("2A576553-F74E-4F34-9914-FC18D87291EA"))
            return;

        if (d.ID == (TraceEventID)1101)
        {
            string content = "Scan Data";
            try
            {
                string payload = d.PayloadString(0);
                content = payload[..Math.Min(payload.Length, 100)];
            }
            catch { }
            Log(d.ProcessID, "API:AMSI_Scan", content);
        }
    }

    private void HandlePowerShellEvents(TraceEvent d)
    {
        if (!_config.Paranoid || d.ProviderGuid != new Guid("A0C1853B-5C40-4B15-8766-3CF1C58F985A"))
            return;

        if ((int)d.ID == 7937)
        {
            string cmd = d.PayloadByName("CommandName")?.ToString() ?? "Script";
            Log(d.ProcessID, "API:PowerShell", cmd);
        }
    }

    private void HandleWmiEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa"))
            return;

        if (d.EventName.Contains("Start", StringComparison.OrdinalIgnoreCase))
        {
            string wmiData = d.PayloadByName("Query")?.ToString() ??
                           d.PayloadByName("Operation")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(wmiData) && !wmiData.Contains("WmiPerfInst"))
                Log(d.ProcessID, "API:WMI_Query", wmiData);
        }
    }

    private void HandleRpcEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("6ad52b32-d609-4a9e-aece-9560b74306e2"))
            return;

        if (d.Opcode == TraceEventOpcode.Start)
        {
            string uuid = d.PayloadByName("InterfaceUuid")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(uuid))
                Log(d.ProcessID, "API:RPC_Call", $"IID:{uuid}");
        }
    }

    private void HandleWinInetEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("43D1A55C-76D6-4F7E-995C-64C711E5CAFE"))
            return;

        for (int i = 0; i < d.PayloadNames.Length; i++)
        {
            string val = d.PayloadString(i);
            if (!string.IsNullOrEmpty(val) &&
                (val.StartsWith("http://") || val.StartsWith("https://")))
            {
                Log(d.ProcessID, "API:InternetOpen", val);
                return;
            }
        }
    }

    private void HandleDnsEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"))
            return;

        if (d.EventName.Contains("Query"))
        {
            string? q = d.PayloadByName("QueryName")?.ToString() ??
                       d.PayloadByName("Name")?.ToString();
            if (!string.IsNullOrEmpty(q) &&
                (!_config.EnableFilter || !FilterHelper.IsNoisy(q)))
            {
                if (!long.TryParse(q, out _))
                    Log(d.ProcessID, "API:GetAddrInfo", q);
            }
        }

        if ((int)d.ID == 3008)
        {
            string queryName = d.PayloadByName("QueryName")?.ToString()?.Trim() ?? "";
            string queryResults = d.PayloadByName("QueryResults")?.ToString() ?? "";

            if (!string.IsNullOrEmpty(queryName) && !string.IsNullOrEmpty(queryResults))
            {
                var ips = ParseDnsResults(queryResults);
                if (ips.Any())
                {
                    _dnsCorrelator.RecordDnsQuery(d.ProcessID, queryName, ips.ToArray());
                    Log(d.ProcessID, "DNS:Query", new
                    {
                        Domain = queryName,
                        ResolvedIPs = string.Join(", ", ips),
                        Count = ips.Count
                    });
                }
            }
        }
    }

    private void HandleWinHttpEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("7D44233D-3055-4B9C-BA64-0D47CA40A232"))
            return;

        if ((int)d.ID == 2007)
        {
            string url = d.PayloadByName("Url")?.ToString() ?? "";
            string headers = d.PayloadByName("Headers")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(url))
                Log(d.ProcessID, "HTTP:WinHTTP_Send", $"{url}\n{headers}");
        }
    }

    private void HandleHttpSysEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("DD5EF90A-6398-47A4-AD34-4DCECDEF795F"))
            return;

        if (d.EventName.Contains("Parse"))
        {
            string uri = d.PayloadByName("Url")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(uri))
                Log(d.ProcessID, "HTTP:HttpSys", uri);
        }
    }

    private void HandleSchannelEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("1F678132-5938-4686-9FDC-C8FF68F15C85"))
            return;

        if ((int)d.ID == 36870)
        {
            string server = d.PayloadByName("ServerName")?.ToString() ?? "";
            if (!string.IsNullOrEmpty(server))
                Log(d.ProcessID, "HTTPS:TLS_Handshake", server);
        }
    }

    private void HandleDotNetHttpEvents(TraceEvent d)
    {
        if (d.ProviderGuid != new Guid("bdd9a83e-1929-5482-0d73-2edc5e1e7ef0"))
            return;

        if ((int)d.ID == 1)
        {
            string scheme = d.PayloadByName("scheme")?.ToString() ?? "";
            string host = d.PayloadByName("host")?.ToString() ?? "";
            string path = d.PayloadByName("pathAndQuery")?.ToString() ?? "";
            Log(d.ProcessID, "HTTP:DotNet", $"{scheme}://{host}{path}");
        }
    }

    private List<string> ParseDnsResults(string results)
    {
        var ips = new List<string>();
        var parts = results.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            string cleaned = Regex.Replace(part.Trim(), @"^type:\d+\s*", "");
            if (IPAddress.TryParse(cleaned, out var ip))
                ips.Add(ip.ToString());
        }

        return ips;
    }

    private static bool IsAdministrator()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

#endregion

#region Network Helper

static class NetworkHelper
{
    public struct TcpInfo
    {
        public IPEndPoint Remote;
        public string State;
    }

    public static List<TcpInfo> GetTcpConnections(int pid)
    {
        var res = new List<TcpInfo>();
        try
        {
            int buffSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, 2, 5, 0);
            IntPtr ptr = Marshal.AllocHGlobal(buffSize);

            try
            {
                if (GetExtendedTcpTable(ptr, ref buffSize, true, 2, 5, 0) == 0)
                {
                    var table = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID_TABLE>(ptr);
                    IntPtr rowPtr = IntPtr.Add(ptr,
                        Marshal.OffsetOf(typeof(MIB_TCPROW_OWNER_PID_TABLE), "table").ToInt32());
                    int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                            IntPtr.Add(rowPtr, i * rowSize));

                        if (row.dwOwningPid == pid)
                        {
                            var remoteIp = new IPAddress(row.dwRemoteAddr);
                            int remotePort = IPAddress.NetworkToHostOrder((short)row.dwRemotePort);
                            res.Add(new TcpInfo
                            {
                                Remote = new IPEndPoint(remoteIp, remotePort),
                                State = ((MIB_TCP_STATE)row.dwState).ToString()
                            });
                        }
                    }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        catch { }

        return res;
    }

    private enum MIB_TCP_STATE
    {
        CLOSED = 1, LISTENING = 2, SYN_SENT = 3, SYN_RCVD = 4,
        ESTABLISHED = 5, FIN_WAIT1 = 6, FIN_WAIT2 = 7, CLOSE_WAIT = 8,
        CLOSING = 9, LAST_ACK = 10, TIME_WAIT = 11, DELETE_TCB = 12
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID_TABLE
    {
        public uint dwNumEntries;
        public MIB_TCPROW_OWNER_PID table;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize,
        bool bOrder, int ulAf, int TableClass, uint Reserved);
}

#endregion