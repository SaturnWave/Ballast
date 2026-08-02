using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace Ballast.App;

/// <summary>
/// Hand-written entry point, replacing the one the XAML compiler generates
/// (see <c>DISABLE_XAML_GENERATED_MAIN</c> in the csproj).
///
/// <para>
/// It exists so Ballast is <b>single-instance</b>: launching it again surfaces the window
/// already open instead of starting a second copy. Two copies of a disk cleaner is a bad idea —
/// both could scan and delete the same paths at once, and their totals would silently disagree.
/// </para>
/// </summary>
/// <remarks>
/// <para>
/// This uses a named mutex plus a window search rather than
/// <c>Microsoft.Windows.AppLifecycle.AppInstance</c>. The AppInstance version was tried first and
/// had a failure mode far worse than the problem it solved: after a crash it left its key
/// registered, so every later launch believed another instance owned the slot, redirected into
/// nothing and exited — the app simply stopped opening at all.
/// </para>
/// <para>
/// The rule here is therefore <b>fail open</b>. If anything is uncertain — the mutex cannot be
/// created, no window can be found, the foreground call is refused — this process starts normally.
/// A stray second window is a mild annoyance; an app that will not launch is a broken app.
/// </para>
/// </remarks>
public static class Program
{
    /// <summary>Session-scoped so it cannot clash with another user signed in at the same time.</summary>
    private const string MutexName = @"Local\Ballast.SingleInstance.v2";

    [STAThread]
    private static int Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();

        // Held for the process lifetime; released by the OS on exit, including a hard kill.
        Mutex? mutex = null;
        bool owned = true;

        try
        {
            mutex = new Mutex(initiallyOwned: true, MutexName, out owned);
        }
        catch (Exception)
        {
            owned = true; // fail open
        }

        if (!owned && TrySurfaceExistingWindow())
        {
            mutex?.Dispose();
            return 0;
        }

        try
        {
            Application.Start(callbackParams =>
            {
                // WinUI expects the UI thread to carry a DispatcherQueue-backed synchronization
                // context. The generated Main does exactly this, so this one must too.
                var queue = DispatcherQueue.GetForCurrentThread();
                SynchronizationContext.SetSynchronizationContext(
                    new DispatcherQueueSynchronizationContext(queue));

                // App registers itself with the framework in its constructor.
                _ = new App();
            });
        }
        finally
        {
            if (owned)
            {
                try { mutex?.ReleaseMutex(); } catch { /* already gone */ }
            }
            mutex?.Dispose();
        }

        return 0;
    }

    /// <summary>
    /// Finds a live Ballast window belonging to another process and brings it forward.
    /// </summary>
    /// <returns>
    /// <see langword="true"/> only when a window was actually found and surfaced. On
    /// <see langword="false"/> the caller starts normally, which is what makes a stale mutex
    /// harmless.
    /// </returns>
    private static bool TrySurfaceExistingWindow()
    {
        try
        {
            int me = Environment.ProcessId;

            foreach (Process other in Process.GetProcessesByName("Ballast.App"))
            {
                using (other)
                {
                    if (other.Id == me) continue;

                    nint hwnd = FindMainWindow(other.Id);
                    if (hwnd == 0) continue;

                    if (IsIconic(hwnd)) ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                    return true;
                }
            }
        }
        catch (Exception)
        {
            // Fall through to starting normally.
        }

        return false;
    }

    /// <summary>Largest visible top-level window owned by <paramref name="processId"/>.</summary>
    private static nint FindMainWindow(int processId)
    {
        nint best = 0;
        long bestArea = 0;

        EnumWindows((hwnd, lParam) =>
        {
            _ = GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid != processId || !IsWindowVisible(hwnd)) return true;

            // Skip anything that is not ours by class, so a splash or tooltip is not picked.
            var cls = new StringBuilder(256);
            _ = GetClassName(hwnd, cls, cls.Capacity);
            if (cls.ToString().Contains("Tooltip", StringComparison.OrdinalIgnoreCase)) return true;

            if (!GetWindowRect(hwnd, out Rect r)) return true;

            long area = (long)(r.Right - r.Left) * (r.Bottom - r.Top);
            if (area > bestArea)
            {
                bestArea = area;
                best = hwnd;
            }

            return true;
        }, 0);

        return best;
    }

    private const int SW_RESTORE = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left, Top, Right, Bottom;
    }

    private delegate bool EnumWindowsProc(nint hWnd, nint lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc callback, nint lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(nint hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(nint hWnd, out Rect rect);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetWindowThreadProcessId(nint hWnd, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(nint hWnd, StringBuilder text, int count);
}
