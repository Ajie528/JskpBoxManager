using System.Text.Json.Nodes;

namespace JskpBoxManager.Core;

public enum BoxPhase
{
    Stopped,
    Starting,
    WaitingScan,
    InGame,
    Refreshing,
    Failed,
}

/// <summary>后台启动/保活进程把当前阶段写进 logs\qbN.state.json，界面据此显示「正在启动 / 等待扫码 / 游戏中」。</summary>
public static class BoxStatusFile
{
    public sealed record State(BoxPhase Phase, string Text, DateTime At, int Pid);

    public static void Write(string box, BoxPhase phase, string text)
    {
        try
        {
            JsonFile.WriteObject(AppPaths.BoxState(box), new JsonObject
            {
                ["phase"] = phase.ToString(),
                ["text"] = text,
                ["at"] = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                ["pid"] = Environment.ProcessId,
            });
        }
        catch { }
    }

    public static State Read(string box)
    {
        var o = JsonFile.ReadObject(AppPaths.BoxState(box));
        if (o == null) return null;
        Enum.TryParse<BoxPhase>(JsonFile.Str(o, "phase"), out var phase);
        DateTime.TryParse(JsonFile.Str(o, "at"), out var at);
        return new State(phase, JsonFile.Str(o, "text"), at, JsonFile.Int(o, "pid") ?? 0);
    }
}
