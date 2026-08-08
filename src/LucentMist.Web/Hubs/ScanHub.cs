using Microsoft.AspNetCore.SignalR;

namespace LucentMist.Web.Hubs;

public class ScanHub : Hub
{
    public async Task JoinScanGroup(string scanId)
        => await Groups.AddToGroupAsync(Context.ConnectionId, scanId);

    public Task LeaveScanGroup(string scanId)
        => Groups.RemoveFromGroupAsync(Context.ConnectionId, scanId);
}
