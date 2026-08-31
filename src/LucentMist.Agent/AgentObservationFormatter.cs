using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using LucentMist.Agent.LLM;
using LucentMist.Tools.Security;

namespace LucentMist.Agent;

internal static class AgentObservationFormatter
{
    private static readonly JsonSerializerOptions Readable = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    // Only the model view is compacted. The session and tool result retain all leads.
    internal static string ForModel(ReActObservation observation)
    {
        try
        {
            var root = JsonNode.Parse(observation.Result);
            if (observation.ToolName == "vuln_scan" && root is JsonObject obj && obj["cloudCandidateGroups"] is JsonArray)
            {
                obj.Remove("cloudCandidates");
                obj["cloudCandidateGroups"] = JsonSerializer.SerializeToNode(CloudLeadRanking.ForPresentation(
                    JsonSerializer.SerializeToElement(obj["cloudCandidateGroups"]).EnumerateArray()));
                obj["presentationGuidance"] = "单目标最终评估尽量控制在600字内，按暴露面、TLS/DNS 风险、未知项、下一步组织；最多列5条优先核实线索并注明非确认漏洞，不复述工具明细。版本未知/DNS 不一致允许有限结论，不应反复扫描。";
            }
            if (observation.ToolName == "ssl_check" && root is JsonObject tls)
            {
                using var document = JsonDocument.Parse(observation.Result);
                if (SecurityAnalysisEvidence.TlsIdentityAssessment(document.RootElement) is { } identity)
                    tls["certificateIdentityAssessment"] = identity;
                if (tls["trustErrors"] is JsonArray { Count: > 0 })
                    tls["trustRemediationBoundary"] = SecurityAnalysisEvidence.TlsTrustGuidance;
            }
            return root?.ToJsonString(Readable) ?? observation.Result;
        }
        catch (JsonException) { return observation.Result; }
    }
}
