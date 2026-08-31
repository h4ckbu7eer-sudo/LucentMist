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
                var remaining = CloudLeadRanking.ModelLeadLimit;
                foreach (var group in obj["cloudCandidateGroups"]!.AsArray().OfType<JsonObject>())
                {
                    if (group["leads"] is not JsonArray leads) continue;
                    var retained = leads.Take(remaining).Select(item => item?.DeepClone()).ToArray();
                    group["modelOmittedCount"] = leads.Count - retained.Length;
                    group["leads"] = new JsonArray(retained);
                    remaining -= retained.Length;
                }
                obj["presentationGuidance"] = "最终评估按暴露面、TLS/DNS 风险、未知项、下一步组织；最多列5条优先核实线索并注明非确认漏洞，历史无版本证据线索已折叠。版本未知/DNS 不一致允许有限结论，不应反复扫描。";
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
