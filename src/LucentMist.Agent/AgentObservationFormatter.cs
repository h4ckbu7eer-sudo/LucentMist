using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using LucentMist.Agent.LLM;

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
                obj.Remove("cloudCandidates");
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
