namespace LucentMist.Agent.LLM;

/// <summary>Expected provider outage, safe to render without a stack trace.</summary>
public sealed class LlmUnavailableException(string message) : Exception(message);
