namespace LucentMist.Tools.Security;

public static class TlsTrustLabels
{
    public static string Describe(string? error) => error switch
    {
        "NameMismatch" => "证书与访问地址/域名不匹配 (NameMismatch)",
        "PartialChain" => "证书链不完整，缺少签发者证书 (PartialChain)",
        "UntrustedRoot" => "根证书不受当前系统信任；不等于叶证书自签 (UntrustedRoot)",
        "ChainErrors" => "证书链验证未通过，具体原因见其它错误 (ChainErrors)",
        "NotTimeValid" => "证书链中存在未生效或已过期证书 (NotTimeValid)",
        "RevocationStatusUnknown" => "无法确认是否已被吊销 (RevocationStatusUnknown)",
        "OfflineRevocation" => "吊销状态查询不可用 (OfflineRevocation)",
        "Revoked" => "证书已被吊销 (Revoked)",
        "CertificateNotAvailable" => "未取得服务器证书 (CertificateNotAvailable)",
        "ChainBuildFailed" => "无法构建并检查证书链 (ChainBuildFailed)",
        _ => "其它证书验证错误：" + error,
    };
}
