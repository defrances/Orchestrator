#!/usr/bin/env python3
"""Apply the narrow DesktopApplication TLS patch in the local checkout."""

from __future__ import annotations

from pathlib import Path

APP = Path("workspace/DesktopApplication")
CLIENT = APP / "src" / "DesktopApplication.Core" / "InsecureVendorBulletinClient.cs"
TESTS = APP / "tests" / "DesktopApplication.Tests" / "InsecureVendorBulletinClientTests.cs"
MDS2 = APP / "docs" / "mds2.md"
VULN = APP / "docs" / "vulnerability-report.md"

CLIENT_SRC = '''using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace DesktopApplication.Core;

/// <summary>
/// Downloads a vendor bulletin over HTTPS and requires a valid server certificate.
/// The process still uses the host TLS/Schannel stack for the handshake.
/// </summary>
public sealed class InsecureVendorBulletinClient
{
    public const string Marker = "TLS_CERTIFICATE_VALIDATED";
    public const string DefaultUrl = "https://www.microsoft.com/en-us/msrc";

    public static bool AcceptAnyServerCertificate(
        object? sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        _ = sender;
        _ = certificate;
        _ = chain;
        return sslPolicyErrors == SslPolicyErrors.None;
    }

    public static HttpMessageHandler CreateTrustingHandler()
    {
        return new SocketsHttpHandler
        {
            SslOptions =
            {
                RemoteCertificateValidationCallback = AcceptAnyServerCertificate
            }
        };
    }

    public async Task<string> FetchAsync(string? url = null, CancellationToken cancellationToken = default)
    {
        using var client = new HttpClient(CreateTrustingHandler(), disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
        return await client.GetStringAsync(url ?? DefaultUrl, cancellationToken).ConfigureAwait(false);
    }
}
'''

TESTS_SRC = '''using System.Net.Security;
using DesktopApplication.Core;

namespace DesktopApplication.Tests;

public sealed class InsecureVendorBulletinClientTests
{
    [Fact]
    [Trait("Category", "Unit")]
    [Trait("TestId", "TC-UNIT-TLS-MARKER")]
    public void Marker_IdentifiesValidatedTlsPath()
    {
        Assert.Equal("TLS_CERTIFICATE_VALIDATED", InsecureVendorBulletinClient.Marker);
    }

    [Fact]
    [Trait("Category", "Regression")]
    [Trait("TestId", "TC-REG-TLS-CALLBACK")]
    public void AcceptAnyServerCertificate_ReturnsFalse_WhenTheChainIsInvalid()
    {
        var accepted = InsecureVendorBulletinClient.AcceptAnyServerCertificate(
            null,
            null,
            null,
            SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors);

        Assert.False(accepted);
    }
}
'''


def replace_once(path: Path, old: str, new: str) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> int:
    if not CLIENT.exists():
        raise SystemExit(f"missing {CLIENT}")
    CLIENT.write_text(CLIENT_SRC, encoding="utf-8")
    if TESTS.exists():
        TESTS.write_text(TESTS_SRC, encoding="utf-8")
    replace_once(
        MDS2,
        "| MDS2-TLS | Cryptography / TLS | **not met** | `AcceptAnyServerCertificate` always returns `true`. The process uses host Schannel for the handshake, then **discards** certificate validation results. Marker: `INTENTIONAL_SKILL_TEST_VULNERABILITY`. |",
        "| MDS2-TLS | Cryptography / TLS | met | Server certificates are validated (`SslPolicyErrors.None`). Host Schannel still performs the handshake. |",
    )
    replace_once(
        VULN,
        "| VR-TLS-001 | Vendor bulletin HTTPS accepts any server certificate | High | **open** | `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` (`AcceptAnyServerCertificate` returns `true`; `CreateTrustingHandler`; `MainViewModel.CheckBulletinCommand`) | **absent**. MDS2-TLS is not met. Marker `INTENTIONAL_SKILL_TEST_VULNERABILITY`. |",
        "| VR-TLS-001 | Vendor bulletin HTTPS accepts any server certificate | High | **closed** | `src/DesktopApplication.Core/InsecureVendorBulletinClient.cs` | **present**. Callback requires `SslPolicyErrors.None`. |",
    )
    print(f"patched {CLIENT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
