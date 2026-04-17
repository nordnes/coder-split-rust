//! AWS EC2 instance-identity document verification.
//!
//! AWS signs the identity document with RSA PKCS1v15 over SHA-256 using the
//! regional EC2 public key. The raw (base64-encoded) signature is sent along
//! with the JSON document inside the workspace-agent bootstrap request.
//!
//! Ports `coder/coderd/awsidentity/awsidentity.go`.

use std::sync::Arc;

use base64::Engine;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::Sha256;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;

use super::{VerifiedInstance, VerifyError};

/// Bundled AWS EC2 regional certificates used to verify identity documents.
///
/// Mirrors the `defaultCertificates` map in
/// `coder/coderd/awsidentity/awsidentity.go` — the certificates are copied
/// verbatim from the Go reference for behavioural parity.
///
/// ⚠️ EXPIRATION CAVEAT: the `Other` commercial-region certificate below
/// expired on **2024-06-05**. AWS rotates these periodically; the Go
/// reference carries the same stale cert, and operators running against
/// signatures minted after that date must supply a current regional cert
/// via [`AwsInstanceVerifier::with_certificates`]. The other embedded
/// certs in this list remain valid (their `notAfter` dates range from 2029
/// through 2200). Fresh certs can be downloaded from
/// <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-signature.html>.
///
/// Additional partition-specific regions not covered here (e.g. `cn-*`
/// China partition beyond what Go already bundles, or `us-iso*` for
/// ISO/ISOB) are not shipped as defaults. Operators on those partitions
/// must inject their own certs through `with_certificates`.
pub(crate) const DEFAULT_CERTIFICATES: &[&str] = &[
    // "Other" — commercial regions except those listed below.
    // notBefore: 2014-06-05, notAfter: 2024-06-05 (⚠️ EXPIRED — see module docs).
    "-----BEGIN CERTIFICATE-----\n\
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV\n\
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw\n\
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu\n\
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC\n\
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV\n\
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w\n\
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3\n\
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD\n\
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL\n\
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs\n\
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq\n\
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh\n\
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h\n\
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF\n\
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T\n\
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ\n\
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=\n\
-----END CERTIFICATE-----",
    // "HongKong" — ap-east-1. notAfter: 2029-02-02.
    "-----BEGIN CERTIFICATE-----\n\
MIICSzCCAbQCCQDtQvkVxRvK9TANBgkqhkiG9w0BAQsFADBqMQswCQYDVQQGEwJV\n\
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEYMBYGA1UE\n\
ChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1hem9uYXdzLmNvbTAe\n\
Fw0xOTAyMDMwMzAwMDZaFw0yOTAyMDIwMzAwMDZaMGoxCzAJBgNVBAYTAlVTMRMw\n\
EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgwFgYDVQQKEw9B\n\
bWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3MuY29tMIGfMA0G\n\
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1kkHXYTfc7gY5Q55JJhjTieHAgacaQkiR\n\
Pity9QPDE3b+NXDh4UdP1xdIw73JcIIG3sG9RhWiXVCHh6KkuCTqJfPUknIKk8vs\n\
M3RXflUpBe8Pf+P92pxqPMCz1Fr2NehS3JhhpkCZVGxxwLC5gaG0Lr4rFORubjYY\n\
Rh84dK98VwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAA6xV9f0HMqXjPHuGILDyaNN\n\
dKcvplNFwDTydVg32MNubAGnecoEBtUPtxBsLoVYXCOb+b5/ZMDubPF9tU/vSXuo\n\
TpYM5Bq57gJzDRaBOntQbX9bgHiUxw6XZWaTS/6xjRJDT5p3S1E0mPI3lP/eJv4o\n\
Ezk5zb3eIf10/sqt4756\n\
-----END CERTIFICATE-----",
    // "Bahrain" — me-south-1. notAfter: 2198-09-29.
    "-----BEGIN CERTIFICATE-----\n\
MIIDPDCCAqWgAwIBAgIJAMl6uIV/zqJFMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV\n\
BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMSAw\n\
HgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzEaMBgGA1UEAwwRZWMyLmFt\n\
YXpvbmF3cy5jb20wIBcNMTkwNDI2MTQzMjQ3WhgPMjE5ODA5MjkxNDMyNDdaMHIx\n\
CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0\n\
dGxlMSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzEaMBgGA1UEAwwR\n\
ZWMyLmFtYXpvbmF3cy5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALVN\n\
CDTZEnIeoX1SEYqq6k1BV0ZlpY5y3KnoOreCAE589TwS4MX5+8Fzd6AmACmugeBP\n\
Qk7Hm6b2+g/d4tWycyxLaQlcq81DB1GmXehRkZRgGeRge1ePWd1TUA0I8P/QBT7S\n\
gUePm/kANSFU+P7s7u1NNl+vynyi0wUUrw7/wIZTAgMBAAGjgdcwgdQwHQYDVR0O\n\
BBYEFILtMd+T4YgH1cgc+hVsVOV+480FMIGkBgNVHSMEgZwwgZmAFILtMd+T4YgH\n\
1cgc+hVsVOV+480FoXakdDByMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGlu\n\
Z3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEgMB4GA1UECgwXQW1hem9uIFdlYiBTZXJ2\n\
aWNlcyBMTEMxGjAYBgNVBAMMEWVjMi5hbWF6b25hd3MuY29tggkAyXq4hX/OokUw\n\
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBhkNTBIFgWFd+ZhC/LhRUY\n\
4OjEiykmbEp6hlzQ79T0Tfbn5A4NYDI2icBP0+hmf6qSnIhwJF6typyd1yPK5Fqt\n\
NTpxxcXmUKquX+pHmIkK1LKDO8rNE84jqxrxRsfDi6by82fjVYf2pgjJW8R1FAw+\n\
mL5WQRFexbfB5aXhcMo0AA==\n\
-----END CERTIFICATE-----",
    // "CapeTown" — af-south-1. notAfter: 2199-05-02.
    "-----BEGIN CERTIFICATE-----\n\
MIICNjCCAZ+gAwIBAgIJAKumfZiRrNvHMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV\n\
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0\n\
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xOTExMjcw\n\
NzE0MDVaGA8yMTk5MDUwMjA3MTQwNVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT\n\
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft\n\
YXpvbiBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n\
gQDFd571nUzVtke3rPyRkYfvs3jh0C0EMzzG72boyUNjnfw1+m0TeFraTLKb9T6F\n\
7TuB/ZEN+vmlYqr2+5Va8U8qLbPF0bRH+FdaKjhgWZdYXxGzQzU3ioy5W5ZM1VyB\n\
7iUsxEAlxsybC3ziPYaHI42UiTkQNahmoroNeqVyHNnBpQIDAQABMA0GCSqGSIb3\n\
DQEBCwUAA4GBAAJLylWyElEgOpW4B1XPyRVD4pAds8Guw2+krgqkY0HxLCdjosuH\n\
RytGDGN+q75aAoXzW5a7SGpxLxk6Hfv0xp3RjDHsoeP0i1d8MD3hAC5ezxS4oukK\n\
s5gbPOnokhKTMPXbTdRn5ZifCbWlx+bYN/mTYKvxho7b5SVg2o1La9aK\n\
-----END CERTIFICATE-----",
    // "Milan" — eu-south-1. notAfter: 2199-03-29.
    "-----BEGIN CERTIFICATE-----\n\
MIICNjCCAZ+gAwIBAgIJAOZ3GEIaDcugMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV\n\
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0\n\
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0xOTEwMjQx\n\
NTE5MDlaGA8yMTk5MDMyOTE1MTkwOVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgT\n\
EFdhc2hpbmd0b24gU3RhdGUxEDAOBgNVBAcTB1NlYXR0bGUxIDAeBgNVBAoTF0Ft\n\
YXpvbiBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n\
gQCjiPgW3vsXRj4JoA16WQDyoPc/eh3QBARaApJEc4nPIGoUolpAXcjFhWplo2O+\n\
ivgfCsc4AU9OpYdAPha3spLey/bhHPRi1JZHRNqScKP0hzsCNmKhfnZTIEQCFvsp\n\
DRp4zr91/WS06/flJFBYJ6JHhp0KwM81XQG59lV6kkoW7QIDAQABMA0GCSqGSIb3\n\
DQEBCwUAA4GBAGLLrY3P+HH6C57dYgtJkuGZGT2+rMkk2n81/abzTJvsqRqGRrWv\n\
XRKRXlKdM/dfiuYGokDGxiC0Mg6TYy6wvsR2qRhtXW1OtZkiHWcQCnOttz+8vpew\n\
wx8JGMvowtuKB1iMsbwyRqZkFYLcvH+Opfb/Aayi20/ChQLdI6M2R5VU\n\
-----END CERTIFICATE-----",
    // "China" — cn-north-1 / cn-northwest-1.
    // notBefore: 2013-08-21, notAfter: 2023-08-21 (⚠️ EXPIRED per Go source).
    "-----BEGIN CERTIFICATE-----\n\
MIICSzCCAbQCCQCQu97teKRD4zANBgkqhkiG9w0BAQUFADBqMQswCQYDVQQGEwJV\n\
UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEYMBYGA1UE\n\
ChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1hem9uYXdzLmNvbTAe\n\
Fw0xMzA4MjExMzIyNDNaFw0yMzA4MjExMzIyNDNaMGoxCzAJBgNVBAYTAlVTMRMw\n\
EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgwFgYDVQQKEw9B\n\
bWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3MuY29tMIGfMA0G\n\
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6GFQ2WoBl1xZYH85INUMaTc4D30QXM6f+\n\
YmWZyJD9fC7Z0UlaZIKoQATqCO58KNCre+jECELYIX56Uq0lb8LRLP8tijrQ9Sp3\n\
qJcXiH66kH0eQ44a5YdewcFOy+CSAYDUIaB6XhTQJ2r7bd4A2vw3ybbxTOWONKdO\n\
WtgIe3M3iwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAHzQC5XZVeuD9GTJTsbO5AyH\n\
ZQvki/jfARNrD9dgBRYZzLC/NOkWG6M9wlrmks9RtdNxc53nLxKq4I2Dd73gI0yQ\n\
wYu9YYwmM/LMgmPlI33Rg2Ohwq4DVgT3hO170PL6Fsgiq3dMvctSImJvjWktBQaT\n\
bcAgaZLHGIpXPrWSA2d+\n\
-----END CERTIFICATE-----",
    // "TelAviv" — il-central-1. notAfter: 2200-11-11.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAX0QQGVLMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTExMTExODI2\n\
MzVaGA8yMjAwMTExMTE4MjYzNVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDr\n\
c24u3AgFxnoPgzxR6yFXOamcPuxYXhYKWmapb+S8vOy5hpLoRe4RkOrY0cM3bN07\n\
GdEMlin5mU0y1t8y3ct4YewvmkgT42kTyMM+t1K4S0xsqjXxxS716uGYh7eWtkxr\n\
Cihj8AbXN/6pa095h+7TZyl2n83keiNUzM2KoqQVMwIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBADwA6VVEIIZD2YL00F12po40xDLzIc9XvqFPS9iFaWi2ho8wLio7wA49\n\
VYEFZSI9CR3SGB9tL8DUib97mlxmd1AcGShMmMlhSB29vhuhrUNB/FmU7H8s62/j\n\
D6cOR1A1cClIyZUe1yT1ZbPySCs43J+Thr8i8FSRxzDBSZZi5foW\n\
-----END CERTIFICATE-----",
    // "UAE" — me-central-1. notAfter: 2200-04-14.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXjRrnDjMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTA0MTQxODM5\n\
MzNaGA8yMjAwMDQxNDE4MzkzM1owXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc\n\
aTgW/KyA6zyruJQrYy00a6wqLA7eeUzk3bMiTkLsTeDQfrkaZMfBAjGaaOymRo1C\n\
3qzE4rIenmahvUplu9ZmLwL1idWXMRX2RlSvIt+d2SeoKOKQWoc2UOFZMHYxDue7\n\
zkyk1CIRaBukTeY13/RIrlc6X61zJ5BBtZXlHwayjQIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBABTqTy3R6RXKPW45FA+cgo7YZEj/Cnz5YaoUivRRdX2A83BHuBTvJE2+\n\
WX00FTEj4hRVjameE1nENoO8Z7fUVloAFDlDo69fhkJeSvn51D1WRrPnoWGgEfr1\n\
+OfK1bAcKTtfkkkP9r4RdwSjKzO5Zu/B+Wqm3kVEz/QNcz6npmA6\n\
-----END CERTIFICATE-----",
    // "Zurich" — eu-central-2. notAfter: 2200-04-14.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXjSGFGiMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTA0MTQyMDM1\n\
MTJaGA8yMjAwMDQxNDIwMzUxMlowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2\n\
mdGdps5Rz2jzYcGNsgETTGUthJRrVqSnUWJXTlVaIbkGPLKO6Or7AfWKFp2sgRJ8\n\
vLsjoBVR5cESVK7cuK1wItjvJyi/opKZAUusJx2hpgU3pUHhlp9ATh/VeVD582jT\n\
d9IY+8t5MDa6Z3fGliByEiXz0LEHdi8MBacLREu1TwIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBAILlpoE3k9o7KdALAxsFJNitVS+g3RMzdbiFM+7MA63Nv5fsf+0xgcjS\n\
NBElvPCDKFvTJl4QQhToy056llO5GvdS9RK+H8xrP2mrqngApoKTApv93vHBixgF\n\
Sn5KrczRO0YSm3OjkqbydU7DFlmkXXR7GYE+5jbHvQHYiT1J5sMu\n\
-----END CERTIFICATE-----",
    // "Spain" — eu-south-2. notAfter: 2200-04-20.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXjwLkiaMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTA0MjAxNjQ3\n\
NDhaGA8yMjAwMDQyMDE2NDc0OFowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB\n\
/VvR1+45Aey5zn3vPk6xBm5o9grSDL6D2iAuprQnfVXn8CIbSDbWFhA3fi5ippjK\n\
kh3sl8VyCvCOUXKdOaNrYBrPRkrdHdBuL2Tc84RO+3m/rxIUZ2IK1fDlC6sWAjdd\n\
f6sBrV2w2a78H0H8EwuwiSgttURBjwJ7KPPJCqaqrQIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBAKR+FzqQDzun/iMMzcFucmLMl5BxEblrFXOz7IIuOeiGkndmrqUeDCyk\n\
ztLku45s7hxdNy4ltTuVAaE5aNBdw5J8U1mRvsKvHLy2ThH6hAWKwTqtPAJp7M21\n\
GDwgDDOkPSz6XVOehg+hBgiphYp84DUbWVYeP8YqLEJSqscKscWC\n\
-----END CERTIFICATE-----",
    // "Melbourne" — ap-southeast-4. notAfter: 2200-04-14.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXjSh40SMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTA0MTQyMjM2\n\
NDJaGA8yMjAwMDQxNDIyMzY0MlowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDH\n\
ezwQr2VQpQSTW5TXNefiQrP+qWTGAbGsPeMX4hBMjAJUKys2NIRcRZaLM/BCew2F\n\
IPVjNtlaj6Gwn9ipU4Mlz3zIwAMWi1AvGMSreppt+wV6MRtfOjh0Dvj/veJe88aE\n\
ZJMozNgkJFRS+WFWsckQeL56tf6kY6QTlNo8V/0CsQIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBAF7vpPghH0FRo5gu49EArRNPrIvW1egMdZHrzJNqbztLCtV/wcgkqIww\n\
uXYj+1rhlL+/iMpQWjdVGEqIZSeXn5fLmdx50eegFCwND837r9e8XYTiQS143Sxt\n\
9+Yi6BZ7U7YD8kK9NBWoJxFqUeHdpRCs0O7COjT3gwm7ZxvAmssh\n\
-----END CERTIFICATE-----",
    // "Jakarta" — ap-southeast-3. notAfter: 2200-01-06.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXbVDG2yMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTAxMDYwMDE1\n\
MzBaGA8yMjAwMDEwNjAwMTUzMFowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCn\n\
CS/Vbt0gQ1ebWcur2hSO7PnJifE4OPxQ7RgSAlc4/spJp1sDP+ZrS0LO1ZJfKhXf\n\
1R9S3AUwLnsc7b+IuVXdY5LK9RKqu64nyXP5dx170zoL8loEyCSuRR2fs+04i2Qs\n\
WBVP+KFNAn7P5L1EHRjkgTO8kjNKviwRV+OkP9ab5wIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBAI4WUy6+DKh0JDSzQEZNyBgNlSoSuC2owtMxCwGB6nBfzzfcekWvs6eo\n\
fLTSGovrReX7MtVgrcJBZjmPIentw5dWUs+87w/g9lNwUnUt0ZHYyh2tuBG6hVJu\n\
UEwDJ/z3wDd6wQviLOTF3MITawt9P8siR1hXqLJNxpjRQFZrgHqi\n\
-----END CERTIFICATE-----",
    // "Hyderabad" — ap-south-2. notAfter: 2200-04-20.
    "-----BEGIN CERTIFICATE-----\n\
MIICMzCCAZygAwIBAgIGAXjwLj9CMA0GCSqGSIb3DQEBBQUAMFwxCzAJBgNVBAYT\n\
AlVTMRkwFwYDVQQIDBBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHDAdTZWF0dGxl\n\
MSAwHgYDVQQKDBdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAgFw0yMTA0MjAxNjQ3\n\
NDVaGA8yMjAwMDQyMDE2NDc0NVowXDELMAkGA1UEBhMCVVMxGTAXBgNVBAgMEFdh\n\
c2hpbmd0b24gU3RhdGUxEDAOBgNVBAcMB1NlYXR0bGUxIDAeBgNVBAoMF0FtYXpv\n\
biBXZWIgU2VydmljZXMgTExDMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDT\n\
wHu0ND+sFcobrjvcAYm0PNRD8f4R1jAzvoLt2+qGeOTAyO1Httj6cmsYN3AP1hN5\n\
iYuppFiYsl2eNPa/CD0Vg0BAfDFlV5rzjpA0j7TJabVh4kj7JvtD+xYMi6wEQA4x\n\
6SPONY4OeZ2+8o/HS8nucpWDVdPRO6ciWUlMhjmDmwIDAQABMA0GCSqGSIb3DQEB\n\
BQUAA4GBAAy6sgTdRkTqELHBeWj69q60xHyUmsWqHAQNXKVc9ApWGG4onzuqlMbG\n\
ETwUZ9mTq2vxlV0KvuetCDNS5u4cJsxe/TGGbYP0yP2qfMl0cCImzRI5W0gn8gog\n\
dervfeT7nH5ih0TWEy/QDWfkQ601L4erm4yh4YQq8vcqAPSkf04N\n\
-----END CERTIFICATE-----",
    // "GovCloud" — us-gov-west-1 / us-gov-east-1.
    // notBefore: 2021-07-14, notAfter: 2024-07-13 (⚠️ EXPIRED per Go source).
    "-----BEGIN CERTIFICATE-----\n\
MIIDCzCCAnSgAwIBAgIJAIe9Hnq82O7UMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV\n\
BAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0\n\
dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0yMTA3MTQx\n\
NDI3NTdaFw0yNDA3MTMxNDI3NTdaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBX\n\
YXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6\n\
b24gV2ViIFNlcnZpY2VzIExMQzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n\
qaIcGFFTx/SO1W5G91jHvyQdGP25n1Y91aXCuOOWAUTvSvNGpXrI4AXNrQF+CmIO\n\
C4beBASnHCx082jYudWBBl9Wiza0psYc9flrczSzVLMmN8w/c78F/95NfiQdnUQP\n\
pvgqcMeJo82cgHkLR7XoFWgMrZJqrcUK0gnsQcb6kakCAwEAAaOB1DCB0TALBgNV\n\
HQ8EBAMCB4AwHQYDVR0OBBYEFNWV53gWJz72F5B1ZVY4O/dfFYBPMIGOBgNVHSME\n\
gYYwgYOAFNWV53gWJz72F5B1ZVY4O/dfFYBPoWCkXjBcMQswCQYDVQQGEwJVUzEZ\n\
MBcGA1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4G\n\
A1UEChMXQW1hem9uIFdlYiBTZXJ2aWNlcyBMTEOCCQCHvR56vNju1DASBgNVHRMB\n\
Af8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4GBACrKjWj460GUPZCGm3/z0dIz\n\
M2BPuH769wcOsqfFZcMKEysSFK91tVtUb1soFwH4/Lb/T0PqNrvtEwD1Nva5k0h2\n\
xZhNNRmDuhOhW1K9wCcnHGRBwY5t4lYL6hNV6hcrqYwGMjTjcAjBG2yMgznSNFle\n\
Rwi/S3BFXISixNx9cILu\n\
-----END CERTIFICATE-----",
];

/// Verifier for AWS EC2 instance-identity documents.
pub(crate) struct AwsInstanceVerifier {
    verifying_keys: Vec<Arc<VerifyingKey<Sha256>>>,
}

impl AwsInstanceVerifier {
    /// Build a verifier with the bundled default regional certificates.
    ///
    /// Invalid bundled certificates are silently dropped so a single malformed
    /// anchor cannot take down startup; this matches the Go reference
    /// behaviour where certificates that fail to parse cause `Validate` to
    /// return early rather than panic.
    #[must_use]
    pub(crate) fn with_default_certificates() -> Self {
        Self::with_certificates(DEFAULT_CERTIFICATES.iter().copied())
    }

    /// Build a verifier from caller-supplied PEM-encoded certificates.
    pub(crate) fn with_certificates<'a>(pem_iter: impl IntoIterator<Item = &'a str>) -> Self {
        let verifying_keys = pem_iter
            .into_iter()
            .filter_map(|pem| parse_rsa_verifying_key(pem).ok())
            .map(Arc::new)
            .collect();
        Self { verifying_keys }
    }

    /// Validate an AWS PKCS1v15 signature against the bundled regional
    /// certificates.
    pub(crate) async fn verify(
        &self,
        document: &str,
        signature_b64: &str,
    ) -> Result<VerifiedInstance, VerifyError> {
        // Structural: the document must parse as JSON and declare an
        // `instanceId`. This is checked even before the signature so that
        // a request with a blatantly malformed document still returns 400
        // rather than 401 (matches the existing behaviour of the stubbed
        // handler plus the Go reference).
        let doc: serde_json::Value = serde_json::from_str(document)
            .map_err(|e| VerifyError::InvalidRequest(format!("malformed JSON: {e}")))?;
        let instance_id = doc
            .get("instanceId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| VerifyError::InvalidRequest("missing instanceId".to_owned()))?
            .to_owned();

        if self.verifying_keys.is_empty() {
            return Err(VerifyError::VerificationFailed);
        }

        let raw_signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64.trim())
            .map_err(|_| VerifyError::VerificationFailed)?;
        let signature = Signature::try_from(raw_signature.as_slice())
            .map_err(|_| VerifyError::VerificationFailed)?;

        for key in &self.verifying_keys {
            if key.verify(document.as_bytes(), &signature).is_ok() {
                return Ok(VerifiedInstance { instance_id });
            }
        }
        Err(VerifyError::VerificationFailed)
    }
}

/// Extract an RSA verifying key from a PEM-encoded X.509 certificate.
fn parse_rsa_verifying_key(pem: &str) -> Result<VerifyingKey<Sha256>, String> {
    let (_, pem_block) = parse_x509_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
    let cert = pem_block
        .parse_x509()
        .map_err(|e| format!("parse X.509: {e}"))?;
    let spki = cert.public_key();
    let parsed = spki.parsed().map_err(|e| format!("parsed spki: {e}"))?;
    let PublicKey::RSA(rsa_key) = parsed else {
        return Err("certificate public key is not RSA".to_owned());
    };
    let modulus = rsa::BigUint::from_bytes_be(rsa_key.modulus);
    let exponent = rsa::BigUint::from_bytes_be(rsa_key.exponent);
    let rsa_pub =
        RsaPublicKey::new(modulus, exponent).map_err(|e| format!("build rsa key: {e}"))?;
    Ok(VerifyingKey::<Sha256>::new(rsa_pub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    fn verifier_with_key(key: VerifyingKey<Sha256>) -> AwsInstanceVerifier {
        AwsInstanceVerifier {
            verifying_keys: vec![Arc::new(key)],
        }
    }

    fn generate_keys() -> Result<(SigningKey<Sha256>, VerifyingKey<Sha256>), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let verifying_key = signing_key.verifying_key();
        Ok((signing_key, verifying_key))
    }

    fn assert_verification_failed<T: std::fmt::Debug>(
        result: Result<T, VerifyError>,
    ) -> Result<(), Box<dyn Error>> {
        match result {
            Err(VerifyError::VerificationFailed) => Ok(()),
            other => Err(format!("expected VerificationFailed, got {other:?}").into()),
        }
    }

    fn assert_invalid_request<T: std::fmt::Debug>(
        result: Result<T, VerifyError>,
    ) -> Result<(), Box<dyn Error>> {
        match result {
            Err(VerifyError::InvalidRequest(_)) => Ok(()),
            other => Err(format!("expected InvalidRequest, got {other:?}").into()),
        }
    }

    #[tokio::test]
    async fn verify_valid_signature_returns_instance_id() -> TestResult {
        let (signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        let document = r#"{"instanceId":"i-abc","region":"us-east-1"}"#;
        let signature = signing_key.sign_with_rng(&mut rand::thread_rng(), document.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let out = verifier
            .verify(document, &signature_b64)
            .await
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        assert_eq!(out.instance_id, "i-abc");
        Ok(())
    }

    #[tokio::test]
    async fn verify_invalid_signature_returns_verification_failed() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let (other_signing, _other_verifying) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        let document = r#"{"instanceId":"i-abc"}"#;
        let signature = other_signing.sign_with_rng(&mut rand::thread_rng(), document.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        assert_verification_failed(verifier.verify(document, &signature_b64).await)
    }

    #[tokio::test]
    async fn verify_malformed_json_returns_invalid_request() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_invalid_request(verifier.verify("not json", "AAAA").await)
    }

    #[tokio::test]
    async fn verify_missing_instance_id_returns_invalid_request() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_invalid_request(verifier.verify("{}", "AAAA").await)
    }

    #[tokio::test]
    async fn verify_non_base64_signature_returns_verification_failed() -> TestResult {
        let (_signing_key, verifying_key) = generate_keys()?;
        let verifier = verifier_with_key(verifying_key);

        assert_verification_failed(
            verifier
                .verify(r#"{"instanceId":"i-abc"}"#, "not-base64$$$")
                .await,
        )
    }

    #[tokio::test]
    async fn verifier_with_empty_keys_rejects_signature() -> TestResult {
        let verifier = AwsInstanceVerifier {
            verifying_keys: Vec::new(),
        };
        assert_verification_failed(verifier.verify(r#"{"instanceId":"i-abc"}"#, "AAAA").await)
    }

    #[test]
    fn parses_bundled_default_certificates() {
        let verifier = AwsInstanceVerifier::with_default_certificates();
        assert_eq!(verifier.verifying_keys.len(), DEFAULT_CERTIFICATES.len());
    }

    #[test]
    fn parse_rsa_verifying_key_rejects_non_pem_input() {
        assert!(parse_rsa_verifying_key("not a cert").is_err());
    }
}
