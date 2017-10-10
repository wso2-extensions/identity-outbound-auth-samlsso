/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.opensaml.common.xml.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.RequestData;

/**
 * Test constants.
 */
public final class TestConstants {

    private TestConstants() {

    }

    public static final String SAML2_POST_REQUEST =
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6QXV0aG5SZXF1ZXN0IHhtbG5zOnNhbWxwPSJ1cm46b2F" +
                    "zaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cDovL2xvY2" +
                    "FsaG9zdDo4MDgwL3RyYXZlbG9jaXR5LmNvbS9ob21lLmpzcCIgRGVzdGluYXRpb249Imh0dHBzOi8vbG9jYWxob3N0Ojk0N" +
                    "DMvc2FtbHNzbyIgRm9yY2VBdXRobj0iZmFsc2UiIElEPSJsaGdiaG9qYmZkb2JvcGRmamRtY2RsaXBkYmpjb21mYWVsbWhu" +
                    "Y2hqIiBJc1Bhc3NpdmU9ImZhbHNlIiBJc3N1ZUluc3RhbnQ9IjIwMTctMDktMjVUMDY6Mjc6MDMuODM3WiIgUHJvdG9jb2x" +
                    "CaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBWZXJzaW9uPSIyLjAiPj" +
                    "xzYW1scDpJc3N1ZXIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnRyYXZlb" +
                    "G9jaXR5LmNvbTwvc2FtbHA6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAv" +
                    "MDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDo" +
                    "vL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dH" +
                    "A6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjbGhnYmhvamJmZ" +
                    "G9ib3BkZmpkbWNkbGlwZGJqY29tZmFlbG1obmNoaiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09" +
                    "Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSB" +
                    "BbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZH" +
                    "M6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6R" +
                    "GlnZXN0VmFsdWU+SU55d0RvenVwcWdCYm8rZC9RVjhqRm1qUExZPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+" +
                    "PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5rTDY0WitkakJKZ2lCYjN2UHdRUmd5czMrK3dNdHpUQ3p6YVp" +
                    "odmVyV3FDa1NmSUp6bitqdFhzVExWQWxqejMxZU03dCs1bmFzb3h6WWNSb3RZQUd0M2E4SnhDdjdLUDJQSVJEY3hDZjJnZF" +
                    "R1MVF3Q2hBVWcvNHRFQnM4SU13NzVyWXFJeTduMnhWV1VvdGVLWENTelJPekNtR0FHY0IycDJkL1pHRHhVZytMcnovUHgzU" +
                    "EtMTXh1Z21XQ2JCd1hacU1GeTNzektiUU5FQ21XczdTN1VuYllUNURrbGdRdWxRY0luaVY2aFFZakdwaEU2TWFIcno5SWxt" +
                    "cHpHZXJ0R2ZPb2NLdXZ5a21KMHRESWYrb1EyanQ5RzJEMmVyb3I0V0gxOXBRemltZ1Q2YlRDRFZqMWpLVFMrL21RaE85eDZ" +
                    "MazdpWlRMVndqekcrNldVM1VYUWc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkcz" +
                    "pYNTA5Q2VydGlmaWNhdGU+TUlJRFNUQ0NBakdnQXdJQkFnSUVSVXViTXpBTkJna3Foa2lHOXcwQkFRc0ZBREJWTVFzd0NRW" +
                    "URWUVFHRXdKVlV6RUxNQWtHQTFVRUNCTUNRMEV4RmpBVUJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hEVEFMQmdOVkJB" +
                    "b1RCRmRUVHpJeEVqQVFCZ05WQkFNVENXeHZZMkZzYUc5emREQWVGdzB4TnpBek1qRXdPVEV6TURkYUZ3MHhOekEyTVRrd09" +
                    "URXpNRGRhTUZVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlFd0pEUVRFV01CUUdBMVVFQnhNTlRXOTFiblJoYVc0Z1" +
                    "ZtbGxkekVOTUFzR0ExVUVDaE1FVjFOUE1qRVNNQkFHQTFVRUF4TUpiRzlqWVd4b2IzTjBNSUlCSWpBTkJna3Foa2lHOXcwQ" +
                    "kFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXU4bGZMQ1FWMmhiaXo4T0dBOGJhS0kxRTFjZ0UvUUxLZWZhNE9kMkcyS2V4dGFB" +
                    "d1NFU3I1SUNha1ZYOHc2dFU1K0loS1lRUUt0OVUzL1UwYWU5dFhmMDRnNmlXaDBkUmxsc3I5bU9nalNaeFFLMDkveWdVc0Z" +
                    "IOHN5TDVhRDNoZVJVWXpKV1ovS09zZDU3Qlh1STJRWm51RWpOMGcwKzVqTnZuc3dmd0QvdE0wMXRvdGFKcEkzeE4rMkpac2" +
                    "FCUkNjMEc1eUEvcGRXODNBYTRJRTMwRUw1N3drSzd1OFlEbDNVVGNtaStITzc0WFFtSzFWRXFTbkErL21GbzNNMTZjUmxtM" +
                    "lBUWjJaMUU1Z2Q0ais1c1YxUDV2NjN1cXlGbmlFVTB6UFhmb3JCYjA2cGdTQm9JUlFCaW50U1NEeUVteXVWelcwcGMyZVlD" +
                    "NURoZmdrMzM3UUlEQVFBQm95RXdIekFkQmdOVkhRNEVGZ1FVNGxuZVpDdktuMDROSDVEdEpJdGRSWGRYYW5rd0RRWUpLb1p" +
                    "JaHZjTkFRRUxCUUFEZ2dFQkFFbkNOcjBKRWNBeHRGL3lwd0dnRnUxcllPdjNpMDJQQjRqRFdiRmo4czU4bDF6RjF0TXI0OD" +
                    "BraFZYNGQzQW1ManNVcHZWK0pnODNKRklrMXJKRkxFYjQ4RUZ2MG5KL0c3cFRRckN5cE5Lb3p5dXlMeng1VXZLTkZCTW1uR" +
                    "3ZrSFZxdDZqNE1TaU9qblJkbG83b2ZEbHVBL3VtU2tTZi9WbXNPSVorNTYxMHBDSnBhaG5QVWtiOEdZSzBIY3dOVjJOTFUv" +
                    "MFg0blNqS2pHd1dZdjB0WDhYVzhSd0pLYi9yMEdEZWhBOFBFU2k3NlhPVnJwWFNqUDlXUEs4WGFLLy84QjBTSDNobTB4cHp" +
                    "tU1FZZ3RrTlF3UDJNcUJlL1pFVXVLeHJuM3BQNm94bzlSeGVTSVE4ZFRMaUJBL21jc0JtQWxwUVBQaTBMcXFES3BreUh0OE" +
                    "FyMnc9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhb" +
                    "WwycDpOYW1lSURQb2xpY3kgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFs" +
                    "bG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnN" +
                    "pc3RlbnQiIFNQTmFtZVF1YWxpZmllcj0iSXNzdWVyIi8+PHNhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgeG1sbnM6c2" +
                    "FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIENvbXBhcmlzb249ImV4YWN0Ij48c2FtbDpBd" +
                    "XRobkNvbnRleHRDbGFzc1JlZiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj51" +
                    "cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDp" +
                    "BdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+PC9zYW1scDpBdXRoblJlcXVlc3Q+";

    public static final String SAML2_REDIRECT_REQUEST = "nVNhb9owEP0rkb+ThLTqwCJUDFQNqZsY0H3YN+NcwNSxPd+F0n8/Jykdmza" +
            "E9vV89+7de8+j+2OlowN4VNbkrB+nLAIjbaHMNmdP64fegN2PRygq7fikpp1Zwo8akKIwZ5C3DzmrveFWoEJuRAXISfLV5PMjz+KUO2" +
            "/JSqtZNEEET2HR1BqsK/Ar8Acl4Wn5mLMdkeNJoq0UemeR+CAdpAl5cYBQU/QaS1slO1tBvEfHolkgoYyglnczjL9ND29vb5KGHaJl0" +
            "YP1Elr6OSuFRmDRfJYzu91bo5+F2xVi/1xo48qylGa7F26v7VaDFBu3gQAwx4VAVAf4NY9Yw9wgCUM5y9L+h1467GV363TA+32e3cTD" +
            "7O47ixZv539UphP1klabrgn5p/V60VtCoTxIYtG3k0GhiZ3saBn4640QJ/nZ+A9ZR8k5YoefOf4lQMxnC6uVfD1bk11vuNb2ZepBUNC" +
            "NfA2tE5WgywBNRRW9sm3lrrkdCUzQYbVoOH2thValAp+zjjFL3jm/xROK1u0QNIIj/Rf5qa2c8Aob2eEogg3dEn6OPNVB1SWUZxuuNu" +
            "Fim+SygQ7lJngv1hdNkEIYoFh7YdBZT51tf+Uz7t7+Jcj45Pj5lx7/BA==";

    public static final String RELAY_STATE = "123456789";

    public static final String XML_STRING = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:AuthnRequest ID=\"_17c9ff9f70f06d4121b45a9b28664ebb\" IssueInstant=\"2017-09-25T04:00:41.832" +
            "Z\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer xmlns:saml2=" +
            "\"urn:oasis:names:tc:SAML:2.0:assertion\">wso2.my.dashboard</saml2:Issuer><saml2p:NameIDPolicy Allow" +
            "Create=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\"/></saml2p:AuthnRequest>";

    public static final String ENCODED_STRING =
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpBdXRoblJlcXVlc3QgSU" +
                    "Q9Il8xN2M5ZmY5ZjcwZjA2ZDQxMjFiNDVhOWIyODY2NGViYiIgSXNzdWVJbnN0YW50PSIyMDE3LTA5LTI1VDA0OjAwOjQxLjgzMl" +
                    "oiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzYW1sMj" +
                    "pJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPndzbzIubXkuZGFzaGJvYX" +
                    "JkPC9zYW1sMjpJc3N1ZXI+PHNhbWwycDpOYW1lSURQb2xpY3kgQWxsb3dDcmVhdGU9InRydWUiIEZvcm1hdD0idXJuOm9hc2lzOm" +
                    "5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5Ii8+PC9zYW1sMnA6QXV0aG5SZXF1ZXN0Pg==";

    public static final String REDIRECT_REQUEST =
            "nVNhb9owEP0rkb+TpCntqEWoGKgaUjcxoPuwb8a5EC+OnfkulP77OUnZaLUhtG/W+d275/fO4/tDpYM9OFTWpOwqjFkARtpMmV3Kn" +
                    "jYPgxG7n4xRVLrm04YKs4KfDSAFvs8g7y5S1jjDrUCF3IgKkJPk6+nnR56EMa+dJSutZsEUERz5QTNrsKnArcHtlYSn1W" +
                    "PKCqKaR5G2UujCIvFRPIojcmIPvqboJZS2igpbQfgDaxbMvQhlBHW622Z80303HF5HrTpEy4IH6yR08lOWC43AgsXcH3V" +
                    "VbksowRZSwHar8t1Ol5WCQpa5qotSiEzaovRoXApEtYc//YgNLAySMJSyJL76MIjvBsnNJr7lyS2/jsPR8OY7C5avz/+o" +
                    "TG/qOa+2PQj5p81mOVhBphxIYsG3Y0AexI5xdArc5UGIo/1s8s7WcXTK2PMnNf/iKRbzpdVKvpyMSS4PXGv7PHMgyPtGr" +
                    "oEuiUrQeYK2orJB3kF53b4dCYz3Yb1sNX1thFa5ApeyXjGLfmt+XU/IurT9ohEc6L/Ez2xVC6ewtR0OwsfQD+GnzDPtXV" +
                    "1BfjLh4hDOwiSXLbUvt4v3bF3WLpJfBsg2ThisraM+tr/qmfR3/zJkckz89EtPfgE=";

    public static final String REDIRECT_DECODED_STRING = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnRequest " +
            "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://localhost:" +
            "8080/travelocity.com/home.jsp\" Destination=\"https://localhost:9443/samlsso\" ForceAuthn=\"false\" " +
            "ID=\"flmkbkekeohcaebbifgglkmiehckfiphkaadcohk\" IsPassive=\"false\" IssueInstant=\"2017-09-25T06:26:" +
            "30.845Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Version=\"2.0\"><sa" +
            "mlp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\">travelocity.com</samlp:Issuer><saml" +
            "2p:NameIDPolicy xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" AllowCreate=\"true\" Format=\"" +
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" SPNameQualifier=\"Issuer\"/><saml2p:Requested" +
            "AuthnContext xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\"><saml:AuthnC" +
            "ontextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:c" +
            "lasses:PasswordProtectedTransport</saml:AuthnContextClassRef></saml2p:RequestedAuthnContext></samlp:" +
            "AuthnRequest>";

    public static final String INVALID_REDIRECT_REQUEST = "ErrornVNhb9owEP0rkb+TpCntqEWoGKgaUjcxoPuwb8a5EC+Onfkul" +
            "P77OUnZaLUhtG/W+d275/fO4" +
            "/tDpYM9OFTWpOwqjFkARtpMmV3KnjYPgxG7n4xRVLrm04YKs4KfDSAFvs8g7y5S1jjDrUCF3IgKkJPk6+nnR56EMa+dJSutZsEUE" +
            "Rz5QTNrsKnArcHtlYSn1WPKCqKaR5G2UujCIvFRPIojcmIPvqboJZS2igpbQfgDaxbMvQhlBHW622Z80303HF5HrTpEy4IH6yR08" +
            "lOWC43AgsXcH3VVbksowRZSwHar8t1Ol5WCQpa5qotSiEzaovRoXApEtYc//YgNLAySMJSyJL76MIjvBsnNJr7lyS2/jsPR8OY7C" +
            "5avz/+oTG/qOa+2PQj5p81mOVhBphxIYsG3Y0AexI5xdArc5UGIo/1s8s7WcXTK2PMnNf/iKRbzpdVKvpyMSS4PXGv7PHMgyPtGr" +
            "oEuiUrQeYK2orJB3kF53b4dCYz3Yb1sNX1thFa5ApeyXjGLfmt+XU/IurT9ohEc6L/Ez2xVC6ewtR0OwsfQD+GnzDPtXV1BfjLh4" +
            "hDOwiSXLbUvt4v3bF3WLpJfBsg2ThisraM+tr/qmfR3/zJkckz89EtPfgE=";

    public static final String POST_REQUEST = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6QXV0aG" +
            "5SZXF1ZXN0IHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFzc2VydGlvbkNvbnN1bW" +
            "VyU2VydmljZVVSTD0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL3RyYXZlbG9jaXR5LmNvbS9ob21lLmpzcCIgRGVzdGluYXRpb249Im" +
            "h0dHBzOi8vbG9jYWxob3N0Ojk0NDMvc2FtbHNzbyIgRm9yY2VBdXRobj0iZmFsc2UiIElEPSJsaGdiaG9qYmZkb2JvcGRmamRtY2" +
            "RsaXBkYmpjb21mYWVsbWhuY2hqIiBJc1Bhc3NpdmU9ImZhbHNlIiBJc3N1ZUluc3RhbnQ9IjIwMTctMDktMjVUMDY6Mjc6MDMuOD" +
            "M3WiIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBWZXJzaW" +
            "9uPSIyLjAiPjxzYW1scDpJc3N1ZXIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPn" +
            "RyYXZlbG9jaXR5LmNvbTwvc2FtbHA6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMD" +
            "AvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3" +
            "d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3" +
            "cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIjbGhnYmhvamJmZG9ib3BkZmpkbW" +
            "NkbGlwZGJqY29tZmFlbG1obmNoaiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudz" +
            "Mub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly" +
            "93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaX" +
            "RobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+SU55d0RvenVwcWdCYm" +
            "8rZC9RVjhqRm1qUExZPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cm" +
            "VWYWx1ZT5rTDY0WitkakJKZ2lCYjN2UHdRUmd5czMrK3dNdHpUQ3p6YVpodmVyV3FDa1NmSUp6bitqdFhzVExWQWxqejMxZU03dC" +
            "s1bmFzb3h6WWNSb3RZQUd0M2E4SnhDdjdLUDJQSVJEY3hDZjJnZFR1MVF3Q2hBVWcvNHRFQnM4SU13NzVyWXFJeTduMnhWV1VvdG" +
            "VLWENTelJPekNtR0FHY0IycDJkL1pHRHhVZytMcnovUHgzUEtMTXh1Z21XQ2JCd1hacU1GeTNzektiUU5FQ21XczdTN1VuYllUNU" +
            "RrbGdRdWxRY0luaVY2aFFZakdwaEU2TWFIcno5SWxtcHpHZXJ0R2ZPb2NLdXZ5a21KMHRESWYrb1EyanQ5RzJEMmVyb3I0V0gxOX" +
            "BRemltZ1Q2YlRDRFZqMWpLVFMrL21RaE85eDZMazdpWlRMVndqekcrNldVM1VYUWc9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOk" +
            "tleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRFNUQ0NBakdnQXdJQkFnSUVSVXViTXpBTkJna3Foa2" +
            "lHOXcwQkFRc0ZBREJWTVFzd0NRWURWUVFHRXdKVlV6RUxNQWtHQTFVRUNCTUNRMEV4RmpBVUJnTlZCQWNURFUxdmRXNTBZV2x1SU" +
            "ZacFpYY3hEVEFMQmdOVkJBb1RCRmRUVHpJeEVqQVFCZ05WQkFNVENXeHZZMkZzYUc5emREQWVGdzB4TnpBek1qRXdPVEV6TURkYU" +
            "Z3MHhOekEyTVRrd09URXpNRGRhTUZVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlFd0pEUVRFV01CUUdBMVVFQnhNTlRXOT" +
            "FiblJoYVc0Z1ZtbGxkekVOTUFzR0ExVUVDaE1FVjFOUE1qRVNNQkFHQTFVRUF4TUpiRzlqWVd4b2IzTjBNSUlCSWpBTkJna3Foa2" +
            "lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXU4bGZMQ1FWMmhiaXo4T0dBOGJhS0kxRTFjZ0UvUUxLZWZhNE9kMkcyS2V4dG" +
            "FBd1NFU3I1SUNha1ZYOHc2dFU1K0loS1lRUUt0OVUzL1UwYWU5dFhmMDRnNmlXaDBkUmxsc3I5bU9nalNaeFFLMDkveWdVc0ZIOH" +
            "N5TDVhRDNoZVJVWXpKV1ovS09zZDU3Qlh1STJRWm51RWpOMGcwKzVqTnZuc3dmd0QvdE0wMXRvdGFKcEkzeE4rMkpac2FCUkNjME" +
            "c1eUEvcGRXODNBYTRJRTMwRUw1N3drSzd1OFlEbDNVVGNtaStITzc0WFFtSzFWRXFTbkErL21GbzNNMTZjUmxtMlBUWjJaMUU1Z2" +
            "Q0ais1c1YxUDV2NjN1cXlGbmlFVTB6UFhmb3JCYjA2cGdTQm9JUlFCaW50U1NEeUVteXVWelcwcGMyZVlDNURoZmdrMzM3UUlEQV" +
            "FBQm95RXdIekFkQmdOVkhRNEVGZ1FVNGxuZVpDdktuMDROSDVEdEpJdGRSWGRYYW5rd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQk" +
            "FFbkNOcjBKRWNBeHRGL3lwd0dnRnUxcllPdjNpMDJQQjRqRFdiRmo4czU4bDF6RjF0TXI0ODBraFZYNGQzQW1ManNVcHZWK0pnOD" +
            "NKRklrMXJKRkxFYjQ4RUZ2MG5KL0c3cFRRckN5cE5Lb3p5dXlMeng1VXZLTkZCTW1uR3ZrSFZxdDZqNE1TaU9qblJkbG83b2ZEbH" +
            "VBL3VtU2tTZi9WbXNPSVorNTYxMHBDSnBhaG5QVWtiOEdZSzBIY3dOVjJOTFUvMFg0blNqS2pHd1dZdjB0WDhYVzhSd0pLYi9yME" +
            "dEZWhBOFBFU2k3NlhPVnJwWFNqUDlXUEs4WGFLLy84QjBTSDNobTB4cHptU1FZZ3RrTlF3UDJNcUJlL1pFVXVLeHJuM3BQNm94bz" +
            "lSeGVTSVE4ZFRMaUJBL21jc0JtQWxwUVBQaTBMcXFES3BreUh0OEFyMnc9PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RG" +
            "F0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpOYW1lSURQb2xpY3kgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaX" +
            "M6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFsbG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0Yz" +
            "pTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiIFNQTmFtZVF1YWxpZmllcj0iSXNzdWVyIi8+PHNhbWwycDpSZXF1ZX" +
            "N0ZWRBdXRobkNvbnRleHQgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIENvbXBhcm" +
            "lzb249ImV4YWN0Ij48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTD" +
            "oyLjA6YXNzZXJ0aW9uIj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW" +
            "5zcG9ydDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+PC9zYW1scDpBdX" +
            "RoblJlcXVlc3Q+";

    public static final String POST_DECODED_STRING = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:AuthnReque" +
            "st xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" AssertionConsumerServiceURL=\"http://localho" +
            "st:8080/travelocity.com/home.jsp\" Destination=\"https://localhost:9443/samlsso\" ForceAuthn=\"false" +
            "\" ID=\"lhgbhojbfdobopdfjdmcdlipdbjcomfaelmhnchj\" IsPassive=\"false\" IssueInstant=\"2017-09-25T06:" +
            "27:03.837Z\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\"><sam" +
            "lp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\">travelocity.com</samlp:Issuer><ds:Si" +
            "gnature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Al" +
            "gorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.o" +
            "rg/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#lhgbhojbfdobopdfjdmcdlipdbjcomfaelmhnchj\"><ds:T" +
            "ransforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Tra" +
            "nsform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algor" +
            "ithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>INywDozupqgBbo+d/QV8jFmjPLY=</ds:Di" +
            "gestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>kL64Z+djBJgiBb3vPwQRgys3++wMtzTCzzaZhver" +
            "WqCkSfIJzn+jtXsTLVAljz31eM7t+5nasoxzYcRotYAGt3a8JxCv7KP2PIRDcxCf2gdTu1QwChAUg/4tEBs8IMw75rYqIy7n2xVW" +
            "UoteKXCSzROzCmGAGcB2p2d/ZGDxUg+Lrz/Px3PKLMxugmWCbBwXZqMFy3szKbQNECmWs7S7UnbYT5DklgQulQcIniV6hQYjGphE" +
            "6MaHrz9IlmpzGertGfOocKuvykmJ0tDIf+oQ2jt9G2D2eror4WH19pQzimgT6bTCDVj1jKTS+/mQhO9x6Lk7iZTLVwjzG+6WU3UX" +
            "Qg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCAjGgAwIBAgIERUubMzANBgk" +
            "qhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFd" +
            "TTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzAzMjEwOTEzMDdaFw0xNzA2MTkwOTEzMDdaMFUxCzAJBgNVBAYTAlVTMQswCQY" +
            "DVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgk" +
            "qhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu8lfLCQV2hbiz8OGA8baKI1E1cgE/QLKefa4Od2G2KextaAwSESr5ICakVX8w6tU5+I" +
            "hKYQQKt9U3/U0ae9tXf04g6iWh0dRllsr9mOgjSZxQK09/ygUsFH8syL5aD3heRUYzJWZ/KOsd57BXuI2QZnuEjN0g0+5jNvnswf" +
            "wD/tM01totaJpI3xN+2JZsaBRCc0G5yA/pdW83Aa4IE30EL57wkK7u8YDl3UTcmi+HO74XQmK1VEqSnA+/mFo3M16cRlm2PTZ2Z1" +
            "E5gd4j+5sV1P5v63uqyFniEU0zPXforBb06pgSBoIRQBintSSDyEmyuVzW0pc2eYC5Dhfgk337QIDAQABoyEwHzAdBgNVHQ4EFgQ" +
            "U4lneZCvKn04NH5DtJItdRXdXankwDQYJKoZIhvcNAQELBQADggEBAEnCNr0JEcAxtF/ypwGgFu1rYOv3i02PB4jDWbFj8s58l1z" +
            "F1tMr480khVX4d3AmLjsUpvV+Jg83JFIk1rJFLEb48EFv0nJ/G7pTQrCypNKozyuyLzx5UvKNFBMmnGvkHVqt6j4MSiOjnRdlo7o" +
            "fDluA/umSkSf/VmsOIZ+5610pCJpahnPUkb8GYK0HcwNV2NLU/0X4nSjKjGwWYv0tX8XW8RwJKb/r0GDehA8PESi76XOVrpXSjP9" +
            "WPK8XaK//8B0SH3hm0xpzmSQYgtkNQwP2MqBe/ZEUuKxrn3pP6oxo9RxeSIQ8dTLiBA/mcsBmAlpQPPi0LqqDKpkyHt8Ar2w=</d" +
            "s:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:NameIDPolicy xmlns:saml2p=\"urn:" +
            "oasis:names:tc:SAML:2.0:protocol\" AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-" +
            "format:persistent\" SPNameQualifier=\"Issuer\"/><saml2p:RequestedAuthnContext xmlns:saml2p=\"urn:oas" +
            "is:names:tc:SAML:2.0:protocol\" Comparison=\"exact\"><saml:AuthnContextClassRef xmlns:saml=\"urn:oas" +
            "is:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</" +
            "saml:AuthnContextClassRef></saml2p:RequestedAuthnContext></samlp:AuthnRequest>";

    public static final String QUERY_STRING =
            "SAMLRequest=nVPRctowEPwVj97BDtCWaDAZCpMpM2mHAslD32T5jGVknauTCfn7yHZoaaZlmL6e9vb2dk" +
                    "%2BTu2OpgwNYUmhidtOPWABGYqrMLmaP2" +
                    "%2FvemN1NJyRKXfFZ7XKzhp81kAt8nyHePsSstoajIEXciBKIO8k3s68PfNCPeGXRoUTNghkRWOcHzdFQXYLdgD0oCY" +
                    "%2Frh5jlzlU8DDVKoXMkx8fROAqdFQfwNeVe%2BhLLMMcS%2BgVVLFh4EcoI1" +
                    "%2BpumumP7tvRaBg26oiQBfdoJbTyY5YJTcCC5SJmSaEw2xfJThVlleTFPldpkqDa5zsosMh2eSr3Sao8mlaCSB3gdz9RDUtDThg" +
                    "Xs0F086kX3fYGH7bRiI9GfBj1Pw7HP1iwelv%2FszKdqZe8SjoQ8S%2Fb7aq3hlRZkI4FT6eAPIid4mgV2OuDECf72fSdrZPwnLH" +
                    "jH1T8m6dYLlaolXw5GzO4PnCt8XluQTjvm7M1tEmUwl0maCoq7WUtlFfN7uTAeB82q0bT91polSmwMesUs%2FCX5rfzhLRN2x%2B" +
                    "ag6P7L%2FFzLCthFTW2w1H4GLoh%2FJx5rr2ra8jOJlwdwkWY5LKh9uXm8J7Rps0h%2BWOAdGuFoQqt62L7q55p9%2FYvQ6anxM%" +
                    "2B%2F9PQV&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=S7Mjer2jAF1nFnGg" +
                    "vjdwNwD4Gyqf4RTGnA9vS5Gc%2BR4ZZJv4FuOoFcMQpJVLj5LfBU95P1fvVutoIY%2Bg79osPEL8K5fKS%2F%2B7Ai7HGEGik7OF" +
                    "8B5b7Teo3qLDDjraokf5%2BAkpTqsk8oVJF7wPlP0tl%2Frse9AjNBi2BKr12on3wpKw6KfCOqBFT9UVjtneTnusuziMN62E0QcL" +
                    "t0ikzUL1XXzPU6F9iKoCOHJnnjwTH7cBl0Vsy21tgUb0TziV3x9eOgOH2A7r%2FCT%2Feg9puWTc9cEwgvMv9CTKTxp7xxD1pcUb" +
                    "YUPTcC2ih%2BIfHM1yfWkLFjKrdqgV0%2BSRi3835OUXlQ%3D%3D&empty=";

    public static final String SAML_REQUEST_PARAMETER = "nVPRctowEPwVj97BDtCWaDAZCpMpM2mHAslD32T5jGVknauTCfn7yHZo" +
            "aaZlmL6e9vb2dk%2BTu2OpgwNYUmhidtOPWABGYqrMLmaP2%2FvemN1NJyRKXfFZ7XKzhp81kAt8nyHePsSstoajIEXciBKIO8k3" +
            "s68PfNCPeGXRoUTNghkRWOcHzdFQXYLdgD0oCY%2Frh5jlzlU8DDVKoXMkx8fROAqdFQfwNeVe%2BhLLMMcS%2BgVVLFh4EcoI1%" +
            "2BpumumP7tvRaBg26oiQBfdoJbTyY5YJTcCC5SJmSaEw2xfJThVlleTFPldpkqDa5zsosMh2eSr3Sao8mlaCSB3gdz9RDUtDThgX" +
            "s0F086kX3fYGH7bRiI9GfBj1Pw7HP1iwelv%2FszKdqZe8SjoQ8S%2Fb7aq3hlRZkI4FT6eAPIid4mgV2OuDECf72fSdrZPwnLHj" +
            "H1T8m6dYLlaolXw5GzO4PnCt8XluQTjvm7M1tEmUwl0maCoq7WUtlFfN7uTAeB82q0bT91polSmwMesUs%2FCX5rfzhLRN2x%2Ba" +
            "g6P7L%2FFzLCthFTW2w1H4GLoh%2FJx5rr2ra8jOJlwdwkWY5LKh9uXm8J7Rps0h%2BWOAdGuFoQqt62L7q55p9%2FYvQ6anxM%2" +
            "B%2F9PQV";

    public static final String SIG_ALG_PARAMETER = "http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1";

    public static final String SIGNATURE_PARAMETER = "S7Mjer2jAF1nFnGgvjdwNwD4Gyqf4RTGnA9vS5Gc%2BR4ZZJv4FuOoFcMQ" +
            "pJVLj5LfBU95P1fvVutoIY%2Bg79osPEL8K5fKS%2F%2B7Ai7HGEGik7OF8B5b7Teo3qLDDjraokf5%2BAkpTqsk8oVJF7wPlP0t" +
            "l%2Frse9AjNBi2BKr12on3wpKw6KfCOqBFT9UVjtneTnusuziMN62E0QcLt0ikzUL1XXzPU6F9iKoCOHJnnjwTH7cBl0Vsy21tgU" +
            "b0TziV3x9eOgOH2A7r%2FCT%2Feg9puWTc9cEwgvMv9CTKTxp7xxD1pcUbYUPTcC2ih%2BIfHM1yfWkLFjKrdqgV0%2BSRi3835O" +
            "UXlQ%3D%3D";

    public static final String KEY_ALIAS = "wso2carbon";

    public static final String KEY_PASSWORD = "wso2carbon";

    public static final String KEY_STORE_PASSWORD = "wso2carbon";

    public static final String SAMPLE_TENANT_DOMAIN_NAME = "wso2";

    public static final String INVALID_TENANT_DOMAIN = "invalid_tenant_domain";

    public static final int SAMPLE_TENANT_ID = 1;

    public static final String IDP_CERTIFICATE = "MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJV\n" +
            "UzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoT\n" +
            "BFdTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3\n" +
            "MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN\n" +
            "TW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWLC6xK\n" +
            "egbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V\n" +
            "9+PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluE\n" +
            "ep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyq\n" +
            "K9neolXI9fYyHOYILVNZ69z/73OOVhkh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+\n" +
            "vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYmlFN+M3tZX6nEcA6g94Iav\n" +
            "yQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUwDQYJKoZI\n" +
            "hvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8r\n" +
            "AJ06Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJ\n" +
            "CSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdoz\n" +
            "qyOniVZd0QOxLAbcdt946chNdQvCm6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU\n" +
            "8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8oWQ8\n" +
            "U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=";

    public static String SAML_RESPONSE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:Response Destination=\"https://localhost:9443/commonauth\" ID=\"_81cb9b7f29a53cd851ebb9c60bbb3" +
            "11b\" InResponseTo=\"_91be4de3aad1f66d8c01f085c299ad86\" IssueInstant=\"2017-10-06T14:13:59.302Z\" Ver" +
            "sion=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer Format=\"urn:oasis:na" +
            "mes:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">idp1</sam" +
            "l2:Issuer><saml2p:Status><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></sa" +
            "ml2p:Status><saml2:Assertion ID=\"_0858c812a810036a3205cbab7bc4c416\" IssueInstant=\"2017-10-06T14:13:" +
            "59.311Z\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Issuer Format=\"" +
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">idp1</saml2:Issuer><ds:Signature xmlns:ds=\"http://" +
            "www.w3.org/2000/09/xmldsig#\">\n" +
            "<ds:SignedInfo>\n" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "<ds:Reference URI=\"#_0858c812a810036a3205cbab7bc4c416\">\n" +
            "<ds:Transforms>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "</ds:Transforms>\n" +
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
            "<ds:DigestValue>ZGeH+OVicgNf8ink+aeV9nMwVM4=</ds:DigestValue>\n" +
            "</ds:Reference>\n" +
            "</ds:SignedInfo>\n" +
            "<ds:SignatureValue>\n" +
            "Z9t7Do+AKoKzARjqxv1xiiQO67ylTnJPlrlxGLIwQS33mPJnAcDc2OVUPC4EQQQLo48XyT81hcyj\n" +
            "t03nVak6eoQHXqC//+ZPqc0t7H657C1AGMb5LC1OdF6bTzjcmXqaeSUJ1qEnm0It5R6NzQ35yn8m\n" +
            "U1w/7vpBGlF1Uc9SktU=\n" +
            "</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICNTCCAZ6gAwIBAgIES343gjANBgkqhkiG9w0BAQUFADBVMQswCQYDVQ" +
            "QGEwJVUzELMAkGA1UE\n" +
            "CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoMBFdTTzIxEjAQBgNVBAMMCWxv\n" +
            "Y2FsaG9zdDAeFw0xMDAyMTkwNzAyMjZaFw0zNTAyMTMwNzAyMjZaMFUxCzAJBgNVBAYTAlVTMQsw\n" +
            "CQYDVQQIDAJDQTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzENMAsGA1UECgwEV1NPMjESMBAGA1UE\n" +
            "AwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUp/oV1vWc8/TkQSiAvTou\n" +
            "sMzOM4asB2iltr2QKozni5aVFu818MpOLZIr8LMnTzWllJvvaA5RAAdpbECb+48FjbBe0hseUdN5\n" +
            "HpwvnH/DW8ZccGvk53I6Orq7hLCv1ZHtuOCokghz/ATrhyPq+QktMfXnRS4HrKGJTzxaCcU7OQID\n" +
            "AQABoxIwEDAOBgNVHQ8BAf8EBAMCBPAwDQYJKoZIhvcNAQEFBQADgYEAW5wPR7cr1LAdq+IrR44i\n" +
            "QlRG5ITCZXY9hI0PygLP2rHANh+PYfTmxbuOnykNGyhM6FjFLbW2uZHQTY1jMrPprjOrmyK5sjJR\n" +
            "O4d1DeGHT/YnIjs9JogRKv4XHECwLtIVdAbIdWHEtVZJyMSktcyysFcvuhPQK8Qc/E/Wq8uHSCo=</ds:X509Certificate></ds:X" +
            "509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:n" +
            "ameid-format:emailAddress\">admin</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:" +
            "SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData InResponseTo=\"_91be4de3aad1f66d8c01f085c299ad86\" " +
            "NotOnOrAfter=\"2017-10-06T14:18:59.302Z\" Recipient=\"https://localhost:9443/commonauth\"/></saml2:Subj" +
            "ectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2017-10-06T14:13:59.311Z\" NotOnOrAfter=\"" +
            "2017-10-06T14:18:59.302Z\"><saml2:AudienceRestriction><saml2:Audience>SAMLSSOIdentity</saml2:Audience><" +
            "/saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant=\"2017-10-06T14:13:59." +
            "315Z\" SessionIndex=\"21720bc3-cdfe-4168-b1ff-e66062df0eaf\"><saml2:AuthnContext><saml2:AuthnContextCla" +
            "ssRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext>" +
            "</saml2:AuthnStatement></saml2:Assertion></saml2p:Response>";

    public static final String HTTP_POST_PARAM_SAML2_AUTH_REQ = "SAMLRequest";

    public static final String HTTP_POST_PARAM_SAML2_RESP = "SAMLResponse";

    public static final String INBOUND_SP_ENTITY_ID = "sample.com";

    public static final String INBOUND_SESSION_INDEX = "123456789";

    public static final String INBOUND_ACS_URL = "http://sample.com/sso";

    public static final String INBOUND_IDP_URL = "https://localhost:9443/samlsso";

    public static final String AUTHENTICATED_USER = "admin";

    public static final String SP_ENTITY_ID = "wso2is";

    public static final String ACS_URL = "http://localhost:9443/commonauth";

    public static final String ACS_INDEX = "123456789";

    public static final String IDP_URL = "https://localhost:9444/samlsso";

    public enum InboundRequestData {

        /**
         * String spEntityId
         * boolean isForce
         * boolean isPassive
         * String httpBinding
         * String acsUrl
         * String idPUrl
         * boolean enableExtensions
         * String acsIndex
         */
        INBOUND_POST_REQUEST(new RequestData(INBOUND_SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, INBOUND_ACS_URL, INBOUND_IDP_URL, false, null)),
        INBOUND_REDIRECT_REQUEST(new RequestData(INBOUND_SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_REDIRECT_BINDING_URI, INBOUND_ACS_URL, INBOUND_IDP_URL, false, null)),
        /**
         * String spEntityId
         * boolean isForce
         * boolean isPassive
         * String httpBinding
         * String acsUrl
         * String idPUrl
         * boolean enableExtensions
         * String acsIndex
         * signRequest
         * protocolBinding
         * includeCertProperty
         * forceAuthenticateProp
         * authenticatorConfigAvailable
         * includeNameIDPolicyProp
         */
        OUTBOUND_POST_REQUEST_SIGNED(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, true, null, false, null)),
        OUTBOUND_POST_REQUEST_SIGNED_CERT_NOT_INCLUDED(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, false, null, false,
                null)),
        OUTBOUND_POST_REQUEST_UNSIGNED(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, false, null)),
        OUTBOUND_POST_REQUEST_NULL_SP(new RequestData(null, false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, null, false, null)),
        OUTBOUND_POST_REQUEST_EMPTRY_SP(new RequestData("", false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, null, false, null)),
        OUTBOUND_POST_REQUEST_FORCE_AUTH_YES(new RequestData("", false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, "yes", false, null)),
        OUTBOUND_POST_REQUEST_FORCE_AUTH_AS_REQUEST(new RequestData("", false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, true, "as_request", false, null)),
        OUTBOUND_POST_REQUEST_EMPTY_PROTOCOL_BINDING(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "", true, null, false,
                null)),
        OUTBOUND_POST_REQUEST_PROTOCOL_BINDING_TRUE(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "true", true, null, false,
                null)),
        OUTBOUND_POST_REQUEST_PROTOCOL_BINDING_FALSE(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "false", true, null,
                false, null)),
        OUTBOUND_POST_REQUEST_AUTH_CONFIG_AVAILABLE(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, true,
                null)),
        OUTBOUND_POST_REQUEST_AUTH_CONFIG_ACS_EMPTY(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, null, IDP_URL, false, null, false, null, false, null, true,
                null)),
        OUTBOUND_POST_REQUEST_WITH_ACS_INDEX(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, ACS_INDEX, false, null, false, null, false, null)),
        OUTBOUND_POST_REQUEST_INCLUDE_NAME_ID_POLICY(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, false, "true")),
        OUTBOUND_POST_REQUEST_NOT_INCLUDE_NAME_ID_POLICY(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, false, "false")),


        OUTBOUND_REDIRECT_REQUEST_SIGNED(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, true, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_SIGNED_CERT_NOT_INCLUDED(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, false, null, true,
                null)),
        OUTBOUND_REDIRECT_REQUEST_UNSIGNED(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_NULL_SP(new RequestData(null, false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_EMPTRY_SP(new RequestData("", false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_FORCE_AUTH_YES(new RequestData("", false, false, SAMLConstants.SAML2_POST_BINDING_URI,
                ACS_URL, IDP_URL, false, null, true, null, true, "yes", true, null)),
        OUTBOUND_REDIRECT_REQUEST_FORCE_AUTH_AS_REQUEST(new RequestData("", false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, null, true, "as_request", true, null)),
        OUTBOUND_REDIRECT_REQUEST_EMPTY_PROTOCOL_BINDING(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "", true, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_PROTOCOL_BINDING_TRUE(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "true", true, null, true,
                null)),
        OUTBOUND_REDIRECT_REQUEST_PROTOCOL_BINDING_FALSE(new RequestData(SP_ENTITY_ID, false, false,
                SAMLConstants.SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, true, "false", true, null,
                true, null)),
        OUTBOUND_REDIRECT_REQUEST_WITH_ACS_INDEX(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, ACS_INDEX, false, null, false, null, true, null)),
        OUTBOUND_REDIRECT_REQUEST_INCLUDE_NAME_ID_POLICY(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, true, "true")),
        OUTBOUND_REDIRECT_REQUEST_NOT_INCLUDE_NAME_ID_POLICY(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, true, "false")),

        /**
         * String spEntityId
         * boolean isForce
         * boolean isPassive
         * String httpBinding
         * String acsUrl
         * String idPUrl
         * boolean enableExtensions
         * String acsIndex
         * signRequest
         * protocolBinding
         * includeCertProperty
         * forceAuthenticateProp
         * authenticatorConfigAvailable
         * includeNameIDPolicyProp
         * includePostParam
         */
        OUTBOUND_REDIRECT_REQUEST_INCLUDE_POST_PARAM(new RequestData(SP_ENTITY_ID, false, false, SAMLConstants
                .SAML2_POST_BINDING_URI, ACS_URL, IDP_URL, false, null, false, null, false, null, true, null, true)),

        /**
         * spEntityId
         * idPUrl
         * sessionIndex
         * user
         */
        INBOUND_LOGOUT_REQUEST(new RequestData(INBOUND_SP_ENTITY_ID, INBOUND_IDP_URL, INBOUND_SESSION_INDEX,
                AUTHENTICATED_USER));

        private final RequestData requestData;

        InboundRequestData(RequestData requestData) {
            this.requestData = requestData;
        }

        public RequestData getRequestData() {
            return requestData;
        }
    }
}
