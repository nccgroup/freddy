// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

/***********************************************************
 * Burp scanner issue class for issues identified by Freddy
 * scanner modules.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FreddyScanIssue implements IScanIssue {
    private final String _title;
    private final String _detail;
    private final String _remediation;
    private final String _confidence;
    private final String _severity;
    private final URL _url;
    private final IHttpService _httpService;
    private final IHttpRequestResponse[] _httpMessages;

    /*******************
     * Create a new FreddyScanIssue with all necessary details.
     *
     * @param title The issue title.
     * @param description The issue description.
     * @param remediation The remediation advice.
     * @param confidence The confidence rating.
     * @param severity The severity rating.
     * @param url The URL where the issue was identified.
     * @param service The HTTP service on which the issue was identified.
     * @param messages The HTTP message(s) affected by the issue.
     *******************/
    public FreddyScanIssue(String title, String description, String remediation, String confidence, String severity, URL url, IHttpService service, IHttpRequestResponse[] messages) {
        _title = title;
        _detail = description;
        _remediation = remediation;
        _confidence = confidence;
        _severity = severity;
        _url = url;
        _httpService = service;
        _httpMessages = messages;
    }

    /*******************
     * Property-based getters.
     ******************/
    public String getIssueName() {
        return _title;
    }

    public String getIssueDetail() {
        return _detail;
    }

    public String getRemediationDetail() {
        return _remediation;
    }

    public String getConfidence() {
        return _confidence;
    }

    public String getSeverity() {
        return _severity;
    }

    public URL getUrl() {
        return _url;
    }

    public IHttpService getHttpService() {
        return _httpService;
    }

    public IHttpRequestResponse[] getHttpMessages() {
        return _httpMessages;
    }

    /*******************
     * Constant getters.
     ******************/
    public int getIssueType() {
        return 0x08000000;
    }

    public String getIssueBackground() {
        return "The application appears to be using a potentially dangerous library or API to deserialize data. " +
                "If an attacker can supply data to be deserialized and the application fails to properly " +
                "validate the data or restrict the deserialization process then an attacker may be able to " +
                "instantiate runtime objects on the server whilst controlling the properties of those objects. " +
                "Using these object properties the attacker may be able to manipulate code in certain methods, " +
                "such as destructors or toString methods, to their advantage in order to attack the application " +
                "or server. In many cases classes or data types exist within the standard library or within " +
                "common third-party libraries which can be used to craft objects that execute arbitrary code " +
                "or OS commands if the object is deserialized.";
    }

    public String getRemediationBackground() {
        return "Proper remediation of such vulnerabilities is two-fold. Firstly, applications should properly " +
                "validate data prior to deserializing it to ensure that it only contains data of the expected " +
                "type and format. In some cases it is possible to apply an additional layer of restriction here " +
                "by supplying a whitelist of object classes or types that the application expects to receive " +
                "deserialize. Secondly, if the application must support deserialization of classes or complex " +
                "data types then those classes should be reviewed in detail to determine if there are potential " +
                "risks to deserializing objects of that type. Care should be taken to validate data and perform " +
                "appropriate checks prior to taking potentially dangerous actions. It may be necessary to avoid " +
                "properties that can be set to (or contain) arbitrary objects as these have the potential to " +
                "vastly increase an attacker's options for exploiting deserialization vulnerabilities.";
    }
}
