import burp.*;
import nb.freddy.Freddy;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({ "javax.crypto.*"}) //"jdk.internal.reflect.*",
public class FreddyTest {
    private Freddy freddy;

    @Before
    public void createFreddy() {
        this.freddy = new Freddy();
    }

    @Test
    public void testPassiveScan() throws MalformedURLException {
        IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class);
        IExtensionHelpers helpers = mock(IExtensionHelpersBase.class);
        IRequestInfo requestInfo = mock(IRequestInfo.class);
        IHttpRequestResponse baseRequestResponse = mock(IHttpRequestResponse.class);

        when(helpers.base64Encode(any(String.class))).thenCallRealMethod();
        when(helpers.base64Encode(any(byte[].class))).thenCallRealMethod();
        when(helpers.base64Decode(any(byte[].class))).thenCallRealMethod();
        when(helpers.base64Decode(any(String.class))).thenCallRealMethod();
        when(helpers.bytesToString(any(byte[].class))).thenCallRealMethod();

        URL url = new URL("http://www.example.com/index.jsp");

        when(callbacks.getHelpers()).thenReturn(helpers);
        when(helpers.analyzeRequest(baseRequestResponse)).thenReturn(requestInfo);
        when(requestInfo.getUrl()).thenReturn(url);
//        when(callbacks.loadExtensionSetting(any(String.class))).thenReturn("FREDDY");
        when(callbacks.loadExtensionSetting(endsWith("DECRYPTION_KEY"))).thenReturn("FREDDY");
        when(callbacks.loadExtensionSetting(endsWith("TESTING"))).thenReturn("FREDDY");

        String baseRequest = "GET / HTTP/1.0";
        String baseResponse = "200 OK";
        when(baseRequestResponse.getRequest()).thenReturn(baseRequest.getBytes());
        when(baseRequestResponse.getResponse()).thenReturn(baseResponse.getBytes());

        freddy.initialise(callbacks);
        freddy.doPassiveScan(baseRequestResponse);
    }
}

class IExtensionHelpersBase implements IExtensionHelpers {

    @Override
    public IRequestInfo analyzeRequest(IHttpRequestResponse request) {
        return null;
    }

    @Override
    public IRequestInfo analyzeRequest(IHttpService httpService, byte[] request) {
        return null;
    }

    @Override
    public IRequestInfo analyzeRequest(byte[] request) {
        return null;
    }

    @Override
    public IResponseInfo analyzeResponse(byte[] response) {
        return null;
    }

    @Override
    public IParameter getRequestParameter(byte[] request, String parameterName) {
        return null;
    }

    @Override
    public String urlDecode(String data) {
        return null;
    }

    @Override
    public String urlEncode(String data) {
        return null;
    }

    @Override
    public byte[] urlDecode(byte[] data) {
        return new byte[0];
    }

    @Override
    public byte[] urlEncode(byte[] data) {
        return new byte[0];
    }

    @Override
    public byte[] base64Decode(String data) {
        return base64Decode(data.getBytes());
    }

    @Override
    public byte[] base64Decode(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    @Override
    public String base64Encode(String data) {
        return base64Encode(data.getBytes());
    }

    @Override
    public String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    @Override
    public byte[] stringToBytes(String data) {
        return new byte[0];
    }

    @Override
    public String bytesToString(byte[] data) {
        return new String(data);
    }

    @Override
    public int indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to) {
        return 0;
    }

    @Override
    public byte[] buildHttpMessage(List<String> headers, byte[] body) {
        return new byte[0];
    }

    @Override
    public byte[] buildHttpRequest(URL url) {
        return new byte[0];
    }

    @Override
    public byte[] addParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] removeParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] updateParameter(byte[] request, IParameter parameter) {
        return new byte[0];
    }

    @Override
    public byte[] toggleRequestMethod(byte[] request) {
        return new byte[0];
    }

    @Override
    public IHttpService buildHttpService(String host, int port, String protocol) {
        return null;
    }

    @Override
    public IHttpService buildHttpService(String host, int port, boolean useHttps) {
        return null;
    }

    @Override
    public IParameter buildParameter(String name, String value, byte type) {
        return null;
    }

    @Override
    public IScannerInsertionPoint makeScannerInsertionPoint(String insertionPointName, byte[] baseRequest, int from, int to) {
        return null;
    }

    @Override
    public IResponseVariations analyzeResponseVariations(byte[]... responses) {
        return null;
    }

    @Override
    public IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses) {
        return null;
    }
}