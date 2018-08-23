// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy.modules;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/***********************************************************
 * Container class mapping a Burp Collaborator payload ID
 * to the HTTP messages that were used to generate the
 * collaborator interaction OR the HTTP service and base
 * request (for payloads used with Burp Intruder).
 *
 * @deprecated as this has been replaced by CollaboratorRecord
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
@SuppressWarnings("ALL")
@Deprecated
public class CollabRecord {
    /*******************
     * Properties
     ******************/
    private final String _payload;
    private final IHttpRequestResponse[] _messages;
    private final IHttpService _service;
    private final byte[] _request;

    /*******************
     * Construct the collaborator record.
     *
     * This constructor is used for payloads used in active scanning.
     *
     * @param payload The collaborator payload.
     * @param messages The HTTP messages used to generate the interaction.
     ******************/
    public CollabRecord(String payload, IHttpRequestResponse[] messages) {
        _payload = payload;
        _messages = messages;
        _service = null;
        _request = null;
    }

    /*******************
     * Construct the collaborator payload.
     *
     * This constructor is used for payloads used in Burp Intruder.
     *
     * @param payload The collaborator payload.
     * @param service The HTTP service targeted by Intruder.
     * @param request The HTTP request targeted by Intruder.
     ******************/
    public CollabRecord(String payload, IHttpService service, byte[] request) {
        _payload = payload;
        _messages = null;
        _service = service;
        _request = request;
    }

    /*******************
     * Get the payload.
     *
     * @return The collaborator payload.
     ******************/
    public String getPayload() {
        return _payload;
    }

    /*******************
     * Get the HTTP messages.
     *
     * @return The HTTP messages.
     ******************/
    public IHttpRequestResponse[] getMessages() {
        return _messages;
    }

    /*******************
     * Get the HTTP service.
     *
     * @return The HTTP service.
     ******************/
    public IHttpService getService() {
        return _service;
    }

    /*******************
     * Get the HTTP request.
     *
     * @return The HTTP request.
     ******************/
    public byte[] getRequest() {
        return _request;
    }
}
