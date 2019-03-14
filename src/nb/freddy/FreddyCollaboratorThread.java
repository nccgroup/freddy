// Freddy the Serial(isation) Killer
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
//
// Project link: https://github.com/nccgroup/freddy/
//
// Released under agpl-3.0 see LICENSE for more information

package nb.freddy;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import nb.freddy.modules.FreddyModuleBase;

import java.util.List;

/***********************************************************
 * Background thread which polls the collaborator server
 * periodically for new interactions before reporting them
 * to the relevant Freddy module.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FreddyCollaboratorThread extends Thread {
    //Interval constants
    private static final long THREAD_SLEEP_INTERVAL = 1000;
    public static final long COLLAB_POLL_INTERVAL = 60000;

    //Collaborator context object used to poll the server
    private final IBurpExtenderCallbacks _callbacks;

    //All loaded Freddy scanner modules
    private final List<FreddyModuleBase> _modules;

    //Thread data
    private boolean _stopFlag;
    private long _lastPollTime;

    /*******************
     * Initialise the collaborator polling thread.
     *
     * @param _callbacks The Collaborator context object from Burp Suite.
     * @param modules A list of all loaded Freddy scanner modules.
     ******************/
    public FreddyCollaboratorThread(IBurpExtenderCallbacks _callbacks, List<FreddyModuleBase> modules) {
       this._callbacks = _callbacks;
        this._modules = modules;
        this._stopFlag = false;
        this._lastPollTime = 0;
    }

    /*******************
     * Set the flag indicating that the Collaborator thread should terminate.
     ******************/
    public void stopCollaborating() {
        _stopFlag = true;
    }

    /*******************
     * Periodically poll the Collaborator server for interactions and dispatch
     * them to Freddy scanner modules to handle and report issues.
     ******************/
    public void run() {
        List<IBurpCollaboratorInteraction> interactions;
        while (!_stopFlag) {
            if (System.currentTimeMillis() - _lastPollTime > COLLAB_POLL_INTERVAL) {
                IBurpCollaboratorClientContext _collabContext = _callbacks.createBurpCollaboratorClientContext();
                interactions = _collabContext.fetchAllCollaboratorInteractions();
                for (IBurpCollaboratorInteraction interaction : interactions) {
                    //Pass the interaction to loaded Freddy scanner modules until one handles it
                    for (FreddyModuleBase _module : _modules) {
                        if (_module.handleCollaboratorInteraction(interaction)) {
                            break;
                        }
                    }
                }
                // check if inactive records need to be removed
                for (FreddyModuleBase _module : _modules) {
                    _module.removeInactiveCollaboratorRecords();
                }
                _lastPollTime = System.currentTimeMillis();
            }
            try {
                Thread.sleep(THREAD_SLEEP_INTERVAL);
            } catch (InterruptedException e) {
                // Ignore sleep interruption
            }
        }
    }
}
