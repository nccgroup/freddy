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
import nb.freddy.modules.FreddyModule;

import java.util.List;

/***********************************************************
 * Background thread which polls the collaborator server
 * periodically to check for interactions.
 *
 * @deprecated  as this has been replaced by FreddyCollaboratorThread
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
@SuppressWarnings("ALL")
@Deprecated
public class FreddyCollaborator extends Thread {
    /*******************
     * Constants
     ******************/
    private static final long THREAD_SLEEP_INTERVAL = 1000;
    private static final long COLLAB_POLL_INTERVAL = 60000;

    /*******************
     * Properties
     ******************/
    private final IBurpCollaboratorClientContext _collabContext;
    private final List<FreddyModule> _modules;
    private boolean _stopped;
    private long _lastPollTime;

    /*******************
     * Initialise the collaborator polling thread with required objects.
     *
     * @param collabContext The Collaborator client context.
     * @param modules A list of Freddy modules to notify of interactions.
     ******************/
    public FreddyCollaborator(IBurpCollaboratorClientContext collabContext, List<FreddyModule> modules) {
        _collabContext = collabContext;
        _modules = modules;
        _stopped = false;
        _lastPollTime = 0;
    }

    /*******************
     * Set the flag to stop the collaborator polling thread.
     ******************/
    public void stopCollaborating() {
        _stopped = true;
    }

    /*******************
     * Main loop for the collaborator polling thread.
     ******************/
    public void run() {
        List<IBurpCollaboratorInteraction> interactions;
        int i;
        int j;

        //Loop until stopped
        while (_stopped == false) {
            //Poll for interactions if the polling interval has passed
            if (System.currentTimeMillis() - _lastPollTime > COLLAB_POLL_INTERVAL) {
                //Poll for interactions
                interactions = _collabContext.fetchAllCollaboratorInteractions();
                for (i = 0; i < interactions.size(); ++i) {
                    //Pass the interaction to loaded Freddy modules
                    for (j = 0; j < _modules.size(); ++j) {
                        if (_modules.get(j).handleCollaboratorInteraction(interactions.get(i))) {
                            //Interaction has been handled, break
                            break;
                        }
                    }
                }

                //Reset the last poll time
                _lastPollTime = System.currentTimeMillis();
            }

            //Put the thread to sleep for a bit
            try {
                Thread.sleep(THREAD_SLEEP_INTERVAL);
            } catch (InterruptedException ie) {
            }
        }
    }
}
