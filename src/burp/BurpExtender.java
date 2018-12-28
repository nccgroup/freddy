package burp;

import nb.freddy.Freddy;

/***********************************************************
 * Main burp extension class, delegate work out to the
 * Freddy class.
 *
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BurpExtender {
    private Freddy _freddy;

    public BurpExtender() {
        this._freddy = new Freddy();
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this._freddy.initialise(callbacks);
    }
}