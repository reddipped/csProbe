package com.reddipped.csprobe;

import java.util.ArrayDeque;

/**
 * Singleton which maintains the most recent probe status results across 
 * multiple instances of the servlet.
 * 
 */
public class CSProbeHistory {

    private static ArrayDeque<String> hitlist = new ArrayDeque<String>() ;
    private static final Integer MAXHITS = 25 ;
    private static volatile CSProbeHistory instance = null; 
    private CSProbeHistory() {}
 
    /**
     * 
     * @return CSProbeHistory instance
     */
    public static CSProbeHistory getInstance() {
        if (instance == null) {
            synchronized (CSProbeHistory .class){
                if (instance == null) {
                    instance = new CSProbeHistory ();
                }
            }
        }
        return instance;
    }
    
    /**
     * This method adds a record to the probe result history. To each hit a 
     * date/timestamp is prepended. 
     * 
     * @param hit data to be logged
     */
    public void addHit(String hit) {
        
        hitlist.addFirst(hit);

        // Trunc list of status lines
        if (hitlist.size() >= MAXHITS) {
            hitlist.removeLast() ;
        }
    }
    
    /**
     * This method returns the current list of probe results.
     * @return List of probe results
     */
    public ArrayDeque<String> getHits() {
        return hitlist ;
    }
    
        
}
