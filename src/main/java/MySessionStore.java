import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class MySessionStore implements SessionStore, Serializable {

    private Map<Pair<String, Integer>, byte[]> sessions = new HashMap<Pair<String, Integer>, byte[]>();

    public MySessionStore() {}

    public synchronized SessionRecord loadSession(SignalProtocolAddress remoteAddress) {
        try {
            if (containsSession(remoteAddress)) {
                return new SessionRecord(sessions.get(new Pair<String, Integer>(remoteAddress.getName(), remoteAddress.getDeviceId())));
            } else {
                return new SessionRecord();
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public synchronized List<Integer> getSubDeviceSessions(String name) {
        List<Integer> deviceIds = new LinkedList<Integer>();

        for (Pair<String, Integer> key : sessions.keySet()) {
            if (name.equals(new SignalProtocolAddress(key.getLeft(), key.getRight())) &&
                    key.getRight() != 1)
            {
                deviceIds.add(key.getRight());
            }
        }

        return deviceIds;
    }

    public synchronized void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessions.put(new Pair<String, Integer>(address.getName(), address.getDeviceId()), record.serialize());
    }

    public synchronized boolean containsSession(SignalProtocolAddress address) {
        return sessions.containsKey(new Pair<String, Integer>(address.getName(), address.getDeviceId()));
    }

    public synchronized void deleteSession(SignalProtocolAddress address) {
        sessions.remove(address);
    }

    public synchronized void deleteAllSessions(String name) {
        for (Pair<String, Integer> key : sessions.keySet()) {
            if (key.getLeft().equals(name)) {
                sessions.remove(key);
            }
        }
    }
}

