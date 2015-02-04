package com.ruptech.tttalk.spark;

import asg.cliche.Command;
import asg.cliche.ShellFactory;
import org.jivesoftware.smack.RosterEntry;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.spark.SparkManager;

import java.io.IOException;
import java.util.Collection;

public class Main {

    public static void main(String[] args) throws IOException {
        ShellFactory.createConsoleShell("xmpp", "", new Main()).commandLoop();
    }

    public Main() {
    }

    @Command
    public String getUserDirectory() {
        return SparkManager.getUserDirectory().getPath();
    }

    @Command
    public String getEntries()  {
        Collection<RosterEntry> rosters = SparkManager
                .getConnection().getRoster().getEntries();
        StringBuffer sb =new StringBuffer();
        for (RosterEntry roster:rosters) {
            sb.append(roster.getName()).append('\n');
        }
        
        return sb.toString();
    }

    @Command
    public String login() {
        Login login = new Login("zhao", "zhao", "test");
        boolean result = login.login();
        return String.valueOf(result);
    }

    @Command
    public String logout() {
        final XMPPConnection con = SparkManager.getConnection();
        if (con.isConnected()) {
            con.disconnect();
        }
        return "ok";
    }
}
