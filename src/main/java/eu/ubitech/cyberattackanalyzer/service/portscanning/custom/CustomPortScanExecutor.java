/*
 *  Copyright 2015-2016 Fail2BanAnalyzer
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package eu.ubitech.cyberattackanalyzer.service.portscanning.custom;

import eu.ubitech.cyberattackanalyzer.service.portscanning.IPortScanExecutor;
import eu.ubitech.cyberattackanalyzer.service.portscanning.ScanResult;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Panagiotis Gouvas (pgouvas@ubitech.eu)
 */
public class CustomPortScanExecutor implements IPortScanExecutor {

    private static final Logger logger = Logger.getLogger(CustomPortScanExecutor.class.getName());

    @Override
    public ScanResult scanTarget(String ip) {
        ScanResult sres = new ScanResult();
        //TODO fill scan results
        try {
            final ExecutorService es = Executors.newFixedThreadPool(20);

            final int timeout = 200;
            final List<Future<PortResult>> futures = new ArrayList<>();
            for (int port = 1; port <= 65535; port++) {
                // for (int port = 1; port <= 80; port++) {
                futures.add(portIsOpen(es, ip, port, timeout));
            }
            es.awaitTermination(200L, TimeUnit.MILLISECONDS);
            int openPorts = 0;
            for (final Future<PortResult> f : futures) {
                if (f.get().isOpen()) {
                    openPorts++;
                    //logger.info(""+f.get().getPort());
                }
            }
            logger.info("There are " + openPorts + " open ports on host " + ip + " (probed with a timeout of "
                    + timeout + "ms)");
        } catch (InterruptedException ex) {
            Logger.getLogger(CustomPortScanExecutor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ExecutionException ex) {
            Logger.getLogger(CustomPortScanExecutor.class.getName()).log(Level.SEVERE, null, ex);
        }
        return sres;
    }//EoM

    public static Future<PortResult> portIsOpen(final ExecutorService es, final String ip, final int port,
            final int timeout) {
        return es.submit(new Callable<PortResult>() {
            @Override
            public PortResult call() {
                try {
                    Socket socket = new Socket();
                    socket.connect(new InetSocketAddress(ip, port), timeout);
                    socket.close();
                    return new PortResult(port, true);
                } catch (Exception ex) {
                    return new PortResult(port, false);
                }
            }
        });
    }//EoM

    public static class PortResult {

        private int port;

        private boolean isOpen;

        public PortResult(int port, boolean isOpen) {
            super();
            this.port = port;
            this.isOpen = isOpen;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public boolean isOpen() {
            return isOpen;
        }

        public void setOpen(boolean isOpen) {
            this.isOpen = isOpen;
        }

    }

}
