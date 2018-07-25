/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.io;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Set;

import org.apache.sshd.common.util.GenericUtils;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface IoAcceptor extends IoService {
    int DEFAULT_BACKLOG = 0;

    void bind(Collection<? extends SocketAddress> addresses) throws IOException;

    void bind(SocketAddress address) throws IOException;

    void unbind(Collection<? extends SocketAddress> addresses);

    void unbind(SocketAddress address);

    void unbind();

    Set<SocketAddress> getBoundAddresses();

    /**
     * @param acceptor The {@link IoAcceptor} - ignored if {@code null}
     * @return The port associated with the <u>first</u> bound address - {@code -1} if none available
     * @see #resolveBoundAddress(IoAcceptor)
     */
    static int resolveBoundPort(IoAcceptor acceptor) {
        SocketAddress boundEndpoint = resolveBoundAddress(acceptor);
        if (boundEndpoint instanceof InetSocketAddress) {
            return ((InetSocketAddress) boundEndpoint).getPort();
        }

        return -1;
    }

    /**
     * @param acceptor The {@link IoAcceptor} - ignored if {@code null}
     * @return The <u>first</u> bound address - {@code null} if none available
     * @see #getBoundAddresses()
     */
    static SocketAddress resolveBoundAddress(IoAcceptor acceptor) {
        Collection<SocketAddress> boundAddresses = (acceptor == null) ? Collections.emptySet() : acceptor.getBoundAddresses();
        if (GenericUtils.isEmpty(boundAddresses)) {
            return null;
        }
        Iterator<SocketAddress> boundIterator = boundAddresses.iterator();
        return boundIterator.next();
    }
}
