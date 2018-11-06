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
package org.apache.sshd.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.sshd.client.auth.pubkey.KeyPairIdentity;
import org.apache.sshd.client.auth.pubkey.PublicKeyIdentity;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.signature.SignatureFactoriesManager;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ClientKeyLoadTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	private int fileCount;

	@Before
	public void setUp() {
		fileCount = 0;
	}

	@Test
	public void createKeyIdentityIterator() throws Exception {
		// Set up two key pair providers reading keys. It doesn't matter whether it's the same
		// key here. Note that we cannot use CommonTestSupportUtils.createTestKeyPairProvider();
		// that one return a provider that has already loaded and cached its keys, but we want
		// to test exactly the original loading from the files here.
		AtomicInteger count = new AtomicInteger(0);
		KeyPairProvider first = createTestKeyPairProvider(count, "dsaprivkey.pem", "dsaprivkey.pem");
		KeyPairProvider second = createTestKeyPairProvider(count, "hostkey.pem", "hostkey.pem");
		Collection<Stream<? extends PublicKeyIdentity>> identities = new LinkedList<>();
		Iterator<? extends PublicKeyIdentity> current;
		// Create a dummy SignatureFactoriesManager. We don't ever use these keys to sign
		// anything.
		SignatureFactoriesManager dummyManager = new DummySignatureFactoriesManager();
		// Perform the same iterator setup as the UserAuthPublicKeyIterator constructor.
		// In real usage the first would be session.getRegisteredIdentities(), and the
		// second would be session.getKeyPairProvider().
		identities.add(Stream.of(KeyIdentityProvider.resolveKeyIdentityProvider(first, second))
				.map(KeyIdentityProvider::loadKeys)
				.flatMap(GenericUtils::stream)
				.map(kp -> new KeyPairIdentity(dummyManager, dummyManager, kp)));

		current = identities.stream().flatMap(r -> r).iterator();
		// Now test that iterator. If it loads the i'th key before the i'th hasNext() or
		// next(), there is a problem: if that i'th key is encrypted, an IdentityPasswordProvider
		// will be called, and the user gets prompted for a password of a key that may not even
		// be used! (If the (i-1)'th key authenticates already.) Such preloading *must not* occur!
		//
		// Pre-loading keys is bad anyway, even for unencrypted keys; one doesn't want to keep
		// private keys in memory needlessly. BTW, when is that cache inside FileKeyPairProvider
		// cleared?
		assertNotNull("KeyIdentity iterator should not be null", current);
		assertEquals("No key should have been loaded yet", 0, count.get());
		int i = 1;
		while (current.hasNext()) {
			assertNotNull("Key #" + i + " unexpectedly null", current.next());
			assertEquals("A key was loaded prematurely", i, count.get());
			i++;
		}
		assertEquals("Unexpected number of keys", 4, i - 1);
	}

	private Path getFile(String resource) {
		// Copy the key from the bundle into the file system at a unique path.
		try (InputStream in = CommonTestSupportUtils.class.getClassLoader().getResourceAsStream(resource)) {
			Path target = folder.newFolder("tmpkey" + fileCount++).toPath().resolve(resource);
			Files.copy(in, target);
			return target;
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private KeyPairProvider createTestKeyPairProvider(AtomicInteger count, String... resources) {
		FileKeyPairProvider provider = new FileKeyPairProvider() {
			@Override
			protected KeyPair doLoadKey(String resourceKey, InputStream inputStream, FilePasswordProvider provider)
					throws IOException, GeneralSecurityException {
				count.incrementAndGet();
				System.out.println("Loading key " + resourceKey);
				return super.doLoadKey(resourceKey, inputStream, provider);
			}
		};
		if (resources != null && resources.length > 0) {
			List<Path> paths = Arrays.stream(resources).map(this::getFile).collect(Collectors.toList());
			provider.setPaths(paths);
		}
		return provider;
	}

	private static class DummySignatureFactoriesManager implements SignatureFactoriesManager {

		@Override
		public List<NamedFactory<Signature>> getSignatureFactories() {
			// Must return something! Doesn't matter what; we're never going to use it.
			// "new KeyPairIdentity(...)" checks that the the returned list is not empty.
			// It does *not* check that the non-empty list doesn't contain null values...
			return Collections.singletonList(null);
		}

		@Override
		public void setSignatureFactories(List<NamedFactory<Signature>> factories) {
			// Not used
		}
	}
}
