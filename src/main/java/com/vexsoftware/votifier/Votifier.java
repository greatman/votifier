/*
 * Copyright (C) 2012 Vex Software LLC
 * This file is part of Votifier.
 * 
 * Votifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Votifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Votifier.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.vexsoftware.votifier;

import java.io.*;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.*;

import net.canarymod.Canary;
import net.canarymod.config.Configuration;
import net.canarymod.plugin.Plugin;
import net.visualillusionsent.utils.PropertiesFile;
import com.vexsoftware.votifier.crypto.RSAIO;
import com.vexsoftware.votifier.crypto.RSAKeygen;
import com.vexsoftware.votifier.model.ListenerLoader;
import com.vexsoftware.votifier.model.VoteListener;
import com.vexsoftware.votifier.net.VoteReceiver;

/**
 * The main Votifier plugin class.
 * 
 * @author Blake Beaupain
 * @author Kramer Campbell
 */
public class Votifier extends Plugin {

	/** The logger instance. */
	private static final Logger LOG = Logger.getLogger("Votifier");

	/** Log entry prefix */
	private static final String logPrefix = "[Votifier] ";

	/** The Votifier instance. */
	private static Votifier instance;

	/** The vote listeners. */
	private final List<VoteListener> listeners = new ArrayList<VoteListener>();

	/** The vote receiver. */
	private VoteReceiver voteReceiver;

	/** The RSA key pair. */
	private KeyPair keyPair;

	/** Debug mode flag */
	private boolean debug;

	/**
	 * Attach custom log filter to logger.
	 */
	static {
		LOG.setFilter(new LogFilter(logPrefix));
	}

	@Override
	public boolean enable() {
		Votifier.instance = this;

		// Handle configuration.x
        PropertiesFile cfg = getConfig();
        File rsaDirectory = new File(new File(new File(Votifier.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParentFile(), "Votifier"), "rsa");
		// Replace to remove a bug with Windows paths - SmilingDevil
		String listenerDirectory = new File(new File(new File(new File(Votifier.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParentFile(), "Votifier"), "rsa"), "listener").toString();

		/*
		 * Use IP address from server.properties as a default for
		 * configurations. Do not use InetAddress.getLocalHost() as it most
		 * likely will return the main server address instead of the address
		 * assigned to the server.
		 */
		String hostAddr = Configuration.getServerConfig().getBindIp();
        if (hostAddr == null || hostAddr.length() == 0)
			hostAddr = "0.0.0.0";

		/*
		 * Create configuration file if it does not exists; otherwise, load it
		 */
		if (!cfg.containsKey("host")) {
			try {
				// First time run - do some initialization.
				LOG.info("Configuring Votifier for the first time...");

				// Initialize the configuration file.


				cfg.setString("host", hostAddr);
				cfg.setInt("port", 8192);
				cfg.setBoolean("debug", false);

				/*
				 * Remind hosted server admins to be sure they have the right
				 * port number.
				 */
				LOG.info("------------------------------------------------------------------------------");
				LOG.info("Assigning Votifier to listen on port 8192. If you are hosting Craftbukkit on a");
				LOG.info("shared server please check with your hosting provider to verify that this port");
				LOG.info("is available for your use. Chances are that your hosting provider will assign");
				LOG.info("a different port, which you need to specify in config.yml");
				LOG.info("------------------------------------------------------------------------------");

				cfg.setString("listener_folder", listenerDirectory);
				cfg.save();
			} catch (Exception ex) {
				LOG.log(Level.SEVERE, "Error creating configuration file", ex);
				gracefulExit();
				return false;
			}
		}

		/*
		 * Create RSA directory and keys if it does not exist; otherwise, read
		 * keys.
		 */
		try {
			if (!rsaDirectory.exists()) {
				rsaDirectory.mkdirs();
				new File(listenerDirectory).mkdir();
				keyPair = RSAKeygen.generate(2048);
				RSAIO.save(rsaDirectory, keyPair);
			} else {
				keyPair = RSAIO.load(rsaDirectory);
			}
		} catch (Exception ex) {
			LOG.log(Level.SEVERE,
					"Error reading configuration file or RSA keys", ex);
			gracefulExit();
			return false;
		}

		// Load the vote listeners.
		listenerDirectory = cfg.getString("listener_folder");
		listeners.addAll(ListenerLoader.load(listenerDirectory));

		// Initialize the receiver.
		String host = cfg.getString("host", hostAddr);
		int port = cfg.getInt("port", 8192);
		debug = cfg.getBoolean("debug", false);
		if (debug)
			LOG.info("DEBUG mode enabled!");

		try {
			voteReceiver = new VoteReceiver(this, host, port);
			voteReceiver.start();

			LOG.info("Votifier enabled.");
            return true;
		} catch (Exception ex) {
			gracefulExit();
			return false;
		}
	}

	@Override
	public void disable() {
		// Interrupt the vote receiver.
		if (voteReceiver != null) {
			voteReceiver.shutdown();
		}
		LOG.info("Votifier disabled.");
	}

	private void gracefulExit() {
		LOG.log(Level.SEVERE, "Votifier did not initialize properly!");
	}

	/**
	 * Gets the instance.
	 * 
	 * @return The instance
	 */
	public static Votifier getInstance() {
		return instance;
	}

	/**
	 * Gets the listeners.
	 * 
	 * @return The listeners
	 */
	public List<VoteListener> getListeners() {
		return listeners;
	}

	/**
	 * Gets the vote receiver.
	 * 
	 * @return The vote receiver
	 */
	public VoteReceiver getVoteReceiver() {
		return voteReceiver;
	}

	/**
	 * Gets the keyPair.
	 * 
	 * @return The keyPair
	 */
	public KeyPair getKeyPair() {
		return keyPair;
	}

	public boolean isDebug() {
		return debug;
	}

}
