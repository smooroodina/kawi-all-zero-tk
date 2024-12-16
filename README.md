Build(need to done once):

	  cd ../hostapd
	  cp defconfig .config
	  make -j 2

Run:

	  cd krackattack
	  # See `command_examples.txt`.


If "connect exception" occured at wpaspy.py, run this modified hostapd directry and check the entire error message.
	 ../hostap-ct/hostapd/hostapd hostapd_rogue.conf