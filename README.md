This is a modified version of the verify_with_emoji.py that was originaly created in the matrix-nio repository and was adapted by wreald to fix a bug of a missing key verification request event.
[Original version](https://github.com/matrix-nio/matrix-nio/blob/45af13b70cc60f4bf7be6cdfd5513b7730ec3108/examples/verify_with_emoji.py)
[Adapted version](https://github.com/wreald/matrix-nio/blob/5cb8e99965bcb622101b1d6ad6fa86f5a9debb9a/examples/verify_with_emoji.py)
[Bug discussion](https://github.com/matrix-nio/matrix-nio/issues/430)

The script create_bot_dir.py prepares a directory that contains a matrix-nio store and a credentials file. It also supports a mechanism to verify the device of the other party by accepting the emoji verification. The created nio bot dir can be used as login credentials for a matrix bot.

To use this script the matrix-nio components for end to end encryption must be installed (see [matrix nio on github](https://github.com/matrix-nio/matrix-nio)). You must have created a Matrix account (for example on [app.element.io](https://app.element.io/)) and have the username and password ready. You have to be logged in to your account with an matrix client like [Element](https://element.io/) or the [browser version of Element](https://app.element.io/).

Start the script and follow the instructions. The script will ask for the device name of the bot. Choose a alphanumeric (can include _) name for the device that is used to recognize the login credentials that you are going to create. The created botdir will be called `botdir_<device_name>` and will be created in the same directory as the script. The program will ask for the homeserver URL, the user ID and the password of the account. Use the same credentials that you use to log in to your account with the matrix client.

After the login was successful the program will wait for the other party to initiate an emoji verification with the bot to verify the cryptographic keys
of the botdir. You now have to initiate the emoji verification with the bot from the other client. In Element you can do this by selecting settings ->
all settings -> sessions -> selecting the session that can be identified by the device name and then selecting "Verify". 

You will be asked to compare the emojis that are displayed on the bot and the other client. If the emojis match you can confirm the verification. Make sure that you first confirm the verification on the other client before you confirm the verification on the bot. After the verification was successful you can use the botdir as login credentials for a matrix bot.

Examples of how to use the botdir with a matrix bot can be found [here](https://github.com/gratach/test-matrix).