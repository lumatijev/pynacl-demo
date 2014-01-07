import curses
import time
import nacl.secret
import nacl.utils
import nacl.encoding
import nacl.signing
import nacl.exceptions
from nacl.public import PrivateKey, Box

def startingSetup(title):
	message = ''
	while message == '':
		screen.clear()
		screen.border(0)
		screen.addstr(1, 1, title, curses.A_STANDOUT)
		screen.addstr(3, 1, 'Enter message to encrypt: ')
		message = screen.getstr(300)
		screen.refresh()
	return message

def endingSetup():
	screen.addstr(positionFix, 1, 'Press any key to continue (or 4 to exit)...')
	screen.refresh()
	return screen.getch()

def symmetricEncryption(toEncrypt):
	#Salsa20 kljuc za enkriptiranje i dekriptiranje poruke
	key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	#"kutija" za enkriptiranje i dekriptiranje poruke
	box = nacl.secret.SecretBox(key)
	#broj koji se koristi samo jednom, ne smatra se tajnim i moze ga se slati uz enkriptiranu poruku
	#dobar izvor za nonce su nasumicna 24 byta
	nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
	#enkriptiranje poruke koja ce potom biti dulja za tocno 40 byta od originalne poruke
	#razlog tome je informacija o autentifikaciji i nonce koji se pohranjuju uz nju
	encrypted = box.encrypt(toEncrypt, nonce, encoder = nacl.encoding.Base64Encoder)
	return box, encrypted

def symmetricDecryption(toDecrypt):
	#dekriptiranje poruke
	return box.decrypt(toDecrypt, encoder = nacl.encoding.Base64Encoder)

def asymmetricEncryption(toEncrypt):
	#generiranje privatnog kljuca posiljatelja koji mora ostati tajan
	skSender = PrivateKey.generate()
	#generiranje javnog kljuca posiljatelja
	pkSender = skSender.public_key
	#generiranje privatnog kljuca primatelja koji mora ostati tajan
	skReceiver = PrivateKey.generate()
	#generiranje javnog kljuca primatelja
	pkReceiver = skReceiver.public_key
	#"kutija" s posiljateljevim privatnim kljucem i primateljevim javnim kljucem
	#sluzi za enkriptiranje poruke
	senderBox = Box(skSender, pkReceiver)
	#broj koji se koristi samo jednom, ne smatra se tajnim i moze ga se slati uz enkriptiranu poruku
	#dobar izvor za nonce su nasumicna 24 byta
	nonce = nacl.utils.random(Box.NONCE_SIZE)
	#enkriptiranje poruke koja ce potom biti dulja za tocno 40 byta od originalne poruke
	#razlog tome je informacija o autentifikaciji i nonce koji se pohranjuju uz nju
	encrypted = senderBox.encrypt(toEncrypt, nonce, encoder = nacl.encoding.Base64Encoder)
	return pkSender, skReceiver, encrypted

def asymmetricDecryption(toDecrypt):
	#"kutija" s primateljevim privatnim kljucem i posiljateljevim javnim kljucem
	#sluzi za dekriptiranje Salsa20 kljuca za dekriptiranje poruke
	receiverBox = Box(skReceiver, pkSender)
	#dekriptiranje Salsa20 kljuca za dekriptiranje poruke
	return receiverBox.decrypt(toDecrypt, encoder = nacl.encoding.Base64Encoder)

def sign(toSign):
	#Ed25519 kljuc za potpisivanje
	signingKey = nacl.signing.SigningKey.generate()
	#potpisivanje enkriptirane poruke Ed25519 kljucem
	signed = signingKey.sign(toSign)
	#dobavljanje kljuca za verifikaciju iz prethodno dobivenog E25519 kljuca za potpisivanje
	verifyKey = signingKey.verify_key
	#serijalizacija kljuca za verifikaciju kako bi se mogao poslati primatelju poruke
	verifyKeySerialized = verifyKey.encode(encoder = nacl.encoding.Base64Encoder)
	return signed, verifyKeySerialized

def verify(toVerify, verificationKey):
	#izrada kljuca za verifikaciju iz serijaliziranog kljuca dobivenog od posiljatelja poruke
	verifyKey = nacl.signing.VerifyKey(verificationKey, encoder = nacl.encoding.Base64Encoder)
	#provjera valjanosti potpisa
	return verifyKey.verify(toVerify)

x = 0

while x != ord('5'):
	screen = curses.initscr()
	curses.curs_set(0)
	curses.start_color()
	curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
	curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
	curses.init_pair(3, curses.COLOR_BLUE, curses.COLOR_BLACK)
	screen.clear()
	screen.border(0)
	screen.addstr(1, 1, 'NaCl: Networking and Cryptography library using PyNaCl', curses.A_STANDOUT)
	screen.addstr(3, 1, 'Choose one:')
	screen.addstr(5, 1, '1) Symmetric encryption')
	screen.addstr(6, 1, '2) Asymmetric encryption')
	screen.addstr(7, 1, '3) Digital envelope')
	screen.addstr(8, 1, '4) Speed test')
	screen.addstr(9, 1, '5) Exit')
	screen.refresh()
	x = screen.getch()

	if x == ord('1'):
		positionFix = 8

		message = startingSetup('Symmetric (secret key) encryption using Salsa20 stream cipher and Poly1305 message authentication code')
		box, encrypted = symmetricEncryption(message)

		screen.addstr(4, 1, 'Encrypted message: ' + encrypted, curses.color_pair(3))
		screen.addstr(6, 1, 'Decrypt message? (y/n): ')
		if screen.getstr(1) in ('y', 'Y'):
			screen.addstr(7, 1, 'Plaintext: ' + symmetricDecryption(encrypted), curses.color_pair(3))
			positionFix += 1

		x = endingSetup()

	if x == ord('2'):
		positionFix = 8

		message = startingSetup('Asymmetric (public key) encryption using Curve25519 elliptic curve cryptography, Salsa20 stream cipher and Poly1305 message authentication code')
		pkSender, skReceiver, encrypted = asymmetricEncryption(message)

		screen.addstr(4, 1, 'Encrypted message: ' + encrypted, curses.color_pair(3))
		screen.addstr(6, 1, 'Decrypt message? (y/n): ')
		if screen.getstr(1) in ('y', 'Y'):
			screen.addstr(7, 1, 'Plaintext: ' + asymmetricDecryption(encrypted), curses.color_pair(3))
			positionFix += 1

		x = endingSetup()

	if x == ord('3'):
		positionFix = 9

		message = startingSetup('Digital envelope (signing using Ed25519 algorithm with SHA-512)')

		pkSender, skReceiver, encrypted = asymmetricEncryption(message)
		screen.addstr(4, 1, 'Encrypted message: ' + encrypted, curses.color_pair(3))

		signed, verifyKeySerialized = sign(encrypted)

		screen.addstr(6, 1, 'Forge signature? (y/n): ', curses.color_pair(2))
		if screen.getstr(1) in ('y', 'Y'):
			signed = 'forge'
			screen.addstr(7, 1, 'Forged signature: ' + signed, curses.color_pair(2))

		try:
			encrypted = verify(signed, verifyKeySerialized)
			screen.addstr(7, 1, 'Signature successfully verified.')
		#prekid u slucaju nevaljalog potpisa
		except nacl.exceptions.BadSignatureError:
			screen.addstr(8, 1, 'Signature was forged or otherwise corrupt!', curses.color_pair(1))
			positionFix += 1

		if signed != 'forge':
			screen.addstr(positionFix, 1, 'Forge message? (y/n): ', curses.color_pair(2))
			if screen.getstr(1) in ('y', 'Y'):
				encrypted = str.replace(encrypted, encrypted[:5], 'forge')
				screen.addstr(10, 1, 'Forged message: ' + encrypted, curses.color_pair(2))
				positionFix += 1
			positionFix += 2

		if signed != 'forge':
			screen.addstr(positionFix, 1, 'Decrypt message? (y/n): ')
			positionFix += 1
			if screen.getstr(1) in ('y', 'Y'):
				try:
					screen.addstr(positionFix, 1, 'Plaintext: ' + asymmetricDecryption(encrypted), curses.color_pair(3))
				#prekid u slucaju nevaljalog kriptiranog teksta
				except nacl.exceptions.CryptoError:
					screen.addstr(positionFix, 1, 'Decryption failed. Ciphertext failed verification!', curses.color_pair(1))
				positionFix += 1
			positionFix += 1

		x = endingSetup()

	if x == ord('4'):
		k = 0
		while k not in (ord('1'), ord('2'), ord('3'), ord('4')):
			screen.clear()
			screen.border(0)
			screen.addstr(1, 1, 'Speed testing NaCl library cryptography methods', curses.A_STANDOUT)
			screen.addstr(3, 1, 'Choose number of lorem ipsum words (txt file size):')
			screen.addstr(5, 1, '1) 1 (5b)')
			screen.addstr(6, 1, '2) 10 (72b)')
			screen.addstr(7, 1, '3) 1000 (7,5kB)')
			screen.addstr(8, 1, '4) 1000000 (7,5MB)')
			screen.refresh()
			k = screen.getch(9, 1)
			screen.clear()

		screen.border(0)
		screen.addstr(1, 1, 'Speed testing NaCl library cryptography methods', curses.A_STANDOUT)

		data = open('test/lorem' + chr(k) + '.txt').read()

		startingTime = time.time()
		box, encrypted = symmetricEncryption(data)
		endingTime = time.time() - startingTime
		screen.addstr(3, 1, 'Encrypted: ' + encrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		startingTime = time.time()
		decrypted = symmetricDecryption(encrypted)
		endingTime = time.time() - startingTime
		screen.addstr(4, 1, 'Decrypted: ' + decrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		startingTime = time.time()
		pkSender, skReceiver, encrypted = asymmetricEncryption(data)
		endingTime = time.time() - startingTime
		screen.addstr(6, 1, 'Encrypted: ' + encrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		startingTime = time.time()
		decrypted = asymmetricDecryption(encrypted)
		endingTime = time.time() - startingTime
		screen.addstr(7, 1, 'Decrypted: ' + decrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		startingTime = time.time()
		pkSender, skReceiver, encrypted = asymmetricEncryption(data)
		signed, verifyKeySerialized = sign(encrypted)
		endingTime = time.time() - startingTime
		screen.addstr(9, 1, 'Digital envelope: ' + encrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		startingTime = time.time()
		decrypted = asymmetricDecryption(verify(signed, verifyKeySerialized))
		endingTime = time.time() - startingTime
		screen.addstr(10, 1, 'Verify and decrypt: ' + decrypted[:50] + "..., in %.10f seconds" % endingTime, curses.color_pair(3))

		screen.addstr(12, 1, 'Press any key to continue (or 4 to exit)...')
		screen.refresh()
		x = screen.getch()

curses.endwin()
