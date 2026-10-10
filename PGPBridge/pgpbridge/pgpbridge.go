// Package pgpbridge is a deliberately tiny wrapper around ProtonMail's GopenPGP
// (MIT licence). It contains NO cryptographic algorithms of its own: it only
// unlocks a key once and exposes decrypt / sign+encrypt for the Swift app.
//
// SECURITY CRITICAL: this package handles the user's private key, passphrase
// and decrypted material. It performs no I/O, no logging and no networking.
package pgpbridge

import (
	"errors"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Key is an unlocked OpenPGP private key held in memory only.
type Key struct {
	unlocked *crypto.Key
	ring     *crypto.KeyRing
}

// OpenPrivateKey parses an armored private key and unlocks it with passphrase.
// An empty passphrase is allowed for keys that are not encrypted.
func OpenPrivateKey(armored string, passphrase []byte) (*Key, error) {
	k, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, errors.New("invalid key")
	}
	if !k.IsPrivate() {
		return nil, errors.New("not a private key")
	}
	locked, err := k.IsLocked()
	if err != nil {
		return nil, errors.New("invalid key")
	}
	if locked {
		u, err := k.Unlock(passphrase)
		if err != nil {
			return nil, errors.New("wrong passphrase")
		}
		k.ClearPrivateParams()
		k = u
	}
	ring, err := crypto.NewKeyRing(k)
	if err != nil {
		return nil, errors.New("invalid key")
	}
	return &Key{unlocked: k, ring: ring}, nil
}

// Fingerprint returns the upper-case hex fingerprint of the key.
func (k *Key) Fingerprint() string {
	return k.unlocked.GetFingerprint()
}

// Decrypt decrypts an armored PGP message. If verifyWithPublicKey is non-empty,
// the message signature must be valid for that key or an error is returned.
func (k *Key) Decrypt(armoredMessage string, verifyWithPublicKey string) ([]byte, error) {
	msg, err := crypto.NewPGPMessageFromArmored(armoredMessage)
	if err != nil {
		return nil, errors.New("decrypt failed")
	}
	if verifyWithPublicKey == "" {
		plain, err := k.ring.Decrypt(msg, nil, 0)
		if err != nil {
			return nil, errors.New("decrypt failed")
		}
		return plain.GetBinary(), nil
	}
	pub, err := crypto.NewKeyFromArmored(verifyWithPublicKey)
	if err != nil {
		return nil, errors.New("invalid verification key")
	}
	verifyRing, err := crypto.NewKeyRing(pub)
	if err != nil {
		return nil, errors.New("invalid verification key")
	}
	plain, err := k.ring.Decrypt(msg, verifyRing, crypto.GetUnixTime())
	if err != nil {
		return nil, errors.New("decrypt or signature verification failed")
	}
	return plain.GetBinary(), nil
}

// SignAndEncrypt signs message with this key and encrypts it to recipientPublicKey.
func (k *Key) SignAndEncrypt(message []byte, recipientPublicKey string) (string, error) {
	pub, err := crypto.NewKeyFromArmored(recipientPublicKey)
	if err != nil {
		return "", errors.New("invalid recipient key")
	}
	recipient, err := crypto.NewKeyRing(pub)
	if err != nil {
		return "", errors.New("invalid recipient key")
	}
	enc, err := recipient.Encrypt(crypto.NewPlainMessage(message), k.ring)
	if err != nil {
		return "", errors.New("encrypt failed")
	}
	return enc.GetArmored()
}

// Close wipes the unlocked key material.
func (k *Key) Close() {
	if k.ring != nil {
		k.ring.ClearPrivateParams()
	}
	if k.unlocked != nil {
		k.unlocked.ClearPrivateParams()
	}
}
