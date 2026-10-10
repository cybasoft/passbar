package pgpbridge

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func TestRoundTrip(t *testing.T) {
	pass := []byte("test-passphrase-not-real")
	armored, err := helper.GenerateKey("Test", "test@example.invalid", pass, "rsa", 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := OpenPrivateKey(armored, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPrivateKey(armored, []byte("wrong")); err == nil {
		t.Fatal("expected wrong passphrase error")
	}
	priv, _ := crypto.NewKeyFromArmored(armored)
	pub, _ := priv.GetArmoredPublicKey()
	enc, err := k.SignAndEncrypt([]byte("hello"), pub)
	if err != nil {
		t.Fatal(err)
	}
	out, err := k.Decrypt(enc, pub)
	if err != nil || string(out) != "hello" {
		t.Fatalf("roundtrip failed: %v", err)
	}
	other, _ := helper.GenerateKey("O", "o@example.invalid", nil, "rsa", 2048)
	op, _ := crypto.NewKeyFromArmored(other)
	opub, _ := op.GetArmoredPublicKey()
	if _, err := k.Decrypt(enc, opub); err == nil {
		t.Fatal("expected signature verification failure")
	}
	k.Close()
}
