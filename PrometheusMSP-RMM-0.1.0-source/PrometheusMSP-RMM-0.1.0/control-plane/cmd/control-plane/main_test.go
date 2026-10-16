package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadJobSigningKeyPEM(t *testing.T) {
	seed:=make([]byte,ed25519.SeedSize);for i:=range seed{seed[i]=byte(31-i)};want:=ed25519.NewKeyFromSeed(seed)
	der,err:=x509.MarshalPKCS8PrivateKey(want);if err!=nil{t.Fatal(err)}
	path:=filepath.Join(t.TempDir(),"signing.pem");if err:=os.WriteFile(path,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der}),0600);err!=nil{t.Fatal(err)}
	got,err:=loadJobSigningKey(path,"");if err!=nil{t.Fatal(err)};if !got.Equal(want){t.Fatal("loaded key does not match")}
}
