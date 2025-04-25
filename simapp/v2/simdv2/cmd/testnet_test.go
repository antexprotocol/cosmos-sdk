package cmd_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/require"

	"cosmossdk.io/core/transaction"
	"cosmossdk.io/errors"
	"cosmossdk.io/simapp/v2/simdv2/cmd"

	ecdsaprysm "github.com/OffchainLabs/prysm/v6/crypto/ecdsa"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	ethereumcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

func TestInitTestFilesCmd(t *testing.T) {
	args := []string{
		"testnet", // Test the testnet init-files command
		"init-files",
		fmt.Sprintf("--%s=%s", flags.FlagKeyringBackend, keyring.BackendTest), // Set keyring-backend to test
	}
	rootCmd, err := cmd.NewRootCmd[transaction.Tx](args...)
	require.NoError(t, err)
	rootCmd.SetArgs(args)
	require.NoError(t, rootCmd.Execute())
}

func TestInitBoostrapNodesCmd(t *testing.T) {
	for i := 0; i < 4; i++ {
		privKey, err := privKeyFromFile(fmt.Sprintf("../../../../.testnets/node%d/simdv2/network-keys", i))
		require.NoError(t, err)
		pubKey := ethereumcrypto.FromECDSAPub(privKey.Public().(*ecdsa.PublicKey))
		fmt.Printf("node %d pubkey: %s\n", i, hex.EncodeToString(pubKey))
		// Create ENR record
		// rec := enr.Record{}
		// rec.Set(enr.IP(net.ParseIP(fmt.Sprintf("192.168.10.%d", i+2))))
		// rec.Set(enr.TCP(26656))
		// rec.Set(enr.UDP(26656))

		db, err := enode.OpenDB("")
		require.NoError(t, err)
		lNode := enode.NewLocalNode(db, privKey)
		ip := net.ParseIP(fmt.Sprintf("192.168.10.%d", i+2))
		udpPort := 26656
		tcpPort := 26656
		ipEntry := enr.IP(ip)
		lNode.Set(ipEntry)

		udpEntry := enr.UDP(udpPort)
		lNode.Set(udpEntry)

		tcpEntry := enr.TCP(tcpPort)
		lNode.Set(tcpEntry)

		lNode.SetFallbackIP(ip)
		lNode.SetStaticIP(ip)
		lNode.SetFallbackUDP(udpPort)

		fmt.Printf("tcp: %d\n", lNode.Node().TCP())
		fmt.Printf("udp: %d\n", lNode.Node().UDP())

		record := lNode.Node().Record()
		s, err := serializeENR(record)
		require.NoError(t, err)
		require.NotEqual(t, "", s)
		s = "enr:" + s
		newRec, err := enode.Parse(enode.ValidSchemes, s)
		require.NoError(t, err)
		require.Equal(t, s, newRec.String())
		fmt.Printf("node %d: %s\n", i, newRec.String())
		// Sign record
		// (&rec, privKey)

		// Get node with this record
		// node, err := enode.New(enode.ValidSchemes, &rec)
		// require.NoError(t, err)

		// Get ENR string
		// fmt.Println(node.String())
	}
}

func privKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	src, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err = hex.Decode(dst, src)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode hex string")
	}
	unmarshalledKey, err := crypto.UnmarshalSecp256k1PrivateKey(dst)
	if err != nil {
		return nil, err
	}
	return ecdsaprysm.ConvertFromInterfacePrivKey(unmarshalledKey)
}

// serializeENR takes the enr record in its key-value form and serializes it.
func serializeENR(record *enr.Record) (string, error) {
	if record == nil {
		return "", errors.New("enr", 1, "could not serialize nil record")
	}
	buf := bytes.NewBuffer([]byte{})
	if err := record.EncodeRLP(buf); err != nil {
		return "", errors.Wrap(err, "could not encode ENR record to bytes")
	}
	enrString := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	return enrString, nil
}
