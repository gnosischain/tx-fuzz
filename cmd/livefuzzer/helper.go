package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

func getRealBackend() (*rpc.Client, *ecdsa.PrivateKey) {
	sk := crypto.ToECDSAUnsafe(common.FromHex(txfuzz.SK))
	if crypto.PubkeyToAddress(sk.PublicKey).Hex() != txfuzz.ADDR {
		panic(fmt.Sprintf("wrong address want %s got %s", crypto.PubkeyToAddress(sk.PublicKey).Hex(), txfuzz.ADDR))
	}
	cl, err := rpc.Dial(address)
    if err != nil {
        panic(err)
    }
	return cl, sk
}

func sendTx(sk *ecdsa.PrivateKey, backend *ethclient.Client, to common.Address, value *big.Int) error {
	sender := common.HexToAddress(txfuzz.ADDR)
	nonce, err := backend.PendingNonceAt(context.Background(), sender)
	if err != nil {
		fmt.Printf("Could not get pending nonce: %v", err)
	}
	fmt.Printf("Nonce: %v\n", nonce)
	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		return err
	}
	gp, _ := backend.SuggestGasPrice(context.Background())
	tx := types.NewTransaction(nonce, to, value, 500000, gp.Mul(gp.Add(gp, common.Big1), common.Big2), nil)
	signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(chainid), sk)
	return backend.SendTransaction(context.Background(), signedTx)
}

func unstuck(sk *ecdsa.PrivateKey, backend *ethclient.Client, sender, to common.Address, value, gasPrice *big.Int) error {
	blocknumber, err := backend.BlockNumber(context.Background())
	if err != nil {
		return err
	}
	nonce, err := backend.NonceAt(context.Background(), sender, big.NewInt(int64(blocknumber)))
	if err != nil {
		return err
	}
	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("Acc: %v Nonce: %v\n", sender, nonce)
	if gasPrice == nil {
		gasPrice, _ = backend.SuggestGasPrice(context.Background())
	}
	tx := types.NewTransaction(nonce, to, value, 21000, gasPrice.Mul(gasPrice.Add(gasPrice, common.Big1), common.Big2), nil)
	signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(chainid), sk)
	return backend.SendTransaction(context.Background(), signedTx)
}
